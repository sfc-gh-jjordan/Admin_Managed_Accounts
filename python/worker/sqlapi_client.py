"""
sqlapi_client.py
Minimal, hardened Snowflake SQL API v2 client for use inside a Snowflake
Python stored procedure that has an EXTERNAL ACCESS INTEGRATION and a
GENERIC_STRING secret containing the PEM private key.

Design references (section 11):
  * short-lived key-pair JWT, canonical account/user, SHA256 fingerprint
  * regional / org hostname kept separate from JWT account identity
  * explicit role on every request, one statement per request
  * durable requestId reused on retry (retry=true)
  * async (202) polling, result partitions
  * bounded polling + exponential backoff, no cross-host redirects
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Optional

import jwt  # PyJWT
import requests
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

_HOST_RE = re.compile(r"^[a-z0-9][a-z0-9._-]*\.snowflakecomputing\.com$")
_RETRYABLE_HTTP = {408, 429, 500, 502, 503, 504}
JWT_LIFETIME_SECONDS = 59 * 60
USER_AGENT = "acct-admin-worker/1.0"


class SqlApiError(Exception):
    def __init__(self, message: str, http_status: Optional[int] = None,
                 sf_code: Optional[str] = None, handle: Optional[str] = None,
                 uncertain: bool = False):
        super().__init__(message)
        self.http_status = http_status
        self.sf_code = sf_code
        self.handle = handle
        # uncertain=True means the statement may or may not have executed
        # remotely; caller must re-read target state before retrying.
        self.uncertain = uncertain


@dataclass
class StatementResult:
    request_id: str
    handle: Optional[str]
    columns: list[str] = field(default_factory=list)
    rows: list[list[Any]] = field(default_factory=list)
    sf_code: Optional[str] = None
    message: Optional[str] = None
    http_status: Optional[int] = None

    def as_dicts(self) -> list[dict[str, Any]]:
        return [dict(zip(self.columns, r)) for r in self.rows]


def redact(text: Optional[str], limit: int = 800) -> Optional[str]:
    """Strip anything that looks like a token, key, or URL query before logging."""
    if text is None:
        return None
    t = re.sub(r"-----BEGIN[\s\S]*?-----END[^-]*-----", "[REDACTED_KEY]", str(text))
    t = re.sub(r"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+", "[REDACTED_JWT]", t)
    t = re.sub(r"https?://\S+", "[REDACTED_URL]", t)
    return t[:limit]


class SnowflakeSqlApiClient:
    def __init__(self, host: str, jwt_account: str, user: str, private_key_pem: str,
                 role: str, warehouse: Optional[str] = None,
                 expected_fingerprint: Optional[str] = None,
                 timeout_s: int = 60, max_poll_s: int = 300, max_retries: int = 4):
        host = (host or "").strip().lower()
        if not _HOST_RE.match(host):
            raise ValueError("SQL API host is not a registered snowflakecomputing.com host")
        self.base_url = f"https://{host}"
        self.host = host
        # JWT account: uppercase, '.' -> '-' (org-account form) ; locator form must
        # NOT include region suffix.
        self.jwt_account = jwt_account.strip().upper().replace(".", "-")
        self.user = user.strip().upper()
        self.role = role
        self.warehouse = warehouse
        self.timeout_s = timeout_s
        self.max_poll_s = max_poll_s
        self.max_retries = max_retries

        self._private_key = serialization.load_pem_private_key(
            private_key_pem.encode(), password=None, backend=default_backend())
        self.fingerprint = self._fingerprint()
        if expected_fingerprint and expected_fingerprint.strip() != self.fingerprint:
            raise ValueError("Private key fingerprint does not match registry PUBLIC_KEY_FP")

        self._jwt: Optional[str] = None
        self._jwt_exp = 0.0
        self._http = requests.Session()
        self._http.max_redirects = 0

    # ------------------------------------------------------------------ auth
    def _fingerprint(self) -> str:
        der = self._private_key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        return "SHA256:" + base64.b64encode(hashlib.sha256(der).digest()).decode()

    def _token(self) -> str:
        now = time.time()
        if self._jwt and now < self._jwt_exp - 120:
            return self._jwt
        qualified = f"{self.jwt_account}.{self.user}"
        payload = {
            "iss": f"{qualified}.{self.fingerprint}",
            "sub": qualified,
            "iat": int(now),
            "exp": int(now + JWT_LIFETIME_SECONDS),
        }
        self._jwt = jwt.encode(payload, self._private_key, algorithm="RS256")
        self._jwt_exp = now + JWT_LIFETIME_SECONDS
        return self._jwt

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self._token()}",
            "X-Snowflake-Authorization-Token-Type": "KEYPAIR_JWT",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": USER_AGENT,
        }

    # --------------------------------------------------------------- request
    def _request(self, method: str, path: str, *, params=None, body=None) -> requests.Response:
        url = self.base_url + path
        resp = self._http.request(method, url, headers=self._headers(), params=params,
                                  data=json.dumps(body) if body is not None else None,
                                  timeout=self.timeout_s, allow_redirects=False, verify=True)
        if 300 <= resp.status_code < 400:
            raise SqlApiError("Redirect refused", http_status=resp.status_code)
        if resp.status_code == 401:
            # expired / bad JWT: force regeneration once
            self._jwt = None
        return resp

    def execute(self, statement: str, *, request_id: Optional[str] = None,
                bindings: Optional[dict] = None, timeout: int = 60) -> StatementResult:
        """Submit ONE statement. Reuses request_id on retry so Snowflake de-duplicates."""
        request_id = request_id or str(uuid.uuid4())
        body: dict[str, Any] = {
            "statement": statement,
            "timeout": timeout,
            "role": self.role,
            "parameters": {"MULTI_STATEMENT_COUNT": "1", "QUERY_TAG": f"acct_admin:{request_id}"},
        }
        if self.warehouse:
            body["warehouse"] = self.warehouse
        if bindings:
            body["bindings"] = bindings

        attempt = 0
        last_exc: Optional[Exception] = None
        while attempt <= self.max_retries:
            params = {"requestId": request_id}
            if attempt > 0:
                params["retry"] = "true"
            try:
                resp = self._request("POST", "/api/v2/statements", params=params, body=body)
            except (requests.ConnectionError, requests.Timeout) as exc:
                last_exc = exc
                attempt += 1
                time.sleep(min(2 ** attempt, 30))
                continue

            if resp.status_code in (200, 202):
                return self._complete(resp, request_id)
            if resp.status_code == 401 and attempt == 0:
                attempt += 1
                continue
            if resp.status_code in _RETRYABLE_HTTP:
                attempt += 1
                time.sleep(min(2 ** attempt, 30))
                continue
            raise self._error_from(resp)

        raise SqlApiError(f"SQL API unreachable after retries: {redact(str(last_exc))}",
                          uncertain=True)

    def _complete(self, resp: requests.Response, request_id: str) -> StatementResult:
        data = resp.json()
        handle = data.get("statementHandle")
        deadline = time.time() + self.max_poll_s
        delay = 0.5
        while resp.status_code == 202:
            if time.time() > deadline:
                raise SqlApiError("Statement still running after poll limit",
                                  http_status=202, handle=handle, uncertain=True)
            time.sleep(delay)
            delay = min(delay * 2, 10)
            resp = self._request("GET", f"/api/v2/statements/{handle}")
            if resp.status_code not in (200, 202):
                if resp.status_code in _RETRYABLE_HTTP:
                    resp.status_code = 202  # keep polling
                    continue
                raise self._error_from(resp, handle)
            data = resp.json()

        meta = data.get("resultSetMetaData") or {}
        columns = [c.get("name") for c in meta.get("rowType", [])]
        rows = list(data.get("data") or [])
        partitions = meta.get("partitionInfo") or []
        for idx in range(1, len(partitions)):
            p = self._request("GET", f"/api/v2/statements/{handle}", params={"partition": idx})
            if p.status_code != 200:
                raise self._error_from(p, handle)
            rows.extend(p.json().get("data") or [])

        return StatementResult(request_id=request_id, handle=handle, columns=columns, rows=rows,
                               sf_code=data.get("code"), message=data.get("message"),
                               http_status=200)

    def _error_from(self, resp: requests.Response, handle: Optional[str] = None) -> SqlApiError:
        try:
            data = resp.json()
        except ValueError:
            data = {}
        return SqlApiError(redact(data.get("message") or resp.text) or "SQL API error",
                           http_status=resp.status_code, sf_code=data.get("code"),
                           handle=handle or data.get("statementHandle"))

    def cancel(self, handle: str) -> None:
        self._request("POST", f"/api/v2/statements/{handle}/cancel")
