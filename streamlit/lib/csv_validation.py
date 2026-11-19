"""CSV request contract validation (design section 5). Pure functions - no Snowflake calls."""
from __future__ import annotations

import csv
import hashlib
import io
import re
from typing import Iterable

EXPECTED_HEADERS = ["username", "email", "first_name", "last_name", "role_name", "default_role", "action"]
ACTIONS = {"ONBOARD", "ADD_ROLES", "SET_MANAGED_ROLES", "DISABLE", "REENABLE"}
MAX_BYTES = 1_000_000
MAX_ROWS = 2_000
MAX_NEW_ROLES = 10
# Snowflake system roles; never auto-created or granted from CSV regardless of BLOCKED_ROLES contents.
SYSTEM_ROLES = {"ACCOUNTADMIN", "SECURITYADMIN", "USERADMIN", "SYSADMIN", "ORGADMIN", "GLOBALORGADMIN", "PUBLIC"}

USER_RE = re.compile(r"^[A-Z][A-Z0-9_]{1,127}$")
ROLE_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,254}$")
EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9.\-]{1,190}\.[A-Za-z]{2,24}$")
NAME_RE = re.compile(r"^[A-Za-z][A-Za-z' .\-]{0,63}$")
FORBIDDEN_CONTENT = re.compile(
    r"(-----BEGIN|password|passwd|secret|private[_ ]?key|\botp\b|\bseed\b|https?://|;|--|/\*"
    r"|\b(select|grant|create|drop|alter|insert|delete|policy)\b)",
    re.IGNORECASE)


class CsvError(ValueError):
    pass


def file_sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def parse(data: bytes) -> list[dict]:
    if len(data) > MAX_BYTES:
        raise CsvError(f"File exceeds {MAX_BYTES} bytes")
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError as e:
        raise CsvError("File must be UTF-8 encoded") from e
    reader = csv.DictReader(io.StringIO(text))
    headers = [h.strip().lower() for h in (reader.fieldnames or [])]
    if headers != EXPECTED_HEADERS:
        raise CsvError(f"Headers must be exactly: {','.join(EXPECTED_HEADERS)}")
    rows = []
    for i, raw in enumerate(reader, start=2):  # header is line 1
        if i - 1 > MAX_ROWS:
            raise CsvError(f"More than {MAX_ROWS} rows")
        if None in raw:
            raise CsvError(f"Line {i}: too many columns")
        rows.append({"row_number": i, **{k.strip().lower(): (v or "").strip() for k, v in raw.items()}})
    if not rows:
        raise CsvError("No data rows")
    return rows


def validate(rows: list[dict], *, allowed_roles: dict[str, bool], blocked_roles: Iterable[str],
             email_domains: Iterable[str], protected_users: Iterable[str],
             existing_users: dict[str, dict], disabled_roles: Iterable[str] = (),
             allow_new_roles: bool = True, max_new_roles: int = MAX_NEW_ROLES) -> list[dict]:
    """
    allowed_roles: ROLE_NAME -> is_default_eligible (active catalog entries)
    disabled_roles: catalog entries that are inactive or APPROVAL_CLASS BLOCKED (never re-enabled by CSV)
    existing_users: USERNAME -> {"IS_MANAGED": bool, "IDENTITY_CLASS": str}
    Roles with no catalog row at all are marked creates_role=True (created on approval) when allow_new_roles.
    """
    blocked = {r.upper() for r in blocked_roles}
    disabled = {r.upper() for r in disabled_roles}

    def is_new(name: str) -> bool:
        return (allow_new_roles and bool(ROLE_RE.match(name)) and name not in allowed_roles
                and name not in disabled and name not in blocked and name not in SYSTEM_ROLES)
    domains = {d.lower().lstrip("@") for d in email_domains}
    protected = {p.upper() for p in protected_users}
    out = []
    seen_ci: dict[str, str] = {}
    per_user: dict[str, tuple] = {}

    for r in rows:
        f: list[str] = []
        notes: list[str] = []
        creates_role = False
        username = r["username"].upper()
        action = r["action"].upper()
        role = r["role_name"].upper()
        default_role = r["default_role"].upper()

        for k, v in r.items():
            if k != "row_number" and v and FORBIDDEN_CONTENT.search(v):
                f.append(f"{k}: forbidden content")
        if not USER_RE.match(username):
            f.append("username: must match ^[A-Z][A-Z0-9_]{1,127}$")
        prev = seen_ci.setdefault(username, r["username"])
        if prev != r["username"]:
            f.append("username: case collision with another row")
        if action not in ACTIONS:
            f.append(f"action: must be one of {sorted(ACTIONS)}")
        if username in protected:
            f.append("username: protected identity")
        ex = existing_users.get(username)
        if ex and ex.get("IDENTITY_CLASS") == "INTERNAL_ADMIN":
            f.append("username: internal admin identities cannot be managed by CSV")
        if ex and not ex.get("IS_MANAGED"):
            f.append("username: existing unmanaged user (adoption requires separate approval)")
        if action in ("ADD_ROLES", "SET_MANAGED_ROLES", "DISABLE", "REENABLE") and not ex:
            f.append("username: not an app-managed user")

        if action in ("ONBOARD", "ADD_ROLES", "SET_MANAGED_ROLES"):
            if not EMAIL_RE.match(r["email"]):
                f.append("email: invalid")
            elif domains and r["email"].split("@")[-1].lower() not in domains:
                f.append("email: domain not approved for this account")
            for k in ("first_name", "last_name"):
                if r[k] and not NAME_RE.match(r[k]):
                    f.append(f"{k}: invalid characters")
            if not role:
                f.append("role_name: required")
            elif role in blocked or (role in SYSTEM_ROLES and role not in allowed_roles):
                f.append(f"role_name: {role} is blocked")
            elif role in disabled:
                f.append("role_name: disabled or blocked in this account's role catalog")
            elif is_new(role):
                creates_role = True
                notes.append(f"role_name: {role} will be created (new role)")
            elif not ROLE_RE.match(role) or role not in allowed_roles:
                f.append("role_name: not in this account's role catalog")
            if default_role:
                if is_new(default_role):
                    pass  # new roles are created default-eligible
                elif default_role in blocked or default_role not in allowed_roles:
                    f.append("default_role: not allowed")
                elif not allowed_roles.get(default_role):
                    f.append("default_role: not default-eligible")
        elif role or default_role:
            f.append("role_name/default_role: must be empty for DISABLE/REENABLE")

        sig = (r["email"].lower(), default_role, action, r["first_name"], r["last_name"])
        if username in per_user and per_user[username] != sig:
            f.append("rows for this username disagree on identity, default role or action")
        per_user.setdefault(username, sig)

        out.append({
            "row_number": r["row_number"], "username": username, "email": r["email"] or None,
            "first_name": r["first_name"] or None, "last_name": r["last_name"] or None,
            "role_name": role or None, "default_role": default_role or None, "action": action,
            "is_valid": not f, "findings": f, "notes": notes, "creates_role": creates_role,
        })

    # cap distinct new roles per batch
    seen_new: list[str] = []
    for o in out:
        if o["creates_role"] and o["role_name"] not in seen_new:
            seen_new.append(o["role_name"])
    over = set(seen_new[max_new_roles:])
    for o in out:
        if o["creates_role"] and o["role_name"] in over:
            o["findings"].append(f"role_name: more than {max_new_roles} new roles in one batch")
            o["is_valid"] = False

    # default role must be among the user's requested roles
    roles_by_user: dict[str, set] = {}
    for o in out:
        if o["role_name"]:
            roles_by_user.setdefault(o["username"], set()).add(o["role_name"])
    for o in out:
        if o["default_role"] and o["default_role"] not in roles_by_user.get(o["username"], set()):
            o["findings"].append("default_role: must be one of the user's requested roles")
            o["is_valid"] = False
    return out


def new_roles(results: list[dict], excluded_rows: Iterable[int] = ()) -> list[str]:
    """Distinct roles to be created by the valid, non-excluded rows, in first-seen order."""
    skip = set(excluded_rows)
    out: list[str] = []
    for o in results:
        if o["creates_role"] and o["is_valid"] and o["row_number"] not in skip and o["role_name"] not in out:
            out.append(o["role_name"])
    return out
