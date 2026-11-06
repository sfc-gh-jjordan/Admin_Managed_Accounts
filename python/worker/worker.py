"""
worker.py
Per-account execution engine. Invoked ONLY through the generated procedure
ACCT_ADMIN_DB.WORKER.EXEC_<ACCOUNT_ID>(MAX_OPS, MODE), which binds this
account's secret + external access integration at CREATE time.

MODE:
  PREFLIGHT  - verify JWT/host/account/role, no changes
  QUEUE      - claim and execute approved operations for this account
  RECONCILE  - read-only drift detection; updates central inventory only

Flow per operation: claim -> verify version/target -> preflight -> execute
fixed steps -> read back -> record (design sections 8-11).
"""
from __future__ import annotations

import json
import re
import traceback
import uuid
from typing import Any, Optional

import _snowflake  # available inside Snowflake Python procedures

import actions as A
from sqlapi_client import SnowflakeSqlApiClient, SqlApiError, redact

CTL = "ACCT_ADMIN_DB.CONTROL"
SECRET_ALIAS = "sqlapi_key"
CIRCUIT_BREAKER_THRESHOLD = 5
URL_RE = re.compile(r"https://[^\s'\"]+")


class Blocked(Exception):
    """Operation cannot proceed safely; requires human review (no retry)."""


# =====================================================================
# Central (EIGHTY451) data helpers - always parameter-bound
# =====================================================================
def q(session, sql: str, params: Optional[list] = None) -> list[dict]:
    return [r.as_dict() for r in session.sql(sql, params=params or []).collect()]


def x(session, sql: str, params: Optional[list] = None) -> None:
    session.sql(sql, params=params or []).collect()


def audit(session, event_type: str, account_id: str, username: Optional[str],
          operation_id: Optional[str], details: dict) -> None:
    x(session, f"""INSERT INTO {CTL}.AUDIT_EVENTS (ACTOR, EVENT_TYPE, ACCOUNT_ID, USERNAME, OPERATION_ID, DETAILS)
                   SELECT 'WORKER', ?, ?, ?, ?, PARSE_JSON(?)""",
      [event_type, account_id, username, operation_id, json.dumps(details, default=str)])


def load_account(session, account_id: str) -> dict:
    rows = q(session, f"SELECT * FROM {CTL}.CUSTOMER_ACCOUNTS WHERE ACCOUNT_ID = ?", [account_id])
    if not rows:
        raise Blocked(f"account {account_id} not registered")
    return rows[0]


def as_list(v) -> list:
    if v is None:
        return []
    if isinstance(v, str):
        try:
            return json.loads(v)
        except ValueError:
            return [v]
    return list(v)


def as_obj(v) -> dict:
    if v is None:
        return {}
    return json.loads(v) if isinstance(v, str) else dict(v)


# =====================================================================
# Remote execution with step recording
# =====================================================================
class StepRunner:
    def __init__(self, session, client: SnowflakeSqlApiClient, operation_id: Optional[str]):
        self.session = session
        self.client = client
        self.operation_id = operation_id
        self.step_no = 0

    def run(self, name: str, statement: str, *, record: bool = True, timeout: int = 60):
        self.step_no += 1
        request_id = str(uuid.uuid4())
        step_id = str(uuid.uuid4())
        if record and self.operation_id:
            x(self.session, f"""INSERT INTO {CTL}.OPERATION_STEPS
                    (STEP_ID, OPERATION_ID, STEP_NO, STEP_NAME, REQUEST_ID, SQL_TEMPLATE, OUTCOME)
                    VALUES (?, ?, ?, ?, ?, ?, 'RUNNING')""",
              [step_id, self.operation_id, self.step_no, name, request_id, name])
        try:
            res = self.client.execute(statement, request_id=request_id, timeout=timeout)
        except SqlApiError as e:
            if record and self.operation_id:
                x(self.session, f"""UPDATE {CTL}.OPERATION_STEPS SET OUTCOME = ?, HTTP_STATUS = ?, SF_CODE = ?,
                        STATEMENT_HANDLE = ?, ERROR = ?, FINISHED_AT = CURRENT_TIMESTAMP() WHERE STEP_ID = ?""",
                  ["UNCERTAIN" if e.uncertain else "FAILED", e.http_status, e.sf_code, e.handle,
                   redact(str(e)), step_id])
            raise
        if record and self.operation_id:
            x(self.session, f"""UPDATE {CTL}.OPERATION_STEPS SET OUTCOME = 'SUCCEEDED', HTTP_STATUS = ?, SF_CODE = ?,
                    STATEMENT_HANDLE = ?, FINISHED_AT = CURRENT_TIMESTAMP() WHERE STEP_ID = ?""",
              [res.http_status, res.sf_code, res.handle, step_id])
        return res


# =====================================================================
# Remote state readers
# =====================================================================
def remote_user(r: StepRunner, username: str) -> Optional[dict]:
    res = r.run("SHOW_USER", A.show_user(username))
    for row in res.as_dicts():
        if (row.get("name") or "").upper() == username.upper():
            return row
    return None


def remote_grants(r: StepRunner, username: str) -> list[dict]:
    res = r.run("SHOW_GRANTS_TO_USER", A.show_grants_to_user(username))
    return [{"role": (g.get("role") or "").upper(), "granted_by": g.get("granted_by"),
             "created_on": g.get("created_on")} for g in res.as_dicts()]


def remote_mfa_enrolled(r: StepRunner, username: str) -> Optional[bool]:
    try:
        res = r.run("SHOW_MFA_METHODS", A.show_mfa_methods(username))
        return len(res.rows) > 0
    except SqlApiError:
        return None   # unknown - never treated as enrolled


def remote_auth_policy(r: StepRunner, username: str) -> Optional[str]:
    try:
        res = r.run("POLICY_REFERENCES", A.show_policy_on_user(username))
        for row in res.as_dicts():
            if (row.get("POLICY_KIND") or "").upper() == "AUTHENTICATION_POLICY":
                return f"{row['POLICY_DB']}.{row['POLICY_SCHEMA']}.{row['POLICY_NAME']}".upper()
        return ""
    except SqlApiError:
        return None


def truthy(v) -> Optional[bool]:
    if v is None:
        return None
    return str(v).strip().lower() in ("true", "1", "yes")


def record_observation(session, account_id: str, username: str, user_row: Optional[dict],
                       grants: Optional[list[dict]], mfa: Optional[bool], policy: Optional[str],
                       expected_policy: Optional[str] = None) -> None:
    exists = user_row is not None
    disabled = truthy(user_row.get("disabled")) if exists else None
    drift: list[str] = []
    ctl = q(session, f"SELECT * FROM {CTL}.USER_CONTROL WHERE ACCOUNT_ID = ? AND USERNAME = ?",
            [account_id, username])
    c = ctl[0] if ctl else None
    if c and c.get("IS_MANAGED"):
        if c["DESIRED_STATE"] == "DISABLED" and disabled is False:
            drift.append("ENABLED_BUT_DESIRED_DISABLED")
        if c["DESIRED_STATE"] == "ENABLED" and disabled is True:
            drift.append("DISABLED_BUT_DESIRED_ENABLED")
        if expected_policy and policy is not None and policy != expected_policy.upper():
            drift.append("AUTH_POLICY_MISMATCH")
        if grants is not None:
            desired = {d["ROLE_NAME"] for d in q(session, f"""SELECT ROLE_NAME FROM {CTL}.USER_ROLE_DESIRED
                        WHERE ACCOUNT_ID = ? AND USERNAME = ?""", [account_id, username])}
            observed = {g["role"] for g in grants}
            if desired - observed:
                drift.append("MISSING_DESIRED_ROLES")
            if c["IDENTITY_CLASS"] == "CPG_CUSTOMER" and "ACCOUNTADMIN" in observed:
                drift.append("CUSTOMER_HAS_ACCOUNTADMIN")
        if exists and user_row.get("default_role", "").upper() == "ACCOUNTADMIN":
            drift.append("ACCOUNTADMIN_DEFAULT_ROLE")

    mfa_evidence = "ENROLLED" if mfa else ("REQUIRED_NOT_YET_OBSERVED" if mfa is False else "UNKNOWN")
    if c and c.get("IDENTITY_CLASS") == "INTERNAL_ADMIN" and mfa is False and grants and \
            any(g["role"] == "ACCOUNTADMIN" for g in grants):
        mfa_evidence = "DRIFT"
        drift.append("ACCOUNTADMIN_WITHOUT_MFA")

    x(session, f"""MERGE INTO {CTL}.USER_CONTROL t
        USING (SELECT ? AS ACCOUNT_ID, ? AS USERNAME) s
        ON t.ACCOUNT_ID = s.ACCOUNT_ID AND t.USERNAME = s.USERNAME
        WHEN MATCHED THEN UPDATE SET
            OBSERVED_EXISTS = ?, OBSERVED_DISABLED = ?, OBSERVED_TYPE = ?, OBSERVED_DEFAULT_ROLE = ?,
            OBSERVED_AUTH_POLICY = COALESCE(?, t.OBSERVED_AUTH_POLICY), MFA_EVIDENCE = ?,
            DRIFT_FLAGS = PARSE_JSON(?), LAST_VERIFIED_AT = CURRENT_TIMESTAMP(),
            ROW_VERSION = t.ROW_VERSION + 1, UPDATED_AT = CURRENT_TIMESTAMP()
        WHEN NOT MATCHED THEN INSERT (ACCOUNT_ID, USERNAME, EMAIL, IDENTITY_CLASS, IS_MANAGED, DESIRED_STATE,
            OBSERVED_EXISTS, OBSERVED_DISABLED, OBSERVED_TYPE, OBSERVED_DEFAULT_ROLE, MFA_EVIDENCE,
            DRIFT_FLAGS, LAST_VERIFIED_AT)
          VALUES (s.ACCOUNT_ID, s.USERNAME, ?, 'UNMANAGED', FALSE, NULL, ?, ?, ?, ?, ?, PARSE_JSON('[]'),
                  CURRENT_TIMESTAMP())""",
      [account_id, username,
       exists, disabled, (user_row or {}).get("type"), (user_row or {}).get("default_role"),
       policy, mfa_evidence, json.dumps(drift),
       (user_row or {}).get("email"), exists, disabled, (user_row or {}).get("type"),
       (user_row or {}).get("default_role"), mfa_evidence])

    if grants is not None:
        x(session, f"DELETE FROM {CTL}.USER_ROLE_OBSERVED WHERE ACCOUNT_ID = ? AND USERNAME = ?",
          [account_id, username])
        for g in grants:
            x(session, f"""INSERT INTO {CTL}.USER_ROLE_OBSERVED (ACCOUNT_ID, USERNAME, ROLE_NAME, GRANTED_BY, GRANTED_ON)
                           VALUES (?, ?, ?, ?, TRY_TO_TIMESTAMP_LTZ(?))""",
              [account_id, username, g["role"], g["granted_by"], g["created_on"]])


# =====================================================================
# Guards
# =====================================================================
def assert_not_protected(acct: dict, username: str) -> None:
    protected = {p.upper() for p in as_list(acct.get("PROTECTED_USERS"))}
    protected.add((acct.get("SERVICE_USER") or "").upper())
    if username.upper() in protected:
        raise Blocked(f"{username} is a protected identity")


def assert_managed(session, account_id: str, username: str, identity_class: str) -> dict:
    rows = q(session, f"""SELECT * FROM {CTL}.USER_CONTROL WHERE ACCOUNT_ID = ? AND USERNAME = ?""",
             [account_id, username])
    if not rows or not rows[0]["IS_MANAGED"] or rows[0]["IDENTITY_CLASS"] != identity_class:
        raise Blocked(f"{username} is not an app-managed {identity_class} user")
    return rows[0]


def superseded_by_disable(session, op: dict) -> bool:
    rows = q(session, f"""SELECT 1 FROM {CTL}.OPERATIONS
            WHERE ACCOUNT_ID = ? AND USERNAME = ? AND SEQUENCE_NO > ?
              AND ACTION IN ('DISABLE_USER','DISABLE_INTERNAL_ADMIN')
              AND STATUS IN ('QUEUED','RUNNING','SUCCEEDED') LIMIT 1""",
             [op["ACCOUNT_ID"], op["USERNAME"], op["SEQUENCE_NO"]])
    return bool(rows)


def desired_state(session, account_id: str, username: str) -> Optional[str]:
    rows = q(session, f"SELECT DESIRED_STATE FROM {CTL}.USER_CONTROL WHERE ACCOUNT_ID = ? AND USERNAME = ?",
             [account_id, username])
    return rows[0]["DESIRED_STATE"] if rows else None


# =====================================================================
# Action handlers. Each returns a result dict; raise Blocked / SqlApiError.
# =====================================================================
def _provision_person(session, r: StepRunner, acct: dict, op: dict, p: dict,
                      identity_class: str, policy: str, roles: list[str], default_role: str) -> dict:
    account_id, username = acct["ACCOUNT_ID"], p["username"].upper()
    assert_not_protected(acct, username)

    existing = remote_user(r, username)
    ctl = q(session, f"SELECT * FROM {CTL}.USER_CONTROL WHERE ACCOUNT_ID = ? AND USERNAME = ?",
            [account_id, username])
    if existing is not None:
        if not ctl or not ctl[0]["IS_MANAGED"] or ctl[0]["IDENTITY_CLASS"] != identity_class:
            if not p.get("adopt_existing"):
                raise Blocked("user already exists on target and is not app-managed; adoption approval required")
        if (existing.get("type") or "PERSON").upper() not in ("PERSON", "NULL", ""):
            raise Blocked("existing user is not a PERSON user")

    # policy must exist and match approved version
    r.run("DESCRIBE_AUTH_POLICY", A.show_auth_policy(policy))

    if existing is None:
        r.run("CREATE_USER_DISABLED", A.create_person_user_disabled(
            username, p.get("email"), p.get("first_name"), p.get("last_name"),
            f"managed by acct-admin op {op['OPERATION_ID'][:8]}"))
    r.run("SET_AUTH_POLICY", A.set_auth_policy(username, policy))
    for role in roles:
        r.run("GRANT_ROLE", A.grant_role(role, username))
    if default_role:
        r.run("SET_DEFAULT_ROLE", A.set_default_role(username, default_role))

    # verify before enabling
    user_row = remote_user(r, username)
    grants = remote_grants(r, username)
    pol = remote_auth_policy(r, username)
    granted = {g["role"] for g in grants}
    missing = [x_ for x_ in roles if x_.upper() not in granted]
    if user_row is None or missing:
        raise Blocked(f"verification failed before enable (missing roles: {missing})")
    if pol is not None and pol != policy.upper():
        raise Blocked("authentication policy not attached as expected; refusing to enable")

    # newer disable or desired DISABLED wins over stale onboarding
    if superseded_by_disable(session, op) or desired_state(session, account_id, username) == "DISABLED":
        record_observation(session, account_id, username, user_row, grants, None, pol, policy)
        return {"enabled": False, "note": "left disabled: superseded by disable"}

    r.run("ENABLE_USER", A.set_disabled(username, False))
    user_row = remote_user(r, username)
    mfa = remote_mfa_enrolled(r, username)
    record_observation(session, account_id, username, user_row, grants, mfa, pol, policy)
    x(session, f"""UPDATE {CTL}.USER_CONTROL SET ONBOARDING_STATE = 'PROVISIONED_PENDING_HANDOFF'
                   WHERE ACCOUNT_ID = ? AND USERNAME = ? AND COALESCE(ONBOARDING_STATE,'PROVISIONING') = 'PROVISIONING'""",
      [account_id, username])
    return {"enabled": not truthy(user_row.get("disabled")), "roles": sorted(granted)}


def h_onboard(session, r, acct, op, p):
    return _provision_person(session, r, acct, op, p, "CPG_CUSTOMER", acct["CUSTOMER_AUTH_POLICY"],
                             [x_.upper() for x_ in p.get("roles", [])], p.get("default_role") or "")


def h_add_roles(session, r, acct, op, p):
    username = p["username"].upper()
    assert_not_protected(acct, username)
    assert_managed(session, acct["ACCOUNT_ID"], username, "CPG_CUSTOMER")
    for role in p.get("roles", []):
        r.run("GRANT_ROLE", A.grant_role(role, username))
    grants = remote_grants(r, username)
    record_observation(session, acct["ACCOUNT_ID"], username, remote_user(r, username), grants, None, None)
    return {"roles": sorted(g["role"] for g in grants)}


def h_set_managed_roles(session, r, acct, op, p):
    username = p["username"].upper()
    assert_not_protected(acct, username)
    assert_managed(session, acct["ACCOUNT_ID"], username, "CPG_CUSTOMER")
    target = {x_.upper() for x_ in p.get("roles", [])}
    # only previously app-managed roles may be removed; external grants preserved
    for role in p.get("remove_roles", []):
        if role.upper() not in target:
            r.run("REVOKE_ROLE", A.revoke_role(role, username))
    for role in target:
        r.run("GRANT_ROLE", A.grant_role(role, username))
    grants = remote_grants(r, username)
    record_observation(session, acct["ACCOUNT_ID"], username, remote_user(r, username), grants, None, None)
    return {"roles": sorted(g["role"] for g in grants)}


def h_set_disabled(session, r, acct, op, p, disabled: bool, identity_class: str = "CPG_CUSTOMER"):
    username = p["username"].upper()
    if not (disabled and p.get("emergency_override")):
        assert_not_protected(acct, username)
    assert_managed(session, acct["ACCOUNT_ID"], username, identity_class)
    before = remote_user(r, username)
    if before is None:
        record_observation(session, acct["ACCOUNT_ID"], username, None, None, None, None)
        return {"result": "NOT_FOUND"}
    if truthy(before.get("disabled")) != disabled:
        r.run("SET_DISABLED", A.set_disabled(username, disabled))
    after = remote_user(r, username)
    if truthy(after.get("disabled")) != disabled:
        raise SqlApiError("read-back did not confirm disabled state", uncertain=True)
    record_observation(session, acct["ACCOUNT_ID"], username, after, remote_grants(r, username), None, None)
    if disabled:
        x(session, f"UPDATE {CTL}.USER_CONTROL SET ONBOARDING_STATE = 'DISABLED' WHERE ACCOUNT_ID = ? AND USERNAME = ?",
          [acct["ACCOUNT_ID"], username])
    return {"result": "VERIFIED_DISABLED" if disabled else "VERIFIED_ENABLED"}


def _store_link(session, op, acct, username, link_type, res) -> bool:
    text = json.dumps(res.rows)
    m = URL_RE.search(text)
    if not m:
        return False
    x(session, f"""INSERT INTO {CTL}.HANDOFF_VAULT (OPERATION_ID, ACCOUNT_ID, USERNAME, LINK_TYPE, LINK_VALUE, EXPIRES_AT)
                   VALUES (?, ?, ?, ?, ?, DATEADD(hour, 12, CURRENT_TIMESTAMP()))""",
      [op["OPERATION_ID"], acct["ACCOUNT_ID"], username, link_type, m.group(0)])
    return True


def h_password_link(session, r, acct, op, p):
    username = p["username"].upper()
    assert_not_protected(acct, username)
    ctl = q(session, f"SELECT IDENTITY_CLASS, IS_MANAGED FROM {CTL}.USER_CONTROL WHERE ACCOUNT_ID = ? AND USERNAME = ?",
            [acct["ACCOUNT_ID"], username])
    if not ctl or not ctl[0]["IS_MANAGED"]:
        raise Blocked("password link only for app-managed users")
    res = r.run("RESET_PASSWORD", A.reset_password(username), record=True)
    stored = _store_link(session, op, acct, username, "PASSWORD_RESET", res)
    x(session, f"UPDATE {CTL}.USER_CONTROL SET ONBOARDING_STATE = 'HANDOFF_ISSUED' WHERE ACCOUNT_ID = ? AND USERNAME = ?",
      [acct["ACCOUNT_ID"], username])
    return {"link_stored": stored}


def h_enroll_mfa(session, r, acct, op, p):
    username = p["username"].upper()
    assert_not_protected(acct, username)
    res = r.run("ENROLL_MFA", A.enroll_mfa(username))
    stored = _store_link(session, op, acct, username, "MFA_ENROLLMENT", res)
    return {"link_stored": stored, "note": "email sent by Snowflake" if not stored else "URL in handoff vault"}


# ------------------------------------------------------- privileged family
def _load_access(session, op) -> dict:
    rows = q(session, f"""SELECT a.*, r.ELIGIBILITY_STATUS, r.EMAIL_VERIFIED, r.CORPORATE_EMAIL, r.FIRST_NAME, r.LAST_NAME
                          FROM {CTL}.ADMIN_ACCOUNT_ACCESS a JOIN {CTL}.INTERNAL_ADMIN_ROSTER r USING (EMPLOYEE_ID)
                          WHERE a.ACCESS_ID = ?""", [op["ACCESS_ID"]])
    if not rows:
        raise Blocked("access request not found")
    a = rows[0]
    if a["ELIGIBILITY_STATUS"] != "ELIGIBLE" or not a["EMAIL_VERIFIED"]:
        raise Blocked("employee not eligible on roster")
    if not a["APPROVED_BY"] or a["APPROVED_BY"] == a["REQUESTED_BY"]:
        raise Blocked("independent approval missing")
    return a


def _set_access(session, access_id, state, **cols):
    sets = ", ".join([f"{k} = ?" for k in cols] + ["WORKFLOW_STATE = ?", "UPDATED_AT = CURRENT_TIMESTAMP()"])
    x(session, f"UPDATE {CTL}.ADMIN_ACCOUNT_ACCESS SET {sets} WHERE ACCESS_ID = ?",
      list(cols.values()) + [state, access_id])


def h_provision_internal(session, r, acct, op, p):
    a = _load_access(session, op)
    p = dict(p, username=a["TARGET_USERNAME"], email=a["CORPORATE_EMAIL"],
             first_name=a["FIRST_NAME"], last_name=a["LAST_NAME"])
    res = _provision_person(session, r, acct, op, p, "INTERNAL_ADMIN", acct["INTERNAL_AUTH_POLICY"],
                            [], acct.get("INTERNAL_DEFAULT_ROLE") or "PUBLIC")
    mfa = remote_mfa_enrolled(r, a["TARGET_USERNAME"])
    _set_access(session, a["ACCESS_ID"], "GRANT_PENDING" if mfa else "AWAITING_MFA",
                OBSERVED_MFA="ENROLLED" if mfa else ("REQUIRED_NOT_YET_OBSERVED" if mfa is False else "UNKNOWN"))
    return res


def h_grant_accountadmin(session, r, acct, op, p):
    a = _load_access(session, op)
    username = a["TARGET_USERNAME"].upper()
    if a["EXPIRES_AT"] is not None:
        expired = q(session, "SELECT ? < CURRENT_TIMESTAMP() AS E", [a["EXPIRES_AT"]])[0]["E"]
        if expired:
            raise Blocked("approval expired")
    assert_managed(session, acct["ACCOUNT_ID"], username, "INTERNAL_ADMIN")
    user_row = remote_user(r, username)
    if user_row is None or truthy(user_row.get("disabled")):
        raise Blocked("internal admin user missing or disabled")
    if (user_row.get("type") or "PERSON").upper() not in ("PERSON", "NULL", ""):
        raise Blocked("target is not a PERSON user")
    mfa = remote_mfa_enrolled(r, username)
    if mfa is not True:
        _set_access(session, a["ACCESS_ID"], "AWAITING_MFA",
                    OBSERVED_MFA="UNKNOWN" if mfa is None else "REQUIRED_NOT_YET_OBSERVED")
        raise Blocked("MFA enrollment not verified; ACCOUNTADMIN not granted")
    if (user_row.get("default_role") or "").upper() == "ACCOUNTADMIN":
        raise Blocked("default role is ACCOUNTADMIN")
    r.run("GRANT_ACCOUNTADMIN", A.grant_role("ACCOUNTADMIN", username, allow_privileged=True))
    grants = remote_grants(r, username)
    ok = any(g["role"] == "ACCOUNTADMIN" for g in grants)
    record_observation(session, acct["ACCOUNT_ID"], username, user_row, grants, mfa, None)
    if not ok:
        raise SqlApiError("ACCOUNTADMIN grant not observed on read-back", uncertain=True)
    _set_access(session, a["ACCESS_ID"], "GRANTED", OBSERVED_ACCOUNTADMIN=True, OBSERVED_MFA="ENROLLED")
    x(session, f"UPDATE {CTL}.ADMIN_ACCOUNT_ACCESS SET LAST_VERIFIED_AT = CURRENT_TIMESTAMP() WHERE ACCESS_ID = ?",
      [a["ACCESS_ID"]])
    return {"granted": True}


def _accountadmin_humans(r: StepRunner, exclude: set[str]) -> int:
    """Direct ACCOUNTADMIN user grants, excluding the given names (service user, target)."""
    res = r.run("SHOW_GRANTS_OF_ACCOUNTADMIN", A.show_grants_of_role("ACCOUNTADMIN"))
    excl = {e.upper() for e in exclude}
    return sum(1 for g in res.as_dicts()
               if (g.get("granted_to") or "").upper() == "USER"
               and (g.get("grantee_name") or "").upper() not in excl)


def h_revoke_accountadmin(session, r, acct, op, p):
    rows = q(session, f"SELECT * FROM {CTL}.ADMIN_ACCOUNT_ACCESS WHERE ACCESS_ID = ?", [op["ACCESS_ID"]])
    if not rows:
        raise Blocked("access record not found")
    a = rows[0]
    username = a["TARGET_USERNAME"].upper()
    remaining = _accountadmin_humans(r, {username, acct["SERVICE_USER"]})
    if remaining < 2 and not p.get("emergency_override"):
        raise Blocked(f"revocation would leave {remaining} human ACCOUNTADMIN(s); override required")
    if p.get("emergency_override"):
        audit(session, "OVERRIDE", acct["ACCOUNT_ID"], username, op["OPERATION_ID"],
              {"reason": "emergency revoke below coverage", "remaining": remaining})
    grants = remote_grants(r, username)
    if any(g["role"] == "ACCOUNTADMIN" for g in grants):
        r.run("REVOKE_ACCOUNTADMIN", A.revoke_role("ACCOUNTADMIN", username))
    grants = remote_grants(r, username)
    if any(g["role"] == "ACCOUNTADMIN" for g in grants):
        raise SqlApiError("ACCOUNTADMIN still observed after revoke", uncertain=True)
    record_observation(session, acct["ACCOUNT_ID"], username, remote_user(r, username), grants, None, None)
    _set_access(session, a["ACCESS_ID"], "REVOKED", OBSERVED_ACCOUNTADMIN=False)
    return {"revoked": True}


def h_disable_internal(session, r, acct, op, p):
    rows = q(session, f"SELECT TARGET_USERNAME FROM {CTL}.ADMIN_ACCOUNT_ACCESS WHERE ACCESS_ID = ?", [op["ACCESS_ID"]])
    p = dict(p, username=rows[0]["TARGET_USERNAME"]) if rows else p
    res = h_set_disabled(session, r, acct, op, p, True, "INTERNAL_ADMIN")
    if rows:
        _set_access(session, op["ACCESS_ID"], "REVOKED")
    return res


HANDLERS = {
    "ONBOARD_USER": h_onboard,
    "ADD_ROLES": h_add_roles,
    "SET_MANAGED_ROLES": h_set_managed_roles,
    "DISABLE_USER": lambda s, r, a, o, p: h_set_disabled(s, r, a, o, p, True),
    "REENABLE_USER": lambda s, r, a, o, p: h_set_disabled(s, r, a, o, p, False),
    "ISSUE_PASSWORD_LINK": h_password_link,
    "ENROLL_MFA": h_enroll_mfa,
    "PROVISION_INTERNAL_ADMIN": h_provision_internal,
    "GRANT_ACCOUNTADMIN": h_grant_accountadmin,
    "REVOKE_ACCOUNTADMIN": h_revoke_accountadmin,
    "DISABLE_INTERNAL_ADMIN": h_disable_internal,
}
PRIVILEGED = {"PROVISION_INTERNAL_ADMIN", "GRANT_ACCOUNTADMIN", "REVOKE_ACCOUNTADMIN", "DISABLE_INTERNAL_ADMIN"}


# =====================================================================
# Preflight / reconciliation
# =====================================================================
def build_client(acct: dict) -> SnowflakeSqlApiClient:
    key = _snowflake.get_generic_secret_string(SECRET_ALIAS)
    return SnowflakeSqlApiClient(
        host=acct["SQL_API_HOST"], jwt_account=acct["JWT_ACCOUNT_IDENTIFIER"],
        user=acct["SERVICE_USER"], private_key_pem=key, role=acct["EXEC_ROLE"],
        warehouse=acct.get("EXEC_WAREHOUSE"), expected_fingerprint=acct.get("PUBLIC_KEY_FP"))


def do_preflight(session, acct: dict, client: SnowflakeSqlApiClient) -> dict:
    r = StepRunner(session, client, None)
    res = r.run("PREFLIGHT", A.preflight(), record=False).as_dicts()[0]
    ok = (res.get("ACCOUNT_LOCATOR", "").upper() == (acct.get("EXPECTED_ACCOUNT_LOCATOR") or "").upper()
          and res.get("ROLE", "").upper() == acct["EXEC_ROLE"].upper()
          and res.get("USER_NAME", "").upper() == acct["SERVICE_USER"].upper())
    result = {"ok": ok, "observed": res, "fingerprint": client.fingerprint}
    x(session, f"""UPDATE {CTL}.CUSTOMER_ACCOUNTS SET LAST_PREFLIGHT_AT = CURRENT_TIMESTAMP(),
                   LAST_PREFLIGHT_RESULT = PARSE_JSON(?),
                   BOOTSTRAP_STATUS = IFF(?, 'VERIFIED', 'ERROR') WHERE ACCOUNT_ID = ?""",
      [json.dumps(result), ok, acct["ACCOUNT_ID"]])
    if not ok:
        raise Blocked("preflight identity mismatch: " + json.dumps(res))
    return result


def do_reconcile(session, acct: dict, client: SnowflakeSqlApiClient, max_users: int) -> dict:
    r = StepRunner(session, client, None)
    account_id = acct["ACCOUNT_ID"]
    users = r.run("SHOW_USERS", A.show_all_users(), record=False).as_dicts()
    by_name = {(u.get("name") or "").upper(): u for u in users}
    managed = q(session, f"""SELECT USERNAME, IDENTITY_CLASS FROM {CTL}.USER_CONTROL
                             WHERE ACCOUNT_ID = ? AND IS_MANAGED ORDER BY LAST_VERIFIED_AT NULLS FIRST LIMIT ?""",
                [account_id, max_users])
    checked = 0
    for m in managed:
        name = m["USERNAME"]
        row = by_name.get(name)
        if row is None:
            record_observation(session, account_id, name, None, None, None, None)
            continue
        expected = acct["INTERNAL_AUTH_POLICY"] if m["IDENTITY_CLASS"] == "INTERNAL_ADMIN" else acct["CUSTOMER_AUTH_POLICY"]
        record_observation(session, account_id, name, row, remote_grants(r, name),
                           remote_mfa_enrolled(r, name), remote_auth_policy(r, name), expected)
        checked += 1
    # Unmanaged population (coverage reporting only; no remote calls per user)
    managed_names = {m["USERNAME"] for m in q(session, f"SELECT USERNAME FROM {CTL}.USER_CONTROL WHERE ACCOUNT_ID = ?",
                                              [account_id])}
    new_unmanaged = 0
    for name, row in by_name.items():
        if name not in managed_names:
            record_observation(session, account_id, name, row, None, None, None)
            new_unmanaged += 1
    # Expired internal grants -> raise for revocation (never auto-revoke)
    expired = q(session, f"""SELECT ACCESS_ID FROM {CTL}.ADMIN_ACCOUNT_ACCESS WHERE ACCOUNT_ID = ?
                             AND WORKFLOW_STATE = 'GRANTED' AND EXPIRES_AT < CURRENT_TIMESTAMP()""", [account_id])
    for e in expired:
        _set_access(session, e["ACCESS_ID"], "REVOKE_PENDING")
    summary = {"remote_users": len(users), "managed_checked": checked,
               "new_unmanaged": new_unmanaged, "expired_grants_flagged": len(expired)}
    audit(session, "RECONCILE", account_id, None, None, summary)
    return summary


# =====================================================================
# Queue processing
# =====================================================================
def _finish(session, op_id: str, status: str, error: Optional[str] = None, retry_in_s: Optional[int] = None):
    if retry_in_s is not None:
        x(session, f"""UPDATE {CTL}.OPERATIONS SET STATUS = 'QUEUED', CLAIMED_BY = NULL, LAST_ERROR = ?,
                       NEXT_ATTEMPT_AT = DATEADD(second, ?, CURRENT_TIMESTAMP()) WHERE OPERATION_ID = ?""",
          [redact(error), retry_in_s, op_id])
    else:
        x(session, f"""UPDATE {CTL}.OPERATIONS SET STATUS = ?, LAST_ERROR = ?, COMPLETED_AT = CURRENT_TIMESTAMP()
                       WHERE OPERATION_ID = ?""", [status, redact(error), op_id])


def _account_health(session, account_id: str, success: bool) -> None:
    if success:
        x(session, f"UPDATE {CTL}.CUSTOMER_ACCOUNTS SET CONSECUTIVE_FAILURES = 0 WHERE ACCOUNT_ID = ?", [account_id])
        return
    x(session, f"""UPDATE {CTL}.CUSTOMER_ACCOUNTS SET CONSECUTIVE_FAILURES = CONSECUTIVE_FAILURES + 1,
                   IS_PAUSED = IFF(CONSECUTIVE_FAILURES + 1 >= ?, TRUE, IS_PAUSED),
                   PAUSE_REASON = IFF(CONSECUTIVE_FAILURES + 1 >= ?, 'circuit breaker: consecutive failures', PAUSE_REASON)
                   WHERE ACCOUNT_ID = ?""", [CIRCUIT_BREAKER_THRESHOLD, CIRCUIT_BREAKER_THRESHOLD, account_id])


def process_queue(session, acct: dict, client: SnowflakeSqlApiClient, max_ops: int, run_id: str) -> dict:
    account_id = acct["ACCOUNT_ID"]
    # Atomic claim (single UPDATE). Only ops bound to the current registry version.
    x(session, f"""UPDATE {CTL}.OPERATIONS SET STATUS = 'RUNNING', CLAIMED_BY = ?, CLAIMED_AT = CURRENT_TIMESTAMP(),
                   ATTEMPTS = ATTEMPTS + 1
                   WHERE OPERATION_ID IN (
                       SELECT OPERATION_ID FROM {CTL}.OPERATIONS
                       WHERE ACCOUNT_ID = ? AND STATUS = 'QUEUED'
                         AND (NEXT_ATTEMPT_AT IS NULL OR NEXT_ATTEMPT_AT <= CURRENT_TIMESTAMP())
                       ORDER BY SEQUENCE_NO LIMIT ?)
                     AND STATUS = 'QUEUED'""", [run_id, account_id, max_ops])
    ops = q(session, f"SELECT * FROM {CTL}.OPERATIONS WHERE CLAIMED_BY = ? AND STATUS = 'RUNNING' ORDER BY SEQUENCE_NO",
            [run_id])
    stats = {"claimed": len(ops), "succeeded": 0, "failed": 0, "blocked": 0, "retry": 0, "cancelled": 0}

    for op in ops:
        op_id = op["OPERATION_ID"]
        p = as_obj(op["PAYLOAD"])
        try:
            if op["REGISTRY_VERSION"] is not None and op["REGISTRY_VERSION"] != acct["REGISTRY_VERSION"]:
                raise Blocked("stale approval: registry changed since approval")
            if not op["APPROVED_BY"] and op["ACTION_FAMILY"] != "SYSTEM":
                raise Blocked("operation not approved")
            if op["ACTION"] in ("ONBOARD_USER", "PROVISION_INTERNAL_ADMIN") and superseded_by_disable(session, op):
                _finish(session, op_id, "CANCELLED", "superseded by newer disable")
                stats["cancelled"] += 1
                continue
            handler = HANDLERS.get(op["ACTION"])
            if handler is None:
                raise Blocked(f"unknown action {op['ACTION']}")
            if op["ACTION"] in PRIVILEGED and acct["EXEC_ROLE"].upper() != "ACCOUNTADMIN":
                raise Blocked("privileged action requires ACCOUNTADMIN execution role")
            result = handler(session, StepRunner(session, client, op_id), acct, op, p)
            _finish(session, op_id, "SUCCEEDED")
            audit(session, "EXECUTE", account_id, op["USERNAME"], op_id, {"action": op["ACTION"], "result": result})
            _account_health(session, account_id, True)
            stats["succeeded"] += 1
        except Blocked as b:
            _finish(session, op_id, "BLOCKED", str(b))
            audit(session, "EXECUTE", account_id, op["USERNAME"], op_id, {"action": op["ACTION"], "blocked": str(b)})
            stats["blocked"] += 1
        except A.ValidationError as v:
            _finish(session, op_id, "BLOCKED", f"validation: {v}")
            stats["blocked"] += 1
        except SqlApiError as e:
            _account_health(session, account_id, False)
            retryable = e.uncertain or (e.http_status in (408, 429, 500, 502, 503, 504))
            if retryable and op["ATTEMPTS"] < op["MAX_ATTEMPTS"]:
                _finish(session, op_id, "QUEUED", str(e), retry_in_s=min(60 * 2 ** op["ATTEMPTS"], 3600))
                stats["retry"] += 1
            else:
                _finish(session, op_id, "FAILED", str(e))
                stats["failed"] += 1
            audit(session, "EXECUTE", account_id, op["USERNAME"], op_id,
                  {"action": op["ACTION"], "error": redact(str(e)), "http": e.http_status, "code": e.sf_code})
        except Exception as e:  # noqa: BLE001
            _finish(session, op_id, "FAILED", f"{type(e).__name__}: {e}")
            audit(session, "EXECUTE", account_id, op["USERNAME"], op_id,
                  {"action": op["ACTION"], "error": redact(traceback.format_exc())})
            stats["failed"] += 1
    return stats


# =====================================================================
# Entry point
# =====================================================================
def run_account(session, account_id: str, max_ops: int = 25, mode: str = "QUEUE") -> dict:
    run_id = str(uuid.uuid4())
    mode = (mode or "QUEUE").upper()
    try:
        acct = load_account(session, account_id)
        client = build_client(acct)
        if mode == "PREFLIGHT":
            return {"account_id": account_id, "mode": mode, **do_preflight(session, acct, client)}
        if not acct["IS_ENABLED"] or acct["IS_PAUSED"]:
            return {"account_id": account_id, "mode": mode, "skipped": "account disabled or paused"}
        do_preflight(session, acct, client)
        if mode == "RECONCILE":
            return {"account_id": account_id, "mode": mode, **do_reconcile(session, acct, client, max_ops or 200)}
        return {"account_id": account_id, "mode": mode, "run_id": run_id,
                **process_queue(session, acct, client, max_ops, run_id)}
    except Blocked as b:
        return {"account_id": account_id, "mode": mode, "blocked": str(b)}
    except SqlApiError as e:
        try:
            _account_health(session, account_id, False)
        finally:
            return {"account_id": account_id, "mode": mode, "error": redact(str(e)), "http": e.http_status}
