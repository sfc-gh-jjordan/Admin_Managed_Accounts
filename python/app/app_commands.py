"""
app_commands.py
Trusted command path for the Streamlit app. Exposed as the owner's-rights
procedure ACCT_ADMIN_DB.APP.COMMAND(ACTOR, COMMAND, ARGS). Only the app
owner role can call it; the app passes st.user.user_name as ACTOR and every
command re-checks ADMIN_AUTHORIZATIONS for that actor.

No command here contacts a target account directly. Remote work happens
only through queued OPERATIONS executed by the worker (or RUN_ACCOUNT).
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Optional

CTL = "ACCT_ADMIN_DB.CONTROL"
ACCT_RE = re.compile(r"^[A-Z0-9_]{1,60}$")
USER_RE = re.compile(r"^[A-Z][A-Z0-9_]{1,127}$")
ROLE_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,254}$")
MAX_NEW_ROLES = 10
SYSTEM_ROLES = {"ACCOUNTADMIN", "SECURITYADMIN", "USERADMIN", "SYSADMIN", "ORGADMIN", "GLOBALORGADMIN", "PUBLIC"}
NEW_ROLE_PARENT = "SYSADMIN"


class Denied(Exception):
    pass


def q(s, sql, p=None):
    return [r.as_dict() for r in s.sql(sql, params=p or []).collect()]


def x(s, sql, p=None):
    s.sql(sql, params=p or []).collect()


def sha(obj: Any) -> str:
    return hashlib.sha256(json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def audit(s, actor, etype, account_id=None, username=None, op_id=None, details=None):
    x(s, f"""INSERT INTO {CTL}.AUDIT_EVENTS (ACTOR, EVENT_TYPE, ACCOUNT_ID, USERNAME, OPERATION_ID, DETAILS)
             SELECT ?, ?, ?, ?, ?, PARSE_JSON(?)""",
      [actor, etype, account_id, username, op_id, json.dumps(details or {}, default=str)])


def is_accountadmin(s, actor: str) -> bool:
    """Actor must hold an active direct ACCOUNTADMIN grant in EIGHTY451.
    ACCOUNT_USAGE has some latency: new grants may take time to appear,
    and revocations are also delayed (pair with user disablement)."""
    rows = q(s, """SELECT 1 FROM SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_USERS
                    WHERE GRANTEE_NAME = ? AND ROLE = 'ACCOUNTADMIN' AND DELETED_ON IS NULL LIMIT 1""",
             [actor.upper()])
    if not rows:
        return False
    disabled = q(s, """SELECT 1 FROM SNOWFLAKE.ACCOUNT_USAGE.USERS
                        WHERE NAME = ? AND DELETED_ON IS NULL AND DISABLED = TRUE LIMIT 1""", [actor.upper()])
    return not disabled


def require(s, actor: str, account_id: str, perm: str) -> None:
    if not is_accountadmin(s, actor):
        raise Denied(f"{actor} does not hold ACCOUNTADMIN in EIGHTY451")
    col = {"view": "CAN_VIEW", "operate": "CAN_OPERATE", "approve": "CAN_APPROVE",
           "priv": "CAN_PRIV_APPROVE"}[perm]
    rows = q(s, f"""SELECT 1 FROM {CTL}.ADMIN_AUTHORIZATIONS
                    WHERE ADMIN_USER = ? AND ACCOUNT_ID IN (?, '*') AND IS_ACTIVE AND {col} LIMIT 1""",
             [actor.upper(), account_id])
    if not rows:
        raise Denied(f"{actor} lacks {perm} on {account_id}")


def account(s, account_id: str) -> dict:
    if not ACCT_RE.match(account_id or ""):
        raise Denied("invalid account id")
    rows = q(s, f"SELECT * FROM {CTL}.CUSTOMER_ACCOUNTS WHERE ACCOUNT_ID = ?", [account_id])
    if not rows:
        raise Denied("unknown account")
    return rows[0]


def catalog_version(s, account_id):
    return q(s, f"SELECT COALESCE(MAX(CATALOG_VERSION),0) V FROM {CTL}.ROLE_CATALOG WHERE ACCOUNT_ID = ?",
             [account_id])[0]["V"]


def new_op(s, actor, acct, action, username, payload, *, family="CUSTOMER", batch_id=None,
           access_id=None, reason=None, ticket=None, depends_on=None) -> str:
    op_id = q(s, "SELECT UUID_STRING() U")[0]["U"]
    x(s, f"""INSERT INTO {CTL}.OPERATIONS (OPERATION_ID, ACCOUNT_ID, USERNAME, ACTION, ACTION_FAMILY, PAYLOAD,
             PAYLOAD_SHA256, BATCH_ID, ACCESS_ID, REGISTRY_VERSION, CATALOG_VERSION, STATUS, REQUESTED_BY, REASON, TICKET,
             DEPENDS_ON)
             SELECT ?, ?, ?, ?, ?, PARSE_JSON(?), ?, ?, ?, ?, ?, 'PENDING_APPROVAL', ?, ?, ?, PARSE_JSON(?)""",
      [op_id, acct["ACCOUNT_ID"], username, action, family, json.dumps(payload), sha(payload), batch_id,
       access_id, acct["REGISTRY_VERSION"], catalog_version(s, acct["ACCOUNT_ID"]), actor, reason, ticket,
       json.dumps(depends_on or [])])
    audit(s, actor, "SUBMIT", acct["ACCOUNT_ID"], username, op_id, {"action": action})
    return op_id


def _arr(v) -> list:
    return json.loads(v) if isinstance(v, str) else (v or [])


def check_roles(s, account_id: str, rows: list[dict], new_roles: list[str]) -> list[str]:
    """Server-side role check for a batch. Every role referenced by a valid, non-excluded row must be an
    active catalog role or a listed new role; new roles must be unknown to the catalog and not blocked.
    Returns the normalized new-role list."""
    new = []
    for n in new_roles or []:
        n = str(n).upper()
        if n not in new:
            new.append(n)
    if len(new) > MAX_NEW_ROLES:
        raise Denied(f"more than {MAX_NEW_ROLES} new roles in one batch")
    blocked = {r["ROLE_NAME"] for r in q(s, f"SELECT ROLE_NAME FROM {CTL}.BLOCKED_ROLES")} | SYSTEM_ROLES
    cat = {r["ROLE_NAME"]: r for r in q(s, f"""SELECT ROLE_NAME, IS_ACTIVE, APPROVAL_CLASS FROM {CTL}.ROLE_CATALOG
                                              WHERE ACCOUNT_ID = ?""", [account_id])}
    for n in new:
        if not ROLE_RE.match(n) or n in blocked:
            raise Denied(f"role {n} cannot be created")
        if n in cat:
            raise Denied(f"role {n} already has a catalog entry; re-upload")
    usable = {k for k, v in cat.items() if v["IS_ACTIVE"] and v["APPROVAL_CLASS"] != "BLOCKED"}
    for r in rows:
        if not r.get("is_valid") or r.get("is_excluded"):
            continue
        for k in ("role_name", "default_role"):
            v = (r.get(k) or "").upper()
            if v and v not in usable and v not in new:
                raise Denied(f"row {r.get('row_number')}: {k} {v} is not in the role catalog")
    return new


# ====================================================================
# Commands
# ====================================================================
def cmd_save_import(s, actor, a):
    """Persist a validated CSV batch (validation performed in-app, re-checked here and at submit)."""
    acct = account(s, a["account_id"])
    require(s, actor, acct["ACCOUNT_ID"], "operate")
    batch_id = q(s, "SELECT UUID_STRING() U")[0]["U"]
    rows = a["rows"]
    new_roles = check_roles(s, acct["ACCOUNT_ID"], rows, a.get("new_roles", []))
    x(s, f"""INSERT INTO {CTL}.IMPORT_BATCHES (BATCH_ID, ACCOUNT_ID, FILE_NAME, FILE_SHA256, PAYLOAD_SHA256, ROW_COUNT,
             ERROR_COUNT, REQUESTED_BY, REASON, TICKET, STATUS, REGISTRY_VERSION, CATALOG_VERSION, NEW_ROLES)
             SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'VALIDATED', ?, ?, PARSE_JSON(?)""",
      [batch_id, acct["ACCOUNT_ID"], a.get("file_name"), a.get("file_sha256"), sha(rows), len(rows),
       sum(1 for r in rows if not r["is_valid"]), actor, a.get("reason"), a.get("ticket"),
       acct["REGISTRY_VERSION"], catalog_version(s, acct["ACCOUNT_ID"]), json.dumps(new_roles)])
    for r in rows:
        x(s, f"""INSERT INTO {CTL}.IMPORT_ROWS (BATCH_ID, ROW_NUMBER, USERNAME, EMAIL, FIRST_NAME, LAST_NAME, ROLE_NAME,
                 DEFAULT_ROLE, ACTION, IS_VALID, IS_EXCLUDED, FINDINGS)
                 SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, PARSE_JSON(?)""",
          [batch_id, r["row_number"], r["username"], r["email"], r["first_name"], r["last_name"], r["role_name"],
           r["default_role"], r["action"], r["is_valid"], r.get("is_excluded", False), json.dumps(r["findings"])])
    audit(s, actor, "IMPORT", acct["ACCOUNT_ID"], None, None, {"batch_id": batch_id, "rows": len(rows)})
    return {"batch_id": batch_id}


def cmd_submit_batch(s, actor, a):
    """Group valid, non-excluded rows per user into OPERATIONS awaiting approval."""
    b = q(s, f"SELECT * FROM {CTL}.IMPORT_BATCHES WHERE BATCH_ID = ?", [a["batch_id"]])
    if not b or b[0]["STATUS"] != "VALIDATED":
        raise Denied("batch not in VALIDATED state")
    b = b[0]
    acct = account(s, b["ACCOUNT_ID"])
    require(s, actor, acct["ACCOUNT_ID"], "operate")
    if b["REGISTRY_VERSION"] != acct["REGISTRY_VERSION"]:
        raise Denied("registry changed since validation; re-upload")
    if b["CATALOG_VERSION"] != catalog_version(s, acct["ACCOUNT_ID"]):
        raise Denied("role catalog changed since validation; re-upload")
    invalid = q(s, f"""SELECT COUNT(*) N FROM {CTL}.IMPORT_ROWS WHERE BATCH_ID = ? AND NOT IS_VALID AND NOT IS_EXCLUDED""",
                [b["BATCH_ID"]])[0]["N"]
    if invalid:
        raise Denied("batch has invalid rows that are not explicitly excluded")
    rows = q(s, f"""SELECT * FROM {CTL}.IMPORT_ROWS WHERE BATCH_ID = ? AND IS_VALID AND NOT IS_EXCLUDED
                    ORDER BY ROW_NUMBER""", [b["BATCH_ID"]])
    new_roles = check_roles(s, acct["ACCOUNT_ID"],
                            [{"row_number": r["ROW_NUMBER"], "role_name": r["ROLE_NAME"], "default_role": r["DEFAULT_ROLE"],
                              "is_valid": True} for r in rows], _arr(b.get("NEW_ROLES")))
    role_ops: dict[str, str] = {}
    for role in new_roles:
        if not any(role in (r["ROLE_NAME"], r["DEFAULT_ROLE"]) for r in rows):
            continue  # all rows that needed it were excluded
        role_ops[role] = new_op(s, actor, acct, "CREATE_ROLE", None,
                                {"role_name": role, "parent_role": NEW_ROLE_PARENT, "batch_id": b["BATCH_ID"]},
                                batch_id=b["BATCH_ID"], reason=b["REASON"], ticket=b["TICKET"])
    grouped: dict[tuple, dict] = {}
    for r in rows:
        key = (r["USERNAME"], r["ACTION"])
        g = grouped.setdefault(key, {"username": r["USERNAME"], "email": r["EMAIL"], "first_name": r["FIRST_NAME"],
                                     "last_name": r["LAST_NAME"], "default_role": r["DEFAULT_ROLE"], "roles": []})
        if r["ROLE_NAME"] and r["ROLE_NAME"] not in g["roles"]:
            g["roles"].append(r["ROLE_NAME"])
    action_map = {"ONBOARD": "ONBOARD_USER", "ADD_ROLES": "ADD_ROLES", "SET_MANAGED_ROLES": "SET_MANAGED_ROLES",
                  "DISABLE": "DISABLE_USER", "REENABLE": "REENABLE_USER"}
    ops = []
    for (username, action), payload in grouped.items():
        if action == "SET_MANAGED_ROLES":
            current = [d["ROLE_NAME"] for d in q(s, f"""SELECT ROLE_NAME FROM {CTL}.USER_ROLE_DESIRED
                        WHERE ACCOUNT_ID = ? AND USERNAME = ?""", [acct["ACCOUNT_ID"], username])]
            payload["remove_roles"] = [r for r in current if r not in payload["roles"]]
        needs = [role_ops[r] for r in payload["roles"] + [payload["default_role"]] if r in role_ops]
        ops.append(new_op(s, actor, acct, action_map[action], username, payload, batch_id=b["BATCH_ID"],
                          reason=b["REASON"], ticket=b["TICKET"], depends_on=list(dict.fromkeys(needs))))
    x(s, f"UPDATE {CTL}.IMPORT_BATCHES SET STATUS = 'SUBMITTED' WHERE BATCH_ID = ?", [b["BATCH_ID"]])
    return {"operations": len(ops) + len(role_ops), "roles_to_create": list(role_ops)}


def _apply_desired(s, op: dict) -> None:
    p = json.loads(op["PAYLOAD"]) if isinstance(op["PAYLOAD"], str) else op["PAYLOAD"]
    acct_id, user, action = op["ACCOUNT_ID"], op["USERNAME"], op["ACTION"]
    if action in ("ONBOARD_USER", "PROVISION_INTERNAL_ADMIN"):
        ident = "INTERNAL_ADMIN" if action == "PROVISION_INTERNAL_ADMIN" else "CPG_CUSTOMER"
        x(s, f"""MERGE INTO {CTL}.USER_CONTROL t USING (SELECT ? A, ? U) src ON t.ACCOUNT_ID = src.A AND t.USERNAME = src.U
                 WHEN MATCHED AND t.IS_MANAGED THEN UPDATE SET DESIRED_STATE = 'ENABLED', DESIRED_DEFAULT_ROLE = ?,
                      EMAIL = COALESCE(?, t.EMAIL), UPDATED_AT = CURRENT_TIMESTAMP()
                 WHEN MATCHED AND NOT t.IS_MANAGED AND ? THEN UPDATE SET IS_MANAGED = TRUE, IDENTITY_CLASS = ?,
                      DESIRED_STATE = 'ENABLED', DESIRED_DEFAULT_ROLE = ?, ONBOARDING_STATE = 'PROVISIONING'
                 WHEN NOT MATCHED THEN INSERT (ACCOUNT_ID, USERNAME, EMAIL, FIRST_NAME, LAST_NAME, IDENTITY_CLASS,
                      IS_MANAGED, DESIRED_STATE, DESIRED_DEFAULT_ROLE, ONBOARDING_STATE, MFA_EVIDENCE)
                   VALUES (src.A, src.U, ?, ?, ?, ?, TRUE, 'ENABLED', ?, 'PROVISIONING', 'REQUIRED_NOT_YET_OBSERVED')""",
          [acct_id, user, p.get("default_role"), p.get("email"), bool(p.get("adopt_existing")), ident,
           p.get("default_role"), p.get("email"), p.get("first_name"), p.get("last_name"), ident, p.get("default_role")])
    if action in ("ONBOARD_USER", "ADD_ROLES", "SET_MANAGED_ROLES"):
        if action == "SET_MANAGED_ROLES":
            x(s, f"DELETE FROM {CTL}.USER_ROLE_DESIRED WHERE ACCOUNT_ID = ? AND USERNAME = ?", [acct_id, user])
        for role in p.get("roles", []):
            x(s, f"""MERGE INTO {CTL}.USER_ROLE_DESIRED t USING (SELECT ? A, ? U, ? R) src
                     ON t.ACCOUNT_ID = src.A AND t.USERNAME = src.U AND t.ROLE_NAME = src.R
                     WHEN NOT MATCHED THEN INSERT (ACCOUNT_ID, USERNAME, ROLE_NAME, SOURCE_OPERATION_ID)
                     VALUES (src.A, src.U, src.R, ?)""", [acct_id, user, role, op["OPERATION_ID"]])
    if action in ("DISABLE_USER", "DISABLE_INTERNAL_ADMIN"):
        x(s, f"UPDATE {CTL}.USER_CONTROL SET DESIRED_STATE = 'DISABLED' WHERE ACCOUNT_ID = ? AND USERNAME = ?",
          [acct_id, user])
    if action == "REENABLE_USER":
        x(s, f"UPDATE {CTL}.USER_CONTROL SET DESIRED_STATE = 'ENABLED' WHERE ACCOUNT_ID = ? AND USERNAME = ?",
          [acct_id, user])


def cmd_approve(s, actor, a):
    approved, refused = [], []
    for op_id in a["operation_ids"]:
        rows = q(s, f"SELECT * FROM {CTL}.OPERATIONS WHERE OPERATION_ID = ?", [op_id])
        if not rows or rows[0]["STATUS"] != "PENDING_APPROVAL":
            refused.append({"id": op_id, "why": "not pending"}); continue
        op = rows[0]
        acct = account(s, op["ACCOUNT_ID"])
        try:
            require(s, actor, acct["ACCOUNT_ID"], "priv" if op["ACTION_FAMILY"] == "PRIVILEGED" else "approve")
        except Denied as d:
            refused.append({"id": op_id, "why": str(d)}); continue
        if op["REQUESTED_BY"].upper() == actor.upper():
            refused.append({"id": op_id, "why": "self-approval not allowed"}); continue
        payload = json.loads(op["PAYLOAD"]) if isinstance(op["PAYLOAD"], str) else op["PAYLOAD"]
        if sha(payload) != op["PAYLOAD_SHA256"]:
            refused.append({"id": op_id, "why": "payload integrity check failed"}); continue
        dead = [d for d in _arr(op.get("DEPENDS_ON")) if q(s, f"""SELECT 1 FROM {CTL}.OPERATIONS WHERE OPERATION_ID = ?
                    AND STATUS IN ('CANCELLED','BLOCKED','FAILED')""", [d])]
        if dead:
            refused.append({"id": op_id, "why": f"depends on rejected or failed operation {dead[0]}"}); continue
        if op["REGISTRY_VERSION"] != acct["REGISTRY_VERSION"] or \
                op["CATALOG_VERSION"] != catalog_version(s, acct["ACCOUNT_ID"]):
            x(s, f"UPDATE {CTL}.OPERATIONS SET STATUS = 'BLOCKED', LAST_ERROR = 'stale approval' WHERE OPERATION_ID = ?",
              [op_id])
            refused.append({"id": op_id, "why": "stale: registry or role catalog changed"}); continue
        x(s, f"""UPDATE {CTL}.OPERATIONS SET STATUS = 'QUEUED', APPROVED_BY = ?, APPROVED_AT = CURRENT_TIMESTAMP()
                 WHERE OPERATION_ID = ? AND STATUS = 'PENDING_APPROVAL'""", [actor, op_id])
        _apply_desired(s, op)
        if op["BATCH_ID"]:
            x(s, f"UPDATE {CTL}.IMPORT_BATCHES SET STATUS = 'APPROVED' WHERE BATCH_ID = ?", [op["BATCH_ID"]])
        audit(s, actor, "APPROVE", op["ACCOUNT_ID"], op["USERNAME"], op_id, {"action": op["ACTION"]})
        approved.append(op_id)
    return {"approved": approved, "refused": refused}


def cmd_reject(s, actor, a):
    n = 0
    for op_id in a["operation_ids"]:
        rows = q(s, f"SELECT ACCOUNT_ID, ACTION_FAMILY FROM {CTL}.OPERATIONS WHERE OPERATION_ID = ?", [op_id])
        if not rows:
            continue
        require(s, actor, rows[0]["ACCOUNT_ID"], "priv" if rows[0]["ACTION_FAMILY"] == "PRIVILEGED" else "approve")
        x(s, f"""UPDATE {CTL}.OPERATIONS SET STATUS = 'CANCELLED', LAST_ERROR = ?, COMPLETED_AT = CURRENT_TIMESTAMP()
                 WHERE OPERATION_ID = ? AND STATUS IN ('PENDING_APPROVAL','QUEUED','BLOCKED','FAILED')""",
          [f"rejected by {actor}: {a.get('reason', '')}"[:500], op_id])
        audit(s, actor, "REJECT", rows[0]["ACCOUNT_ID"], None, op_id, {"reason": a.get("reason")})
        n += 1
        # cascade: operations that depend on this one can never run
        for d in q(s, f"""SELECT OPERATION_ID FROM {CTL}.OPERATIONS WHERE ARRAY_CONTAINS(?::VARIANT, DEPENDS_ON)
                         AND STATUS IN ('PENDING_APPROVAL','QUEUED','BLOCKED','FAILED')""", [op_id]):
            x(s, f"""UPDATE {CTL}.OPERATIONS SET STATUS = 'CANCELLED', LAST_ERROR = ?, COMPLETED_AT = CURRENT_TIMESTAMP()
                     WHERE OPERATION_ID = ?""", [f"dependency {op_id} rejected by {actor}", d["OPERATION_ID"]])
            audit(s, actor, "REJECT", rows[0]["ACCOUNT_ID"], None, d["OPERATION_ID"], {"cascade_from": op_id})
            n += 1
    return {"rejected": n}


def cmd_retry(s, actor, a):
    for op_id in a["operation_ids"]:
        rows = q(s, f"SELECT ACCOUNT_ID FROM {CTL}.OPERATIONS WHERE OPERATION_ID = ?", [op_id])
        if rows:
            require(s, actor, rows[0]["ACCOUNT_ID"], "approve")
            x(s, f"""UPDATE {CTL}.OPERATIONS SET STATUS = 'QUEUED', NEXT_ATTEMPT_AT = NULL, ATTEMPTS = 0
                     WHERE OPERATION_ID = ? AND STATUS IN ('FAILED','PARTIAL','BLOCKED') AND APPROVED_BY IS NOT NULL""", [op_id])
            audit(s, actor, "SUBMIT", rows[0]["ACCOUNT_ID"], None, op_id, {"retry": True})
    return {"ok": True}


def cmd_request_user_action(s, actor, a):
    """DISABLE_USER / REENABLE_USER / ISSUE_PASSWORD_LINK / ENROLL_MFA for selected managed users."""
    acct = account(s, a["account_id"])
    require(s, actor, acct["ACCOUNT_ID"], "operate")
    action = a["action"]
    if action not in ("DISABLE_USER", "REENABLE_USER", "ISSUE_PASSWORD_LINK", "ENROLL_MFA"):
        raise Denied("unsupported action")
    ids = []
    for u in a["usernames"]:
        u = u.upper()
        if not USER_RE.match(u):
            raise Denied(f"invalid username {u}")
        ids.append(new_op(s, actor, acct, action, u, {"username": u}, reason=a.get("reason"), ticket=a.get("ticket")))
    return {"operations": ids}


def eligible_admin(s, username: str) -> Optional[dict]:
    """A user is eligible when they hold ACCOUNTADMIN directly in EIGHTY451, are enabled, and are a PERSON.
    ACCOUNT_USAGE has some latency, so very recent grants may take time to appear."""
    rows = q(s, """SELECT u.NAME, u.EMAIL, u.FIRST_NAME, u.LAST_NAME
                   FROM SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_USERS g
                   JOIN SNOWFLAKE.ACCOUNT_USAGE.USERS u ON u.NAME = g.GRANTEE_NAME
                   WHERE g.ROLE = 'ACCOUNTADMIN' AND g.DELETED_ON IS NULL AND u.DELETED_ON IS NULL
                     AND u.DISABLED = FALSE AND (u.TYPE IS NULL OR u.TYPE = 'PERSON') AND u.NAME = ? LIMIT 1""", [username])
    return rows[0] if rows else None


def cmd_request_internal_access(s, actor, a):
    """Create ADMIN_ACCOUNT_ACCESS + PROVISION and GRANT operations (privileged family) for each
    (EIGHTY451 ACCOUNTADMIN user, managed account) pair."""
    usernames = [str(u).strip().upper() for u in _arr(a.get("usernames"))]
    account_ids = _arr(a.get("account_ids"))
    if not usernames or not account_ids or not a.get("reason") or not a.get("expires_at"):
        raise Denied("users, accounts, reason and expiry are required")
    for account_id in account_ids:
        require(s, actor, account(s, account_id)["ACCOUNT_ID"], "operate")
    people = {}
    for u in usernames:
        emp = eligible_admin(s, u)
        if not emp:
            raise Denied(f"{u} is not an enabled ACCOUNTADMIN user in EIGHTY451")
        if not USER_RE.match(emp["NAME"].upper()):
            raise Denied(f"{u} cannot be created as a managed-account username")
        people[u] = emp
    out, access_ids = [], []
    for u, emp in people.items():
        for account_id in account_ids:
            acct = account(s, account_id)
            access_id = q(s, "SELECT UUID_STRING() U")[0]["U"]
            access_ids.append(access_id)
            x(s, f"""INSERT INTO {CTL}.ADMIN_ACCOUNT_ACCESS (ACCESS_ID, EMPLOYEE_ID, ACCOUNT_ID, TARGET_USERNAME,
                     CORPORATE_EMAIL, FIRST_NAME, LAST_NAME, REQUESTED_STATE, WORKFLOW_STATE, REASON, TICKET,
                     REQUESTED_BY, REVIEW_BY, EXPIRES_AT)
                     SELECT ?, ?, ?, ?, ?, ?, ?, 'GRANTED', 'PENDING_APPROVAL', ?, ?, ?, TRY_TO_DATE(?),
                            TRY_TO_TIMESTAMP_LTZ(?)""",
              [access_id, u, account_id, u, emp["EMAIL"], emp["FIRST_NAME"], emp["LAST_NAME"], a.get("reason"),
               a.get("ticket"), actor, a.get("review_by"), a.get("expires_at")])
            p = {"employee_id": u, "username": u}
            out.append(new_op(s, actor, acct, "PROVISION_INTERNAL_ADMIN", u, p, family="PRIVILEGED",
                              access_id=access_id, reason=a.get("reason"), ticket=a.get("ticket")))
            out.append(new_op(s, actor, acct, "GRANT_ACCOUNTADMIN", u, p, family="PRIVILEGED",
                              access_id=access_id, reason=a.get("reason"), ticket=a.get("ticket")))
    return {"operations": out, "access_ids": access_ids}


def cmd_approve_internal_access(s, actor, a):
    """Approve access rows (binds approver) and the linked privileged operations."""
    for access_id in a["access_ids"]:
        row = q(s, f"SELECT * FROM {CTL}.ADMIN_ACCOUNT_ACCESS WHERE ACCESS_ID = ?", [access_id])
        if not row:
            continue
        row = row[0]
        require(s, actor, row["ACCOUNT_ID"], "priv")
        if row["REQUESTED_BY"].upper() == actor.upper():
            raise Denied("self-approval not allowed")
        x(s, f"""UPDATE {CTL}.ADMIN_ACCOUNT_ACCESS SET APPROVED_BY = ?, APPROVED_AT = CURRENT_TIMESTAMP(),
                 WORKFLOW_STATE = IFF(WORKFLOW_STATE = 'PENDING_APPROVAL', 'GRANT_PENDING', WORKFLOW_STATE)
                 WHERE ACCESS_ID = ?""", [actor, access_id])
        ops = [o["OPERATION_ID"] for o in q(s, f"""SELECT OPERATION_ID FROM {CTL}.OPERATIONS
                WHERE ACCESS_ID = ? AND STATUS = 'PENDING_APPROVAL'""", [access_id])]
        cmd_approve(s, actor, {"operation_ids": ops})
    return {"ok": True}


def cmd_request_revoke(s, actor, a):
    """REVOKE_ACCOUNTADMIN or DISABLE_INTERNAL_ADMIN for existing access rows."""
    action = a["action"]
    if action not in ("REVOKE_ACCOUNTADMIN", "DISABLE_INTERNAL_ADMIN"):
        raise Denied("unsupported action")
    out = []
    for access_id in a["access_ids"]:
        row = q(s, f"SELECT * FROM {CTL}.ADMIN_ACCOUNT_ACCESS WHERE ACCESS_ID = ?", [access_id])[0]
        acct = account(s, row["ACCOUNT_ID"])
        require(s, actor, acct["ACCOUNT_ID"], "operate")
        p = {"username": row["TARGET_USERNAME"], "emergency_override": bool(a.get("emergency_override"))}
        x(s, f"UPDATE {CTL}.ADMIN_ACCOUNT_ACCESS SET WORKFLOW_STATE = 'REVOKE_PENDING' WHERE ACCESS_ID = ?", [access_id])
        out.append(new_op(s, actor, acct, action, row["TARGET_USERNAME"], p, family="PRIVILEGED",
                          access_id=access_id, reason=a.get("reason"), ticket=a.get("ticket")))
    return {"operations": out}


def cmd_mark_handoff_delivered(s, actor, a):
    rows = q(s, f"SELECT ACCOUNT_ID, USERNAME, LINK_TYPE FROM {CTL}.HANDOFF_VAULT WHERE HANDOFF_ID = ?", [a["handoff_id"]])
    if not rows:
        raise Denied("not found")
    require(s, actor, rows[0]["ACCOUNT_ID"], "approve")
    # Overwrite the link immediately; purge task deletes the row.
    x(s, f"""UPDATE {CTL}.HANDOFF_VAULT SET LINK_VALUE = NULL, DELIVERED_BY = ?, DELIVERED_AT = CURRENT_TIMESTAMP()
             WHERE HANDOFF_ID = ?""", [actor, a["handoff_id"]])
    audit(s, actor, "HANDOFF", rows[0]["ACCOUNT_ID"], rows[0]["USERNAME"], None,
          {"link_type": rows[0]["LINK_TYPE"], "delivered": True, "channel": a.get("channel")})
    return {"ok": True}


def cmd_set_account_state(s, actor, a):
    acct = account(s, a["account_id"])
    require(s, actor, acct["ACCOUNT_ID"], "approve")
    x(s, f"""UPDATE {CTL}.CUSTOMER_ACCOUNTS SET IS_PAUSED = ?, PAUSE_REASON = ?, CONSECUTIVE_FAILURES =
             IFF(?, CONSECUTIVE_FAILURES, 0), UPDATED_AT = CURRENT_TIMESTAMP(), UPDATED_BY = ? WHERE ACCOUNT_ID = ?""",
      [bool(a["paused"]), a.get("reason"), bool(a["paused"]), actor, acct["ACCOUNT_ID"]])
    audit(s, actor, "PAUSE", acct["ACCOUNT_ID"], None, None, {"paused": a["paused"], "reason": a.get("reason")})
    return {"ok": True}


def cmd_update_registry(s, actor, a):
    """Edit non-secret registry fields. Bumps REGISTRY_VERSION (invalidates pending approvals)."""
    acct = account(s, a["account_id"])
    require(s, actor, acct["ACCOUNT_ID"], "priv")
    allowed = {"DISPLAY_NAME", "CUSTOMER_ID", "APPROVED_EMAIL_DOMAINS", "PROTECTED_USERS", "EXEC_ROLE",
               "EXEC_WAREHOUSE", "IS_ENABLED", "INTERNAL_DEFAULT_ROLE", "CUSTOMER_AUTH_POLICY", "INTERNAL_AUTH_POLICY"}
    sets, params = [], []
    for k, v in a["changes"].items():
        if k not in allowed:
            raise Denied(f"field {k} cannot be edited here")
        if k in ("APPROVED_EMAIL_DOMAINS", "PROTECTED_USERS"):
            sets.append(f"{k} = PARSE_JSON(?)"); params.append(json.dumps(v))
        else:
            sets.append(f"{k} = ?"); params.append(v)
    if not sets:
        return {"ok": True}
    if a["changes"].get("IS_ENABLED") and acct["BOOTSTRAP_STATUS"] != "VERIFIED":
        raise Denied("account cannot be enabled before a successful preflight")
    x(s, f"""UPDATE {CTL}.CUSTOMER_ACCOUNTS SET {', '.join(sets)}, REGISTRY_VERSION = REGISTRY_VERSION + 1,
             UPDATED_AT = CURRENT_TIMESTAMP(), UPDATED_BY = ? WHERE ACCOUNT_ID = ?""",
      params + [actor, acct["ACCOUNT_ID"]])
    audit(s, actor, "REGISTRY", acct["ACCOUNT_ID"], None, None, {"changes": list(a["changes"].keys())})
    return {"ok": True}


def cmd_upsert_roles(s, actor, a):
    acct = account(s, a["account_id"])
    require(s, actor, acct["ACCOUNT_ID"], "priv")
    blocked = {r["ROLE_NAME"] for r in q(s, f"SELECT ROLE_NAME FROM {CTL}.BLOCKED_ROLES")}
    new_ver = catalog_version(s, acct["ACCOUNT_ID"]) + 1
    for r in a["roles"]:
        name = r["ROLE_NAME"].upper()
        if not ROLE_RE.match(name) or name in blocked:
            raise Denied(f"role {name} not allowed in catalog")
        x(s, f"""MERGE INTO {CTL}.ROLE_CATALOG t USING (SELECT ? A, ? R) src ON t.ACCOUNT_ID = src.A AND t.ROLE_NAME = src.R
                 WHEN MATCHED THEN UPDATE SET IS_DEFAULT_ELIGIBLE = ?, IS_ACTIVE = ?, APPROVAL_CLASS = ?, CATALOG_VERSION = ?,
                      UPDATED_AT = CURRENT_TIMESTAMP()
                 WHEN NOT MATCHED THEN INSERT (ACCOUNT_ID, ROLE_NAME, IS_DEFAULT_ELIGIBLE, IS_ACTIVE, APPROVAL_CLASS, CATALOG_VERSION)
                      VALUES (src.A, src.R, ?, ?, ?, ?)""",
          [acct["ACCOUNT_ID"], name, bool(r.get("IS_DEFAULT_ELIGIBLE", True)), bool(r.get("IS_ACTIVE", True)),
           r.get("APPROVAL_CLASS", "STANDARD"), new_ver,
           bool(r.get("IS_DEFAULT_ELIGIBLE", True)), bool(r.get("IS_ACTIVE", True)),
           r.get("APPROVAL_CLASS", "STANDARD"), new_ver])
    x(s, f"UPDATE {CTL}.ROLE_CATALOG SET CATALOG_VERSION = ? WHERE ACCOUNT_ID = ?", [new_ver, acct["ACCOUNT_ID"]])
    audit(s, actor, "REGISTRY", acct["ACCOUNT_ID"], None, None, {"role_catalog_version": new_ver})
    return {"catalog_version": new_ver}


def cmd_run_now(s, actor, a):
    acct = account(s, a["account_id"])
    mode = a.get("mode", "QUEUE")
    require(s, actor, acct["ACCOUNT_ID"], "approve" if mode == "QUEUE" else "operate")
    r = s.sql("CALL ACCT_ADMIN_DB.WORKER.RUN_ACCOUNT(?, ?)", params=[acct["ACCOUNT_ID"], mode]).collect()[0][0]
    audit(s, actor, "RECONCILE" if mode != "QUEUE" else "EXECUTE", acct["ACCOUNT_ID"], None, None, {"run_now": mode})
    return json.loads(r) if isinstance(r, str) else r


COMMANDS = {
    "SAVE_IMPORT": cmd_save_import,
    "SUBMIT_BATCH": cmd_submit_batch,
    "APPROVE": cmd_approve,
    "REJECT": cmd_reject,
    "RETRY": cmd_retry,
    "REQUEST_USER_ACTION": cmd_request_user_action,
    "REQUEST_INTERNAL_ACCESS": cmd_request_internal_access,
    "APPROVE_INTERNAL_ACCESS": cmd_approve_internal_access,
    "REQUEST_REVOKE": cmd_request_revoke,
    "MARK_HANDOFF_DELIVERED": cmd_mark_handoff_delivered,
    "SET_ACCOUNT_STATE": cmd_set_account_state,
    "UPDATE_REGISTRY": cmd_update_registry,
    "UPSERT_ROLES": cmd_upsert_roles,
    "RUN_NOW": cmd_run_now,
}


def main(session, actor: str, command: str, args) -> dict:
    if not actor or not re.match(r"^[A-Za-z0-9_.@\-]{1,255}$", actor):
        return {"ok": False, "error": "invalid actor"}
    fn = COMMANDS.get((command or "").upper())
    if fn is None:
        return {"ok": False, "error": "unknown command"}
    args = json.loads(args) if isinstance(args, str) else (args or {})
    expected = session.sql("SELECT CURRENT_ACCOUNT_NAME() N, CURRENT_ACCOUNT() L").collect()[0]
    if "EIGHTY451" not in (expected["N"], expected["L"]):
        return {"ok": False, "error": "app may only run in EIGHTY451"}
    try:
        return {"ok": True, "result": fn(session, actor.upper(), args)}
    except Denied as d:
        audit(session, actor.upper(), "DENIED", args.get("account_id"), None, None,
              {"command": command, "reason": str(d)})
        return {"ok": False, "error": str(d)}
