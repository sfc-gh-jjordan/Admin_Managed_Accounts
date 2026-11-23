"""Sample data for running the app locally without Snowflake (ACCT_ADMIN_MOCK=1).

Used only to preview the UI and capture user-guide screenshots. MockSession recognizes the
queries the pages issue and returns filtered pandas DataFrames; no SQL is executed and
commands are never sent anywhere. All names, emails and IDs below are fictitious.
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timedelta

import pandas as pd

NOW = datetime(2026, 11, 19, 9, 30)


def _t(hours: float):
    return NOW - timedelta(hours=hours)


ACCOUNTS = pd.DataFrame([
    dict(ACCOUNT_ID="CPG_ACME", DISPLAY_NAME="Acme Foods", ACCOUNT_LOCATOR="AB12345", REGION="AWS_US_EAST_1",
         IS_ENABLED=True, IS_PAUSED=False, PAUSE_REASON=None, BOOTSTRAP_STATUS="VERIFIED", REGISTRY_VERSION=4,
         CONSECUTIVE_FAILURES=0, SQL_API_HOST="eighty451-acme_ext.snowflakecomputing.com",
         JWT_ACCOUNT_IDENTIFIER="EIGHTY451-ACME_EXT", EXPECTED_ACCOUNT_LOCATOR="AB12345",
         SERVICE_USER="SVC_ACCT_ADMIN", EXEC_ROLE="ACCOUNTADMIN", WORKER_PROCEDURE="ACCT_ADMIN_DB.WORKER.EXEC_CPG_ACME",
         SECRET_NAME="ACCT_ADMIN_DB.SECRETS.SQLAPI_KEY_CPG_ACME", PUBLIC_KEY_FP="SHA256:q3Vx...demo",
         LAST_PREFLIGHT_AT=_t(2), LAST_PREFLIGHT_RESULT='{"ok": true}',
         APPROVED_EMAIL_DOMAINS='["acmefoods.example"]', PROTECTED_USERS='["ACME_BREAKGLASS"]'),
    dict(ACCOUNT_ID="CPG_BRIGHT", DISPLAY_NAME="Bright Beverages", ACCOUNT_LOCATOR="CD67890", REGION="AZURE_EASTUS2",
         IS_ENABLED=True, IS_PAUSED=False, PAUSE_REASON=None, BOOTSTRAP_STATUS="VERIFIED", REGISTRY_VERSION=2,
         CONSECUTIVE_FAILURES=1, SQL_API_HOST="eighty451-bright_ext.snowflakecomputing.com",
         JWT_ACCOUNT_IDENTIFIER="EIGHTY451-BRIGHT_EXT", EXPECTED_ACCOUNT_LOCATOR="CD67890",
         SERVICE_USER="SVC_ACCT_ADMIN", EXEC_ROLE="ACCOUNTADMIN", WORKER_PROCEDURE="ACCT_ADMIN_DB.WORKER.EXEC_CPG_BRIGHT",
         SECRET_NAME="ACCT_ADMIN_DB.SECRETS.SQLAPI_KEY_CPG_BRIGHT", PUBLIC_KEY_FP="SHA256:Lm9p...demo",
         LAST_PREFLIGHT_AT=_t(5), LAST_PREFLIGHT_RESULT='{"ok": true}',
         APPROVED_EMAIL_DOMAINS='["brightbev.example"]', PROTECTED_USERS='[]'),
    dict(ACCOUNT_ID="CPG_CRUNCH", DISPLAY_NAME="Crunch Snacks", ACCOUNT_LOCATOR="EF24680", REGION="AWS_US_WEST_2",
         IS_ENABLED=True, IS_PAUSED=True, PAUSE_REASON="circuit breaker: consecutive failures",
         BOOTSTRAP_STATUS="VERIFIED", REGISTRY_VERSION=3, CONSECUTIVE_FAILURES=5,
         SQL_API_HOST="eighty451-crunch_ext.snowflakecomputing.com", JWT_ACCOUNT_IDENTIFIER="EIGHTY451-CRUNCH_EXT",
         EXPECTED_ACCOUNT_LOCATOR="EF24680", SERVICE_USER="SVC_ACCT_ADMIN", EXEC_ROLE="ACCT_USER_ADMIN",
         WORKER_PROCEDURE="ACCT_ADMIN_DB.WORKER.EXEC_CPG_CRUNCH", SECRET_NAME="ACCT_ADMIN_DB.SECRETS.SQLAPI_KEY_CPG_CRUNCH",
         PUBLIC_KEY_FP="SHA256:Zt4k...demo", LAST_PREFLIGHT_AT=_t(30), LAST_PREFLIGHT_RESULT='{"ok": false}',
         APPROVED_EMAIL_DOMAINS='["crunch.example"]', PROTECTED_USERS='[]'),
    dict(ACCOUNT_ID="JJAWS_DEMO999", DISPLAY_NAME="Demo sandbox", ACCOUNT_LOCATOR="GH13579", REGION="AWS_US_WEST_2",
         IS_ENABLED=True, IS_PAUSED=False, PAUSE_REASON=None, BOOTSTRAP_STATUS="VERIFIED", REGISTRY_VERSION=1,
         CONSECUTIVE_FAILURES=0, SQL_API_HOST="eighty451-demo999_ext.snowflakecomputing.com",
         JWT_ACCOUNT_IDENTIFIER="EIGHTY451-DEMO999_EXT", EXPECTED_ACCOUNT_LOCATOR="GH13579",
         SERVICE_USER="SVC_ACCT_ADMIN", EXEC_ROLE="ACCOUNTADMIN", WORKER_PROCEDURE="ACCT_ADMIN_DB.WORKER.EXEC_JJAWS_DEMO999",
         SECRET_NAME="ACCT_ADMIN_DB.SECRETS.SQLAPI_KEY_JJAWS_DEMO999", PUBLIC_KEY_FP="SHA256:Hd2w...demo",
         LAST_PREFLIGHT_AT=_t(1), LAST_PREFLIGHT_RESULT='{"ok": true}',
         APPROVED_EMAIL_DOMAINS='["snowflake.com"]', PROTECTED_USERS='[]'),
    dict(ACCOUNT_ID="CPG_DAIRY", DISPLAY_NAME="Dairy Fresh", ACCOUNT_LOCATOR="IJ97531", REGION="GCP_US_CENTRAL1",
         IS_ENABLED=False, IS_PAUSED=False, PAUSE_REASON=None, BOOTSTRAP_STATUS="NOT_BOOTSTRAPPED", REGISTRY_VERSION=1,
         CONSECUTIVE_FAILURES=0, SQL_API_HOST="eighty451-dairy_ext.snowflakecomputing.com",
         JWT_ACCOUNT_IDENTIFIER="EIGHTY451-DAIRY_EXT", EXPECTED_ACCOUNT_LOCATOR="IJ97531",
         SERVICE_USER="SVC_ACCT_ADMIN", EXEC_ROLE="ACCOUNTADMIN", WORKER_PROCEDURE=None, SECRET_NAME=None,
         PUBLIC_KEY_FP=None, LAST_PREFLIGHT_AT=None, LAST_PREFLIGHT_RESULT=None,
         APPROVED_EMAIL_DOMAINS='[]', PROTECTED_USERS='[]'),
])


def _u(acct, user, email, managed=True, ident="CPG_CUSTOMER", state="ENABLED", default="CPG_ANALYST",
       desired=("CPG_ANALYST",), observed=("CPG_ANALYST",), mfa="ENROLLED", drift=(), verified=3, last_op=None,
       disabled=False, stale=False, onboarding="HANDOFF_ISSUED"):
    return dict(ACCOUNT_ID=acct, USERNAME=user, EMAIL=email, FIRST_NAME=user.split("_")[0].title(),
                LAST_NAME=(user.split("_") + ["User"])[1].title(), IDENTITY_CLASS=ident if managed else "UNMANAGED",
                IS_MANAGED=managed, DESIRED_STATE=state if managed else None,
                DESIRED_DEFAULT_ROLE=default if managed else None, ONBOARDING_STATE=onboarding if managed else None,
                OBSERVED_EXISTS=True, OBSERVED_DISABLED=disabled, OBSERVED_DEFAULT_ROLE=default,
                DESIRED_ROLES=list(desired) if managed else [], OBSERVED_ROLES=list(observed), MFA_EVIDENCE=mfa,
                DRIFT_FLAGS=list(drift), IS_STALE=stale, LAST_VERIFIED_AT=_t(verified), LAST_OPERATION_STATUS=last_op)


USERS = pd.DataFrame([
    _u("CPG_ACME", "JANE_SMITH", "jane.smith@acmefoods.example", last_op="SUCCEEDED"),
    _u("CPG_ACME", "PAT_LEE", "pat.lee@acmefoods.example", state="DISABLED", disabled=True, onboarding="DISABLED",
       last_op="SUCCEEDED"),
    _u("CPG_ACME", "RAVI_PATEL", "ravi.patel@acmefoods.example", desired=("CPG_ANALYST", "CPG_WRITER"),
       observed=("CPG_ANALYST",), drift=("MISSING_DESIRED_ROLES",), last_op="FAILED"),
    _u("CPG_ACME", "MAYA_CHEN", "maya.chen@acmefoods.example", mfa="REQUIRED_NOT_YET_OBSERVED",
       onboarding="PROVISIONED_PENDING_HANDOFF", last_op="SUCCEEDED"),
    _u("CPG_ACME", "ACME_BREAKGLASS", "it@acmefoods.example", managed=False, observed=("ACCOUNTADMIN",),
       mfa="UNKNOWN"),
    _u("CPG_ACME", "LEGACY_ETL", None, managed=False, observed=("SYSADMIN",), mfa="UNKNOWN", stale=True, verified=40),
    _u("CPG_ACME", "J_ORTIZ_8451", "j.ortiz@8451.example", ident="INTERNAL_ADMIN", default="PUBLIC",
       desired=(), observed=("ACCOUNTADMIN",), last_op="SUCCEEDED"),
    _u("CPG_BRIGHT", "SAM_RIVERA", "sam.rivera@brightbev.example", last_op="SUCCEEDED"),
    _u("CPG_BRIGHT", "LEE_KIM", "lee.kim@brightbev.example", state="ENABLED", disabled=True,
       drift=("DISABLED_BUT_DESIRED_ENABLED",), last_op="BLOCKED"),
    _u("CPG_BRIGHT", "ANALYTICS_SVC", None, managed=False, observed=("BRIGHT_READER",), mfa="UNKNOWN"),
    _u("CPG_CRUNCH", "OMAR_HASSAN", "omar.hassan@crunch.example", mfa="REQUIRED_NOT_YET_OBSERVED", stale=True,
       verified=30, last_op="FAILED"),
    _u("CPG_CRUNCH", "NINA_BROOKS", "nina.brooks@crunch.example", stale=True, verified=30),
    _u("JJAWS_DEMO999", "DEMO_ADMIN", "demo.admin@snowflake.com", managed=False, observed=("ACCOUNTADMIN",),
       mfa="ENROLLED"),
])

ROLE_CATALOG = pd.DataFrame([
    dict(ACCOUNT_ID="CPG_ACME", ROLE_NAME="CPG_ANALYST", IS_DEFAULT_ELIGIBLE=True, APPROVAL_CLASS="STANDARD",
         IS_ACTIVE=True, CATALOG_VERSION=3, REVIEW_NOTES=None),
    dict(ACCOUNT_ID="CPG_ACME", ROLE_NAME="CPG_WRITER", IS_DEFAULT_ELIGIBLE=False, APPROVAL_CLASS="ELEVATED",
         IS_ACTIVE=True, CATALOG_VERSION=3, REVIEW_NOTES=None),
    dict(ACCOUNT_ID="CPG_ACME", ROLE_NAME="CPG_LEGACY_LOADER", IS_DEFAULT_ELIGIBLE=False, APPROVAL_CLASS="BLOCKED",
         IS_ACTIVE=False, CATALOG_VERSION=3, REVIEW_NOTES=None),
    dict(ACCOUNT_ID="CPG_ACME", ROLE_NAME="ACME_PROMO_ANALYST", IS_DEFAULT_ELIGIBLE=True, APPROVAL_CLASS="STANDARD",
         IS_ACTIVE=True, CATALOG_VERSION=3,
         REVIEW_NOTES="auto-created from import 7f3c... by ADMIN_ONE, approved by ADMIN_TWO"),
    dict(ACCOUNT_ID="CPG_BRIGHT", ROLE_NAME="CPG_ANALYST", IS_DEFAULT_ELIGIBLE=True, APPROVAL_CLASS="STANDARD",
         IS_ACTIVE=True, CATALOG_VERSION=1, REVIEW_NOTES=None),
    dict(ACCOUNT_ID="CPG_CRUNCH", ROLE_NAME="CPG_ANALYST", IS_DEFAULT_ELIGIBLE=True, APPROVAL_CLASS="STANDARD",
         IS_ACTIVE=True, CATALOG_VERSION=1, REVIEW_NOTES=None),
    dict(ACCOUNT_ID="JJAWS_DEMO999", ROLE_NAME="CPG_ANALYST", IS_DEFAULT_ELIGIBLE=True, APPROVAL_CLASS="STANDARD",
         IS_ACTIVE=True, CATALOG_VERSION=1, REVIEW_NOTES=None),
])

BLOCKED_ROLES = pd.DataFrame({"ROLE_NAME": ["ACCOUNTADMIN", "SECURITYADMIN", "USERADMIN", "SYSADMIN", "ORGADMIN",
                                            "GLOBALORGADMIN"]})

AUTHZ = pd.DataFrame([
    dict(ADMIN_USER="ADMIN_TWO", ACCOUNT_ID="*", CAN_VIEW=True, CAN_OPERATE=True, CAN_APPROVE=True,
         CAN_PRIV_APPROVE=True, IS_ACTIVE=True),
    dict(ADMIN_USER="ADMIN_ONE", ACCOUNT_ID="*", CAN_VIEW=True, CAN_OPERATE=True, CAN_APPROVE=False,
         CAN_PRIV_APPROVE=False, IS_ACTIVE=True),
])


def _op(i, acct, user, action, status, hours, family="CUSTOMER", by="ADMIN_ONE", appr="ADMIN_TWO", err=None,
        attempts=1, payload=None, batch=None, reason="Customer request", ticket="CHG-1042", reg=None):
    return dict(OPERATION_ID=f"op-{i:04d}-demo", REQUESTED_AT=_t(hours), ACCOUNT_ID=acct, USERNAME=user,
                ACTION=action, ACTION_FAMILY=family, STATUS=status, ATTEMPTS=attempts,
                NEXT_ATTEMPT_AT=_t(-0.5) if status == "QUEUED" and attempts > 1 else None, REQUESTED_BY=by,
                APPROVED_BY=None if status == "PENDING_APPROVAL" else appr, LAST_ERROR=err,
                COMPLETED_AT=_t(hours - 0.2) if status in ("SUCCEEDED", "FAILED", "BLOCKED", "CANCELLED") else None,
                REASON=reason, TICKET=ticket, BATCH_ID=batch,
                REGISTRY_VERSION=reg if reg is not None else int(ACCOUNTS.set_index("ACCOUNT_ID").loc[acct, "REGISTRY_VERSION"]),
                PAYLOAD=json.dumps(payload or {"username": user}))


OPERATIONS = pd.DataFrame([
    _op(1, "JJAWS_DEMO999", None, "CREATE_ROLE", "PENDING_APPROVAL", 0.3, batch="b-demo-01",
        payload={"role_name": "DEMO_ANALYST_ROLE", "parent_role": "SYSADMIN", "batch_id": "b-demo-01"},
        reason="Onboard demo tester", ticket="DEMO-1"),
    _op(2, "JJAWS_DEMO999", "TEST_USER_001", "ONBOARD_USER", "PENDING_APPROVAL", 0.3, batch="b-demo-01",
        payload={"username": "TEST_USER_001", "email": "joe.jordan@snowflake.com", "first_name": "Test",
                 "last_name": "User", "default_role": "DEMO_ANALYST_ROLE", "roles": ["DEMO_ANALYST_ROLE"]},
        reason="Onboard demo tester", ticket="DEMO-1"),
    _op(3, "CPG_ACME", "KAI_NGUYEN", "ONBOARD_USER", "PENDING_APPROVAL", 1.5, batch="b-acme-07",
        payload={"username": "KAI_NGUYEN", "email": "kai.nguyen@acmefoods.example", "default_role": "CPG_ANALYST",
                 "roles": ["CPG_ANALYST"]}),
    _op(4, "CPG_BRIGHT", "LEE_KIM", "REENABLE_USER", "PENDING_APPROVAL", 3, reg=1, ticket="CHG-1039"),
    _op(5, "CPG_ACME", "J_ORTIZ_8451", "GRANT_ACCOUNTADMIN", "PENDING_APPROVAL", 2, family="PRIVILEGED",
        payload={"employee_id": "J_ORTIZ_8451", "username": "J_ORTIZ_8451"}, ticket="SEC-220"),
    _op(6, "CPG_ACME", "MAYA_CHEN", "ISSUE_PASSWORD_LINK", "QUEUED", 0.8),
    _op(7, "CPG_ACME", "RAVI_PATEL", "ADD_ROLES", "FAILED", 6, attempts=5,
        err="SQL API 002003: Role 'CPG_WRITER' does not exist or not authorized."),
    _op(8, "CPG_BRIGHT", "LEE_KIM", "DISABLE_USER", "BLOCKED", 8, err="stale approval: registry changed since approval"),
    _op(9, "CPG_CRUNCH", "OMAR_HASSAN", "ONBOARD_USER", "FAILED", 26, attempts=5,
        err="SQL API HTTP 401: JWT token is invalid"),
    _op(10, "CPG_ACME", "JANE_SMITH", "ONBOARD_USER", "SUCCEEDED", 48),
    _op(11, "CPG_ACME", "PAT_LEE", "DISABLE_USER", "SUCCEEDED", 24),
    _op(12, "CPG_BRIGHT", "SAM_RIVERA", "ONBOARD_USER", "RUNNING", 0.1),
    _op(13, "CPG_ACME", None, "CREATE_ROLE", "SUCCEEDED", 72, batch="b-acme-05",
        payload={"role_name": "ACME_PROMO_ANALYST", "parent_role": "SYSADMIN", "batch_id": "b-acme-05"}),
])

STEPS = pd.DataFrame([
    dict(OPERATION_ID="op-0007-demo", STEP_NO=n, STEP_NAME=name, OUTCOME=out, HTTP_STATUS=http, SF_CODE=code,
         REQUEST_ID=f"8c1d-{n}", STATEMENT_HANDLE=f"01b9-{n}", ERROR=err, STARTED_AT=_t(6), FINISHED_AT=_t(5.99))
    for n, name, out, http, code, err in [
        (1, "GRANT_ROLE", "SUCCEEDED", 200, "090001", None),
        (2, "GRANT_ROLE", "FAILED", 422, "002003", "Role 'CPG_WRITER' does not exist or not authorized."),
    ]
] + [
    dict(OPERATION_ID="op-0010-demo", STEP_NO=n, STEP_NAME=name, OUTCOME="SUCCEEDED", HTTP_STATUS=200,
         SF_CODE="090001", REQUEST_ID=f"5a2e-{n}", STATEMENT_HANDLE=f"01b8-{n}", ERROR=None, STARTED_AT=_t(48),
         FINISHED_AT=_t(47.99))
    for n, name in enumerate(["SHOW_USER", "DESCRIBE_AUTH_POLICY", "CREATE_USER_DISABLED", "SET_AUTH_POLICY",
                              "GRANT_ROLE", "SET_DEFAULT_ROLE", "SHOW_USER", "SHOW_GRANTS_TO_USER",
                              "POLICY_REFERENCES", "ENABLE_USER", "SHOW_USER", "SHOW_MFA_METHODS"], start=1)
])

AUDIT = pd.DataFrame([
    dict(EVENT_TS=_t(h), ACTOR=actor, EVENT_TYPE=etype, ACCOUNT_ID=acct, USERNAME=user, OPERATION_ID=op,
         DETAILS=json.dumps(details))
    for h, actor, etype, acct, user, op, details in [
        (0.3, "ADMIN_ONE", "IMPORT", "JJAWS_DEMO999", None, None, {"batch_id": "b-demo-01", "rows": 1}),
        (0.3, "ADMIN_ONE", "SUBMIT", "JJAWS_DEMO999", None, "op-0001-demo", {"action": "CREATE_ROLE"}),
        (0.3, "ADMIN_ONE", "SUBMIT", "JJAWS_DEMO999", "TEST_USER_001", "op-0002-demo", {"action": "ONBOARD_USER"}),
        (0.1, "WORKER", "EXECUTE", "CPG_BRIGHT", "SAM_RIVERA", "op-0012-demo", {"action": "ONBOARD_USER"}),
        (6, "WORKER", "EXECUTE", "CPG_ACME", "RAVI_PATEL", "op-0007-demo", {"action": "ADD_ROLES", "http": 422}),
        (8, "WORKER", "EXECUTE", "CPG_BRIGHT", "LEE_KIM", "op-0008-demo", {"blocked": "stale approval"}),
        (12, "WORKER", "RECONCILE", "CPG_ACME", None, None, {"remote_users": 7, "managed_checked": 5}),
        (24, "ADMIN_TWO", "APPROVE", "CPG_ACME", "PAT_LEE", "op-0011-demo", {"action": "DISABLE_USER"}),
        (30, "WORKER", "PAUSE", "CPG_CRUNCH", None, None, {"reason": "circuit breaker"}),
        (72, "WORKER", "REGISTRY", "CPG_ACME", None, "op-0013-demo", {"role_created": "ACME_PROMO_ANALYST"}),
    ]
])

ELIGIBLE_ADMINS = pd.DataFrame([
    dict(NAME="J_ORTIZ_8451", EMAIL="j.ortiz@8451.example", FIRST_NAME="Jo", LAST_NAME="Ortiz"),
    dict(NAME="A_BAKER_8451", EMAIL="a.baker@8451.example", FIRST_NAME="Alex", LAST_NAME="Baker"),
    dict(NAME="C_NGUYEN_8451", EMAIL="c.nguyen@8451.example", FIRST_NAME="Casey", LAST_NAME="Nguyen"),
])

ACCESS = pd.DataFrame([
    dict(ACCESS_ID="acc-01", EMPLOYEE_ID="A_BAKER_8451", CORPORATE_EMAIL="a.baker@8451.example", ACCOUNT_ID="CPG_BRIGHT", TARGET_USERNAME="A_BAKER_8451",
         WORKFLOW_STATE="PENDING_APPROVAL", REASON="Quarterly support rotation", TICKET="SEC-231",
         REQUESTED_BY="ADMIN_ONE", APPROVED_BY=None, CREATED_AT=_t(4), REVIEW_BY=None, EXPIRES_AT=_t(-24 * 30),
         OBSERVED_ACCOUNTADMIN=None, OBSERVED_MFA=None, LAST_VERIFIED_AT=None),
    dict(ACCESS_ID="acc-02", EMPLOYEE_ID="J_ORTIZ_8451", CORPORATE_EMAIL="j.ortiz@8451.example", ACCOUNT_ID="CPG_ACME", TARGET_USERNAME="J_ORTIZ_8451",
         WORKFLOW_STATE="GRANTED", REASON="Incident response", TICKET="SEC-220", REQUESTED_BY="ADMIN_ONE",
         APPROVED_BY="ADMIN_TWO", CREATED_AT=_t(200), REVIEW_BY=_t(-24 * 14), EXPIRES_AT=_t(-24 * 60),
         OBSERVED_ACCOUNTADMIN=True, OBSERVED_MFA="ENROLLED", LAST_VERIFIED_AT=_t(3)),
    dict(ACCESS_ID="acc-03", EMPLOYEE_ID="J_ORTIZ_8451", CORPORATE_EMAIL="j.ortiz@8451.example", ACCOUNT_ID="JJAWS_DEMO999", TARGET_USERNAME="J_ORTIZ_8451",
         WORKFLOW_STATE="AWAITING_MFA", REASON="Demo support", TICKET="SEC-225", REQUESTED_BY="ADMIN_ONE",
         APPROVED_BY="ADMIN_TWO", CREATED_AT=_t(20), REVIEW_BY=None, EXPIRES_AT=_t(-24 * 7),
         OBSERVED_ACCOUNTADMIN=False, OBSERVED_MFA="REQUIRED_NOT_YET_OBSERVED", LAST_VERIFIED_AT=_t(1)),
])

HANDOFF = pd.DataFrame([
    dict(HANDOFF_ID="h-01", OPERATION_ID="op-0014-demo", ACCOUNT_ID="CPG_ACME", USERNAME="MAYA_CHEN",
         LINK_TYPE="PASSWORD_RESET", LINK_VALUE="https://eighty451-acme_ext.snowflakecomputing.com/console/login#/reset/DEMO-NOT-REAL",
         CREATED_AT=_t(1), EXPIRES_AT=_t(-11)),
])

TABLES = {"CUSTOMER_ACCOUNTS": ACCOUNTS, "USER_CONTROL": USERS, "ROLE_CATALOG": ROLE_CATALOG,
          "BLOCKED_ROLES": BLOCKED_ROLES, "ADMIN_AUTHORIZATIONS": AUTHZ, "OPERATIONS": OPERATIONS,
          "OPERATION_STEPS": STEPS, "AUDIT_EVENTS": AUDIT,
          "ADMIN_ACCOUNT_ACCESS": ACCESS, "V_HANDOFF_PENDING": HANDOFF, "V_USER_INVENTORY": USERS}


# ---------------------------------------------------------------------------- query routing
def _project(sql: str, df: pd.DataFrame) -> pd.DataFrame:
    m = re.match(r"\s*SELECT\s+(.*?)\s+FROM\s", sql, re.S | re.I)
    cols = [c.strip() for c in m.group(1).split(",")] if m else ["*"]
    if cols == ["*"] or not all(re.fullmatch(r"[A-Z_]+", c) for c in cols):
        return df.reset_index(drop=True)
    return df[[c for c in cols if c in df.columns]].reset_index(drop=True)


def _overview_metrics() -> pd.DataFrame:
    m, u, o = ACCOUNTS, USERS, OPERATIONS
    return pd.DataFrame([dict(
        ACCOUNTS_TOTAL=len(m), ACCOUNTS_ACTIVE=int((m.IS_ENABLED & ~m.IS_PAUSED).sum()),
        ACCOUNTS_PAUSED=int(m.IS_PAUSED.sum()), PENDING_APPROVALS=int((o.STATUS == "PENDING_APPROVAL").sum()),
        MANAGED_ENABLED=int((u.IS_MANAGED & (u.DESIRED_STATE == "ENABLED")).sum()),
        MANAGED_DISABLED=int((u.IS_MANAGED & (u.DESIRED_STATE == "DISABLED")).sum()),
        UNMANAGED_USERS=int((~u.IS_MANAGED).sum()), IN_FLIGHT=int(o.STATUS.isin(["QUEUED", "RUNNING"]).sum()),
        FAILED_OPS=int(o.STATUS.isin(["FAILED", "BLOCKED", "PARTIAL"]).sum()), HANDOFF_PENDING=len(HANDOFF),
        MFA_PENDING=int((u.MFA_EVIDENCE == "REQUIRED_NOT_YET_OBSERVED").sum()),
        DRIFTED_USERS=int((u.IS_MANAGED & (u.DRIFT_FLAGS.map(len) > 0)).sum()))])


def _by_account() -> pd.DataFrame:
    rows = []
    for a in ACCOUNTS.itertuples():
        u = USERS[USERS.ACCOUNT_ID == a.ACCOUNT_ID]
        rows.append(dict(ACCOUNT_ID=a.ACCOUNT_ID, DISPLAY_NAME=a.DISPLAY_NAME, IS_ENABLED=a.IS_ENABLED,
                         IS_PAUSED=a.IS_PAUSED, BOOTSTRAP_STATUS=a.BOOTSTRAP_STATUS,
                         MANAGED_USERS=int(u.IS_MANAGED.sum()), UNMANAGED_USERS=int((~u.IS_MANAGED).sum()),
                         DRIFTED=int((u.IS_MANAGED & (u.DRIFT_FLAGS.map(len) > 0)).sum()),
                         MFA_PENDING=int((u.MFA_EVIDENCE == "REQUIRED_NOT_YET_OBSERVED").sum()),
                         LAST_VERIFIED_AT=u.LAST_VERIFIED_AT.max() if len(u) else None))
    return pd.DataFrame(rows).sort_values(["DRIFTED", "ACCOUNT_ID"], ascending=[False, True])


def _inventory(sql: str, params: list) -> pd.DataFrame:
    df, p = USERS.copy(), list(params)
    m = re.search(r"ACCOUNT_ID IN \(([?,]+)\)", sql)
    if m:
        n = m.group(1).count("?")
        df, p = df[df.ACCOUNT_ID.isin(p[:n])], p[n:]
    if "USERNAME ILIKE ?" in sql:
        needle = p.pop(0).strip("%").upper()
        df = df[df.USERNAME.str.contains(needle, regex=False)]
    if "NOT IS_MANAGED" in sql:
        df = df[~df.IS_MANAGED]
    elif "AND IS_MANAGED" in sql:
        df = df[df.IS_MANAGED]
    if "ARRAY_SIZE(DRIFT_FLAGS) > 0" in sql:
        df = df[df.DRIFT_FLAGS.map(len) > 0]
    if "IS_STALE" in sql:
        df = df[df.IS_STALE]
    if "MFA_EVIDENCE = 'REQUIRED_NOT_YET_OBSERVED'" in sql:
        df = df[df.MFA_EVIDENCE == "REQUIRED_NOT_YET_OBSERVED"]
    if "LAST_OPERATION_STATUS IN" in sql:
        df = df[df.LAST_OPERATION_STATUS.isin(["FAILED", "BLOCKED", "PARTIAL"])]
    return df.sort_values(["ACCOUNT_ID", "USERNAME"]).reset_index(drop=True)


def _operations(sql: str, params: list) -> pd.DataFrame:
    df, p = OPERATIONS.copy(), list(params)
    if "ACCOUNT_ID = ?" in sql:
        df = df[df.ACCOUNT_ID == p.pop(0)]
    if "STATUS IN (?" in sql:
        df = df[df.STATUS.isin(p)]
    df = df.sort_values("REQUESTED_AT", ascending=False)
    return _project(sql, df)


def _approvals(params: list) -> pd.DataFrame:
    df = OPERATIONS[(OPERATIONS.STATUS == "PENDING_APPROVAL") & (OPERATIONS.ACTION_FAMILY == params[0])].copy()
    cur = ACCOUNTS.set_index("ACCOUNT_ID").REGISTRY_VERSION
    df["VERSION_CHECK"] = ["CURRENT" if r.REGISTRY_VERSION == cur[r.ACCOUNT_ID] else "STALE" for r in df.itertuples()]
    cols = ["OPERATION_ID", "REQUESTED_AT", "ACCOUNT_ID", "USERNAME", "ACTION", "REQUESTED_BY", "REASON", "TICKET",
            "BATCH_ID", "REGISTRY_VERSION", "VERSION_CHECK", "PAYLOAD"]
    return df.sort_values("REQUESTED_AT")[cols].reset_index(drop=True)


def route(sql: str, params: list) -> pd.DataFrame:
    s = " ".join(sql.split())
    if "GRANTS_TO_USERS" in s and "u.NAME" in s:
        return _project(s.replace("u.", ""), ELIGIBLE_ADMINS)
    if "GRANTS_TO_USERS" in s:
        return pd.DataFrame({"1": [1]})
    if "V_OVERVIEW_METRICS" in s:
        return _overview_metrics()
    if "LEFT JOIN" in s and "USER_CONTROL" in s:
        return _by_account()
    if "V_USER_INVENTORY" in s:
        return _inventory(s, params)
    if "o.STATUS = 'PENDING_APPROVAL'" in s:
        return _approvals(params)
    if "FROM ACCT_ADMIN_DB.CONTROL.OPERATIONS" in s and "OPERATION_STEPS" not in s:
        if "STATUS IN ('FAILED','PARTIAL','BLOCKED')" in s:
            df = OPERATIONS[OPERATIONS.STATUS.isin(["FAILED", "PARTIAL", "BLOCKED"])]
            return _project(s, df.sort_values("REQUESTED_AT", ascending=False))
        return _operations(s, params)
    if "OPERATION_STEPS" in s:
        return _project(s, STEPS[STEPS.OPERATION_ID == params[0]])
    if "CONSECUTIVE_FAILURES > 0" in s:
        df = ACCOUNTS[ACCOUNTS.IS_PAUSED | (ACCOUNTS.CONSECUTIVE_FAILURES > 0) | (ACCOUNTS.BOOTSTRAP_STATUS != "VERIFIED")]
        df = df.assign(PREFLIGHT_OK=df.LAST_PREFLIGHT_RESULT.map(lambda v: json.loads(v)["ok"] if v else None))
        return df[["ACCOUNT_ID", "IS_ENABLED", "IS_PAUSED", "PAUSE_REASON", "CONSECUTIVE_FAILURES", "BOOTSTRAP_STATUS",
                   "LAST_PREFLIGHT_AT", "PREFLIGHT_OK"]].sort_values("CONSECUTIVE_FAILURES", ascending=False)
    if "AUDIT_EVENTS" in s:
        return AUDIT.sort_values("EVENT_TS", ascending=False).reset_index(drop=True)
    if "ADMIN_ACCOUNT_ACCESS" in s and "= 'PENDING_APPROVAL'" in s:
        df = ACCESS[ACCESS.WORKFLOW_STATE == "PENDING_APPROVAL"]
        return df[["ACCESS_ID", "ACCOUNT_ID", "TARGET_USERNAME", "CORPORATE_EMAIL", "REASON", "TICKET", "REQUESTED_BY",
                   "CREATED_AT", "EXPIRES_AT"]]
    if "ADMIN_ACCOUNT_ACCESS" in s:
        if "'AWAITING_MFA'" in s:
            return _project(s, ACCESS[ACCESS.WORKFLOW_STATE == "AWAITING_MFA"])
        return _project(s, ACCESS[~ACCESS.WORKFLOW_STATE.isin(["PENDING_APPROVAL", "REVOKED"])])
    if "ADMIN_AUTHORIZATIONS" in s:
        return _project(s, AUTHZ[(AUTHZ.ADMIN_USER == params[0]) & AUTHZ.IS_ACTIVE])
    if "EXEC_ROLE = 'ACCOUNTADMIN'" in s:
        df = ACCOUNTS[ACCOUNTS.IS_ENABLED & ~ACCOUNTS.IS_PAUSED & (ACCOUNTS.EXEC_ROLE == "ACCOUNTADMIN")]
        return _project(s, df)
    m = re.search(r"FROM ACCT_ADMIN_DB\.CONTROL\.([A-Z_]+)", s)
    if m and m.group(1) in TABLES:
        df = TABLES[m.group(1)]
        if "WHERE ACCOUNT_ID = ?" in s:
            df = df[df.ACCOUNT_ID == params[0]]
        if "ORDER BY ROLE_NAME" in s:
            df = df.sort_values("ROLE_NAME")
        return _project(s, df)
    raise KeyError(f"mock_data has no route for query: {s[:160]}")


class _Result:
    def __init__(self, df: pd.DataFrame):
        self.df = df

    def to_pandas(self) -> pd.DataFrame:
        return self.df.copy()

    def collect(self):
        return [tuple(r) for r in self.df.itertuples(index=False)]


class MockSession:
    def sql(self, sql: str, params=None) -> _Result:
        if sql.strip().upper().startswith("CALL"):
            return _Result(pd.DataFrame({"R": [json.dumps({"ok": True, "result": {"mock": "no changes were made"}})]}))
        return _Result(route(sql, list(params or [])))
