/* =====================================================================
   06_worker_dispatch_and_tasks.sql
   - Dispatcher procedure (fans out to per-account EXEC_<ID> procedures)
   - Scheduled tasks: dispatch, reconcile, handoff purge
   Run as ACCT_ADMIN_WORKER (PUT from SnowSQL / Snow CLI).
   ===================================================================== */

USE ROLE ACCT_ADMIN_WORKER;
USE DATABASE ACCT_ADMIN_DB;
USE SCHEMA WORKER;
USE WAREHOUSE ACCT_ADMIN_WH;

-- ---------------------------------------------------------------------
-- 1. Upload code (run from the project root with snow sql / snowsql)
--    Re-run after changes; generated EXEC_<ID> procs pick up new code
--    on next invocation.
-- ---------------------------------------------------------------------
-- PUT file://python/worker/sqlapi_client.py @ACCT_ADMIN_DB.WORKER.CODE_STAGE AUTO_COMPRESS=FALSE OVERWRITE=TRUE;
-- PUT file://python/worker/actions.py       @ACCT_ADMIN_DB.WORKER.CODE_STAGE AUTO_COMPRESS=FALSE OVERWRITE=TRUE;
-- PUT file://python/worker/worker.py        @ACCT_ADMIN_DB.WORKER.CODE_STAGE AUTO_COMPRESS=FALSE OVERWRITE=TRUE;
-- ALTER STAGE ACCT_ADMIN_DB.WORKER.CODE_STAGE REFRESH;

-- ---------------------------------------------------------------------
-- 2. Dispatcher: bounded, sequential fan-out across accounts.
--    Only calls procedure names that match the generated pattern and
--    are recorded in the registry (never from operation payloads).
-- ---------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE ACCT_ADMIN_DB.WORKER.DISPATCH(MODE VARCHAR, MAX_ACCOUNTS NUMBER, MAX_OPS_PER_ACCOUNT NUMBER)
RETURNS VARIANT
LANGUAGE PYTHON
RUNTIME_VERSION = '3.11'
PACKAGES = ('snowflake-snowpark-python')
HANDLER = 'main'
EXECUTE AS OWNER
AS
$$
import json, re

PROC_RE = re.compile(r"^ACCT_ADMIN_DB\.WORKER\.EXEC_[A-Z0-9_]{1,60}$")

def main(session, mode, max_accounts, max_ops):
    mode = (mode or "QUEUE").upper()
    if mode not in ("QUEUE", "RECONCILE"):
        return {"error": "mode must be QUEUE or RECONCILE"}
    if mode == "QUEUE":
        sql = """SELECT a.ACCOUNT_ID, a.WORKER_PROCEDURE
                 FROM ACCT_ADMIN_DB.CONTROL.CUSTOMER_ACCOUNTS a
                 WHERE a.IS_ENABLED AND NOT a.IS_PAUSED AND a.BOOTSTRAP_STATUS = 'VERIFIED'
                   AND EXISTS (SELECT 1 FROM ACCT_ADMIN_DB.CONTROL.OPERATIONS o
                               WHERE o.ACCOUNT_ID = a.ACCOUNT_ID AND o.STATUS = 'QUEUED'
                                 AND (o.NEXT_ATTEMPT_AT IS NULL OR o.NEXT_ATTEMPT_AT <= CURRENT_TIMESTAMP()))
                 ORDER BY (SELECT MIN(SEQUENCE_NO) FROM ACCT_ADMIN_DB.CONTROL.OPERATIONS o2
                           WHERE o2.ACCOUNT_ID = a.ACCOUNT_ID AND o2.STATUS = 'QUEUED')
                 LIMIT ?"""
    else:
        sql = """SELECT ACCOUNT_ID, WORKER_PROCEDURE FROM ACCT_ADMIN_DB.CONTROL.CUSTOMER_ACCOUNTS
                 WHERE IS_ENABLED AND NOT IS_PAUSED AND BOOTSTRAP_STATUS = 'VERIFIED'
                 ORDER BY LAST_PREFLIGHT_AT NULLS FIRST LIMIT ?"""
    accounts = session.sql(sql, params=[int(max_accounts or 50)]).collect()
    results = []
    for a in accounts:
        proc = (a["WORKER_PROCEDURE"] or "").upper()
        if not PROC_RE.match(proc) or proc != f"ACCT_ADMIN_DB.WORKER.EXEC_{a['ACCOUNT_ID']}":
            results.append({"account_id": a["ACCOUNT_ID"], "error": "unexpected worker procedure name"})
            continue
        try:
            r = session.sql(f"CALL {proc}(?, ?)", params=[int(max_ops or 25), mode]).collect()[0][0]
            results.append(json.loads(r) if isinstance(r, str) else r)
        except Exception as e:  # one account failing never stops the batch
            results.append({"account_id": a["ACCOUNT_ID"], "error": str(e)[:500]})
    return {"mode": mode, "accounts": len(accounts), "results": results}
$$;

-- On-demand single account (used by the app's "Run now" / "Reconcile" button)
CREATE OR REPLACE PROCEDURE ACCT_ADMIN_DB.WORKER.RUN_ACCOUNT(P_ACCOUNT_ID VARCHAR, MODE VARCHAR)
RETURNS VARIANT
LANGUAGE PYTHON
RUNTIME_VERSION = '3.11'
PACKAGES = ('snowflake-snowpark-python')
HANDLER = 'main'
EXECUTE AS OWNER
AS
$$
import json, re
def main(session, account_id, mode):
    mode = (mode or "QUEUE").upper()
    if mode not in ("QUEUE", "RECONCILE", "PREFLIGHT"):
        return {"error": "invalid mode"}
    if not re.match(r"^[A-Z0-9_]{1,60}$", account_id or ""):
        return {"error": "invalid account id"}
    rows = session.sql("SELECT WORKER_PROCEDURE FROM ACCT_ADMIN_DB.CONTROL.CUSTOMER_ACCOUNTS WHERE ACCOUNT_ID = ?",
                       params=[account_id]).collect()
    expected = f"ACCT_ADMIN_DB.WORKER.EXEC_{account_id}"
    if not rows or (rows[0][0] or "").upper() != expected:
        return {"error": "account not registered for execution"}
    r = session.sql(f"CALL {expected}(?, ?)", params=[25, mode]).collect()[0][0]
    return json.loads(r) if isinstance(r, str) else r
$$;

-- ---------------------------------------------------------------------
-- 3. Tasks (single non-overlapping dispatcher, per design section 2)
-- ---------------------------------------------------------------------
CREATE OR REPLACE TASK ACCT_ADMIN_DB.WORKER.DISPATCH_TASK
  WAREHOUSE = ACCT_ADMIN_WH
  SCHEDULE  = '5 MINUTE'
  ALLOW_OVERLAPPING_EXECUTION = FALSE
  USER_TASK_TIMEOUT_MS = 3000000
  COMMENT = 'Execute approved operations via SQL API'
AS
  CALL ACCT_ADMIN_DB.WORKER.DISPATCH('QUEUE', 50, 25);

CREATE OR REPLACE TASK ACCT_ADMIN_DB.WORKER.RECONCILE_TASK
  WAREHOUSE = ACCT_ADMIN_WH
  SCHEDULE  = 'USING CRON 0 */6 * * * UTC'
  ALLOW_OVERLAPPING_EXECUTION = FALSE
  USER_TASK_TIMEOUT_MS = 3600000
  COMMENT = 'Read-only drift detection across managed accounts'
AS
  CALL ACCT_ADMIN_DB.WORKER.DISPATCH('RECONCILE', 200, 200);

CREATE OR REPLACE TASK ACCT_ADMIN_DB.WORKER.PURGE_HANDOFF_TASK
  WAREHOUSE = ACCT_ADMIN_WH
  SCHEDULE  = '60 MINUTE'
  COMMENT = 'Remove expired / delivered credential links'
AS
  DELETE FROM ACCT_ADMIN_DB.CONTROL.HANDOFF_VAULT
  WHERE EXPIRES_AT <= CURRENT_TIMESTAMP() OR DELIVERED_AT IS NOT NULL;

-- Tasks are created suspended. Resume after pilot validation:
ALTER TASK ACCT_ADMIN_DB.WORKER.PURGE_HANDOFF_TASK RESUME;
ALTER TASK ACCT_ADMIN_DB.WORKER.RECONCILE_TASK     RESUME;
ALTER TASK ACCT_ADMIN_DB.WORKER.DISPATCH_TASK      RESUME;

-- Allow the app owner (owner's-rights command procs) to trigger on-demand runs
GRANT USAGE ON PROCEDURE ACCT_ADMIN_DB.WORKER.RUN_ACCOUNT(VARCHAR, VARCHAR) TO ROLE ACCT_ADMIN_OWNER;

-- ---------------------------------------------------------------------
-- Per-account usage (after 05 registered connectivity for the account)
-- ---------------------------------------------------------------------
-- Preflight (verifies JWT, host, CURRENT_ACCOUNT(), role) - no changes:
USE ROLE ACCT_ADMIN_WORKER;
CALL ACCT_ADMIN_DB.WORKER.RUN_ACCOUNT('CPG_ACME', 'PREFLIGHT');
--Expected: the result contains "ok": true and CUSTOMER_ACCOUNTS.BOOTSTRAP_STATUS becomes VERIFIED

--Verify BOOTSTRAP_STATUS = 'VERIFIED'
SELECT ACCOUNT_ID, ACCOUNT_LOCATOR, REGION, SQL_API_HOST, JWT_ACCOUNT_IDENTIFIER, BOOTSTRAP_STATUS, IS_ENABLED
FROM ACCT_ADMIN_DB.CONTROL.CUSTOMER_ACCOUNTS
WHERE ACCOUNT_ID = 'CPG_ACME'; --Update for given managed account

-- Enable after successful preflight connectivity check:
UPDATE ACCT_ADMIN_DB.CONTROL.CUSTOMER_ACCOUNTS SET IS_ENABLED = TRUE WHERE ACCOUNT_ID = 'CPG_ACME';

--Verify IS_ENABLED = TRUE
SELECT ACCOUNT_ID, ACCOUNT_LOCATOR, REGION, SQL_API_HOST, JWT_ACCOUNT_IDENTIFIER, BOOTSTRAP_STATUS, IS_ENABLED
FROM ACCT_ADMIN_DB.CONTROL.CUSTOMER_ACCOUNTS
WHERE ACCOUNT_ID = 'CPG_ACME'; --Update for given managed account