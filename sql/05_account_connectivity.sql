/* =====================================================================
   05_account_connectivity.sql
   Per-account connectivity in the CENTRAL account:
     NETWORK RULE (egress to that account's SQL API host only)
     SECRET       (that account's private key - never stored elsewhere)
     EXTERNAL ACCESS INTEGRATION (rule + secret)
     WORKER PROCEDURE WORKER.EXEC_<ACCOUNT_ID> bound to that secret/EAI

   Why one procedure per account: Python procedure SECRETS and
   EXTERNAL_ACCESS_INTEGRATIONS are fixed at CREATE time, so binding
   per account gives strict isolation (a compromised payload can never
   point account A's key at account B's host).
   ===================================================================== */

USE ROLE ACCT_ADMIN_BOOTSTRAP;
USE DATABASE ACCT_ADMIN_DB;
USE WAREHOUSE ACCT_ADMIN_WH;

-- ---------------------------------------------------------------------
-- STEP A (manual, per account): store the private key in a SECRET.
-- Run interactively in a worksheet; do not script with key in files.
-- ---------------------------------------------------------------------
-- Update the suffix in the secret name and in the comment for the ACCOUNT_ID of the given managed account
-- CREATE OR REPLACE SECRET ACCT_ADMIN_DB.SECRETS.SQLAPI_KEY_<ACCOUNT_ID>
--   TYPE = GENERIC_STRING
--   SECRET_STRING = '-----BEGIN PRIVATE KEY-----
-- ...
-- -----END PRIVATE KEY-----'
--   COMMENT = 'SQL API private key for <ACCOUNT_ID> (v1)';
--
-- Then record the fingerprint in the registry:
-- UPDATE ACCT_ADMIN_DB.CONTROL.CUSTOMER_ACCOUNTS
--    SET PUBLIC_KEY_FP = 'SHA256:<<from DESC USER SVC_ACCT_ADMIN>>',
--        SECRET_VERSION = 1, REGISTRY_VERSION = REGISTRY_VERSION + 1, UPDATED_AT = CURRENT_TIMESTAMP()
--  WHERE ACCOUNT_ID = '<ACCOUNT_ID>'; --Update this value with the ACCOUNT_ID for the given managed account

-- ---------------------------------------------------------------------
-- STEP B: generator procedure (network rule + EAI + worker procedure)
-- ---------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE ACCT_ADMIN_DB.WORKER.REGISTER_ACCOUNT_CONNECTIVITY(P_ACCOUNT_ID VARCHAR)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_id      VARCHAR;
    v_host    VARCHAR;
    v_rule    VARCHAR;
    v_secret  VARCHAR;
    v_eai     VARCHAR;
    v_proc    VARCHAR;
    v_sql     VARCHAR;
    c         CURSOR FOR SELECT ACCOUNT_ID, SQL_API_HOST
                         FROM ACCT_ADMIN_DB.CONTROL.CUSTOMER_ACCOUNTS
                         WHERE ACCOUNT_ID = ?;
    bad_input EXCEPTION (-20001, 'Invalid account id or SQL API host in registry');
BEGIN
    OPEN c USING (:P_ACCOUNT_ID);
    FETCH c INTO v_id, v_host;
    CLOSE c;

    -- Strict validation before building any DDL text
    IF (v_id IS NULL OR NOT REGEXP_LIKE(v_id, '^[A-Z0-9_]{1,60}$')) THEN RAISE bad_input; END IF;
    IF (v_host IS NULL OR NOT REGEXP_LIKE(v_host, '^[a-z0-9][a-z0-9._-]*\\.snowflakecomputing\\.com$')) THEN RAISE bad_input; END IF;

    v_rule   := 'ACCT_ADMIN_DB.NET.SQLAPI_RULE_' || v_id;
    v_secret := 'ACCT_ADMIN_DB.SECRETS.SQLAPI_KEY_' || v_id;
    v_eai    := 'ACCT_ADMIN_EAI_' || v_id;
    v_proc   := 'ACCT_ADMIN_DB.WORKER.EXEC_' || v_id;

    -- 1. Network rule: this account's host only
    v_sql := 'CREATE OR REPLACE NETWORK RULE ' || v_rule ||
             ' MODE = EGRESS TYPE = HOST_PORT VALUE_LIST = (''' || v_host || ':443'')';
    EXECUTE IMMEDIATE :v_sql;

    -- 2. EAI: rule + secret
    v_sql := 'CREATE OR REPLACE EXTERNAL ACCESS INTEGRATION ' || v_eai ||
             ' ALLOWED_NETWORK_RULES = (' || v_rule || ')' ||
             ' ALLOWED_AUTHENTICATION_SECRETS = (' || v_secret || ')' ||
             ' ENABLED = TRUE COMMENT = ''SQL API egress for ' || v_id || '''';
    EXECUTE IMMEDIATE :v_sql;

    -- 3. Grants to worker role
    EXECUTE IMMEDIATE 'GRANT USAGE ON INTEGRATION ' || v_eai || ' TO ROLE ACCT_ADMIN_WORKER';
    EXECUTE IMMEDIATE 'GRANT USAGE ON SECRET ' || v_secret || ' TO ROLE ACCT_ADMIN_WORKER';
    EXECUTE IMMEDIATE 'GRANT READ ON SECRET '  || v_secret || ' TO ROLE ACCT_ADMIN_WORKER';

    -- 4. Per-account worker procedure. Account id is baked into the body.
    v_sql := 'CREATE OR REPLACE PROCEDURE ' || v_proc || '(MAX_OPS NUMBER, MODE VARCHAR)
RETURNS VARIANT
LANGUAGE PYTHON
RUNTIME_VERSION = ''3.11''
PACKAGES = (''snowflake-snowpark-python'', ''requests'', ''pyjwt'', ''cryptography'')
IMPORTS = (''@ACCT_ADMIN_DB.WORKER.CODE_STAGE/sqlapi_client.py'',
           ''@ACCT_ADMIN_DB.WORKER.CODE_STAGE/actions.py'',
           ''@ACCT_ADMIN_DB.WORKER.CODE_STAGE/worker.py'')
EXTERNAL_ACCESS_INTEGRATIONS = (' || v_eai || ')
SECRETS = (''sqlapi_key'' = ' || v_secret || ')
HANDLER = ''main''
EXECUTE AS OWNER
AS
''
import worker
def main(session, max_ops, mode):
    return worker.run_account(session, "' || v_id || '", int(max_ops or 25), mode or "QUEUE")
''';
    EXECUTE IMMEDIATE :v_sql;

    EXECUTE IMMEDIATE 'GRANT OWNERSHIP ON PROCEDURE ' || v_proc || '(NUMBER, VARCHAR) TO ROLE ACCT_ADMIN_WORKER COPY CURRENT GRANTS';

    UPDATE ACCT_ADMIN_DB.CONTROL.CUSTOMER_ACCOUNTS
       SET SECRET_NAME      = :v_secret,
           EAI_NAME         = :v_eai,
           WORKER_PROCEDURE = :v_proc,
           BOOTSTRAP_STATUS = 'CONNECTIVITY_READY',
           REGISTRY_VERSION = REGISTRY_VERSION + 1,
           UPDATED_AT       = CURRENT_TIMESTAMP(),
           UPDATED_BY       = CURRENT_USER()
     WHERE ACCOUNT_ID = :v_id;

    INSERT INTO ACCT_ADMIN_DB.CONTROL.AUDIT_EVENTS (ACTOR, EVENT_TYPE, ACCOUNT_ID, DETAILS)
      SELECT CURRENT_USER(), 'REGISTRY', :v_id,
             OBJECT_CONSTRUCT('action','REGISTER_CONNECTIVITY','eai',:v_eai,'procedure',:v_proc);

    RETURN OBJECT_CONSTRUCT('account_id', v_id, 'network_rule', v_rule, 'eai', v_eai, 'procedure', v_proc);
END;
$$;

-- ---------------------------------------------------------------------
-- ALTERNATIVE: instead of snow sql, you can upload the three files in the Snowsight UI. 
-- Go to Catalog → Database Explorer, open ACCT_ADMIN_DB → WORKER → Stages → --CODE_STAGE, 
-- then choose + Files and select sqlapi_client.py, actions.py and worker.py. -- --    
-- Make sure the files are not compressed and are uploaded to the root of the stage.
-- ---------------------------------------------------------------------
-- Upload code (run from the project root with snow sql / snowsql)
-- PUT file://python/worker/sqlapi_client.py @ACCT_ADMIN_DB.WORKER.CODE_STAGE AUTO_COMPRESS=FALSE OVERWRITE=TRUE;
-- PUT file://python/worker/actions.py       @ACCT_ADMIN_DB.WORKER.CODE_STAGE AUTO_COMPRESS=FALSE OVERWRITE=TRUE;
-- PUT file://python/worker/worker.py        @ACCT_ADMIN_DB.WORKER.CODE_STAGE AUTO_COMPRESS=FALSE OVERWRITE=TRUE;
-- ALTER STAGE ACCT_ADMIN_DB.WORKER.CODE_STAGE REFRESH;

-- ---------------------------------------------------------------------
-- STEP C: usage (per account, after STEP A)
-- ****** IMPORTANT First upload the 3 worker Python modules to the code stage *****
-- Update procedure parameter to given managed account
-- ---------------------------------------------------------------------
CALL ACCT_ADMIN_DB.WORKER.REGISTER_ACCOUNT_CONNECTIVITY('CPG_ACME');

--View objects bound to a specific managed account
SHOW PROCEDURES LIKE 'EXEC_%' IN SCHEMA ACCT_ADMIN_DB.WORKER;

SHOW NETWORK RULES IN SCHEMA ACCT_ADMIN_DB.NET;

SHOW EXTERNAL ACCESS INTEGRATIONS LIKE 'ACCT_ADMIN_EAI_%';

--Verify BOOTSTRAP_STATUS = 'CONNECTIVITY_READY'
SELECT ACCOUNT_ID, ACCOUNT_LOCATOR, REGION, SQL_API_HOST, JWT_ACCOUNT_IDENTIFIER, BOOTSTRAP_STATUS, IS_ENABLED
FROM ACCT_ADMIN_DB.CONTROL.CUSTOMER_ACCOUNTS
WHERE ACCOUNT_ID = 'CPG_ACME';

-- Next: run 06_worker_dispatch_and_tasks.sql, then run the preflight and
-- enable steps at the end of that script.

