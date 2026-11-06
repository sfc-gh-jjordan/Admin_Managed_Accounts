/* =====================================================================
   01_central_setup.sql
   Run in the CENTRAL account (EIGHTY451) as ACCOUNTADMIN.
   Creates the admin database, schemas, warehouse, stages and the
   application role model described in the design (section 12).
   ===================================================================== */

USE ROLE ACCOUNTADMIN;

-- ---------------------------------------------------------------------
-- Guard: this solution must only be deployed in EIGHTY451 (Azure East US 2)
-- ---------------------------------------------------------------------
EXECUTE IMMEDIATE $$
BEGIN
  IF (NOT ((CURRENT_ACCOUNT_NAME() = 'EIGHTY451' OR CURRENT_ACCOUNT() = 'EIGHTY451')
           AND CURRENT_REGION() ILIKE '%AZURE_EASTUS2')) THEN
    RAISE STATEMENT_ERROR;
  END IF;
  RETURN 'EIGHTY451 / AZURE_EASTUS2 confirmed';
END;
$$;

-- ---------------------------------------------------------------------
-- Warehouse
-- ---------------------------------------------------------------------
CREATE WAREHOUSE IF NOT EXISTS ACCT_ADMIN_WH
  WAREHOUSE_SIZE = XSMALL
  AUTO_SUSPEND   = 60
  AUTO_RESUME    = TRUE
  INITIALLY_SUSPENDED = TRUE
  COMMENT = 'Managed-accounts admin app + SQL API worker';

-- ---------------------------------------------------------------------
-- Application roles
--   App access: ONLY users who hold ACCOUNTADMIN in EIGHTY451. The
--   Streamlit app is granted to ACCOUNTADMIN only, and every command
--   re-verifies the viewer's ACCOUNTADMIN grant. ADMIN_AUTHORIZATIONS
--   then splits those ACCOUNTADMIN users into operator / approver /
--   privileged-approver duties (separation of duties, no self-approval).
--
--   ACCT_ADMIN_OWNER      : owns DB objects + Streamlit app (no secrets)
--   ACCT_ADMIN_VIEWER     : read-only inventory / health
--   ACCT_ADMIN_OPERATOR   : upload CSV, request operations
--   ACCT_ADMIN_APPROVER   : approve customer operations
--   ACCT_ADMIN_PRIV_APPROVER : approve internal ACCOUNTADMIN grants
--   ACCT_ADMIN_WORKER     : owns worker procs, reads secrets, uses EAIs
--   ACCT_ADMIN_BOOTSTRAP  : registers accounts (network rules, EAIs, secrets)
-- ---------------------------------------------------------------------
CREATE ROLE IF NOT EXISTS ACCT_ADMIN_OWNER;
CREATE ROLE IF NOT EXISTS ACCT_ADMIN_VIEWER;
CREATE ROLE IF NOT EXISTS ACCT_ADMIN_OPERATOR;
CREATE ROLE IF NOT EXISTS ACCT_ADMIN_APPROVER;
CREATE ROLE IF NOT EXISTS ACCT_ADMIN_PRIV_APPROVER;
CREATE ROLE IF NOT EXISTS ACCT_ADMIN_WORKER;
CREATE ROLE IF NOT EXISTS ACCT_ADMIN_BOOTSTRAP;

GRANT ROLE ACCT_ADMIN_VIEWER        TO ROLE ACCT_ADMIN_OPERATOR;
GRANT ROLE ACCT_ADMIN_OPERATOR      TO ROLE ACCT_ADMIN_APPROVER;
GRANT ROLE ACCT_ADMIN_APPROVER      TO ROLE ACCT_ADMIN_PRIV_APPROVER;
GRANT ROLE ACCT_ADMIN_PRIV_APPROVER TO ROLE ACCT_ADMIN_OWNER;
GRANT ROLE ACCT_ADMIN_OWNER         TO ROLE ACCOUNTADMIN;
GRANT ROLE ACCT_ADMIN_WORKER        TO ROLE ACCOUNTADMIN;
GRANT ROLE ACCT_ADMIN_BOOTSTRAP     TO ROLE ACCOUNTADMIN;

-- App owner verifies that viewers hold ACCOUNTADMIN via ACCOUNT_USAGE.GRANTS_TO_USERS
GRANT DATABASE ROLE SNOWFLAKE.SECURITY_VIEWER TO ROLE ACCT_ADMIN_OWNER;

GRANT USAGE ON WAREHOUSE ACCT_ADMIN_WH TO ROLE ACCT_ADMIN_VIEWER;
GRANT USAGE ON WAREHOUSE ACCT_ADMIN_WH TO ROLE ACCT_ADMIN_WORKER;
GRANT USAGE ON WAREHOUSE ACCT_ADMIN_WH TO ROLE ACCT_ADMIN_BOOTSTRAP;

-- Bootstrap must create network rules / EAIs / secrets
GRANT CREATE INTEGRATION ON ACCOUNT TO ROLE ACCT_ADMIN_BOOTSTRAP;
-- Worker must run tasks
GRANT EXECUTE TASK ON ACCOUNT TO ROLE ACCT_ADMIN_WORKER;

-- ---------------------------------------------------------------------
-- Database & schemas
--   CONTROL : registry, inventory, queue, audit
--   SECRETS : one SECRET per managed account (worker-only)
--   NET     : network rules
--   WORKER  : Python procedures that call the SQL API
--   APP     : Streamlit app + owner's-rights command procedures
-- ---------------------------------------------------------------------
CREATE DATABASE IF NOT EXISTS ACCT_ADMIN_DB COMMENT = 'Managed accounts user lifecycle admin';
GRANT OWNERSHIP ON DATABASE ACCT_ADMIN_DB TO ROLE ACCT_ADMIN_OWNER COPY CURRENT GRANTS;

USE ROLE ACCT_ADMIN_OWNER;
USE DATABASE ACCT_ADMIN_DB;

CREATE SCHEMA IF NOT EXISTS CONTROL WITH MANAGED ACCESS;
CREATE SCHEMA IF NOT EXISTS APP;
CREATE SCHEMA IF NOT EXISTS WORKER;
CREATE SCHEMA IF NOT EXISTS NET;
CREATE SCHEMA IF NOT EXISTS SECRETS WITH MANAGED ACCESS;

GRANT USAGE ON DATABASE ACCT_ADMIN_DB TO ROLE ACCT_ADMIN_VIEWER;
GRANT USAGE ON DATABASE ACCT_ADMIN_DB TO ROLE ACCT_ADMIN_WORKER;
GRANT USAGE ON DATABASE ACCT_ADMIN_DB TO ROLE ACCT_ADMIN_BOOTSTRAP;
GRANT USAGE ON SCHEMA CONTROL TO ROLE ACCT_ADMIN_VIEWER;
GRANT USAGE ON SCHEMA APP     TO ROLE ACCT_ADMIN_VIEWER;
GRANT USAGE ON SCHEMA CONTROL TO ROLE ACCT_ADMIN_WORKER;
GRANT USAGE ON SCHEMA CONTROL TO ROLE ACCT_ADMIN_BOOTSTRAP;

-- Worker owns WORKER schema objects; bootstrap owns NET / SECRETS objects
GRANT USAGE, CREATE PROCEDURE, CREATE TASK ON SCHEMA WORKER TO ROLE ACCT_ADMIN_WORKER;
GRANT USAGE, CREATE PROCEDURE              ON SCHEMA WORKER TO ROLE ACCT_ADMIN_BOOTSTRAP;
GRANT USAGE, CREATE NETWORK RULE           ON SCHEMA NET     TO ROLE ACCT_ADMIN_BOOTSTRAP;
GRANT USAGE, CREATE SECRET                 ON SCHEMA SECRETS TO ROLE ACCT_ADMIN_BOOTSTRAP;
GRANT USAGE ON SCHEMA NET     TO ROLE ACCT_ADMIN_WORKER;
GRANT USAGE ON SCHEMA SECRETS TO ROLE ACCT_ADMIN_WORKER;

-- ---------------------------------------------------------------------
-- Stages for code
-- ---------------------------------------------------------------------
CREATE STAGE IF NOT EXISTS WORKER.CODE_STAGE
  DIRECTORY = (ENABLE = TRUE)
  COMMENT = 'sqlapi_client.py / actions.py / worker.py';
CREATE STAGE IF NOT EXISTS APP.STREAMLIT_STAGE
  DIRECTORY = (ENABLE = TRUE)
  COMMENT = 'Streamlit app source';

GRANT READ ON STAGE WORKER.CODE_STAGE TO ROLE ACCT_ADMIN_WORKER;
GRANT READ ON STAGE WORKER.CODE_STAGE TO ROLE ACCT_ADMIN_BOOTSTRAP;

-- ---------------------------------------------------------------------
-- Human access: no per-user role grants are needed. App users are the
-- EIGHTY451 ACCOUNTADMIN holders; seed their duties in
-- CONTROL.ADMIN_AUTHORIZATIONS (see 07_app_commands_and_streamlit.sql).
--   SHOW GRANTS OF ROLE ACCOUNTADMIN;   -- list eligible users
-- ---------------------------------------------------------------------
