/* =====================================================================
   07_app_commands_and_streamlit.sql
   - Upload app_commands.py and the Streamlit source
   - APP.COMMAND owner's-rights procedure (trusted command path)
   - Streamlit app object + grants
   Run as ACCT_ADMIN_OWNER.
   ===================================================================== */

USE ROLE ACCT_ADMIN_OWNER;
USE DATABASE ACCT_ADMIN_DB;
USE SCHEMA APP;
USE WAREHOUSE ACCT_ADMIN_WH;

-- ---------------------------------------------------------------------
-- 1. Upload code (from project root)
-- ---------------------------------------------------------------------
-- PUT file://python/app/app_commands.py            @ACCT_ADMIN_DB.APP.STREAMLIT_STAGE/cmd AUTO_COMPRESS=FALSE OVERWRITE=TRUE;
-- PUT file://streamlit/streamlit_app.py            @ACCT_ADMIN_DB.APP.STREAMLIT_STAGE/app AUTO_COMPRESS=FALSE OVERWRITE=TRUE;
-- PUT file://streamlit/environment.yml             @ACCT_ADMIN_DB.APP.STREAMLIT_STAGE/app AUTO_COMPRESS=FALSE OVERWRITE=TRUE;
-- PUT file://streamlit/lib/*.py                    @ACCT_ADMIN_DB.APP.STREAMLIT_STAGE/app/lib AUTO_COMPRESS=FALSE OVERWRITE=TRUE;
-- PUT file://streamlit/app_pages/*.py              @ACCT_ADMIN_DB.APP.STREAMLIT_STAGE/app/app_pages AUTO_COMPRESS=FALSE OVERWRITE=TRUE;
-- ALTER STAGE ACCT_ADMIN_DB.APP.STREAMLIT_STAGE REFRESH;

-- ---------------------------------------------------------------------
-- 2. Trusted command procedure. Only the app owner role may call it.
-- ---------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE ACCT_ADMIN_DB.APP.COMMAND(ACTOR VARCHAR, COMMAND VARCHAR, ARGS VARIANT)
RETURNS VARIANT
LANGUAGE PYTHON
RUNTIME_VERSION = '3.11'
PACKAGES = ('snowflake-snowpark-python')
IMPORTS = ('@ACCT_ADMIN_DB.APP.STREAMLIT_STAGE/cmd/app_commands.py')
HANDLER = 'app_commands.main'
EXECUTE AS OWNER;

REVOKE ALL ON PROCEDURE ACCT_ADMIN_DB.APP.COMMAND(VARCHAR, VARCHAR, VARIANT) FROM ROLE PUBLIC;

-- ---------------------------------------------------------------------
-- 3. Streamlit app (warehouse runtime, owner's rights)
-- ---------------------------------------------------------------------
CREATE OR REPLACE STREAMLIT ACCT_ADMIN_DB.APP.MANAGED_ACCOUNTS_ADMIN
  FROM '@ACCT_ADMIN_DB.APP.STREAMLIT_STAGE/app'
  MAIN_FILE = 'streamlit_app.py'
  QUERY_WAREHOUSE = ACCT_ADMIN_WH
  TITLE = 'Managed accounts admin'
  COMMENT = 'User lifecycle admin for all managed Snowflake accounts';

-- Only EIGHTY451 ACCOUNTADMIN holders may open the app (they must use the
-- ACCOUNTADMIN role in Snowsight). APP.COMMAND re-verifies the grant.
GRANT USAGE ON STREAMLIT ACCT_ADMIN_DB.APP.MANAGED_ACCOUNTS_ADMIN TO ROLE ACCOUNTADMIN;
REVOKE USAGE ON STREAMLIT ACCT_ADMIN_DB.APP.MANAGED_ACCOUNTS_ADMIN FROM ROLE ACCT_ADMIN_VIEWER;

-- ---------------------------------------------------------------------
-- 4. Seed duties for EIGHTY451 ACCOUNTADMIN users (edit). '*' = all accounts.
--    Rows for users without an active ACCOUNTADMIN grant are ignored.
-- ---------------------------------------------------------------------
-- INSERT INTO ACCT_ADMIN_DB.CONTROL.ADMIN_AUTHORIZATIONS
--   (ADMIN_USER, ACCOUNT_ID, CAN_VIEW, CAN_OPERATE, CAN_APPROVE, CAN_PRIV_APPROVE)
-- VALUES ('JDOE',   '*', TRUE, TRUE, FALSE, FALSE),
--        ('ASMITH', '*', TRUE, TRUE, TRUE,  FALSE),
--        ('BLEE',   '*', TRUE, TRUE, TRUE,  TRUE);
