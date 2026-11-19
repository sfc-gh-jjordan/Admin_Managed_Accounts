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

/*
--View and pin the package versions in the environment.yml file

ls @ACCT_ADMIN_DB.APP.STREAMLIT_STAGE;

CREATE OR REPLACE TEMPORARY FILE FORMAT ACCT_ADMIN_DB.APP.RAW_TEXT_FF
  TYPE = CSV
  FIELD_DELIMITER = NONE
  RECORD_DELIMITER = '\n'
  SKIP_BLANK_LINES = FALSE
  ESCAPE_UNENCLOSED_FIELD = NONE;

SELECT METADATA$FILE_ROW_NUMBER AS line_no, $1 AS line
FROM @ACCT_ADMIN_DB.APP.STREAMLIT_STAGE/app/environment.yml
  (FILE_FORMAT => 'ACCT_ADMIN_DB.APP.RAW_TEXT_FF')
ORDER BY line_no;

--Use the LATEST_VERSION values the query returns.
SELECT package_name,
       MAX_BY(version, TRY_TO_NUMBER(SPLIT_PART(version,'.',1))*1e6
                     + TRY_TO_NUMBER(SPLIT_PART(version,'.',2))*1e3
                     + TRY_TO_NUMBER(SPLIT_PART(version,'.',3))) AS latest_version,
       ARRAY_AGG(DISTINCT version) WITHIN GROUP (ORDER BY version DESC) AS all_versions
FROM ACCT_ADMIN_DB.INFORMATION_SCHEMA.PACKAGES
WHERE language = 'python'
  AND package_name IN ('streamlit', 'pandas', 'snowflake-snowpark-python')
GROUP BY package_name;

*/

-- ---------------------------------------------------------------------
-- 1. Upload code (from project root) or via the Snowsight UI
-- ---------------------------------------------------------------------
-- PUT file://python/app/app_commands.py            @ACCT_ADMIN_DB.APP.STREAMLIT_STAGE/cmd AUTO_COMPRESS=FALSE OVERWRITE=TRUE;
-- PUT file://streamlit/streamlit_app.py            @ACCT_ADMIN_DB.APP.STREAMLIT_STAGE/app AUTO_COMPRESS=FALSE OVERWRITE=TRUE;
-- PUT file://streamlit/environment.yml             @ACCT_ADMIN_DB.APP.STREAMLIT_STAGE/app AUTO_COMPRESS=FALSE OVERWRITE=TRUE;
-- PUT file://streamlit/lib/*.py                    @ACCT_ADMIN_DB.APP.STREAMLIT_STAGE/app/lib AUTO_COMPRESS=FALSE OVERWRITE=TRUE;
-- PUT file://streamlit/app_pages/*.py              @ACCT_ADMIN_DB.APP.STREAMLIT_STAGE/app/app_pages AUTO_COMPRESS=FALSE OVERWRITE=TRUE;
--
-- ALTER STAGE ACCT_ADMIN_DB.APP.STREAMLIT_STAGE REFRESH;

--Verify files are uploaded
ls @ACCT_ADMIN_DB.APP.STREAMLIT_STAGE;

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
  -- Explicit: since BCR 2026_06, omitting RUNTIME_NAME defaults to the
  -- container runtime, which ignores environment.yml.
  RUNTIME_NAME = 'SYSTEM$WAREHOUSE_RUNTIME'
  QUERY_WAREHOUSE = ACCT_ADMIN_WH
  TITLE = 'Managed Accounts Admin'
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

--View managed accounts admin app permissions
SELECT * FROM ACCT_ADMIN_DB.CONTROL.ADMIN_AUTHORIZATIONS;