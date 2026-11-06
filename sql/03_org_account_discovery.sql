/* =====================================================================
   03_org_account_discovery.sql
   Populate CUSTOMER_ACCOUNTS from the Snowflake organization.
   Run in the CENTRAL account with a role that can see org accounts
   (ORGADMIN, or GLOBALORGADMIN in the organization account).

   Discovery only seeds the registry. New rows are IS_ENABLED = FALSE
   and BOOTSTRAP_STATUS = 'NOT_BOOTSTRAPPED' until an admin completes
   04_target_account_bootstrap.sql + 05_account_connectivity.sql.
   ===================================================================== */

USE ROLE ORGADMIN;            -- or GLOBALORGADMIN
USE SECONDARY ROLES ALL;      -- running user must also hold ACCT_ADMIN_OWNER (writes to CONTROL)
USE WAREHOUSE ACCT_ADMIN_WH;

SHOW ORGANIZATION ACCOUNTS;

-- Stage results so the owner role can merge them
CREATE OR REPLACE TEMPORARY TABLE ACCT_ADMIN_DB.CONTROL.TMP_ORG_ACCOUNTS AS
SELECT  "organization_name"   AS ORGANIZATION_NAME,
        "account_name"        AS ACCOUNT_NAME,
        "account_locator"     AS ACCOUNT_LOCATOR,
        "snowflake_region"    AS REGION,
        "edition"             AS EDITION,
        "account_url"         AS ACCOUNT_URL,
        "comment"             AS ACCOUNT_COMMENT
FROM TABLE(RESULT_SCAN(LAST_QUERY_ID()));

-- Exclude the central account itself
DELETE FROM ACCT_ADMIN_DB.CONTROL.TMP_ORG_ACCOUNTS
WHERE ACCOUNT_LOCATOR = CURRENT_ACCOUNT();

-- ---------------------------------------------------------------------
-- Merge into registry. Connectivity values are derived but MUST be
-- verified by the preflight before the account is enabled.
--   SQL_API_HOST           = <org>-<account>.snowflakecomputing.com
--   JWT_ACCOUNT_IDENTIFIER = <ORG>-<ACCOUNT>   (uppercase, '_' kept, '.' -> '-')
-- ---------------------------------------------------------------------
MERGE INTO ACCT_ADMIN_DB.CONTROL.CUSTOMER_ACCOUNTS t
USING (
    SELECT  UPPER(REGEXP_REPLACE(ACCOUNT_NAME, '[^A-Za-z0-9_]', '_'))               AS ACCOUNT_ID,
            ORGANIZATION_NAME, ACCOUNT_NAME, ACCOUNT_LOCATOR, REGION,
            SPLIT_PART(REGION, '_', 1)                                              AS CLOUD,
            LOWER(REPLACE(REGEXP_REPLACE(ACCOUNT_URL, '^https?://', ''), '/', ''))  AS SQL_API_HOST,
            UPPER(ORGANIZATION_NAME || '-' || REPLACE(ACCOUNT_NAME, '.', '-'))      AS JWT_ACCOUNT_IDENTIFIER,
            COALESCE(ACCOUNT_COMMENT, ACCOUNT_NAME)                                 AS DISPLAY_NAME
    FROM ACCT_ADMIN_DB.CONTROL.TMP_ORG_ACCOUNTS
) s
ON t.ACCOUNT_LOCATOR = s.ACCOUNT_LOCATOR
WHEN MATCHED THEN UPDATE SET
     t.ORGANIZATION_NAME = s.ORGANIZATION_NAME,
     t.ACCOUNT_NAME      = s.ACCOUNT_NAME,
     t.REGION            = s.REGION,
     t.CLOUD             = s.CLOUD,
     t.UPDATED_AT        = CURRENT_TIMESTAMP(),
     t.UPDATED_BY        = CURRENT_USER()
     -- host / JWT identity are NOT overwritten once set: changes must go
     -- through the registry edit flow and bump REGISTRY_VERSION.
WHEN NOT MATCHED THEN INSERT (
     ACCOUNT_ID, DISPLAY_NAME, ORGANIZATION_NAME, ACCOUNT_NAME, ACCOUNT_LOCATOR, REGION, CLOUD,
     SQL_API_HOST, JWT_ACCOUNT_IDENTIFIER, EXPECTED_ACCOUNT_LOCATOR,
     SECRET_NAME, WORKER_PROCEDURE, EAI_NAME,
     IS_ENABLED, BOOTSTRAP_STATUS, DISCOVERED_FROM_ORG)
VALUES (
     s.ACCOUNT_ID, s.DISPLAY_NAME, s.ORGANIZATION_NAME, s.ACCOUNT_NAME, s.ACCOUNT_LOCATOR, s.REGION, s.CLOUD,
     s.SQL_API_HOST, s.JWT_ACCOUNT_IDENTIFIER, s.ACCOUNT_LOCATOR,
     'ACCT_ADMIN_DB.SECRETS.SQLAPI_KEY_' || s.ACCOUNT_ID,
     'ACCT_ADMIN_DB.WORKER.EXEC_'        || s.ACCOUNT_ID,
     'ACCT_ADMIN_EAI_'                   || s.ACCOUNT_ID,
     FALSE, 'NOT_BOOTSTRAPPED', TRUE);

INSERT INTO ACCT_ADMIN_DB.CONTROL.AUDIT_EVENTS (ACTOR, EVENT_TYPE, DETAILS)
SELECT CURRENT_USER(), 'REGISTRY',
       OBJECT_CONSTRUCT('action','ORG_DISCOVERY','accounts_seen',(SELECT COUNT(*) FROM ACCT_ADMIN_DB.CONTROL.TMP_ORG_ACCOUNTS));

-- Review what was discovered
SELECT ACCOUNT_ID, ACCOUNT_LOCATOR, REGION, SQL_API_HOST, JWT_ACCOUNT_IDENTIFIER, BOOTSTRAP_STATUS, IS_ENABLED
FROM ACCT_ADMIN_DB.CONTROL.CUSTOMER_ACCOUNTS
ORDER BY ACCOUNT_ID;
