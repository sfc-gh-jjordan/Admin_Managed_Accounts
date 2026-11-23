-- =====================================================================
-- 09_internal_admin_from_accountadmin.sql
-- Run in EIGHTY451 on an existing deployment (fresh installs get the new
-- columns from 02_control_tables.sql). Idempotent.
--
-- Eligible internal admins are now read live from the users holding
-- ACCOUNTADMIN in EIGHTY451 (ACCOUNT_USAGE). The INTERNAL_ADMIN_ROSTER
-- table is retired; the email and name it supplied are snapshotted on
-- each ADMIN_ACCOUNT_ACCESS row. After this, redeploy the APP.COMMAND
-- procedure, the worker procedures and the Streamlit app.
-- =====================================================================
USE ROLE ACCOUNTADMIN;
USE SCHEMA ACCT_ADMIN_DB.CONTROL;

ALTER TABLE ADMIN_ACCOUNT_ACCESS ADD COLUMN IF NOT EXISTS CORPORATE_EMAIL VARCHAR;
ALTER TABLE ADMIN_ACCOUNT_ACCESS ADD COLUMN IF NOT EXISTS FIRST_NAME VARCHAR;
ALTER TABLE ADMIN_ACCOUNT_ACCESS ADD COLUMN IF NOT EXISTS LAST_NAME VARCHAR;

-- Keep existing access rows working: copy the details from the old roster.
EXECUTE IMMEDIATE $$
BEGIN
  IF (EXISTS (SELECT 1 FROM INFORMATION_SCHEMA.TABLES
              WHERE TABLE_SCHEMA = 'CONTROL' AND TABLE_NAME = 'INTERNAL_ADMIN_ROSTER')) THEN
    UPDATE ADMIN_ACCOUNT_ACCESS a
       SET CORPORATE_EMAIL = r.CORPORATE_EMAIL, FIRST_NAME = r.FIRST_NAME, LAST_NAME = r.LAST_NAME
      FROM INTERNAL_ADMIN_ROSTER r
     WHERE a.EMPLOYEE_ID = r.EMPLOYEE_ID AND a.CORPORATE_EMAIL IS NULL;
  END IF;
END;
$$;

DROP TABLE IF EXISTS ROSTER_REQUESTS;
DROP TABLE IF EXISTS INTERNAL_ADMIN_ROSTER;
