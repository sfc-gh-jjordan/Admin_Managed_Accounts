-- =====================================================================
-- 08_migrate_csv_role_creation.sql
-- Run in EIGHTY451 on an existing deployment (fresh installs get these
-- columns from 02_control_tables.sql). Idempotent.
--
-- Lets a CSV import request creation of roles that have no ROLE_CATALOG
-- entry: SUBMIT_BATCH queues CREATE_ROLE operations, user operations wait
-- on them through DEPENDS_ON. After this, redeploy the APP.COMMAND
-- procedure, the worker procedures and the Streamlit app.
-- =====================================================================
USE ROLE ACCOUNTADMIN;
USE SCHEMA ACCT_ADMIN_DB.CONTROL;

ALTER TABLE IMPORT_BATCHES ADD COLUMN IF NOT EXISTS NEW_ROLES ARRAY;
ALTER TABLE OPERATIONS     ADD COLUMN IF NOT EXISTS DEPENDS_ON ARRAY;
