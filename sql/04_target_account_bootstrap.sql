/* =====================================================================
   04_target_account_bootstrap.sql
   Run ONCE in EACH managed account (not in EIGHTY451), as ACCOUNTADMIN,
   through a separately approved change. Creates:
     - SERVICE user used by the central SQL API worker (key-pair only)
     - authentication policies for customer humans and internal admins
     - a network policy for the service user (optional, recommended)

   Replace <<...>> placeholders. Generate the key pair OUTSIDE Snowflake:
     openssl genrsa 2048 | openssl pkcs8 -topk8 -inform PEM -out sqlapi_<acct>.p8 -nocrypt
     openssl rsa -in sqlapi_<acct>.p8 -pubout -out sqlapi_<acct>.pub
   Use a distinct key pair per account. The private key goes ONLY into
   the central SECRET (05_account_connectivity.sql).
   ===================================================================== */

USE ROLE ACCOUNTADMIN;

-- ---------------------------------------------------------------------
-- 1. Policy container
-- ---------------------------------------------------------------------
CREATE DATABASE IF NOT EXISTS ADMIN_POLICIES COMMENT = 'Managed by 84.51 accounts admin';
CREATE SCHEMA   IF NOT EXISTS ADMIN_POLICIES.POLICIES;

-- ---------------------------------------------------------------------
-- 2. Authentication policies (versioned by name: _V1, _V2 ...)
--    Inspect existing account-level policy first:
--      SHOW AUTHENTICATION POLICIES ON ACCOUNT;
--    Never weaken a stronger existing policy.
-- ---------------------------------------------------------------------
CREATE AUTHENTICATION POLICY IF NOT EXISTS ADMIN_POLICIES.POLICIES.CPG_HUMAN_MFA_V1
  AUTHENTICATION_METHODS = ('PASSWORD')
  MFA_ENROLLMENT         = REQUIRED
  MFA_POLICY             = (ALLOWED_METHODS = ('PASSKEY', 'TOTP'))
  COMMENT = 'V1 - CPG customer humans: password + required MFA';

CREATE AUTHENTICATION POLICY IF NOT EXISTS ADMIN_POLICIES.POLICIES.INTERNAL_ADMIN_MFA_V1
  AUTHENTICATION_METHODS = ('PASSWORD')
  MFA_ENROLLMENT         = REQUIRED
  MFA_POLICY             = (ALLOWED_METHODS = ('PASSKEY', 'TOTP'))
  COMMENT = 'V1 - 84.51 internal admins: password + required MFA';

CREATE AUTHENTICATION POLICY IF NOT EXISTS ADMIN_POLICIES.POLICIES.SQLAPI_SERVICE_V1
  AUTHENTICATION_METHODS = ('KEYPAIR')
  CLIENT_TYPES           = ('DRIVERS')
  COMMENT = 'V1 - central SQL API service user: key-pair only';

-- ---------------------------------------------------------------------
-- 3. (Optional, recommended) network policy for the service user.
--    Allow only the egress path of the central account's external
--    access integration. Verify the correct ranges / private
--    connectivity for EIGHTY451 before enabling.
-- ---------------------------------------------------------------------
-- CREATE NETWORK RULE ADMIN_POLICIES.POLICIES.CENTRAL_EGRESS
--   MODE = INGRESS TYPE = IPV4 VALUE_LIST = (<<central egress CIDRs>>);
-- CREATE NETWORK POLICY SQLAPI_SERVICE_NP
--   ALLOWED_NETWORK_RULE_LIST = ('ADMIN_POLICIES.POLICIES.CENTRAL_EGRESS');

-- ---------------------------------------------------------------------
-- 4. Service user for SQL API.
--    Per request, the worker executes as ACCOUNTADMIN on this account.
--    (A narrower alternative role is provided below - see README.)
-- ---------------------------------------------------------------------
CREATE USER IF NOT EXISTS SVC_ACCT_ADMIN
  TYPE           = SERVICE
  RSA_PUBLIC_KEY = '<<PASTE PUBLIC KEY BODY WITHOUT BEGIN/END LINES>>'
  DEFAULT_ROLE   = ACCOUNTADMIN
  COMMENT        = 'Central 84.51 managed-accounts SQL API worker (do not modify)';

ALTER USER SVC_ACCT_ADMIN SET AUTHENTICATION POLICY ADMIN_POLICIES.POLICIES.SQLAPI_SERVICE_V1;
-- ALTER USER SVC_ACCT_ADMIN SET NETWORK_POLICY = SQLAPI_SERVICE_NP;

GRANT ROLE ACCOUNTADMIN TO USER SVC_ACCT_ADMIN;

-- ---------------------------------------------------------------------
-- 4b. OPTIONAL least-privilege role (recommended by design sec. 12).
--     To use it, set CUSTOMER_ACCOUNTS.EXEC_ROLE = 'ACCT_USER_ADMIN'
--     for this account. ACCOUNTADMIN grants for internal admins then
--     still require EXEC_ROLE = ACCOUNTADMIN on a separate worker.
-- ---------------------------------------------------------------------
CREATE ROLE IF NOT EXISTS ACCT_USER_ADMIN;
GRANT CREATE USER                    ON ACCOUNT TO ROLE ACCT_USER_ADMIN;
GRANT MANAGE GRANTS                  ON ACCOUNT TO ROLE ACCT_USER_ADMIN;
GRANT APPLY AUTHENTICATION POLICY    ON ACCOUNT TO ROLE ACCT_USER_ADMIN;
GRANT USAGE ON DATABASE ADMIN_POLICIES         TO ROLE ACCT_USER_ADMIN;
GRANT USAGE ON SCHEMA   ADMIN_POLICIES.POLICIES TO ROLE ACCT_USER_ADMIN;
GRANT ROLE ACCT_USER_ADMIN TO USER SVC_ACCT_ADMIN;

-- ---------------------------------------------------------------------
-- 5. Capture values for the central registry
-- ---------------------------------------------------------------------
DESC USER SVC_ACCT_ADMIN;                       -- copy RSA_PUBLIC_KEY_FP (SHA256:...)
SELECT CURRENT_ORGANIZATION_NAME() AS ORG,
       CURRENT_ACCOUNT_NAME()      AS ACCOUNT_NAME,
       CURRENT_ACCOUNT()           AS ACCOUNT_LOCATOR,
       CURRENT_REGION()            AS REGION;

-- ---------------------------------------------------------------------
-- 6. Customer roles that the app may grant. Roles are never created
--    from CSV - create/approve them here, then add to ROLE_CATALOG.
-- ---------------------------------------------------------------------
-- CREATE ROLE IF NOT EXISTS CPG_ANALYST;
-- CREATE ROLE IF NOT EXISTS CPG_WRITER;
-- GRANT ROLE CPG_ANALYST TO ROLE ACCT_USER_ADMIN;   -- needed only if using ACCT_USER_ADMIN
-- GRANT ROLE CPG_WRITER  TO ROLE ACCT_USER_ADMIN;
