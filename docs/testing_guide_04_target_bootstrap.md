# Testing Guide: 04_target_account_bootstrap.sql

Scope: validates the per-account bootstrap that runs in each managed account (not EIGHTY451). It creates the SQL API service user, authentication policies, the central egress network rule and policy, and the optional `ACCT_USER_ADMIN` role. Scenarios that depend on script 05 are marked as handoff checks.

Use a sandbox managed account for the first run. Never run the first test pass against a production customer account.

## 1. Prerequisites

| ID | Check | Expected |
|----|-------|----------|
| P-1 | Target account has a row in `ACCT_ADMIN_DB.CONTROL.CUSTOMER_ACCOUNTS` with `BOOTSTRAP_STATUS = 'NOT_BOOTSTRAPPED'` | Row exists; `ACCOUNT_ID` noted |
| P-2 | Change approval for this account is recorded | Approval reference available |
| P-3 | Key pair generated locally with distinct files per account (`sqlapi_<acct>.p8`, `sqlapi_<acct>.pub`) | Files exist; `.p8` is unencrypted PKCS8 (`-nocrypt`) |
| P-4 | Public key body (no BEGIN/END lines) pasted into `RSA_PUBLIC_KEY` placeholder | No `<<PASTE PUBLIC KEY...>>` text remains |
| P-5 | Central egress CIDRs obtained in EIGHTY451 via `SYSTEM$GET_SNOWFLAKE_EGRESS_IP_RANGES()` and pasted into `VALUE_LIST` | No `<<central egress CIDRs>>` text remains |
| P-6 | Session role is ACCOUNTADMIN in the target account | `SELECT CURRENT_ROLE();` returns `ACCOUNTADMIN` |
| P-7 | Script is **not** being run in EIGHTY451 | `SELECT CURRENT_ACCOUNT();` is not the central locator |

## 2. Happy-path execution

| ID | Scenario | Steps | Expected |
|----|----------|-------|----------|
| H-1 | Full script runs top to bottom | Run `04_target_account_bootstrap.sql` in a worksheet with the placeholders filled | No errors. The `SHOW AUTHENTICATION POLICIES` output is captured before creation. |
| H-2 | Database and schema created | `SHOW SCHEMAS IN DATABASE ADMIN_POLICIES;` | `POLICIES` schema present; database comment is `Managed by 84.51 accounts admin` |
| H-3 | Three auth policies created | `SHOW AUTHENTICATION POLICIES IN SCHEMA ADMIN_POLICIES.POLICIES;` | `CPG_HUMAN_MFA_V1`, `INTERNAL_ADMIN_MFA_V1`, `SQLAPI_SERVICE_V1` present with the expected comments |
| H-4 | Human policies require MFA | `DESC AUTHENTICATION POLICY ADMIN_POLICIES.POLICIES.CPG_HUMAN_MFA_V1;` (repeat for internal admin) | `AUTHENTICATION_METHODS = PASSWORD`, `MFA_ENROLLMENT = REQUIRED`, allowed MFA methods PASSKEY and TOTP |
| H-5 | Service policy is key-pair only | `DESC AUTHENTICATION POLICY ...SQLAPI_SERVICE_V1;` | `AUTHENTICATION_METHODS = KEYPAIR`, `CLIENT_TYPES = DRIVERS` |
| H-6 | Network rule and policy created | `SHOW NETWORK RULES IN SCHEMA ADMIN_POLICIES.POLICIES;` and `SHOW NETWORK POLICIES LIKE 'SQLAPI_SERVICE_NP';` | `CENTRAL_EGRESS` is `INGRESS`/`IPV4` with the CIDRs from P-5; policy references it |
| H-7 | Service user created with correct attributes | `DESC USER SVC_ACCT_ADMIN;` | `TYPE = SERVICE`, `DEFAULT_ROLE = ACCOUNTADMIN`, `RSA_PUBLIC_KEY_FP` is populated |
| H-8 | Policies attached to the service user | `DESC USER SVC_ACCT_ADMIN;` and `SELECT * FROM TABLE(ADMIN_POLICIES.INFORMATION_SCHEMA.POLICY_REFERENCES(REF_ENTITY_NAME => 'SVC_ACCT_ADMIN', REF_ENTITY_DOMAIN => 'USER'));` | `SQLAPI_SERVICE_V1` and `SQLAPI_SERVICE_NP` attached (see the warehouse note in the README if the reference query returns nothing) |
| H-9 | Role grants to service user | `SHOW GRANTS TO USER SVC_ACCT_ADMIN;` | `ACCOUNTADMIN` and `ACCT_USER_ADMIN` granted |
| H-10 | `ACCT_USER_ADMIN` privileges | `SHOW GRANTS TO ROLE ACCT_USER_ADMIN;` | `CREATE USER`, `MANAGE GRANTS`, `APPLY AUTHENTICATION POLICY` on account; `USAGE` on `ADMIN_POLICIES` and `POLICIES` schema |
| H-11 | Capture registry values | Record `RSA_PUBLIC_KEY_FP` (from `DESC USER`), org, account name, account locator, region from the final SELECT | Values entered in the central registry (`PUBLIC_KEY_FP`) |

## 3. Idempotency and re-run

| ID | Scenario | Steps | Expected |
|----|----------|-------|----------|
| I-1 | Re-run the policy section | Run section 2 again | `IF NOT EXISTS` statements succeed without changing existing policies |
| I-2 | Re-run the service user section | Run again with the same public key | `CREATE USER IF NOT EXISTS` is a no-op; the key and policies are unchanged |
| I-3 | Re-run with a different public key | Run `CREATE USER IF NOT EXISTS` with a new key | No-op; the old key remains. Key rotation must use `ALTER USER SET RSA_PUBLIC_KEY`. Confirm the team knows this. |
| I-4 | Re-run the network rule and policy | Run `CREATE NETWORK RULE` and `CREATE NETWORK POLICY` again | **Expected to fail** (no `IF NOT EXISTS`). Record as a known gap; the script should use `CREATE OR REPLACE` or `IF NOT EXISTS` before a second run is allowed. |
| I-5 | Re-run the role section | Run `CREATE ROLE IF NOT EXISTS` and the grants | Succeeds; grants are idempotent |

## 4. Negative and guard-rail tests

| ID | Scenario | Steps | Expected |
|----|----------|-------|----------|
| N-1 | Placeholder left in public key | Run with `<<PASTE PUBLIC KEY BODY...>>` | Statement fails with an invalid key error; no user created |
| N-2 | Placeholder left in CIDRs | Run with `<<central egress CIDRs>>` | Network rule creation fails; the policy is not created. Confirm the failure is visible and not swallowed. |
| N-3 | Malformed public key | Use a key with a line-break error or an EC key | Rejected at `CREATE USER` |
| N-4 | Non-ACCOUNTADMIN session | Run as SYSADMIN | Creation of policies and users fails with insufficient privileges |
| N-5 | Existing stronger policy is not weakened | Pre-create an account-level auth policy requiring MFA and KEYPAIR; run section 2 | Script does not detach or replace the existing account policy. The comment at step 2 says to "never weaken"; verify the script does not do this. |
| N-6 | Account-level network policy conflict | Account already has a restrictive account-level policy that blocks the egress CIDRs | Script runs, but the worker in script 05 fails the connectivity check. Confirm the README note about account-level policies is followed before handoff. |

## 5. Authentication behavior

These tests need a test user and a browser, and must run in the sandbox account.

| ID | Scenario | Steps | Expected |
|----|----------|-------|----------|
| A-1 | Human user, password only | Create a test user under `CPG_HUMAN_MFA_V1`, sign in with password, do not enroll MFA | Sign-in is blocked or forced to enroll MFA per `MFA_ENROLLMENT = REQUIRED` |
| A-2 | Human user, password plus passkey | Enroll a passkey, sign in | Sign-in succeeds |
| A-3 | Human user, password plus TOTP | Enroll TOTP, sign in | Sign-in succeeds |
| A-4 | Service user, password login attempt | Attempt password login as `SVC_ACCT_ADMIN` | Rejected (`KEYPAIR` only) |
| A-5 | Service user, key-pair login | Connect with the `.p8` key from the workstation | Succeeds |
| A-6 | Service user, wrong key | Connect with a different `.p8` | Rejected |
| A-7 | Key fingerprint matches | `openssl rsa -pubin -in sqlapi_<acct>.pub -outform DER \| openssl dgst -sha256 -binary \| openssl enc -base64` and compare to `RSA_PUBLIC_KEY_FP` | Fingerprints match |
| A-8 | Service user from outside allowed network | Connect as `SVC_ACCT_ADMIN` from a non-CENTRAL_EGRESS IP | Rejected by `SQLAPI_SERVICE_NP` |
| A-9 | Service user from allowed network | Connect from an allowed egress range (or the EIGHTY451 path in pilot) | Succeeds |

Note: A-1 and A-2 depend on the MFA syntax in the policy. The README asks for this to be checked against the account's release before the pilot. If `MFA_POLICY` fails to parse, record it and treat the policy as not yet verified.

## 6. Handoff to script 05 (connectivity)

| ID | Scenario | Steps | Expected |
|----|----------|-------|----------|
| X-1 | Secret created with the matching private key | Run step A of script 05 with the `.p8` contents | Secret stored; `.p8` deleted from workstation afterward |
| X-2 | `PUBLIC_KEY_FP` and `SECRET_VERSION` set | Update `CUSTOMER_ACCOUNTS` | Values match `RSA_PUBLIC_KEY_FP` |
| X-3 | Registration returns ready | `WORKER.REGISTER_ACCOUNT_CONNECTIVITY('<ACCOUNT_ID>')` | Returns `CONNECTIVITY_READY` |
| X-4 | Preflight identity check | `RUN_ACCOUNT('<ACCOUNT_ID>', 'PREFLIGHT')` | `CURRENT_ACCOUNT`, `CURRENT_ROLE`, `CURRENT_USER` match the registry |
| X-5 | Role-based check | Set `EXEC_ROLE = 'ACCT_USER_ADMIN'` for one test account | Privileged worker actions are refused for that account; non-privileged actions still run |

## 7. Security checks

| ID | Scenario | Expected |
|----|----------|----------|
| S-1 | Private key not in source control | `git status` and `git grep -l "PRIVATE KEY"` in the repo return nothing |
| S-2 | Private key not on workstation after handoff | `.p8` removed; only the Snowflake secret holds it |
| S-3 | Private key never in a SQL statement or log | Query history for the session does not contain the key body |
| S-4 | Service user cannot log in as human | `SVC_ACCT_ADMIN` has no password and no MFA path |
| S-5 | Per-account keys are distinct | No two accounts share an `RSA_PUBLIC_KEY_FP` |

## 8. Known issues to resolve before the pilot

These came from reviewing the script against the README. Each one should be confirmed or fixed before the pilot.

1. **Step reference mismatch.** The header says to store the key in "step 6.3". The secret is created in step A of script 05. Update the header.
2. **Non-idempotent network objects.** `CREATE NETWORK RULE` and `CREATE NETWORK POLICY` have no `IF NOT EXISTS`, so re-running the script fails at that point (test I-4).
3. **Client type for the SQL API.** `SQLAPI_SERVICE_V1` sets `CLIENT_TYPES = ('DRIVERS')`. Confirm the worker's SQL API calls are classified as a permitted client type in the target account. If they are not, the service user's first login will fail (test A-5).
4. **Customer roles TODO.** Section 6 is commented out. Either pre-create shared roles or rely on CSV role creation (see the README).
5. **Hardcoded CPG naming.** Policy names contain `CPG` and `84.51`. Confirm this naming is acceptable for all managed accounts.

## 9. Test record template

| Field | Value |
|-------|-------|
| Account ID | |
| Account locator | |
| Tester | |
| Date | |
| Script version | |
| Results (IDs passed / failed / blocked) | |
| Defects raised | |
| Sign-off to proceed to script 05 | |
