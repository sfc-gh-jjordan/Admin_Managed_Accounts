# Managed Accounts Admin (84.51 CPG user lifecycle)

Streamlit in Snowflake app + SQL API worker that manages human users across every
Snowflake account in the organization, built from `8451_subaccounts_admin_app.html`.
Nothing in this project has been executed.

**Central account:** `EIGHTY451` in `azeastus2prod` (Azure East US 2). All scripts except
`04_target_account_bootstrap.sql` run there; script 01 and `APP.COMMAND` refuse to run elsewhere.

**Who can use it:** only users holding ACCOUNTADMIN in EIGHTY451. The Streamlit object is
granted to the ACCOUNTADMIN role only, the app checks the viewer's ACCOUNTADMIN grant on load,
and `APP.COMMAND` re-checks it (via `SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_USERS`) on every action.
`ADMIN_AUTHORIZATIONS` then assigns duties among those admins (operator / approver /
privileged approver) so one admin cannot both request and approve.

## Layout

```
sql/
  01_central_setup.sql               roles, warehouse, ACCT_ADMIN_DB, schemas, stages   (central, ACCOUNTADMIN)
  02_control_tables.sql              registry, catalog, roster, queue, inventory, audit, views
  03_org_account_discovery.sql       SHOW ORGANIZATION ACCOUNTS -> CUSTOMER_ACCOUNTS     (ORGADMIN)
  04_target_account_bootstrap.sql    run IN EACH managed account: service user, auth policies
  05_account_connectivity.sql        per-account secret, network rule, EAI, EXEC_<ID> worker proc
  06_worker_dispatch_and_tasks.sql   code upload, DISPATCH / RUN_ACCOUNT procs, tasks
  07_app_commands_and_streamlit.sql  APP.COMMAND trusted proc, STREAMLIT object, admin seed
python/worker/
  sqlapi_client.py                   SQL API v2 client (key-pair JWT, async poll, partitions, retries)
  actions.py                         fixed SQL templates + identifier/literal validation
  worker.py                          claim -> preflight -> execute -> verify -> record
python/app/
  app_commands.py                    authorization, CSV batch submit, approvals, privileged workflow
streamlit/
  streamlit_app.py                   st.navigation entry point
  lib/db.py, lib/csv_validation.py
  app_pages/                         overview, inventory, operations, import_review, approvals,
                                     accounts, internal_admin
```

## How it works

```
CSV / UI request ──> APP.COMMAND (owner's rights, checks ADMIN_AUTHORIZATIONS for st.user)
                       └─> OPERATIONS (PENDING_APPROVAL) ──approve (no self-approval)──> QUEUED
DISPATCH_TASK (5 min) ─> WORKER.DISPATCH ─> WORKER.EXEC_<ACCOUNT_ID>
                                              ├─ secret + EAI bound at CREATE time (one per account)
                                              ├─ JWT -> https://<host>/api/v2/statements  role=EXEC_ROLE
                                              ├─ preflight: CURRENT_ACCOUNT/ROLE/USER must match registry
                                              └─ fixed steps -> read back -> USER_CONTROL / AUDIT_EVENTS
RECONCILE_TASK (6 h)  ─> read-only drift detection (never auto-repairs)
```

The Streamlit app never holds keys and never calls a target account directly.

## Deployment order

1. `01_central_setup.sql`, `02_control_tables.sql` in EIGHTY451.
2. `03_org_account_discovery.sql` to seed the registry from the organization.
3. Per managed account:
   1. Generate a key pair locally (commands in script 04).
   2. Run `04_target_account_bootstrap.sql` in that account; copy `RSA_PUBLIC_KEY_FP`.
   3. In EIGHTY451: create the secret (step A of script 05), set `PUBLIC_KEY_FP`,
      `CALL WORKER.REGISTER_ACCOUNT_CONNECTIVITY('<ACCOUNT_ID>')`.
4. Upload worker code and create procs/tasks: `06_worker_dispatch_and_tasks.sql`.
5. Per account: `CALL WORKER.RUN_ACCOUNT('<ACCOUNT_ID>', 'PREFLIGHT')`; when `VERIFIED`, enable the
   account in the app (Account registry page) and populate its role catalog and email domains.
6. Upload app code and create the app: `07_app_commands_and_streamlit.sql`; seed `ADMIN_AUTHORIZATIONS`.
7. Pilot on one sandbox account, then resume tasks.

## Decisions and assumptions to confirm

- **ACCOUNTADMIN check latency.** `ACCOUNT_USAGE.GRANTS_TO_USERS` lags real time, so a newly
  granted admin may wait before gaining access and a revoked admin may keep app access briefly.
  Opening the app still requires the live ACCOUNTADMIN role, which takes effect immediately.
  Only direct grants of ACCOUNTADMIN to the user are recognized.
- **Cross-cloud egress.** EIGHTY451 is on Azure; target accounts on AWS/GCP are reached over
  public HTTPS through each account's EAI. Private Link targets need their own connectivity.
- **Org discovery** (script 03) needs ORGADMIN (or GLOBALORGADMIN) enabled in EIGHTY451.
- **ACCOUNTADMIN execution role (per request).** `CUSTOMER_ACCOUNTS.EXEC_ROLE` defaults to
  `ACCOUNTADMIN`, and the service user is granted ACCOUNTADMIN. The design doc recommends a
  narrow role for customer work and a separate privileged worker for ACCOUNTADMIN grants.
  Script 04 also creates `ACCT_USER_ADMIN`; set `EXEC_ROLE = 'ACCT_USER_ADMIN'` per account to
  use it (privileged actions are then refused by the worker for that account).
- **One worker procedure per account** because Python procedure `SECRETS` / EAIs are fixed at
  create time. This gives hard isolation between accounts' keys and hosts.
- **Host and JWT identity** are derived from `account_url` (org-account form) during discovery and
  verified by preflight. Private Link hosts also pass the host validation regex.
- **Network policies** on target accounts must admit the central account's egress path; script
  04 leaves this commented out because the correct ranges were not verified.
- **Authentication policy syntax** (`MFA_ENROLLMENT`, `MFA_POLICY = (ALLOWED_METHODS = ...)`) and
  `SHOW MFA METHODS` output columns should be checked against your account's current release
  during the pilot. The worker treats any failure reading MFA methods as `UNKNOWN`, never as
  enrolled.
- **Auth-policy read-back** uses `ADMIN_POLICIES.INFORMATION_SCHEMA.POLICY_REFERENCES`, which
  needs a warehouse on the target; set `EXEC_WAREHOUSE` per account or the value stays unknown
  (the onboarding enable step still proceeds only if the policy attachment statement succeeded).
- **Credential links** (`RESET PASSWORD`, `ENROLL MFA`) go only to `HANDOFF_VAULT`
  (approver-only secure view, zero time travel, erased on delivery, purged hourly).
- **Streamlit version:** pin a version in `environment.yml` that supports `st.navigation`,
  `st.segmented_control`, `st.pills`, and `st.container(horizontal=True)`.
