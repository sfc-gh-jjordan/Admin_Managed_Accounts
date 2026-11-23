# Managed Accounts Admin (84.51 CPG user lifecycle)

Streamlit in Snowflake app + SQL API worker that manages human users across every
Snowflake account in the organization, built from `8451_subaccounts_admin_app.html`.
Nothing in this project has been executed.

**Central account:** `EIGHTY451` in `azeastus2prod` (Azure East US 2). All scripts except
`04_target_account_bootstrap.sql` run there; script 01 refuses to run elsewhere. The matching
EIGHTY451 check in `APP.COMMAND` (`python/app/app_commands.py`) is currently commented out;
re-enable it before production.

**Who can use it:** only users holding ACCOUNTADMIN in EIGHTY451. The Streamlit object is
granted to the ACCOUNTADMIN role only, the app checks the viewer's ACCOUNTADMIN grant on load,
and `APP.COMMAND` re-checks it (via `SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_USERS`) on every action.
`ADMIN_AUTHORIZATIONS` then assigns duties among those admins (operator / approver /
privileged approver) so one admin cannot both request and approve.

## Layout

```
sql/
  01_central_setup.sql               roles, warehouse, ACCT_ADMIN_DB, schemas, stages   (central, ACCOUNTADMIN)
  02_control_tables.sql              registry, catalog, queue, inventory, audit, views
  03_org_account_discovery.sql       SHOW ACCOUNTS LIKE '<pattern>' -> CUSTOMER_ACCOUNTS (ORGADMIN)
  04_target_account_bootstrap.sql    run IN EACH managed account: service user, auth + network policies
  05_account_connectivity.sql        per-account secret, worker code upload, network rule, EAI, EXEC_<ID> proc
  06_worker_dispatch_and_tasks.sql   DISPATCH / RUN_ACCOUNT procs, tasks (resumed), preflight + enable
  07_app_commands_and_streamlit.sql  APP.COMMAND trusted proc, STREAMLIT object, admin seed
  08_migrate_csv_role_creation.sql   upgrade only: NEW_ROLES / DEPENDS_ON columns for CSV role creation
  09_internal_admin_from_accountadmin.sql  upgrade only: retire INTERNAL_ADMIN_ROSTER; eligibility from ACCOUNTADMIN holders
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
tests/
  test_role_creation.py              pytest: CSV validation, role checks, CREATE_ROLE templates/handler
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

CSV rows whose role has no `ROLE_CATALOG` entry add a `CREATE_ROLE` operation to the batch;
the user operations that need that role carry it in `DEPENDS_ON` and wait until it succeeds
(see [Creating roles from a CSV import](#creating-roles-from-a-csv-import)).

The Streamlit app never holds keys and never calls a target account directly.

## Deployment order

Scripts 05 and 06 contain live statements hard-coded to `'CPG_ACME'`; replace it with the
target `ACCOUNT_ID` before running. See `deployment_guide.html` for the full walkthrough.

1. `01_central_setup.sql`, `02_control_tables.sql` in EIGHTY451.
2. `03_org_account_discovery.sql` to seed the registry. Edit the `SHOW ACCOUNTS LIKE` pattern first.
3. Per managed account (use an `ACCOUNT_ID` with `BOOTSTRAP_STATUS = 'NOT_BOOTSTRAPPED'`):
   1. Generate a key pair locally (commands in script 04).
   2. In EIGHTY451, get egress CIDRs with `SYSTEM$GET_SNOWFLAKE_EGRESS_IP_RANGES()` (query in script 04).
   3. Run `04_target_account_bootstrap.sql` in that account with the public key and CIDRs filled in;
      copy `RSA_PUBLIC_KEY_FP`.
   4. In EIGHTY451: create the secret (step A of script 05) and set `PUBLIC_KEY_FP` / `SECRET_VERSION`.
   5. Upload `python/worker/*.py` to `WORKER.CODE_STAGE` (PUT or Snowsight), then run script 05,
      which calls `WORKER.REGISTER_ACCOUNT_CONNECTIVITY('<ACCOUNT_ID>')`; expect `CONNECTIVITY_READY`.
4. `06_worker_dispatch_and_tasks.sql`: creates procs and tasks, **resumes the tasks**, runs
   `RUN_ACCOUNT('<ACCOUNT_ID>', 'PREFLIGHT')`, and enables the account once `VERIFIED`. Comment out
   the `RESUME` lines to keep tasks paused until the pilot passes.
5. Upload app code (PUT or Snowsight), then run `07_app_commands_and_streamlit.sql`; seed
   `ADMIN_AUTHORIZATIONS`. Populate each account's role catalog and email domains in the app.
6. Pilot on one sandbox account; resume tasks if they were left paused.

**Upgrading an existing deployment** to CSV role creation: run `08_migrate_csv_role_creation.sql`
in EIGHTY451, re-upload `python/worker/*.py` to `WORKER.CODE_STAGE`, `python/app/app_commands.py`
and `streamlit/` to `APP.STREAMLIT_STAGE`, then re-run script 07 so `APP.COMMAND` picks up the new
code. Fresh installs get the columns from script 02 and do not need script 08.

## Creating roles from a CSV import

A CSV row may name a `role_name` / `default_role` that is not yet in the account's role catalog.

1. **Import and review.** The row is valid and its findings show `will be created (new role)`.
   The page lists the new roles under **Roles to be created**; the operator must tick the
   confirmation before **Submit for approval** is enabled.
2. **Submit.** `APP.COMMAND` re-checks every role server-side, then `SUBMIT_BATCH` creates one
   `CREATE_ROLE` operation per new role (payload `role_name`, `parent_role = SYSADMIN`,
   `batch_id`; `USERNAME` is NULL) plus the usual user operations, which list the role
   operations they need in `DEPENDS_ON`.
3. **Approve.** `CREATE_ROLE` is in the CUSTOMER family, so the regular batch approver
   (`CAN_APPROVE`) approves it; self-approval is refused. Rejecting it also cancels the user
   operations that depend on it, and an operation whose dependency was rejected or failed
   cannot be approved.
4. **Execute.** The worker runs `CREATE_ROLE` first (lower sequence number). It runs
   `SHOW ROLES LIKE`, then `CREATE ROLE IF NOT EXISTS ... COMMENT = 'managed by acct-admin op ...'`
   and `GRANT ROLE ... TO ROLE SYSADMIN`, reads the role back, and adds it to `ROLE_CATALOG`
   (active, `STANDARD`, default-eligible, `REVIEW_NOTES` naming the batch, requester and
   approver). User operations stay `QUEUED` until their dependencies are `SUCCEEDED`, and are set
   to `BLOCKED` if a dependency failed or was cancelled.

Rules:

- Needs `EXEC_ROLE = ACCOUNTADMIN` on the account; otherwise the operation is `BLOCKED`.
- Roles in `BLOCKED_ROLES`, Snowflake system roles (ACCOUNTADMIN, SECURITYADMIN, USERADMIN,
  SYSADMIN, ORGADMIN, GLOBALORGADMIN, PUBLIC), and names that do not match
  `^[A-Z][A-Z0-9_]{0,254}$` are never created.
- A role with an inactive or `BLOCKED` catalog entry is rejected, never re-enabled by a CSV.
- At most 10 new roles per batch.
- The new role has **no privileges**. Grant it access to warehouses, databases and schemas in the
  managed account separately.
- A role that already exists on the target but is not in the catalog is adopted as-is: it is
  added to the catalog (noted as pre-existing) but its hierarchy is not changed.
- Adding the role bumps the account's catalog version. Pending operations in the same batch
  are re-bound to the new version; pending approvals from other batches become stale, as with
  any catalog edit.
- A batch is refused at submit if the role catalog changed since it was uploaded; re-upload it.
- Typos in `role_name` now create a new role instead of failing, so check the
  **Roles to be created** list before submitting and approving.

Tests: `python -m pytest tests -q` (needs `pytest`, `pandas`, `pyjwt`, `cryptography`, `requests`).

## User guide and local preview

`user_guide.html` is the end-user guide, with one screenshot per page in `docs/user_guide/img/`.
The screenshots were taken from a local run in **mock mode**, which uses the fictitious sample data in
`streamlit/lib/mock_data.py` and never connects to Snowflake (commands return a no-op result).
To re-capture them, use Python 3.11 or 3.12 with `streamlit==1.52.2` and `pandas==2.3.3`:

```
cd streamlit
ACCT_ADMIN_MOCK=1 streamlit run streamlit_app.py --client.toolbarMode viewer
```

`ACCT_ADMIN_MOCK_USER` sets the signed-in user (default `ADMIN_TWO`, who has every duty).
`docs/user_guide/sample_import_acme.csv` is the CSV used for the import screenshots. Mock mode is
off unless the variable is set, so the deployed app is unaffected; `mock_data.py` does not need to
be uploaded to the stage.

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
- **Network policies.** Script 04 creates `SQLAPI_SERVICE_NP` (rule `CENTRAL_EGRESS`) and attaches
  it to `SVC_ACCT_ADMIN`; fill in the central egress CIDRs first. Egress ranges have expiry dates,
  so review them periodically. Account-level network policies must also admit this path.
- **Customer roles.** Script 04 does not create shared customer roles yet (TODO). Either
  pre-create them and add them to `ROLE_CATALOG`, or let CSV imports create them (see
  [Creating roles from a CSV import](#creating-roles-from-a-csv-import)).
- **Approval level for new roles.** `CREATE_ROLE` is approved by the regular batch approver, not
  the privileged approver who edits the role catalog directly. Move it to the PRIVILEGED family in
  `cmd_submit_batch` if role creation should need `CAN_PRIV_APPROVE`.
- **Authentication policy syntax** (`MFA_ENROLLMENT`, `MFA_POLICY = (ALLOWED_METHODS = ...)`) and
  `SHOW MFA METHODS` output columns should be checked against your account's current release
  during the pilot. The worker treats any failure reading MFA methods as `UNKNOWN`, never as
  enrolled.
- **Auth-policy read-back** uses `ADMIN_POLICIES.INFORMATION_SCHEMA.POLICY_REFERENCES`, which
  needs a warehouse on the target; set `EXEC_WAREHOUSE` per account or the value stays unknown
  (the onboarding enable step still proceeds only if the policy attachment statement succeeded).
- **Credential links** (`RESET PASSWORD`, `ENROLL MFA`) go only to `HANDOFF_VAULT`
  (approver-only secure view, zero time travel, erased on delivery, purged hourly).
- **Streamlit runtime and versions.** The app is created with
  `RUNTIME_NAME = 'SYSTEM$WAREHOUSE_RUNTIME'`, because since BCR 2026_06 the default container
  runtime ignores `environment.yml`. That file pins `streamlit=1.52.2`, `pandas=2.3.3`, and
  `snowflake-snowpark-python=1.56.0`. Confirm availability with the `INFORMATION_SCHEMA.PACKAGES`
  query at the top of script 07. The Streamlit version must support `st.navigation`,
  `st.segmented_control`, `st.pills`, and `st.container(horizontal=True)`.
