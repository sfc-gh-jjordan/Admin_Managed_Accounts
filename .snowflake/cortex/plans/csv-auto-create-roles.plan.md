# Plan: Auto-create missing roles from CSV import

## Decisions
- **Approval:** the regular approver (`CAN_APPROVE`), in the same batch as the users. Self-approval is still refused.
- **Hierarchy:** `GRANT ROLE <new> TO ROLE SYSADMIN`.
- **Catalog entry:** inserted with `IS_DEFAULT_ELIGIBLE=TRUE`, `APPROVAL_CLASS='STANDARD'`, `IS_ACTIVE=TRUE`, and `REVIEW_NOTES='auto-created from import <batch_id> by <requester>, approved by <approver>'`.
- **Executor:** ACCOUNTADMIN only. If `EXEC_ROLE` is not ACCOUNTADMIN, the CREATE_ROLE operation is blocked with a clear reason. No bootstrap change.
- **Scope:** the role is created with no privileges. Granting it access to data stays manual.

## Guardrails (unchanged or new)
- Blocked roles (`BLOCKED_ROLES`) and any name matching Snowflake system roles (ACCOUNTADMIN, SECURITYADMIN, USERADMIN, SYSADMIN, ORGADMIN, GLOBALORGADMIN, PUBLIC) are still hard errors.
- A catalog row with `IS_ACTIVE=FALSE` or `APPROVAL_CLASS='BLOCKED'` is still a hard error. "Missing" means no catalog row at all, so the CSV can't quietly re-enable a role an admin turned off.
- The name must match `ROLE_RE` and still passes `FORBIDDEN_CONTENT`. In the worker, `actions.ident()` quotes and validates it.
- Add a cap on new roles per batch (default 10). Anything over it is an error.

## Changes

### 1. `streamlit/lib/csv_validation.py`
- Split the check at line 109. A role missing from the catalog adds the role to a `new_roles` set and records an informational note (`role_name: will be created (new role)`). It no longer marks the row invalid.
- The `default_role` checks treat roles in `new_roles` as allowed and default-eligible.
- Inactive or blocked catalog rows still fail. This needs the loader to pass them, as described in the next section.
- Return `new_roles` alongside the rows, or add a `creates_role` flag to each row.

### 2. `streamlit/app_pages/import_review.py`
- Load every catalog row for the account, including inactive and BLOCKED ones, so the validator can tell "missing" apart from "disabled".
- Show a "Roles to be created" panel listing the new roles. The user ticks an acknowledgement before Submit is enabled.
- Pass `new_roles` in the `SAVE_IMPORT` payload.

### 3. `python/app/app_commands.py`
- **`cmd_save_import`:** store `NEW_ROLES` (an ARRAY) on `IMPORT_BATCHES`. On the server, re-check that each name matches the regex, is not blocked or a system role, has no catalog row at all, and that the batch is under the cap.
- **`cmd_submit_batch`:**
  - Re-run the server checks.
  - Create one `CREATE_ROLE` operation per new role, with payload `{role_name, parent_role: "SYSADMIN", batch_id}`, in the CUSTOMER family.
  - Record each user operation's dependency on the role operations it needs: add a `DEPENDS_ON` array column to `OPERATIONS`, holding operation IDs.
  - Add a catalog-version staleness check here as well, closing the gap found in the research.
- **`cmd_approve`:** approve normally. The CREATE_ROLE operations don't change the catalog version at approval time. Approving a user operation whose role operation was rejected is refused.
- **`cmd_reject`:** rejecting a CREATE_ROLE operation also rejects the operations that depend on it, and records why.
- Fix the regex mismatch: `cmd_upsert_roles` should use `ROLE_RE` instead of `USER_RE`.

### 4. `python/worker/actions.py`
- Add `create_role(name)` → `CREATE ROLE IF NOT EXISTS {ident(name)} COMMENT = 'managed by acct admin app'`.
- Add `grant_role_to_role(name, parent)` → `GRANT ROLE {ident(name)} TO ROLE {ident(parent)}`. The parent may only be SYSADMIN, so this template is not a general role-to-role grant.

### 5. `python/worker/worker.py`
- Add a `CREATE_ROLE` handler:
  1. Require `EXEC_ROLE == 'ACCOUNTADMIN'`; otherwise BLOCKED.
  2. Run `SHOW ROLES LIKE` first. If the role already exists, reuse it and record "existed".
  3. Create the role and grant it to SYSADMIN.
  4. MERGE the role into `ROLE_CATALOG` and bump the catalog version to `MAX+1`.
  5. Write an audit event.
- **Dependency gating in `process_queue`:** a QUEUED operation whose `DEPENDS_ON` operations aren't all SUCCEEDED is skipped, so it stays QUEUED. If any dependency FAILED or was BLOCKED, the operation is set to BLOCKED: "dependency <id> failed".
- **Catalog-version bump vs. staleness:** the worker doesn't re-check the catalog version, and approval happened before the bump, so dependent operations aren't made stale. Approvals the version bump makes stale are allowed only for operations in the same batch. Pending approvals in other batches go stale as they do today, which is consistent with a catalog edit.

### 6. SQL migrations (`sql/02_control_tables.sql` + a new migration file)
- `ALTER TABLE IMPORT_BATCHES ADD COLUMN NEW_ROLES ARRAY`
- `ALTER TABLE OPERATIONS ADD COLUMN DEPENDS_ON ARRAY`
- Update the bootstrap comment ("Roles are never created from CSV") and the README and deployment guide to describe the new flow.

### 7. Tests
- Validator unit tests:
  - A missing role becomes a new role.
  - Blocked, system and inactive catalog roles are errors.
  - A new role is accepted as default_role.
  - The cap is enforced.
- Command tests:
  - The server re-validates.
  - Dependencies are recorded.
  - Rejecting a role cascades to its dependents.
- Worker tests:
  - The role is created, the existing-role path works, a non-ACCOUNTADMIN executor is blocked, and dependency gating works.
- End-to-end with `test_data/jjaws_demo999_onboard_test.csv`.

## Open risks
- Typos in `role_name` will now create new roles instead of failing validation. The acknowledgement panel and the approver review are the only safeguards.
- Approval by the regular approver is weaker than the current rule that only priv-approvers edit the catalog. This is your stated choice.
