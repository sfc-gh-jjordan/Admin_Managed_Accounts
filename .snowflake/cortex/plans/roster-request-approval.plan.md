# Plan: Roster request and approval

## Behavior
1. On **Internal admin access > Request**, the user fills a free-form form instead of picking from the roster:
   - Employee ID, target username, corporate email, first name, last name
   - Accounts (multiselect of enabled ACCOUNTADMIN-exec accounts), reason, ticket, review-by, expires
   - Requires `operate` on each selected account (same as today).
2. Submitting creates a row in a new `ROSTER_REQUESTS` table (`PENDING_APPROVAL`). Nothing touches `INTERNAL_ADMIN_ROSTER` yet.
3. On the **Approve** tab, a privileged approver (`CAN_PRIV_APPROVE` on `*`) sees pending roster requests and approves or rejects them. Self-approval is blocked.
4. On approval, in one command:
   - MERGE into `ACCT_ADMIN_DB.CONTROL.INTERNAL_ADMIN_ROSTER` with `ELIGIBILITY_STATUS='ELIGIBLE'`, `EMAIL_VERIFIED=TRUE`, `REVIEWED_BY`/`REVIEWED_AT` = approver.
   - Create the access request (`ADMIN_ACCOUNT_ACCESS` + `PROVISION_INTERNAL_ADMIN` / `GRANT_ACCOUNTADMIN` ops) as the original requester, then approve it as the approver. This is one approval, not two. Existing MFA gating (`AWAITING_MFA`) is unchanged.
5. Rejection marks the request `REJECTED` with a reason; audited.

## Changes
- **sql/09_roster_requests.sql** (new, plus same DDL in 02_control_tables.sql): `ROSTER_REQUESTS(REQUEST_ID, EMPLOYEE_ID, TARGET_USERNAME, CORPORATE_EMAIL, FIRST_NAME, LAST_NAME, ACCOUNT_IDS VARIANT, REASON, TICKET, REVIEW_BY, EXPIRES_AT, STATUS, REQUESTED_BY, REQUESTED_AT, DECIDED_BY, DECIDED_AT, DECISION_NOTE)` and grants matching other control tables.
- **python/app/app_commands.py**: new `cmd_request_roster_entry`, `cmd_approve_roster_entry`, `cmd_reject_roster_entry`; register in `COMMANDS`. Validation: employee ID, username (reuse existing role/user regex style), email domain against the approved internal domain, no duplicate pending request, existing ELIGIBLE roster rows allowed (MERGE updates). Refactor `cmd_request_internal_access` to return `access_ids` too.
- **streamlit/app_pages/internal_admin.py**: new Request form; Approve tab gets a "Roster requests" section (disabled unless `can("priv")`).
- **streamlit/lib/mock_data.py**: add `ROSTER_REQUESTS` sample + query routing so mock mode and screenshots work.
- **tests/test_roster_requests.py**: self-approval denied, non-priv denied, approval upserts roster and creates approved access ops, rejection leaves roster untouched.
- Docs: short note in user guide and deployment guide.

## Deployment
Run sql/09 as ACCT_ADMIN_OWNER, PUT the updated `app_commands.py` and Streamlit files, then re-run the `CREATE OR REPLACE PROCEDURE ACCT_ADMIN_DB.APP.COMMAND` statement from sql/07.

## Open assumptions
- Email domain check uses the registry's approved internal domain if one exists; I will confirm during implementation and otherwise only validate email format.
- Direct SQL inserts into the roster still work, so the manual path remains available.
