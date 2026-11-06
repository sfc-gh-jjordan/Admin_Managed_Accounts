---
name: "cpg-user-lifecycle-admin"
created: "2026-11-05T14:20:58.171Z"
status: pending
---

# Design plan: 84.51 CPG User Lifecycle Admin

**Status: Design only. Do not execute or deploy until separately authorized.**

## Purpose and scope

Create an internal Streamlit in Snowflake application in 84.51's main account, identified as `EIGHTY451`, to manage human users across more than 150 CPG customer accounts. These are full Snowflake accounts with read/write capabilities, not reader accounts.

CPG customers send CSV user and role requests to the 84.51 admin team. The application validates and stages those requests, supports administrative approval, and queues onboarding or offboarding through the Snowflake SQL API. A central inventory displays verified remote user status and assigned roles.

The app also supports adding named human users from the 84.51 admin team to selected CPG accounts and granting them `ACCOUNTADMIN` through a separate privileged-access workflow. Customer CSVs cannot request this access. Administrator access is tracked per person and target account, not through a shared human login.

Customer authentication uses native Snowflake passwords plus MFA. Customer SSO and SCIM are excluded. For the initial design, newly provisioned 84.51 human administrators also use local PERSON users with password plus native MFA; internal-admin SSO is not introduced by this change. This document does not authorize account changes. EIGHTY451's full identifier, region, connection, and existing infrastructure remain to be verified; the current Snowhouse connection is not the deployment target. All table names below are proposed, not existing object identifiers.

## Architecture

```text
CPG-provided CSV
       |
       v
84.51 Streamlit app in EIGHTY451
  Upload -> Validate -> Preview changes -> Approve
       |
       v
Control tables and durable operation queue
       |
       v
Scheduled Snowflake Task -> Python worker procedure
       |
  Account-scoped secret + external access integration
       |
       v
Registered customer-account SQL API endpoint
  Preflight -> Execute -> Verify -> Record results
       |
       v
Central inventory, reconciliation, and audit history
```

Separate the UI from remote execution. The app must not hold target private keys or depend on an open browser to finish a batch. A scheduled worker retrieves approved operations and processes bounded batches. Start with a single non-overlapping dispatcher; introduce account-sharded concurrency only after pilot testing.

A warehouse-runtime Streamlit app is the initial UI baseline, subject to runtime/package validation. The embedded session accesses central control data, not remote customer user administration. Target administration occurs through the SQL API using the target service identity.

## Account registry and security boundary

Maintain an admin-controlled customer registry containing:

- Customer ID and display name.
- Account locator, region/cloud, organization/account name where available, and verified HTTPS SQL API hostname.
- Expected target account identity for preflight verification.
- Service username, explicit execution role, and execution context.
- Worker procedure reference and secret/credential version references, never key material.
- Approved customer email domains, roles, protected users, and account paused/enabled state.
- Customer and internal-human-admin MFA policy FQNs, expected versions, and bootstrap health.
- Approved internal-admin roster references, account-scoped privileged approvers, lower-privilege admin default role, and emergency-access coverage.

An account locator alone is insufficient connection configuration. `SL18775` in `azeastus2prod` is a user-provided candidate, not a verified endpoint.

Admins select the customer and account from this registry. CSV files cannot supply arbitrary hosts, credentials, procedure names, SQL, or policy definitions. If a locator is included, require it to match the selected account. Bind each approved payload to the registry and role-catalog versions to prevent redirection after approval.

## Central data model

Select a dedicated database/schema in EIGHTY451 before implementation. Normalize role assignments rather than storing comma-separated role lists. A joined inventory view provides one user-facing control grid.

| Proposed table          | Purpose                                                                                                                                                                         |
| ----------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `CUSTOMER_ACCOUNTS`     | Registered accounts, trusted endpoints, worker references, policy baseline, health.                                                                                             |
| `ROLE_CATALOG`          | Allowed roles per account, default-role eligibility, approval class, effective-privilege review.                                                                                |
| `ADMIN_AUTHORIZATIONS`  | Named app admins, permitted customers, viewer/operator/approver permissions, and separate privileged-access approval authority.                                                 |
| `INTERNAL_ADMIN_ROSTER` | Authoritative approved 84.51 employee identities, verified corporate email, employment/eligibility status, and reviewer.                                                        |
| `ADMIN_ACCOUNT_ACCESS`  | One internal admin and target account; requested/observed ACCOUNTADMIN grant, reason, approver, review/expiry date, grant/revocation timestamps, and privileged workflow state. |
| `IMPORT_BATCHES`        | Upload metadata, customer/account, hashes, requester, validation and approval state.                                                                                            |
| `IMPORT_ROWS`           | Original row number, normalized input, requested action, validation findings.                                                                                                   |
| `USER_CONTROL`          | Account and username, identity, desired state, observed disabled flag, policy, MFA evidence, last verification.                                                                 |
| `USER_ROLE_DESIRED`     | Approved role assignments managed by the app.                                                                                                                                   |
| `USER_ROLE_OBSERVED`    | Verified direct grants, including externally managed grants.                                                                                                                    |
| `OPERATIONS`            | Immutable approved actions, payload/version, requester/approver, attempts, queue status.                                                                                        |
| `OPERATION_STEPS`       | Request UUID, API statement handle, step outcome, timestamps, redacted error.                                                                                                   |
| `AUDIT_EVENTS`          | Append-only import, approval, execution, handoff, recovery, and reconciliation history.                                                                                         |

Distinguish these dimensions explicitly:

- Desired user state: ENABLED or DISABLED.
- Operation state: PENDING\_APPROVAL, QUEUED, RUNNING, SUCCEEDED, PARTIAL, FAILED, BLOCKED, CANCELLED.
- Observed state: existence and disabled flag, each true/false/unknown, with verification time.
- Onboarding state: PROVISIONING, PROVISIONED\_PENDING\_HANDOFF, HANDOFF\_ISSUED, DISABLED.
- MFA evidence: REQUIRED\_NOT\_YET\_OBSERVED, ENROLLED, UNKNOWN, DRIFT.
- Identity class: CPG\_CUSTOMER or INTERNAL\_ADMIN; set by the trusted workflow, never by customer CSV.
- Internal privileged access: PENDING\_APPROVAL, AWAITING\_MFA, GRANT\_PENDING, GRANTED, REVOKE\_PENDING, REVOKED, BLOCKED; independent of whether the user is enabled.

Attaching a required-MFA policy does not prove enrollment. An unreachable account does not prove disablement. Direct grants do not represent the full inherited privilege graph.

Enforce logical uniqueness, queue claiming, and concurrency through application transactions and version checks. Do not rely solely on primary/unique declarations on standard Snowflake tables.

## CSV contract

Use one row per user-role assignment. Repeated rows for a username must agree on identity, default role, and action.

```csv
username,email,first_name,last_name,role_name,default_role,action
JANE_SMITH,jane.smith@customer.example,Jane,Smith,CPG_ANALYST,CPG_ANALYST,ONBOARD
JANE_SMITH,jane.smith@customer.example,Jane,Smith,CPG_WRITER,CPG_ANALYST,ONBOARD
PAT_LEE,pat.lee@customer.example,Pat,Lee,,,DISABLE
```

These identities and roles are illustrative. The selected account registry supplies the locator stored on normalized requests.

Validation requirements:

- Strict headers, encoding, file-size and row-count limits.
- Approved email domains and a documented exception process.
- Strict username conventions and rejection of case collisions/ambiguous identifiers.
- Existing roles from the account-specific allowlist; never create roles from CSV requests.
- Block privileged system roles, including ACCOUNTADMIN, and custom roles whose inherited privileges violate the customer baseline in all customer CSV operations. A CSV cannot promote a customer user into the internal-admin identity class.
- Protect service users, emergency admins, internal identities, and unknown existing users from customer lifecycle operations. Internal identities are managed only through the separately authorized privileged workflow.
- Reject passwords, private keys, MFA seeds, SQL text, policy names, and URLs.
- Render uploaded values as text; protect downloadable CSVs against formula injection.
- Hash source files and normalized payloads for duplicate detection and approval integrity.

Import semantics:

- ONBOARD is additive and idempotent; replay does not recreate users or reset credentials.
- ADD\_ROLES adds approved assignments.
- Optional SET\_MANAGED\_ROLES replaces only app-managed grants after previewing removals; it preserves external grants.
- DISABLE is explicit. Missing rows never imply offboarding.
- REENABLE is separately reviewed, never implied by an onboarding replay.

## Streamlit screens

### Overview

Display app-managed enabled/disabled users, pending approvals, handoff/MFA pending users, failed operations, and stale/drifted inventory. Clearly distinguish managed coverage from the entire account population.

### Import and review

Select customer/account, upload CSV, inspect row errors, and preview users created, roles added/removed, disable actions, and policy impacts. Validate the complete batch first. Rejected rows require explicit exclusion; do not silently process a partial import.

### Approval queue

Capture requester, approver, reason/ticket, customer confirmation, and payload version. Recommend a second admin for bulk actions. A separately authorized emergency-offboarding capability requires a reason and subsequent review. Show customer and locator prominently; reject stale approval if payload or security preconditions change.

### User inventory

Filter by customer/account, user/email, lifecycle/operation/MFA status, and drift. Show requested roles alongside observed direct grants, policy, default role, disabled flag, and last verification. User detail provides redacted history and controlled password/enrollment recovery actions.

### Internal admin access

Provide a separate screen restricted to privileged-access operators/approvers. Select a person from `INTERNAL_ADMIN_ROSTER`, select registered target accounts, record a reason/ticket and review or expiry date, and preview explicit ACCOUNTADMIN grants or revocations. Do not permit free-text identities or arbitrary role requests to bypass roster validation.

Show each person's verified account grants, lower-privilege default role, MFA evidence, approval history, review deadline, and last reconciliation. Multi-account requests create independently tracked operations; no implicit fleet-wide grant. A user may be enabled while ACCOUNTADMIN remains pending MFA verification.

### Operations and account health

Show step-level results, API handles, retry eligibility, paused accounts, and credential/network/policy failures. Refresh triggers reconciliation, not provisioning. Cancelling future steps does not roll back completed remote DDL. Ordinary operators cannot modify account endpoints or secrets.

## Authentication policy baseline

Bootstrap each customer account through a separately approved process:

- Create a dedicated local policy schema where needed.
- Establish a versioned customer-human policy allowing PASSWORD with MFA enrollment REQUIRED.
- Prefer PASSKEY and TOTP, subject to client testing; permit Duo only as an approved alternative baseline.
- Keep Snowsight available for enrollment. Passkeys in this flow are second factors, not a claimed passwordless replacement.
- Attach the customer policy directly to app-managed customer users for the MVP, avoiding unintended changes to internal humans and services.
- Define a separate versioned internal-human-admin policy with PASSWORD and required native MFA. Recommend passkeys/security keys for privileged users; any TOTP/Duo fallback requires explicit security approval and client validation. Attach and verify this policy before privileged access; unknown enrollment evidence blocks ACCOUNTADMIN grants. Do not weaken an existing admin's stronger effective policy through automatic adoption.
- Inspect existing effective policies; user-level policies override account-wide policies.
- Block unexpected policy differences instead of blindly overwriting with CREATE OR REPLACE or FORCE.
- Preserve `SVC_DBA_ACCOUNT` key-pair access and separately tested emergency access.

Per-user policy attachment does not protect unmanaged users. Report coverage and policy drift. Account-wide human enforcement is a separately approved hardening change.

## Onboarding workflow

1. Claim an approved operation and verify its version, target, and preconditions.
2. Generate an account-specific key-pair JWT and verify the connected account, service identity, and requested role.
3. Inspect user existence, roles, and policy. Existing unknown users require explicit adoption approval, not automatic takeover.
4. Ensure the customer policy exists and matches the approved version.
5. Create the PERSON user initially disabled, without a centrally chosen password, with approved identity/default properties.
6. Attach the policy, grant allowed roles, and explicitly grant the default role.
7. Verify user type, policy, and grants before enabling the user. Password-only authentication without an initial password requires controlled setup before login.
8. Generate the password-setup/reset link on explicit authorized request. Pilot the no-initial-password setup flow; if unsupported, block activation pending approval of an alternative secure setup process.
9. Initiate MFA enrollment when appropriate. Verified email receives Snowflake's message; otherwise an enrollment URL is returned for secure delivery.
10. Record verified target configuration. Track provisioning, handoff, and actual MFA enrollment separately.

Password-reset links are single-use and expire after 12 hours. Generate them near delivery; do not reset existing working credentials on import replay.

### Sensitive handoff

MVP handoff uses a restricted admin workflow and an approved customer communication channel, not an assumed automatic email integration.

Never store reset/enrollment links in ordinary audit tables, logs, exports, or shared caches. If asynchronous handoff requires persistence, use a separately protected encrypted short-retention artifact store with actor-bound retrieval and purge. Validate the store and delivery mechanism before enabling this feature. Do not assume an unverified enrollment-link expiration interval.

Customer MFA seeds and private passkeys remain under customer control. No confidential data is sent to unapproved external services.

## Internal 84.51 human ACCOUNTADMIN workflow

This is a separate trusted action family, not an exception to the customer CSV role allowlist.

1. Validate the employee against the approved internal roster, including verified corporate email and eligibility. An email domain alone is insufficient proof of employee identity.
2. Require approval by another authorized privileged-access approver; prohibit self-approval and requester/beneficiary self-approval. Bind approval to the named person, exact account list, reason, review/expiry date, and registry/policy versions. App approval authority does not itself confer target ACCOUNTADMIN.
3. Verify the target account, authorized privileged worker identity, and protected-user boundaries. Reuse an existing internal PERSON user only after explicit identity/adoption verification; do not convert customer or service users.
4. For a new identity, create an initially disabled PERSON user, attach the internal-admin MFA policy, and grant only the approved low-privilege access needed for setup. Use PUBLIC or an approved lower-privilege role as the default; never default to ACCOUNTADMIN. Existing role grants are inventoried before changes.
5. Enable secure password setup and MFA enrollment through the existing restricted handoff mechanism. At this stage, ACCOUNTADMIN is not granted.
6. Reconcile the user's required-MFA policy and actual permitted MFA enrollment. If evidence is missing, stale, or incompatible, retain AWAITING\_MFA/BLOCKED. A required policy or sent invitation alone cannot satisfy this gate.
7. Revalidate approval, eligibility, target identity, and operation version immediately before granting ACCOUNTADMIN. Grant directly to the named user through the privileged worker, then verify the direct grant remotely. Do not place ACCOUNTADMIN in a customer role hierarchy or expose a generic grant endpoint.
8. Record verified GRANTED state, approval and API evidence, default role, policy/enrollment evidence, and review/expiry date. The human explicitly selects ACCOUNTADMIN when needed in Snowsight; membership does not make it the default role.
9. Reconcile privileged grants and MFA policy drift on a schedule. Raise unauthorized or expired grants for approved revocation; expiry is application-enforced, not an assumed native expiring role grant. Failed expiry processing remains visibly overdue and alerts the team.

### Revocation and employee offboarding

Support two distinct reviewed actions: REVOKE\_ACCOUNTADMIN removes only the privileged grant and preserves separately approved ordinary access; DISABLE\_INTERNAL\_ADMIN disables the user in the selected accounts and verifies the outcome, with role cleanup tracked separately. Employee departures must be reconciled against every managed-account assignment, including partial failures. Neither customer CSV nor a missing customer roster row can trigger these actions.

Before planned grant removal or disablement, check remaining verified human-admin and emergency-access coverage. Snowflake recommends assigning ACCOUNTADMIN to at least two users and not using it as a user's default role. Maintain a reviewed coverage baseline that includes independently controlled emergency access; do not count the administrative service identity as proof of human/emergency readiness. If removing the last usable administrator, require a replacement or an explicitly authorized security-response override. Emergency disabling of a compromised identity must not be silently prevented by this coverage check; record the override and alert for recovery.

User ownership or separately held grants can remain after ACCOUNTADMIN revocation. Inventory these and handle ownership transfer/other grant cleanup through explicitly approved steps; do not claim revoking one role removes all access.

## Offboarding workflow

1. Select users or upload explicit DISABLE requests; record account, reason, and approval.
2. Set desired state DISABLED and queue the action; do not change observed state yet.
3. Verify the target is an app-managed customer human and not a protected identity.
4. Disable the user through the target SQL API.
5. Read back remote state and record verified disablement centrally.
6. Retain user/role history. Do not drop users by default. Optional role revocation is a separately tracked step.

Already-disabled users yield verified success. Absent users display NOT\_FOUND, not fabricated disablement. Unreachable accounts remain pending/failed with stale or unknown observation. Reconciliation repairs central state if remote success precedes a failed central write.

Snowflake documents that disabling a user blocks login/new queries and aborts running/scheduled queries. Test existing-session/client containment during the pilot; do not assert all sessions or tokens disappear without evidence.

## Reliable SQL API execution

- Short-lived key-pair JWTs with correct account/user canonicalization and fingerprint.
- Separate regional endpoint hostname from JWT account identity.
- Explicit execution role on every request.
- One bounded logical step per request, with durable request UUID and statement handle.
- Handle asynchronous completion even for initially synchronous submissions; retrieve required result partitions.
- Use documented resubmission semantics and preserved request IDs after ambiguous failure; never blindly replay credential issuance.
- Re-read target state when outcomes are uncertain.
- Resume from verified steps: remote DDL and central writes are not a distributed atomic transaction.
- Serialize conflicting account/user actions; a newer disable supersedes stale unstarted onboarding work. Check versions before activation.
- Bounded polling, retries/backoff, circuit breakers, and account pause controls.
- Fixed SQL action templates, bindings where supported, and validated/quoted identifiers where required.
- Registered HTTPS destinations only; TLS verification and same-account status URLs; reject cross-host redirects.

## Roles, credentials, and network controls

Use dedicated central app-owner, viewer, operator, approver, bootstrap, and worker roles. The UI owner should not hold ACCOUNTADMIN or read target secrets. Restrict editing of trusted app and worker code.

Identify viewers through supported `st.user.user_name` and validate runtime support. Do not use owner-rights CURRENT\_ROLE as viewer identity. Enforce authorization in trusted command paths and revalidate approved operations in the worker; hiding buttons is insufficient. Prevent direct unauthorized writes to queues and inventory.

Prefer a dedicated target service user/custom role with only required user management, allowed customer role-grant, and policy privileges. The ordinary customer worker must not have authority to grant ACCOUNTADMIN.

Use a separate privileged worker/procedure and credential path for internal-admin grants/revocations. Its target role must have the actual privileges required to grant/revoke ACCOUNTADMIN, validated during bootstrap; do not assume ownership of created users is sufficient. MANAGE GRANTS is broad authority, so any approved use requires narrow central procedure permissions, fixed actions, explicit per-account approvals, and monitoring. Keep this authority and its keys unavailable to the ordinary customer worker and UI.

`SVC_DBA_ACCOUNT` can be a controlled bootstrap/migration starting point, but fleet-wide permanent ACCOUNTADMIN-backed automation remains a material risk. Adding named human admins does not justify assigning ACCOUNTADMIN to the Streamlit owner.

Prefer independent account keys in Snowflake secret objects. Use narrow external access integrations. Static per-account/per-shard worker secret bindings are a concrete deployment option; validate limits for the fleet rather than assuming dynamic secret lookup is supported.

Verify target network policies admit the worker path. Public Snowflake-hosted egress is not assumed to have a fixed allowlistable address. Choose and test supported public/private connectivity before deployment. Keys, JWTs, customer passwords, MFA seeds, and credential links never enter source, ordinary inventory, logs, or exports.

## Reconciliation

Scheduled and on-demand read-only checks verify user existence/type, disabled flag, direct grants, default settings, policy version, and available MFA enrollment evidence. Record last success and reasons for missing evidence. Use immediate metadata for post-operation verification rather than relying solely on delayed account-usage views.

Reconciliation detects drift by default; it does not silently revoke external grants, repair policies, or re-enable users. For internal admins, also verify ACCOUNTADMIN direct grants, roster eligibility, approval/review validity, lower-privilege default roles, MFA evidence, and emergency-access coverage. Time-bound grants may enqueue revocation only when their original approval explicitly authorized expiry; unresolved execution must remain visible. Add login-history reporting later as a separate approved capability.

## Acceptance tests

- CSV cannot redirect accounts, inject SQL, request protected users, or bypass role restrictions.
- Policy attachment precedes activation; administrative key-pair access remains intact.
- Password setup and MFA enrollment work with Snowsight and actual customer clients.
- Duplicate uploads/UI reruns do not duplicate provisioning or reset links.
- Browser closure does not stop execution.
- Expired JWTs, permission failures, timeouts, async responses, and result partitions are handled.
- Partial remote execution and failed central writes reconcile safely.
- Concurrent disable/onboard actions cannot re-enable through stale work.
- Offboarding is remotely verified before central completion.
- Unknown, absent, stale, MFA-required, and enrolled states remain distinct.
- Approval/actor attribution, secret isolation, sensitive handoff, and retention are tested.
- Customer CSVs, ordinary customer operators, and ordinary worker credentials cannot grant ACCOUNTADMIN or alter internal-admin identities.
- Internal-admin grants require an eligible roster identity, independent approval, actual permitted MFA enrollment, and remote verification; duplicate requests do not reissue credentials.
- Newly provisioned internal admins have a lower-privilege default role, not ACCOUNTADMIN; privilege removal and user disablement remain distinct.
- Review/expiry enforcement, employee departure across accounts, partial revocation failures, and emergency coverage/compromise overrides are tested.

## Delivery phases

1. Confirm EIGHTY451, pilot account, roles/policies, network path, credential strategy, and runtime prerequisites.
2. Build registry, CSV validation, inventory, diff, and dry-run review without remote changes.
3. Run an approved single-account sandbox customer onboarding/offboarding pilot and separate internal-admin provisioning, MFA-gated ACCOUNTADMIN grant, revocation, and disablement tests.
4. Harden task-driven execution, approvals, retries, reconciliation, and sensitive handoff.
5. Validate a small customer cohort and operational support workload.
6. Roll out incrementally with account pause controls and measured concurrency.

### Implementation checklist — not started

- [ ] Confirm account registry and secure execution prerequisites.
- [ ] Define control tables and lifecycle state model.
- [ ] Design CSV validation and administrative approval screens.
- [ ] Implement durable key-pair SQL API execution.
- [ ] Implement onboarding and MFA policy safeguards.
- [ ] Implement offboarding and target-state reconciliation.
- [ ] Implement the separate internal-human-admin ACCOUNTADMIN approval, MFA verification, grant/revocation, and coverage workflow.
- [ ] Validate pilot workflows and stage fleet rollout.

Before deployment, confirm exact database/schema/warehouse choices, sandbox target, approved role lists, key/network compatibility, delivery mechanism, retention, and approval rules. Implementation and all account changes remain pending separate authorization.

## Documentation

- SQL API authentication
- SQL API submissions
- SQL API reference
- External access integrations
- Streamlit security
- Streamlit owner rights
- Streamlit viewer identity
- Authentication policies
- Native MFA
- ALTER USER
- Configuring access control and role assignments
- Access control considerations and ACCOUNTADMIN best practices
