import streamlit as st

from lib.db import CTL, can, command, query, show_result, visible_accounts

st.title("Operations and health")
st.caption("Step-level SQL API results. Refresh reads central data only; use Account registry to trigger runs.")

accounts = visible_accounts()
with st.container(horizontal=True, vertical_alignment="bottom"):
    acct = st.selectbox("Account", ["All"] + accounts["ACCOUNT_ID"].tolist(), key="ops_acct")
    statuses = st.pills("Status", ["QUEUED", "RUNNING", "SUCCEEDED", "FAILED", "BLOCKED", "CANCELLED", "PENDING_APPROVAL"],
                        selection_mode="multi", default=["QUEUED", "RUNNING", "FAILED", "BLOCKED"], key="ops_status")
    if st.button("Refresh", icon=":material/refresh:"):
        st.rerun()

where, params = ["1=1"], []
if acct != "All":
    where.append("ACCOUNT_ID = ?"); params.append(acct)
if statuses:
    where.append(f"STATUS IN ({','.join('?' * len(statuses))})"); params += statuses

ops = query(f"""SELECT OPERATION_ID, REQUESTED_AT, ACCOUNT_ID, USERNAME, ACTION, ACTION_FAMILY, STATUS, ATTEMPTS,
                       NEXT_ATTEMPT_AT, REQUESTED_BY, APPROVED_BY, LAST_ERROR, COMPLETED_AT
                FROM {CTL}.OPERATIONS WHERE {' AND '.join(where)} ORDER BY REQUESTED_AT DESC LIMIT 1000""", params)
ops.insert(0, "select", False)
ed = st.data_editor(ops, hide_index=True, disabled=[c for c in ops.columns if c != "select"],
                    key="ops_editor", alt="Operations")
chosen = ed[ed["select"]]

with st.container(horizontal=True):
    if st.button("Retry selected", icon=":material/replay:", disabled=chosen.empty or not can("approve")):
        show_result(command("RETRY", {"operation_ids": chosen["OPERATION_ID"].tolist()}), "Re-queued.")
    if st.button("Cancel selected", icon=":material/cancel:", disabled=chosen.empty or not can("approve")):
        show_result(command("REJECT", {"operation_ids": chosen["OPERATION_ID"].tolist(), "reason": "cancelled"}),
                    "Cancelled.")

if len(chosen) == 1:
    st.subheader("Steps")
    steps = query(f"""SELECT STEP_NO, STEP_NAME, OUTCOME, HTTP_STATUS, SF_CODE, REQUEST_ID, STATEMENT_HANDLE, ERROR,
                             STARTED_AT, FINISHED_AT
                      FROM {CTL}.OPERATION_STEPS WHERE OPERATION_ID = ? ORDER BY STEP_NO""",
                  [chosen["OPERATION_ID"].iloc[0]])
    st.dataframe(steps, hide_index=True, alt="Operation step results")

st.subheader("Account health")
health = query(f"""SELECT ACCOUNT_ID, IS_ENABLED, IS_PAUSED, PAUSE_REASON, CONSECUTIVE_FAILURES, BOOTSTRAP_STATUS,
                          LAST_PREFLIGHT_AT, LAST_PREFLIGHT_RESULT:ok::BOOLEAN AS PREFLIGHT_OK
                   FROM {CTL}.CUSTOMER_ACCOUNTS
                   WHERE IS_PAUSED OR CONSECUTIVE_FAILURES > 0 OR BOOTSTRAP_STATUS <> 'VERIFIED'
                   ORDER BY CONSECUTIVE_FAILURES DESC""")
st.dataframe(health, hide_index=True, alt="Accounts needing attention")

st.subheader("Audit trail")
audit = query(f"""SELECT EVENT_TS, ACTOR, EVENT_TYPE, ACCOUNT_ID, USERNAME, OPERATION_ID, DETAILS
                  FROM {CTL}.AUDIT_EVENTS ORDER BY EVENT_TS DESC LIMIT 500""")
st.dataframe(audit, hide_index=True, column_config={"DETAILS": st.column_config.JsonColumn()}, alt="Audit events")
