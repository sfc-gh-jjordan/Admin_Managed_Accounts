import streamlit as st

from lib.db import CTL, cached_query

st.title("Overview")
st.caption("Managed coverage across all registered accounts. Observed values come from the last verified reconciliation.")

m = cached_query(f"SELECT * FROM {CTL}.V_OVERVIEW_METRICS").iloc[0]

with st.container(horizontal=True):
    st.metric("Accounts registered", int(m.ACCOUNTS_TOTAL), border=True)
    st.metric("Accounts active", int(m.ACCOUNTS_ACTIVE), border=True)
    st.metric("Accounts paused", int(m.ACCOUNTS_PAUSED), border=True)
    st.metric("Pending approvals", int(m.PENDING_APPROVALS), border=True)

with st.container(horizontal=True):
    st.metric("Managed users enabled", int(m.MANAGED_ENABLED), border=True)
    st.metric("Managed users disabled", int(m.MANAGED_DISABLED), border=True)
    st.metric("Unmanaged users observed", int(m.UNMANAGED_USERS), border=True)
    st.metric("Operations in flight", int(m.IN_FLIGHT), border=True)

with st.container(horizontal=True):
    st.metric("Failed / blocked operations", int(m.FAILED_OPS), border=True)
    st.metric("Handoff pending", int(m.HANDOFF_PENDING), border=True)
    st.metric("MFA not yet observed", int(m.MFA_PENDING), border=True)
    st.metric("Drifted users", int(m.DRIFTED_USERS), border=True)

st.subheader("By account")
by_acct = cached_query(f"""
    SELECT a.ACCOUNT_ID, a.DISPLAY_NAME, a.IS_ENABLED, a.IS_PAUSED, a.BOOTSTRAP_STATUS,
           COUNT_IF(u.IS_MANAGED)                                 AS MANAGED_USERS,
           COUNT_IF(NOT u.IS_MANAGED)                             AS UNMANAGED_USERS,
           COUNT_IF(u.IS_MANAGED AND ARRAY_SIZE(u.DRIFT_FLAGS)>0) AS DRIFTED,
           COUNT_IF(u.MFA_EVIDENCE = 'REQUIRED_NOT_YET_OBSERVED') AS MFA_PENDING,
           MAX(u.LAST_VERIFIED_AT)                                AS LAST_VERIFIED_AT
    FROM {CTL}.CUSTOMER_ACCOUNTS a LEFT JOIN {CTL}.USER_CONTROL u USING (ACCOUNT_ID)
    GROUP BY 1,2,3,4,5 ORDER BY DRIFTED DESC, ACCOUNT_ID""")
st.dataframe(by_acct, hide_index=True)

st.subheader("Recent failures")
fails = cached_query(f"""SELECT REQUESTED_AT, ACCOUNT_ID, USERNAME, ACTION, STATUS, ATTEMPTS, LAST_ERROR
                         FROM {CTL}.OPERATIONS WHERE STATUS IN ('FAILED','PARTIAL','BLOCKED')
                         ORDER BY REQUESTED_AT DESC LIMIT 50""")
st.dataframe(fails, hide_index=True)
