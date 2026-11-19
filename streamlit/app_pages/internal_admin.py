import streamlit as st

from lib.db import CTL, can, command, query, show_result

st.title("Internal admin access")
st.caption("84.51 ACCOUNTADMIN workflow: roster validation, independent approval, verified MFA, then a direct grant. "
           "ACCOUNTADMIN is never a default role.")

tab_request, tab_approve, tab_active, tab_handoff = st.tabs(["Request", "Approve", "Active grants", "Secure handoff"])

with tab_request:
    roster = query(f"""SELECT EMPLOYEE_ID, TARGET_USERNAME, CORPORATE_EMAIL, FIRST_NAME, LAST_NAME
                       FROM {CTL}.INTERNAL_ADMIN_ROSTER WHERE ELIGIBILITY_STATUS = 'ELIGIBLE' AND EMAIL_VERIFIED
                       ORDER BY LAST_NAME""")
    accts = query(f"SELECT ACCOUNT_ID, DISPLAY_NAME FROM {CTL}.CUSTOMER_ACCOUNTS WHERE IS_ENABLED AND NOT IS_PAUSED "
                  "AND EXEC_ROLE = 'ACCOUNTADMIN' ORDER BY ACCOUNT_ID")
    if roster.empty:
        st.info("No eligible employees on the roster.", icon=":material/info:")
    else:
        labels = {r.EMPLOYEE_ID: f"{r.FIRST_NAME} {r.LAST_NAME} ({r.CORPORATE_EMAIL})" for r in roster.itertuples()}
        with st.form("req_internal"):
            emp = st.selectbox("Employee", list(labels), format_func=labels.get)
            targets = st.multiselect("Accounts", accts["ACCOUNT_ID"].tolist())
            reason = st.text_input("Reason")
            ticket = st.text_input("Ticket")
            with st.container(horizontal=True):
                review_by = st.date_input("Review by", value=None)
                expires = st.date_input("Expires", value=None)
            go = st.form_submit_button("Request access", type="primary", icon=":material/send:",
                                       disabled=not can("operate"))
        if go:
            if not (targets and reason and expires):
                st.error("Accounts, reason and expiry are required.")
            else:
                show_result(command("REQUEST_INTERNAL_ACCESS", {
                    "employee_id": emp, "account_ids": targets, "reason": reason, "ticket": ticket,
                    "review_by": str(review_by) if review_by else None, "expires_at": str(expires)}),
                    "Request created. A different privileged approver must approve it.")

with tab_approve:
    pend = query(f"""SELECT a.ACCESS_ID, a.ACCOUNT_ID, a.TARGET_USERNAME, r.CORPORATE_EMAIL, a.REASON, a.TICKET,
                            a.REQUESTED_BY, a.CREATED_AT, a.EXPIRES_AT
                     FROM {CTL}.ADMIN_ACCOUNT_ACCESS a JOIN {CTL}.INTERNAL_ADMIN_ROSTER r USING (EMPLOYEE_ID)
                     WHERE a.WORKFLOW_STATE = 'PENDING_APPROVAL' ORDER BY a.CREATED_AT""")
    if pend.empty:
        st.success("Nothing pending.", icon=":material/done_all:")
    else:
        pend.insert(0, "select", False)
        ed = st.data_editor(pend, hide_index=True, disabled=[c for c in pend.columns if c != "select"],
                            key="priv_pending")
        ids = ed[ed["select"]]["ACCESS_ID"].tolist()
        if st.button("Approve selected", type="primary", icon=":material/verified_user:",
                     disabled=not ids or not can("priv")):
            show_result(command("APPROVE_INTERNAL_ACCESS", {"access_ids": ids}),
                        "Approved. Provisioning is queued; the grant waits for verified MFA.")

with tab_active:
    act = query(f"""SELECT ACCESS_ID, ACCOUNT_ID, TARGET_USERNAME, WORKFLOW_STATE, OBSERVED_ACCOUNTADMIN, OBSERVED_MFA,
                           APPROVED_BY, REVIEW_BY, EXPIRES_AT, LAST_VERIFIED_AT
                    FROM {CTL}.ADMIN_ACCOUNT_ACCESS
                    WHERE WORKFLOW_STATE NOT IN ('PENDING_APPROVAL','REVOKED') ORDER BY ACCOUNT_ID, TARGET_USERNAME""")
    act.insert(0, "select", False)
    ed = st.data_editor(act, hide_index=True, disabled=[c for c in act.columns if c != "select"],
                        key="priv_active")
    ids = ed[ed["select"]]["ACCESS_ID"].tolist()
    with st.form("revoke"):
        action = st.segmented_control("Action", ["REVOKE_ACCOUNTADMIN", "DISABLE_INTERNAL_ADMIN"],
                                      default="REVOKE_ACCOUNTADMIN",
                                      format_func=lambda a: "Revoke ACCOUNTADMIN" if a.startswith("REVOKE") else "Disable user")
        reason = st.text_input("Reason")
        override = st.toggle("Emergency override (bypass ACCOUNTADMIN coverage check; audited and alerted)")
        go = st.form_submit_button("Request", icon=":material/remove_moderator:", disabled=not ids)
    if go:
        show_result(command("REQUEST_REVOKE", {"access_ids": ids, "action": action, "reason": reason,
                                               "emergency_override": override}),
                    "Submitted for privileged approval.")
    retry = query(f"""SELECT ACCESS_ID FROM {CTL}.ADMIN_ACCOUNT_ACCESS WHERE WORKFLOW_STATE = 'AWAITING_MFA'""")
    if not retry.empty:
        st.caption(f"{len(retry)} grant(s) waiting for verified MFA. Re-queue blocked GRANT_ACCOUNTADMIN operations "
                   "from Operations and health after the user enrolls.")

with tab_handoff:
    st.caption("Single-use links (12h). Deliver through the approved channel, then mark delivered - the link is erased.")
    if not can("approve"):
        st.info("Approver permission required.", icon=":material/lock:")
    else:
        h = query(f"SELECT * FROM {CTL}.V_HANDOFF_PENDING ORDER BY CREATED_AT")
        if h.empty:
            st.success("No pending handoffs.", icon=":material/done_all:")
        for r in h.itertuples():
            with st.container(border=True):
                st.markdown(f"**{r.ACCOUNT_ID} / {r.USERNAME}** - {r.LINK_TYPE} - expires {r.EXPIRES_AT}")
                if st.toggle("Reveal link", key=f"rev_{r.HANDOFF_ID}"):
                    st.code(r.LINK_VALUE, language="text")
                channel = st.text_input("Delivery channel", key=f"ch_{r.HANDOFF_ID}")
                if st.button("Mark delivered", key=f"del_{r.HANDOFF_ID}", disabled=not channel):
                    show_result(command("MARK_HANDOFF_DELIVERED", {"handoff_id": r.HANDOFF_ID, "channel": channel}),
                                "Marked delivered; link erased.")
