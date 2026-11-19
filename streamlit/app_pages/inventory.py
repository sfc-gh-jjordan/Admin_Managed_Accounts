import streamlit as st

from lib.db import CTL, can, command, csv_safe, query, show_result, visible_accounts

st.title("User inventory")
st.caption("Desired vs. observed state. Unknown means not yet verified - it never implies enabled, disabled or enrolled.")

accounts = visible_accounts()
with st.container(horizontal=True, vertical_alignment="bottom"):
    acct_filter = st.multiselect("Accounts", accounts["ACCOUNT_ID"].tolist(), key="inv_accounts")
    user_filter = st.text_input("Username contains", key="inv_user")
    scope = st.segmented_control("Scope", ["Managed", "Unmanaged", "All"], default="Managed", key="inv_scope")
    issues = st.pills("Issues", ["Drift", "Stale", "MFA pending", "Failed op"], selection_mode="multi", key="inv_issues")

where, params = ["1=1"], []
if acct_filter:
    where.append(f"ACCOUNT_ID IN ({','.join('?' * len(acct_filter))})")
    params += acct_filter
else:
    ids = accounts["ACCOUNT_ID"].tolist() or [""]
    where.append(f"ACCOUNT_ID IN ({','.join('?' * len(ids))})")
    params += ids
if user_filter:
    where.append("USERNAME ILIKE ?")
    params.append(f"%{user_filter}%")
if scope == "Managed":
    where.append("IS_MANAGED")
elif scope == "Unmanaged":
    where.append("NOT IS_MANAGED")
for i in issues or []:
    where.append({"Drift": "ARRAY_SIZE(DRIFT_FLAGS) > 0", "Stale": "IS_STALE",
                  "MFA pending": "MFA_EVIDENCE = 'REQUIRED_NOT_YET_OBSERVED'",
                  "Failed op": "LAST_OPERATION_STATUS IN ('FAILED','BLOCKED','PARTIAL')"}[i])

df = query(f"SELECT * FROM {CTL}.V_USER_INVENTORY WHERE {' AND '.join(where)} ORDER BY ACCOUNT_ID, USERNAME LIMIT 5000",
           params)
df.insert(0, "select", False)

edited = st.data_editor(
    df,
    hide_index=True,
    disabled=[c for c in df.columns if c != "select"],
    column_config={
        "select": st.column_config.CheckboxColumn("Select"),
        "DESIRED_ROLES": st.column_config.ListColumn("Desired roles"),
        "OBSERVED_ROLES": st.column_config.ListColumn("Observed roles"),
        "DRIFT_FLAGS": st.column_config.ListColumn("Drift"),
        "LAST_VERIFIED_AT": st.column_config.DatetimeColumn("Last verified"),
    },
    key="inv_editor",
)
st.download_button("Download CSV", csv_safe(df.drop(columns=["select"])).to_csv(index=False),
                   file_name="user_inventory.csv", icon=":material/download:")

chosen = edited[edited["select"] & edited["IS_MANAGED"] & (edited["IDENTITY_CLASS"] == "CPG_CUSTOMER")]
st.subheader("Request action for selected customer users")
if chosen.empty:
    st.caption("Select managed customer users above. Internal admins are handled on the Internal admin access page.")
    st.stop()
if chosen["ACCOUNT_ID"].nunique() > 1:
    st.warning("Select users from a single account.", icon=":material/warning:")
    st.stop()
account_id = chosen["ACCOUNT_ID"].iloc[0]
if not can("operate", account_id):
    st.warning("Operator permission required.", icon=":material/lock:")
    st.stop()

with st.form("user_action"):
    action = st.segmented_control(
        "Action", ["DISABLE_USER", "REENABLE_USER", "ISSUE_PASSWORD_LINK", "ENROLL_MFA"],
        default="DISABLE_USER",
        format_func=lambda a: {"DISABLE_USER": "Disable", "REENABLE_USER": "Re-enable",
                               "ISSUE_PASSWORD_LINK": "Password setup link", "ENROLL_MFA": "MFA enrollment"}[a])
    reason = st.text_input("Reason")
    ticket = st.text_input("Ticket")
    go = st.form_submit_button(f"Request for {len(chosen)} user(s)", type="primary", icon=":material/send:")
if go:
    if not reason:
        st.error("Reason is required.")
    else:
        show_result(command("REQUEST_USER_ACTION", {"account_id": account_id, "action": action,
                                                    "usernames": chosen["USERNAME"].tolist(),
                                                    "reason": reason, "ticket": ticket}),
                    "Submitted for approval.")
