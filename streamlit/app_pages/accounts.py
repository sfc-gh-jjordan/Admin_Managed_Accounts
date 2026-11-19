import json

import streamlit as st

from lib.db import CTL, can, command, query, show_result, visible_accounts

st.title("Account registry")
st.caption("Accounts discovered from the organization. An account is usable only after bootstrap, connectivity "
           "registration, and a successful preflight. Credentials are never shown or entered here.")

df = visible_accounts()
st.dataframe(df, hide_index=True)

account_id = st.selectbox("Manage account", df["ACCOUNT_ID"].tolist(), index=None, key="reg_account")
if not account_id:
    st.stop()

acct = query(f"SELECT * FROM {CTL}.CUSTOMER_ACCOUNTS WHERE ACCOUNT_ID = ?", [account_id]).iloc[0]


def _arr(v):
    return json.loads(v) if isinstance(v, str) else (v or [])


with st.container(horizontal=True):
    st.metric("Bootstrap", acct.BOOTSTRAP_STATUS, border=True)
    st.metric("Enabled", "Yes" if acct.IS_ENABLED else "No", border=True)
    st.metric("Paused", "Yes" if acct.IS_PAUSED else "No", border=True)
    st.metric("Registry version", int(acct.REGISTRY_VERSION), border=True)

with st.expander("Connection (read-only)"):
    st.table({
        "SQL API host": acct.SQL_API_HOST, "JWT account": acct.JWT_ACCOUNT_IDENTIFIER,
        "Expected locator": acct.EXPECTED_ACCOUNT_LOCATOR, "Service user": acct.SERVICE_USER,
        "Execution role": acct.EXEC_ROLE, "Worker procedure": acct.WORKER_PROCEDURE,
        "Secret reference": acct.SECRET_NAME, "Key fingerprint": acct.PUBLIC_KEY_FP,
        "Last preflight": str(acct.LAST_PREFLIGHT_AT),
    })

with st.container(horizontal=True):
    if st.button("Run preflight", icon=":material/network_check:", disabled=not can("operate", account_id)):
        show_result(command("RUN_NOW", {"account_id": account_id, "mode": "PREFLIGHT"}), "Preflight complete.")
    if st.button("Reconcile now", icon=":material/sync:", disabled=not can("operate", account_id)):
        show_result(command("RUN_NOW", {"account_id": account_id, "mode": "RECONCILE"}), "Reconciliation complete.")
    if st.button("Execute queue now", icon=":material/play_arrow:", disabled=not can("approve", account_id)):
        show_result(command("RUN_NOW", {"account_id": account_id, "mode": "QUEUE"}), "Queue processed.")
    paused = bool(acct.IS_PAUSED)
    if st.button("Resume account" if paused else "Pause account",
                 icon=":material/play_circle:" if paused else ":material/pause_circle:",
                 disabled=not can("approve", account_id)):
        show_result(command("SET_ACCOUNT_STATE", {"account_id": account_id, "paused": not paused,
                                                  "reason": "manual via app"}), "Account state updated.")

st.subheader("Settings")
st.caption("Changing settings bumps the registry version and invalidates pending approvals for this account.")
with st.form("registry_edit"):
    display = st.text_input("Display name", acct.DISPLAY_NAME or "")
    domains = st.text_input("Approved email domains (comma-separated)", ", ".join(_arr(acct.APPROVED_EMAIL_DOMAINS)))
    protected = st.text_input("Protected users (comma-separated)", ", ".join(_arr(acct.PROTECTED_USERS)))
    exec_role = st.segmented_control("Execution role", ["ACCOUNTADMIN", "ACCT_USER_ADMIN"], default=acct.EXEC_ROLE)
    enabled = st.toggle("Enabled", bool(acct.IS_ENABLED))
    save = st.form_submit_button("Save", type="primary", disabled=not can("priv", account_id))
if save:
    split = lambda s: [p.strip() for p in s.split(",") if p.strip()]  # noqa: E731
    show_result(command("UPDATE_REGISTRY", {"account_id": account_id, "changes": {
        "DISPLAY_NAME": display, "APPROVED_EMAIL_DOMAINS": [d.lower() for d in split(domains)],
        "PROTECTED_USERS": [u.upper() for u in split(protected)], "EXEC_ROLE": exec_role, "IS_ENABLED": enabled}}),
        "Registry updated.")

st.subheader("Role catalog")
roles = query(f"""SELECT ROLE_NAME, IS_DEFAULT_ELIGIBLE, APPROVAL_CLASS, IS_ACTIVE, CATALOG_VERSION
                  FROM {CTL}.ROLE_CATALOG WHERE ACCOUNT_ID = ? ORDER BY ROLE_NAME""", [account_id])
edited = st.data_editor(
    roles.drop(columns=["CATALOG_VERSION"]),
    num_rows="dynamic",
    hide_index=True,
    column_config={"APPROVAL_CLASS": st.column_config.SelectboxColumn(options=["STANDARD", "ELEVATED", "BLOCKED"])},
    key="role_catalog",
)
if st.button("Save role catalog", icon=":material/save:", disabled=not can("priv", account_id)):
    show_result(command("UPSERT_ROLES", {"account_id": account_id,
                                         "roles": edited.dropna(subset=["ROLE_NAME"]).to_dict("records")}),
                "Role catalog saved.")
