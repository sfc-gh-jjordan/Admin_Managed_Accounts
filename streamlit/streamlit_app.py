import streamlit as st

from lib.db import can, is_accountadmin, permissions, viewer

st.set_page_config(page_title="Managed accounts admin", page_icon=":material/admin_panel_settings:", layout="wide")

user = viewer()
if not is_accountadmin(user):
    st.error(f"{user} does not hold ACCOUNTADMIN in EIGHTY451. This app is restricted to account administrators.",
             icon=":material/lock:")
    st.stop()
if permissions(user).empty:
    st.error(f"{user} has no duties assigned in ADMIN_AUTHORIZATIONS.", icon=":material/lock:")
    st.stop()

pages = {
    "Monitor": [
        st.Page("app_pages/overview.py", title="Overview", icon=":material/dashboard:", default=True),
        st.Page("app_pages/inventory.py", title="User inventory", icon=":material/group:"),
        st.Page("app_pages/operations.py", title="Operations and health", icon=":material/monitor_heart:"),
    ],
    "Manage": [
        st.Page("app_pages/import_review.py", title="Import and review", icon=":material/upload_file:"),
        st.Page("app_pages/approvals.py", title="Approval queue", icon=":material/fact_check:"),
        st.Page("app_pages/accounts.py", title="Account registry", icon=":material/domain:"),
    ],
}
if can("priv") or can("operate"):
    pages["Privileged"] = [
        st.Page("app_pages/internal_admin.py", title="Internal admin access", icon=":material/shield_person:"),
    ]

nav = st.navigation(pages)
st.sidebar.caption(f"Signed in as **{user}**")
nav.run()
