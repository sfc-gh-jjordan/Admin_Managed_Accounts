import json

import pandas as pd
import streamlit as st

from lib import csv_validation as cv
from lib.db import CTL, account_picker, can, command, query, show_result

st.title("Import and review")
st.caption("Upload a customer CSV, review every row, then submit for approval. Nothing reaches the target account until approved.")

account_id = account_picker("import_account", only_enabled=True)
if not account_id:
    st.stop()
if not can("operate", account_id):
    st.warning("You need operator permission on this account to import.", icon=":material/lock:")
    st.stop()

with st.expander("CSV contract"):
    st.code(",".join(cv.EXPECTED_HEADERS) + "\n"
            "JANE_SMITH,jane.smith@customer.example,Jane,Smith,CPG_ANALYST,CPG_ANALYST,ONBOARD\n"
            "PAT_LEE,pat.lee@customer.example,Pat,Lee,,,DISABLE", language="text")

upload = st.file_uploader("Customer CSV", type=["csv"], key="csv_upload")
if upload is None:
    st.stop()

data = upload.getvalue()
try:
    parsed = cv.parse(data)
except cv.CsvError as e:
    st.error(str(e), icon=":material/error:")
    st.stop()

acct = query(f"SELECT APPROVED_EMAIL_DOMAINS, PROTECTED_USERS, SERVICE_USER FROM {CTL}.CUSTOMER_ACCOUNTS WHERE ACCOUNT_ID = ?",
             [account_id]).iloc[0]
roles = query(f"SELECT ROLE_NAME, IS_DEFAULT_ELIGIBLE FROM {CTL}.ROLE_CATALOG WHERE ACCOUNT_ID = ? AND IS_ACTIVE "
              "AND APPROVAL_CLASS <> 'BLOCKED'", [account_id])
blocked = query(f"SELECT ROLE_NAME FROM {CTL}.BLOCKED_ROLES")["ROLE_NAME"].tolist()
existing = query(f"SELECT USERNAME, IS_MANAGED, IDENTITY_CLASS FROM {CTL}.USER_CONTROL WHERE ACCOUNT_ID = ?", [account_id])


def _arr(v):
    return json.loads(v) if isinstance(v, str) else (v or [])


protected = _arr(acct.PROTECTED_USERS) + [acct.SERVICE_USER or ""]
results = cv.validate(
    parsed,
    allowed_roles=dict(zip(roles["ROLE_NAME"], roles["IS_DEFAULT_ELIGIBLE"])),
    blocked_roles=blocked,
    email_domains=_arr(acct.APPROVED_EMAIL_DOMAINS),
    protected_users=protected,
    existing_users={r.USERNAME: {"IS_MANAGED": r.IS_MANAGED, "IDENTITY_CLASS": r.IDENTITY_CLASS}
                    for r in existing.itertuples()},
)

valid = sum(r["is_valid"] for r in results)
with st.container(horizontal=True):
    st.metric("Rows", len(results), border=True)
    st.metric("Valid", valid, border=True)
    st.metric("Rejected", len(results) - valid, border=True)
    st.metric("Users", len({r["username"] for r in results}), border=True)

df = pd.DataFrame([{**r, "findings": "; ".join(r["findings"]), "exclude": False} for r in results])
st.caption("Rejected rows must be explicitly excluded before the batch can be submitted.")
edited = st.data_editor(
    df,
    hide_index=True,
    disabled=[c for c in df.columns if c != "exclude"],
    column_config={
        "is_valid": st.column_config.CheckboxColumn("Valid"),
        "exclude": st.column_config.CheckboxColumn("Exclude"),
        "findings": st.column_config.TextColumn("Findings", width="large"),
    },
    key="import_editor",
    alt="Validated CSV rows",
)

st.subheader("Impact preview")
active = edited[edited["is_valid"] & ~edited["exclude"]]
with st.container(horizontal=True):
    st.metric("Onboard", active[active.action == "ONBOARD"].username.nunique(), border=True)
    st.metric("Role changes", active[active.action.isin(["ADD_ROLES", "SET_MANAGED_ROLES"])].username.nunique(), border=True)
    st.metric("Disable", active[active.action == "DISABLE"].username.nunique(), border=True)
    st.metric("Re-enable", active[active.action == "REENABLE"].username.nunique(), border=True)

unresolved = edited[~edited["is_valid"] & ~edited["exclude"]]
with st.form("submit_batch"):
    reason = st.text_input("Reason")
    ticket = st.text_input("Ticket / customer confirmation reference")
    submitted = st.form_submit_button("Submit for approval", icon=":material/send:", type="primary",
                                      disabled=not unresolved.empty or active.empty)
if not unresolved.empty:
    st.warning(f"{len(unresolved)} rejected row(s) are not excluded.", icon=":material/warning:")

if submitted:
    if not reason or not ticket:
        st.error("Reason and ticket are required.")
        st.stop()
    rows = []
    for r in edited.to_dict("records"):
        orig = next(x for x in results if x["row_number"] == r["row_number"])
        rows.append({**orig, "is_excluded": bool(r["exclude"])})
    saved = command("SAVE_IMPORT", {"account_id": account_id, "file_name": upload.name,
                                    "file_sha256": cv.file_sha256(data), "rows": rows,
                                    "reason": reason, "ticket": ticket})
    if not saved.get("ok"):
        show_result(saved, "")
        st.stop()
    res = command("SUBMIT_BATCH", {"batch_id": saved["result"]["batch_id"]})
    show_result(res, "Batch submitted for approval.")
