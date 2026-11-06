import streamlit as st

from lib.db import CTL, can, command, query, show_result, viewer

st.title("Approval queue")
st.caption("Self-approval is not allowed. Approvals are bound to the payload hash and the current registry and role-catalog versions.")

if not can("approve"):
    st.info("You have view-only access to this queue.", icon=":material/visibility:")

family = st.segmented_control("Action family", ["CUSTOMER", "PRIVILEGED"], default="CUSTOMER", key="appr_family")
if family == "PRIVILEGED" and not can("priv"):
    st.warning("Privileged approvals require privileged-approver permission.", icon=":material/lock:")

pending = query(f"""SELECT o.OPERATION_ID, o.REQUESTED_AT, o.ACCOUNT_ID, o.USERNAME, o.ACTION, o.REQUESTED_BY,
                           o.REASON, o.TICKET, o.BATCH_ID, o.REGISTRY_VERSION,
                           IFF(o.REGISTRY_VERSION = a.REGISTRY_VERSION, 'CURRENT', 'STALE') AS VERSION_CHECK,
                           o.PAYLOAD
                    FROM {CTL}.OPERATIONS o JOIN {CTL}.CUSTOMER_ACCOUNTS a USING (ACCOUNT_ID)
                    WHERE o.STATUS = 'PENDING_APPROVAL' AND o.ACTION_FAMILY = ?
                    ORDER BY o.REQUESTED_AT""", [family or "CUSTOMER"])

if pending.empty:
    st.success("Nothing pending.", icon=":material/done_all:")
    st.stop()

pending.insert(0, "select", False)
me = viewer()
edited = st.data_editor(
    pending,
    hide_index=True,
    disabled=[c for c in pending.columns if c != "select"],
    column_config={"select": st.column_config.CheckboxColumn("Select"),
                   "PAYLOAD": st.column_config.JsonColumn("Payload", width="medium")},
    key=f"appr_editor_{family}",
    alt="Operations pending approval",
)
chosen = edited[edited["select"]]
own = chosen[chosen["REQUESTED_BY"].str.upper() == me]
if not own.empty:
    st.warning(f"{len(own)} selected operation(s) were requested by you and will be refused.", icon=":material/warning:")
if len(chosen) > 10:
    st.info(f"Bulk approval of {len(chosen)} operations. Confirm the customer request reference before approving.",
            icon=":material/info:")

with st.container(horizontal=True, vertical_alignment="bottom"):
    reject_reason = st.text_input("Rejection reason", key="reject_reason")
    approve = st.button("Approve selected", type="primary", icon=":material/check:",
                        disabled=chosen.empty or not can("approve"))
    reject = st.button("Reject selected", icon=":material/close:", disabled=chosen.empty or not can("approve"))

ids = chosen["OPERATION_ID"].tolist()
if approve:
    show_result(command("APPROVE", {"operation_ids": ids}), "Approval processed.")
if reject:
    show_result(command("REJECT", {"operation_ids": ids, "reason": reject_reason}), "Rejected.")
