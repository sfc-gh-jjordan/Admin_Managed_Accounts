"""Snowflake access helpers. The app only reads CONTROL data and calls APP.COMMAND."""
from __future__ import annotations

import json
from typing import Any, Optional

import pandas as pd
import streamlit as st

CTL = "ACCT_ADMIN_DB.CONTROL"


@st.cache_resource
def session():
    from snowflake.snowpark.context import get_active_session
    return get_active_session()


def viewer() -> str:
    """Viewer identity (owner's-rights app: CURRENT_USER is not the viewer)."""
    user = getattr(st, "user", None) or getattr(st, "experimental_user", None)
    name = getattr(user, "user_name", None) if user is not None else None
    if not name:
        st.error("Unable to determine viewer identity.", icon=":material/lock:")
        st.stop()
    return name.upper()


def query(sql: str, params: Optional[list] = None) -> pd.DataFrame:
    return session().sql(sql, params=params or []).to_pandas()


@st.cache_data(ttl=60, show_spinner=False)
def cached_query(sql: str, params: tuple = ()) -> pd.DataFrame:
    return query(sql, list(params))


def command(name: str, args: dict[str, Any]) -> dict:
    """Invoke the trusted command procedure; clears read caches on success."""
    raw = session().sql("CALL ACCT_ADMIN_DB.APP.COMMAND(?, ?, PARSE_JSON(?))",
                        params=[viewer(), name, json.dumps(args, default=str)]).collect()[0][0]
    res = json.loads(raw) if isinstance(raw, str) else raw
    if res.get("ok"):
        cached_query.clear()
    return res


def show_result(res: dict, success: str) -> None:
    if res.get("ok"):
        st.success(success, icon=":material/check_circle:")
        if res.get("result"):
            with st.expander("Details"):
                st.json(res["result"])
    else:
        st.error(res.get("error", "Command failed"), icon=":material/error:")


@st.cache_data(ttl=120, show_spinner=False)
def is_accountadmin(user: str) -> bool:
    """App is restricted to EIGHTY451 ACCOUNTADMIN holders (re-checked in APP.COMMAND)."""
    return not query("""SELECT 1 FROM SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_USERS
                         WHERE GRANTEE_NAME = ? AND ROLE = 'ACCOUNTADMIN' AND DELETED_ON IS NULL LIMIT 1""",
                     [user]).empty


@st.cache_data(ttl=120, show_spinner=False)
def permissions(user: str) -> pd.DataFrame:
    return query(f"""SELECT ACCOUNT_ID, CAN_VIEW, CAN_OPERATE, CAN_APPROVE, CAN_PRIV_APPROVE
                     FROM {CTL}.ADMIN_AUTHORIZATIONS WHERE ADMIN_USER = ? AND IS_ACTIVE""", [user])


def can(perm: str, account_id: str = "*") -> bool:
    col = {"view": "CAN_VIEW", "operate": "CAN_OPERATE", "approve": "CAN_APPROVE",
           "priv": "CAN_PRIV_APPROVE"}[perm]
    df = permissions(viewer())
    if df.empty:
        return False
    rows = df if account_id == "*" else df[(df["ACCOUNT_ID"] == "*") | (df["ACCOUNT_ID"] == account_id)]
    return bool(rows[col].any())


def visible_accounts() -> pd.DataFrame:
    df = cached_query(f"""SELECT ACCOUNT_ID, DISPLAY_NAME, ACCOUNT_LOCATOR, REGION, IS_ENABLED, IS_PAUSED,
                                 BOOTSTRAP_STATUS, REGISTRY_VERSION
                          FROM {CTL}.CUSTOMER_ACCOUNTS ORDER BY ACCOUNT_ID""")
    perms = permissions(viewer())
    if (perms["ACCOUNT_ID"] == "*").any():
        return df
    return df[df["ACCOUNT_ID"].isin(perms["ACCOUNT_ID"])]


def account_picker(key: str, label: str = "Account", only_enabled: bool = False) -> Optional[str]:
    df = visible_accounts()
    if only_enabled:
        df = df[df["IS_ENABLED"] & ~df["IS_PAUSED"]]
    if df.empty:
        st.info("No accounts available.", icon=":material/info:")
        return None
    labels = {r.ACCOUNT_ID: f"{r.ACCOUNT_ID} - {r.DISPLAY_NAME or ''}" for r in df.itertuples()}
    return st.selectbox(label, list(labels), format_func=labels.get, key=key)


def csv_safe(df: pd.DataFrame) -> pd.DataFrame:
    """Neutralize spreadsheet formula injection in downloads."""
    out = df.copy()
    for c in out.columns:
        if out[c].dtype == object:
            out[c] = out[c].map(lambda v: "'" + v if isinstance(v, str) and v[:1] in ("=", "+", "-", "@", "\t", "\r") else v)
    return out
