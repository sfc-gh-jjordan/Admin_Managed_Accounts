"""
actions.py
Fixed SQL action templates executed on target accounts through the SQL API.
No free-form SQL ever reaches a target: every statement is built here from
validated identifiers and escaped literals.
"""
from __future__ import annotations

import re
from typing import Optional

_IDENT_RE = re.compile(r"^[A-Z][A-Z0-9_$]{0,254}$")
_QUALIFIED_RE = re.compile(r"^[A-Z][A-Z0-9_$]*\.[A-Z][A-Z0-9_$]*\.[A-Z][A-Z0-9_$]*$")
_EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9.\-]{1,190}\.[A-Za-z]{2,24}$")
_NAME_RE = re.compile(r"^[A-Za-z][A-Za-z' .\-]{0,63}$")

BLOCKED_CUSTOMER_ROLES = {"ACCOUNTADMIN", "SECURITYADMIN", "USERADMIN", "SYSADMIN",
                          "ORGADMIN", "GLOBALORGADMIN"}


class ValidationError(ValueError):
    pass


# ---------------------------------------------------------------- helpers
def ident(value: str) -> str:
    """Validate and double-quote an uppercase unquoted-style identifier."""
    v = (value or "").strip().upper()
    if not _IDENT_RE.match(v):
        raise ValidationError(f"invalid identifier: {value!r}")
    return f'"{v}"'


def qualified(value: str) -> str:
    v = (value or "").strip().upper()
    if not _QUALIFIED_RE.match(v):
        raise ValidationError(f"invalid qualified name: {value!r}")
    return ".".join(f'"{p}"' for p in v.split("."))


def lit(value: Optional[str], pattern: re.Pattern, label: str) -> str:
    if value is None or value == "":
        return "NULL"
    if not pattern.match(value):
        raise ValidationError(f"invalid {label}")
    return "'" + value.replace("\\", "\\\\").replace("'", "''") + "'"


def like_literal(value: str) -> str:
    """Escape LIKE wildcards for SHOW ... LIKE (exact filter done in Python)."""
    v = (value or "").strip().upper()
    if not _IDENT_RE.match(v):
        raise ValidationError("invalid identifier")
    return "'" + v.replace("_", "\\\\_") + "'"


# --------------------------------------------------------------- read-only
def preflight() -> str:
    return "SELECT CURRENT_ACCOUNT() AS ACCOUNT_LOCATOR, CURRENT_ROLE() AS ROLE, CURRENT_USER() AS USER_NAME, CURRENT_ACCOUNT_NAME() AS ACCOUNT_NAME"


def show_user(username: str) -> str:
    return f"SHOW USERS LIKE {like_literal(username)}"


def show_all_users() -> str:
    return "SHOW USERS"


def describe_user(username: str) -> str:
    return f"DESCRIBE USER {ident(username)}"


def show_grants_to_user(username: str) -> str:
    return f"SHOW GRANTS TO USER {ident(username)}"


def show_mfa_methods(username: str) -> str:
    return f"SHOW MFA METHODS FOR USER {ident(username)}"


def show_policy_on_user(username: str) -> str:
    u = (username or "").strip().upper()
    if not _IDENT_RE.match(u):
        raise ValidationError("invalid identifier")
    return ("SELECT POLICY_DB, POLICY_SCHEMA, POLICY_NAME, POLICY_KIND "
            "FROM TABLE(ADMIN_POLICIES.INFORMATION_SCHEMA.POLICY_REFERENCES("
            f"REF_ENTITY_NAME => '{u}', REF_ENTITY_DOMAIN => 'USER'))")


def show_auth_policy(policy_fqn: str) -> str:
    return f"DESCRIBE AUTHENTICATION POLICY {qualified(policy_fqn)}"


def show_grants_of_role(role: str) -> str:
    return f"SHOW GRANTS OF ROLE {ident(role)}"


# ---------------------------------------------------------------- mutations
def create_person_user_disabled(username: str, email: str, first: Optional[str],
                                last: Optional[str], comment: str) -> str:
    # No password is set centrally. User is created DISABLED.
    return (f"CREATE USER IF NOT EXISTS {ident(username)} TYPE = PERSON DISABLED = TRUE "
            f"EMAIL = {lit(email, _EMAIL_RE, 'email')} "
            f"FIRST_NAME = {lit(first, _NAME_RE, 'first name')} "
            f"LAST_NAME = {lit(last, _NAME_RE, 'last name')} "
            f"COMMENT = {lit(comment, re.compile(r'^[A-Za-z0-9 :._-]{0,200}$'), 'comment')}")


def set_auth_policy(username: str, policy_fqn: str) -> str:
    return f"ALTER USER {ident(username)} SET AUTHENTICATION POLICY {qualified(policy_fqn)} FORCE"


def grant_role(role: str, username: str, *, allow_privileged: bool = False) -> str:
    r = (role or "").strip().upper()
    if r in BLOCKED_CUSTOMER_ROLES and not (allow_privileged and r == "ACCOUNTADMIN"):
        raise ValidationError(f"role {r} is blocked")
    return f"GRANT ROLE {ident(r)} TO USER {ident(username)}"


def revoke_role(role: str, username: str) -> str:
    return f"REVOKE ROLE {ident(role)} FROM USER {ident(username)}"


def set_default_role(username: str, role: str) -> str:
    if role.strip().upper() == "ACCOUNTADMIN":
        raise ValidationError("ACCOUNTADMIN can never be a default role")
    return f"ALTER USER {ident(username)} SET DEFAULT_ROLE = {ident(role)}"


def set_disabled(username: str, disabled: bool) -> str:
    return f"ALTER USER {ident(username)} SET DISABLED = {'TRUE' if disabled else 'FALSE'}"


def reset_password(username: str) -> str:
    return f"ALTER USER {ident(username)} RESET PASSWORD"


def enroll_mfa(username: str) -> str:
    return f"ALTER USER {ident(username)} ENROLL MFA"
