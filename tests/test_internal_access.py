"""Tests for internal admin requests sourced from EIGHTY451 ACCOUNTADMIN holders. Run: python -m pytest tests -q"""
from __future__ import annotations

import sys
import types
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "python" / "app")]
sys.modules.setdefault("_snowflake", types.ModuleType("_snowflake"))

import app_commands as C  # noqa: E402

PEOPLE = {"J_ORTIZ": {"NAME": "J_ORTIZ", "EMAIL": "j@x.com", "FIRST_NAME": "J", "LAST_NAME": "O"}}


@pytest.fixture
def env(monkeypatch):
    log = {"sql": [], "ops": [], "require": []}

    def q(s, sql, p=None):
        if "UUID_STRING" in sql:
            return [{"U": f"id{len(log['sql'])}"}]
        if "GRANTS_TO_USERS" in sql:
            return [PEOPLE[p[0]]] if p[0] in PEOPLE else []
        return []

    monkeypatch.setattr(C, "q", q)
    monkeypatch.setattr(C, "x", lambda s, sql, p=None: log["sql"].append((sql, p)))
    monkeypatch.setattr(C, "account", lambda s, a: {"ACCOUNT_ID": a})
    monkeypatch.setattr(C, "require", lambda s, actor, acct, perm: log["require"].append((acct, perm)))
    monkeypatch.setattr(C, "new_op", lambda s, actor, acct, action, user, p, **k: log["ops"].append((acct["ACCOUNT_ID"], action, user)) or "op")
    return log


def args(**kw):
    a = {"usernames": ["j_ortiz"], "account_ids": ["A1", "A2"], "reason": "r", "expires_at": "2030-01-01"}
    a.update(kw)
    return a


def test_creates_access_and_ops_per_user_and_account(env):
    res = C.cmd_request_internal_access(None, "ALICE", args())
    assert len(res["access_ids"]) == 2
    assert env["ops"] == [("A1", "PROVISION_INTERNAL_ADMIN", "J_ORTIZ"), ("A1", "GRANT_ACCOUNTADMIN", "J_ORTIZ"),
                          ("A2", "PROVISION_INTERNAL_ADMIN", "J_ORTIZ"), ("A2", "GRANT_ACCOUNTADMIN", "J_ORTIZ")]
    assert ("A1", "operate") in env["require"] and ("A2", "operate") in env["require"]
    params = env["sql"][0][1]
    assert "J_ORTIZ" in params and "j@x.com" in params


def test_non_accountadmin_user_denied(env):
    with pytest.raises(C.Denied):
        C.cmd_request_internal_access(None, "ALICE", args(usernames=["NOBODY"]))
    assert env["sql"] == []


@pytest.mark.parametrize("bad", [dict(usernames=[]), dict(account_ids=[]), dict(reason=""), dict(expires_at="")])
def test_required_fields(env, bad):
    with pytest.raises(C.Denied):
        C.cmd_request_internal_access(None, "ALICE", args(**bad))
