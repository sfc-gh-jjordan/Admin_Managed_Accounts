"""Tests for CSV-driven role creation. Run: python -m pytest tests -q"""
from __future__ import annotations

import json
import sys
import types
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "streamlit"), str(ROOT / "python" / "app"), str(ROOT / "python" / "worker")]
sys.modules.setdefault("_snowflake", types.ModuleType("_snowflake"))

from lib import csv_validation as cv  # noqa: E402
import app_commands as C  # noqa: E402
import actions as A  # noqa: E402
import worker as W  # noqa: E402

TEST_CSV = ROOT / "test_data" / "jjaws_demo999_onboard_test.csv"


def validate(rows, **kw):
    args = dict(allowed_roles={"CPG_ANALYST": True, "NOT_DEFAULT": False}, blocked_roles=["ACCOUNTADMIN"],
                email_domains=[], protected_users=[], existing_users={})
    args.update(kw)
    return cv.validate(rows, **args)


def row(role="NEW_ROLE", default="NEW_ROLE", user="TEST_USER_001", n=2):
    return {"row_number": n, "username": user, "email": "a@b.com", "first_name": "A", "last_name": "B",
            "role_name": role, "default_role": default, "action": "ONBOARD"}


# ------------------------------------------------------------------ validator
def test_test_csv_now_valid_and_creates_role():
    res = validate(cv.parse(TEST_CSV.read_bytes()))
    assert res[0]["is_valid"], res[0]["findings"]
    assert res[0]["creates_role"]
    assert cv.new_roles(res) == ["DEMO_ANALYST_ROLE"]


def test_catalog_role_not_new():
    res = validate([row("CPG_ANALYST", "CPG_ANALYST")])
    assert res[0]["is_valid"] and not res[0]["creates_role"]


@pytest.mark.parametrize("role", ["ACCOUNTADMIN", "SECURITYADMIN", "SYSADMIN", "PUBLIC"])
def test_blocked_and_system_roles_rejected(role):
    res = validate([row(role, "")])
    assert not res[0]["is_valid"] and not res[0]["creates_role"]


def test_disabled_catalog_role_not_recreated():
    res = validate([row("OLD_ROLE", "")], disabled_roles=["OLD_ROLE"])
    assert not res[0]["is_valid"]
    assert any("disabled or blocked" in f for f in res[0]["findings"])


def test_allow_new_roles_off_keeps_old_behavior():
    res = validate([row()], allow_new_roles=False)
    assert "role_name: not in this account's role catalog" in res[0]["findings"]
    assert "default_role: not allowed" in res[0]["findings"]


def test_existing_non_default_eligible_still_enforced():
    res = validate([row("NOT_DEFAULT", "NOT_DEFAULT")])
    assert "default_role: not default-eligible" in res[0]["findings"]


def test_new_role_cap():
    rows = [row(f"R{i}", "", user=f"USER_{i:02d}", n=i + 2) for i in range(12)]
    res = validate(rows, max_new_roles=10)
    assert sum(r["is_valid"] for r in res) == 10
    assert len(cv.new_roles(res)) == 10


def test_new_roles_ignores_excluded_rows():
    res = validate([row("R_A", "", n=2), row("R_B", "", user="OTHER_USER", n=3)])
    assert cv.new_roles(res, excluded_rows=[3]) == ["R_A"]


# ------------------------------------------------------------------ commands
class FakeQ:
    def __init__(self, blocked=(), catalog=()):
        self.blocked, self.catalog = list(blocked), list(catalog)

    def __call__(self, s, sql, p=None):
        if "BLOCKED_ROLES" in sql:
            return [{"ROLE_NAME": b} for b in self.blocked]
        if "ROLE_CATALOG" in sql:
            return self.catalog
        raise AssertionError(sql)


def _rows(*roles):
    return [{"row_number": i + 2, "role_name": r, "default_role": r, "is_valid": True} for i, r in enumerate(roles)]


def test_check_roles_accepts_new_and_catalog(monkeypatch):
    monkeypatch.setattr(C, "q", FakeQ(catalog=[{"ROLE_NAME": "CPG_ANALYST", "IS_ACTIVE": True,
                                               "APPROVAL_CLASS": "STANDARD"}]))
    assert C.check_roles(None, "A1", _rows("CPG_ANALYST", "NEW_ONE"), ["new_one"]) == ["NEW_ONE"]


def test_check_roles_rejects_unlisted_role(monkeypatch):
    monkeypatch.setattr(C, "q", FakeQ())
    with pytest.raises(C.Denied, match="not in the role catalog"):
        C.check_roles(None, "A1", _rows("SNEAKY"), [])


@pytest.mark.parametrize("name", ["SYSADMIN", "BAD-NAME", "CUSTOM_BLOCKED"])
def test_check_roles_rejects_bad_new_role(monkeypatch, name):
    monkeypatch.setattr(C, "q", FakeQ(blocked=["CUSTOM_BLOCKED"]))
    with pytest.raises(C.Denied, match="cannot be created"):
        C.check_roles(None, "A1", [], [name])


def test_check_roles_rejects_catalogued_new_role(monkeypatch):
    monkeypatch.setattr(C, "q", FakeQ(catalog=[{"ROLE_NAME": "OLD", "IS_ACTIVE": False, "APPROVAL_CLASS": "STANDARD"}]))
    with pytest.raises(C.Denied, match="already has a catalog entry"):
        C.check_roles(None, "A1", _rows("OLD"), ["OLD"])


def test_check_roles_cap(monkeypatch):
    monkeypatch.setattr(C, "q", FakeQ())
    with pytest.raises(C.Denied, match="more than"):
        C.check_roles(None, "A1", [], [f"R{i}" for i in range(11)])


# ------------------------------------------------------------------ actions
def test_create_role_sql():
    assert A.create_role("demo_role", "managed by x").startswith('CREATE ROLE IF NOT EXISTS "DEMO_ROLE" COMMENT = ')
    assert A.grant_role_to_parent("DEMO_ROLE", "SYSADMIN") == 'GRANT ROLE "DEMO_ROLE" TO ROLE "SYSADMIN"'


@pytest.mark.parametrize("bad", ["ACCOUNTADMIN", "PUBLIC", 'X"; DROP', ""])
def test_create_role_rejects(bad):
    with pytest.raises(A.ValidationError):
        A.create_role(bad, "c")


def test_parent_must_be_sysadmin():
    with pytest.raises(A.ValidationError):
        A.grant_role_to_parent("DEMO_ROLE", "ACCOUNTADMIN")


# ------------------------------------------------------------------ worker
@pytest.mark.parametrize("statuses,expected", [
    ([], "READY"), (["SUCCEEDED"], "READY"), (["QUEUED"], "WAIT"), (["PENDING_APPROVAL"], "WAIT"),
    (["SUCCEEDED", "FAILED"], "DEAD"), (["CANCELLED"], "DEAD"), (None, "DEAD"),
])
def test_dependency_state(monkeypatch, statuses, expected):
    deps = ["d1"] if statuses is None else [f"d{i}" for i in range(len(statuses))]
    monkeypatch.setattr(W, "q", lambda s, sql, p=None: [] if statuses is None else [{"STATUS": x} for x in statuses])
    assert W.dependency_state(None, {"DEPENDS_ON": json.dumps(deps)}) == expected


class FakeRunner:
    def __init__(self, exists_seq):
        self.exists_seq, self.ran = list(exists_seq), []

    def run(self, name, stmt, **kw):
        self.ran.append(name)
        if name == "SHOW_ROLE":
            found = self.exists_seq.pop(0)
            return types.SimpleNamespace(as_dicts=lambda: [{"name": "DEMO_ANALYST_ROLE"}] if found else [])
        return types.SimpleNamespace()


def _worker_env(monkeypatch, catalog=()):
    writes = []
    monkeypatch.setattr(W, "q", lambda s, sql, p=None: list(catalog) if "IS_ACTIVE" in sql else [{"V": 3}])
    monkeypatch.setattr(W, "x", lambda s, sql, p=None: writes.append((sql, p)))
    monkeypatch.setattr(W, "audit", lambda *a, **k: None)
    return writes


ACCT = {"ACCOUNT_ID": "JJAWS_DEMO999", "EXEC_ROLE": "ACCOUNTADMIN"}
OP = {"OPERATION_ID": "op-12345678", "BATCH_ID": "b1", "REQUESTED_BY": "ALICE", "APPROVED_BY": "BOB"}
P = {"role_name": "DEMO_ANALYST_ROLE", "parent_role": "SYSADMIN", "batch_id": "b1"}


def test_create_role_handler_creates_and_catalogs(monkeypatch):
    writes = _worker_env(monkeypatch)
    r = FakeRunner([False, True])
    res = W.h_create_role(None, r, ACCT, OP, P)
    assert r.ran == ["SHOW_ROLE", "CREATE_ROLE", "GRANT_ROLE_TO_PARENT", "SHOW_ROLE"]
    assert res == {"role": "DEMO_ANALYST_ROLE", "created": True, "catalog_version": 4}
    merge = next(p for sql, p in writes if "MERGE INTO" in sql)
    assert merge[1] == "DEMO_ANALYST_ROLE" and merge[-1] == 4
    rebind = next(p for sql, p in writes if "UPDATE" in sql and "OPERATIONS" in sql)
    assert rebind == [4, "b1", 3]


def test_create_role_handler_adopts_existing(monkeypatch):
    _worker_env(monkeypatch)
    r = FakeRunner([True])
    res = W.h_create_role(None, r, ACCT, OP, P)
    assert r.ran == ["SHOW_ROLE"] and res["created"] is False


def test_create_role_handler_requires_accountadmin(monkeypatch):
    _worker_env(monkeypatch)
    with pytest.raises(W.Blocked, match="ACCOUNTADMIN"):
        W.h_create_role(None, FakeRunner([]), dict(ACCT, EXEC_ROLE="ACCT_USER_ADMIN"), OP, P)


def test_create_role_handler_respects_disabled_catalog(monkeypatch):
    _worker_env(monkeypatch, catalog=[{"IS_ACTIVE": False, "APPROVAL_CLASS": "STANDARD"}])
    with pytest.raises(W.Blocked, match="disabled"):
        W.h_create_role(None, FakeRunner([]), ACCT, OP, P)
