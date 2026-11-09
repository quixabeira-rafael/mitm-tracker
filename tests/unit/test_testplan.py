from __future__ import annotations

import json
from pathlib import Path

import pytest

from mitm_tracker import testplan
from mitm_tracker.testplan import ActiveTest, PlanStore, TestPlanError


@pytest.fixture
def store(tmp_path: Path) -> PlanStore:
    return PlanStore(tmp_path / "profile")


def _write_case(store: PlanStore, plan: str, case: str, source: str) -> Path:
    path = store.case_path(plan, case)
    path.write_text(source, encoding="utf-8")
    return path


def test_create_plan_writes_metadata(store: PlanStore) -> None:
    plan = store.create_plan("checkout", title="Checkout", description="Payment flows")
    data = json.loads(store.plan_path("checkout").read_text(encoding="utf-8"))
    assert data == {"title": "Checkout", "description": "Payment flows"}
    assert plan.name == "checkout"
    assert plan.cases == []


def test_create_plan_rejects_duplicates_and_bad_names(store: PlanStore) -> None:
    store.create_plan("checkout")
    with pytest.raises(TestPlanError, match="already exists"):
        store.create_plan("checkout")
    with pytest.raises(TestPlanError, match="invalid test plan name"):
        store.create_plan("../escape")


def test_create_case_uses_template_and_lists_it(store: PlanStore) -> None:
    store.create_plan("checkout")
    case = store.create_case("checkout", "returns_400", description="Cart returns 400")
    assert case.description == "Cart returns 400"
    assert case.hooks == ["on_request", "on_response"]
    assert case.claims == []
    assert store.load_plan("checkout").cases == ["returns_400"]


def test_create_case_requires_existing_plan(store: PlanStore) -> None:
    with pytest.raises(TestPlanError, match="not found"):
        store.create_case("missing", "case")


def test_list_plans_skips_directories_without_plan_json(store: PlanStore) -> None:
    store.create_plan("a")
    store.create_plan("b")
    (store.tests_dir / "stray").mkdir()
    assert [p.name for p in store.list_plans()] == ["a", "b"]


def test_inspect_case_reads_docstring_hooks_and_claims(store: PlanStore) -> None:
    store.create_plan("p")
    _write_case(
        store,
        "p",
        "c",
        '"""Docs here."""\nCLAIMS = ["https://api.example.com/users/**"]\n\n'
        "def on_response(request, response):\n    pass\n",
    )
    info = store.inspect_case("p", "c")
    assert info.description == "Docs here."
    assert info.hooks == ["on_response"]
    assert info.claims == ["https://api.example.com/users/**"]


@pytest.mark.parametrize(
    "source,message",
    [
        ("def on_request(request)\n    pass\n", "does not compile"),
        ("def helper():\n    pass\n", "must define on_request"),
        ("async def on_request(request):\n    pass\n", "plain def"),
        ('CLAIMS = ["no-scheme"]\ndef on_request(request):\n    pass\n', "invalid CLAIMS"),
        ('CLAIMS = ["https://h:*/x"]\ndef on_request(request):\n    pass\n', "invalid CLAIMS"),
        ("CLAIMS = build()\ndef on_request(request):\n    pass\n", "literal list"),
        ("CLAIMS = [1]\ndef on_request(request):\n    pass\n", "pattern strings"),
    ],
)
def test_inspect_case_rejects_invalid_scripts(store: PlanStore, source: str, message: str) -> None:
    store.create_plan("p")
    _write_case(store, "p", "c", source)
    with pytest.raises(TestPlanError, match=message):
        store.inspect_case("p", "c")


def test_active_roundtrip_and_clear_removes_error(tmp_path: Path) -> None:
    path = tmp_path / "runtime" / "active_test.json"
    active = ActiveTest(
        profile="default",
        plan="p",
        case="c",
        script_path="/x/c.py",
        state_path="/x/state.json",
        applied_at="2026-01-01T00:00:00+00:00",
    )
    testplan.write_active(path, active)
    testplan.record_error(path, {"hook": "on_request", "error": "boom"})

    assert testplan.read_active(path) == active
    assert testplan.read_error(path)["error"] == "boom"

    assert testplan.clear_active(path) is True
    assert testplan.read_active(path) is None
    assert testplan.read_error(path) is None
    assert testplan.clear_active(path) is False


def test_read_active_ignores_corrupt_file(tmp_path: Path) -> None:
    path = tmp_path / "active_test.json"
    path.write_text("{not json", encoding="utf-8")
    assert testplan.read_active(path) is None


def test_list_plans_reports_broken_plan_without_failing(store: PlanStore) -> None:
    store.create_plan("good")
    store.create_plan("broken")
    store.plan_path("broken").write_text("{not json", encoding="utf-8")
    plans = {p.name: p for p in store.list_plans()}
    assert plans["good"].error is None
    assert "invalid JSON" in plans["broken"].error
    assert plans["broken"].to_dict()["error"]


def test_non_utf8_files_raise_test_plan_error(store: PlanStore) -> None:
    store.create_plan("p")
    store.plan_path("p").write_bytes(b"\xff\xfe")
    with pytest.raises(TestPlanError, match="invalid JSON"):
        store.load_plan("p")
    store.case_path("p", "c").write_bytes(b"\xff\xfe")
    with pytest.raises(TestPlanError, match="not valid UTF-8"):
        testplan.inspect_case_source("c", store.case_path("p", "c"))
