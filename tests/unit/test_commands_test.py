from __future__ import annotations

import json
from pathlib import Path

import pytest

from mitm_tracker import testplan
from mitm_tracker.cli import main
from mitm_tracker.commands import record as record_module
from mitm_tracker.config import workspace_for
from mitm_tracker.output import EXIT_INVALID_STATE, EXIT_OK
from mitm_tracker.session_manager import SessionManager


@pytest.fixture
def running(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(SessionManager, "is_running", lambda self: True)


def _json_out(capsys: pytest.CaptureFixture) -> dict:
    return json.loads(capsys.readouterr().out.strip().splitlines()[-1])


def _setup_plan(capsys: pytest.CaptureFixture) -> None:
    assert main(["test", "new", "--test", "plan-a", "--title", "Plan A"]) == EXIT_OK
    assert main(["test", "new-case", "--test", "plan-a", "--test-case", "returns_201", "--description", "Returns 201"]) == EXIT_OK
    capsys.readouterr()


def test_new_list_and_show(tmp_repo: Path, capsys: pytest.CaptureFixture) -> None:
    _setup_plan(capsys)

    assert main(["test", "list", "--json"]) == EXIT_OK
    listed = _json_out(capsys)
    assert listed["count"] == 1
    assert listed["plans"][0]["title"] == "Plan A"
    assert listed["plans"][0]["cases"] == ["returns_201"]

    assert main(["test", "show", "--test", "plan-a", "--json"]) == EXIT_OK
    shown = _json_out(capsys)
    assert shown["cases"][0]["description"] == "Returns 201"
    assert shown["cases"][0]["hooks"] == ["on_request", "on_response"]


def test_apply_requires_running_proxy(tmp_repo: Path, capsys: pytest.CaptureFixture) -> None:
    _setup_plan(capsys)
    rc = main(["test", "apply", "--test", "plan-a", "--test-case", "returns_201"])
    assert rc == EXIT_INVALID_STATE
    assert "no running proxy session" in capsys.readouterr().err
    assert not workspace_for(tmp_repo).active_test_path.exists()


def test_apply_writes_active_and_status_reports_it(
    tmp_repo: Path, running: None, capsys: pytest.CaptureFixture
) -> None:
    _setup_plan(capsys)
    assert main(["test", "apply", "--test", "plan-a", "--test-case", "returns_201", "--json"]) == EXIT_OK
    payload = _json_out(capsys)
    assert payload["plan"] == "plan-a"
    assert payload["case"] == "returns_201"

    active = testplan.read_active(workspace_for(tmp_repo).active_test_path)
    assert active is not None and active.label == "plan-a/returns_201"

    assert main(["test", "status", "--json"]) == EXIT_OK
    assert _json_out(capsys)["active"]["case"] == "returns_201"

    assert main(["test", "clear", "--json"]) == EXIT_OK
    assert _json_out(capsys) == {"cleared": True}
    assert not workspace_for(tmp_repo).active_test_path.exists()


def test_apply_rejects_invalid_case_without_activating(
    tmp_repo: Path, running: None, capsys: pytest.CaptureFixture
) -> None:
    _setup_plan(capsys)
    rc = main(["test", "apply", "--test", "plan-a", "--test-case", "missing"])
    assert rc == EXIT_INVALID_STATE
    assert not workspace_for(tmp_repo).active_test_path.exists()


def test_state_show_and_clear(tmp_repo: Path, capsys: pytest.CaptureFixture) -> None:
    _setup_plan(capsys)
    state_path = testplan.PlanStore(workspace_for(tmp_repo).profile_dir("default")).state_path("plan-a")
    state_path.write_text(json.dumps({"calls": 3}), encoding="utf-8")

    assert main(["test", "state", "show", "--test", "plan-a", "--json"]) == EXIT_OK
    assert _json_out(capsys)["state"] == {"calls": 3}

    assert main(["test", "state", "clear", "--test", "plan-a"]) == EXIT_OK
    assert json.loads(state_path.read_text(encoding="utf-8")) == {}


def test_record_stop_clears_active_test(
    tmp_repo: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
) -> None:
    workspace = workspace_for(tmp_repo)
    workspace.ensure()
    sm = SessionManager(workspace)
    sm.write_state({"running": True, "pid": 0})
    workspace.active_test_path.write_text("{}", encoding="utf-8")

    assert main(["record", "stop", "--json"]) == EXIT_OK
    assert not workspace.active_test_path.exists()


def test_mitmdump_command_passes_active_test_path(tmp_path: Path) -> None:
    active = tmp_path / "active_test.json"
    cmd = record_module._build_mitmdump_command(
        mitmdump_bin="mitmdump",
        listen_host="127.0.0.1",
        listen_port=8080,
        db_path=tmp_path / "s.db",
        mode="all",
        allow_regex="^$",
        active_test_path=active,
    )
    assert f"tracker_active_test_path={active}" in cmd


def test_api_prints_reference(tmp_repo: Path, capsys: pytest.CaptureFixture) -> None:
    assert main(["test", "api"]) == EXIT_OK
    assert "TEST CASE SCRIPT API" in capsys.readouterr().out
    assert main(["test", "api", "--json"]) == EXIT_OK
    payload = _json_out(capsys)
    assert {h["signature"] for h in payload["hooks"]} == {
        "on_request(request)",
        "on_response(request, response)",
    }


def test_api_reference_matches_script_objects() -> None:
    from mitm_tracker.testcase_api import Request, Response, StateStore
    from mitm_tracker.testcase_reference import REFERENCE

    def names(section: str) -> set[str]:
        return {item["name"].split("(", 1)[0] for item in REFERENCE[section]}

    def public(cls) -> set[str]:
        return {name for name in vars(cls) if not name.startswith("_")}

    assert names("request") == public(Request)
    assert names("response") == public(Response)
    assert names("store") == public(StateStore) - {"path"}


def test_record_stop_survives_clear_active_failure(
    tmp_repo: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
) -> None:
    workspace = workspace_for(tmp_repo)
    workspace.ensure()
    SessionManager(workspace).write_state({"running": True, "pid": 0})

    def boom(path):
        raise PermissionError("denied")

    monkeypatch.setattr(testplan, "clear_active", boom)
    assert main(["record", "stop", "--json"]) == EXIT_OK
    assert "failed to clear the active test case" in capsys.readouterr().err
    assert SessionManager(workspace).read_state()["running"] is False


def test_record_start_aborts_before_system_proxy_when_clear_fails(
    tmp_repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from mitm_tracker.proxy_manager import ProxyManager

    touched: list[str] = []

    def boom(path):
        raise PermissionError("denied")

    monkeypatch.setattr(testplan, "clear_active", boom)
    monkeypatch.setattr(record_module, "_find_mitmdump", lambda: "/usr/bin/true")
    monkeypatch.setattr(ProxyManager, "get_active_service", lambda self: touched.append("proxy") or "Wi-Fi")

    with pytest.raises(record_module.ProxyLaunchError) as excinfo:
        record_module.launch_proxy(
            mode="all",
            port=18999,
            listen_host="127.0.0.1",
            keep_cache=False,
            configure_system_proxy=True,
            start_tray=False,
        )
    assert excinfo.value.error == "test_state_failed"
    assert touched == []
