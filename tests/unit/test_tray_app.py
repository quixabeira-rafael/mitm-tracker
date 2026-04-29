from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from mitm_tracker.config import Workspace
from mitm_tracker.session_manager import SessionManager


@pytest.fixture
def fake_rumps(monkeypatch):
    fake = MagicMock()
    fake.App = type("App", (), {"__init__": lambda self, *a, **kw: None, "run": lambda self: None})
    fake.MenuItem = MagicMock()
    fake.Timer = MagicMock()
    fake.alert = MagicMock()
    fake.quit_application = MagicMock()
    monkeypatch.setitem(sys.modules, "rumps", fake)
    monkeypatch.delitem(sys.modules, "mitm_tracker.tray_app", raising=False)
    yield fake


def _make_manager(tmp_path: Path, *, pid_alive=lambda pid: True) -> SessionManager:
    ws = Workspace(root=tmp_path)
    ws.ensure()
    return SessionManager(ws, pid_alive=pid_alive)


def test_compute_status_running(tmp_path: Path, fake_rumps) -> None:
    from mitm_tracker.tray_app import Status, compute_status

    sm = _make_manager(tmp_path, pid_alive=lambda _: True)
    sm.start(pid=1234, mode="all", port=8080, session_db=Path("x.db"), proxy_service=None)

    assert compute_status(sm) is Status.RUNNING


def test_compute_status_stopped(tmp_path: Path, fake_rumps) -> None:
    from mitm_tracker.tray_app import Status, compute_status

    sm = _make_manager(tmp_path)

    assert compute_status(sm) is Status.STOPPED


def test_compute_status_crashed(tmp_path: Path, fake_rumps) -> None:
    from mitm_tracker.tray_app import Status, compute_status

    sm = _make_manager(tmp_path, pid_alive=lambda _: False)
    sm.start(pid=1234, mode="all", port=8080, session_db=Path("x.db"), proxy_service=None)

    assert compute_status(sm) is Status.CRASHED


def test_invoke_cli_success_does_not_alert(tmp_path: Path, fake_rumps, monkeypatch) -> None:
    monkeypatch.setattr("shutil.which", lambda _name: "/usr/local/bin/mitm-tracker")
    runner = MagicMock(return_value=subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr=""))

    ws = Workspace(root=tmp_path)
    ws.ensure()

    from mitm_tracker.tray_app import TrayApp

    app = TrayApp.__new__(TrayApp)
    app._workspace = ws
    app._runner = runner

    app._invoke_cli(["record", "start", "--json"])

    runner.assert_called_once()
    fake_rumps.alert.assert_not_called()


def test_invoke_cli_failure_alerts_with_json_message(tmp_path: Path, fake_rumps, monkeypatch) -> None:
    monkeypatch.setattr("shutil.which", lambda _name: "/usr/local/bin/mitm-tracker")
    failing = subprocess.CompletedProcess(
        args=[],
        returncode=2,
        stdout="",
        stderr='{"error":"already_running","message":"a session is already running"}\n',
    )
    runner = MagicMock(return_value=failing)

    ws = Workspace(root=tmp_path)
    ws.ensure()

    from mitm_tracker.tray_app import TrayApp

    app = TrayApp.__new__(TrayApp)
    app._workspace = ws
    app._runner = runner

    app._invoke_cli(["record", "start", "--json"])

    fake_rumps.alert.assert_called_once_with("mitm-tracker", "a session is already running")


def test_invoke_cli_alerts_when_binary_missing(tmp_path: Path, fake_rumps, monkeypatch) -> None:
    monkeypatch.setattr("shutil.which", lambda _name: None)
    runner = MagicMock()

    ws = Workspace(root=tmp_path)
    ws.ensure()

    from mitm_tracker.tray_app import TrayApp

    app = TrayApp.__new__(TrayApp)
    app._workspace = ws
    app._runner = runner

    app._invoke_cli(["record", "stop", "--json"])

    runner.assert_not_called()
    fake_rumps.alert.assert_called_once()
    args, _ = fake_rumps.alert.call_args
    assert "binary not found" in args[1]


def test_on_quit_stops_record_when_running(tmp_path: Path, fake_rumps, monkeypatch) -> None:
    monkeypatch.setattr("shutil.which", lambda _name: "/usr/local/bin/mitm-tracker")
    runner = MagicMock(return_value=subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr=""))

    ws = Workspace(root=tmp_path)
    ws.ensure()

    from mitm_tracker.tray_app import TrayApp

    sm = _make_manager(tmp_path, pid_alive=lambda _: True)
    sm.start(pid=1234, mode="all", port=8080, session_db=Path("x.db"), proxy_service=None)

    app = TrayApp.__new__(TrayApp)
    app._workspace = ws
    app._runner = runner
    app._sessions = sm

    app._on_quit(None)

    runner.assert_called_once()
    args, _ = runner.call_args
    cmd, _cwd = args
    assert cmd[1:] == ["record", "stop", "--json"]
    fake_rumps.quit_application.assert_called_once()


def test_on_quit_stops_record_when_crashed(tmp_path: Path, fake_rumps, monkeypatch) -> None:
    monkeypatch.setattr("shutil.which", lambda _name: "/usr/local/bin/mitm-tracker")
    runner = MagicMock(return_value=subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr=""))

    ws = Workspace(root=tmp_path)
    ws.ensure()

    from mitm_tracker.tray_app import TrayApp

    sm = _make_manager(tmp_path, pid_alive=lambda _: False)
    sm.start(pid=1234, mode="all", port=8080, session_db=Path("x.db"), proxy_service=None)

    app = TrayApp.__new__(TrayApp)
    app._workspace = ws
    app._runner = runner
    app._sessions = sm

    app._on_quit(None)

    runner.assert_called_once()
    fake_rumps.quit_application.assert_called_once()


def test_on_quit_skips_stop_when_already_stopped(tmp_path: Path, fake_rumps, monkeypatch) -> None:
    monkeypatch.setattr("shutil.which", lambda _name: "/usr/local/bin/mitm-tracker")
    runner = MagicMock()

    ws = Workspace(root=tmp_path)
    ws.ensure()

    from mitm_tracker.tray_app import TrayApp

    sm = _make_manager(tmp_path)

    app = TrayApp.__new__(TrayApp)
    app._workspace = ws
    app._runner = runner
    app._sessions = sm

    app._on_quit(None)

    runner.assert_not_called()
    fake_rumps.quit_application.assert_called_once()


def test_format_status_line_includes_pid_and_port(tmp_path: Path, fake_rumps) -> None:
    from mitm_tracker.tray_app import Status, _format_status_line

    line = _format_status_line(Status.RUNNING, {"pid": 1234, "port": 8080})

    assert "1234" in line
    assert "8080" in line
    assert "Running" in line


def test_format_status_line_crashed_mentions_pid(tmp_path: Path, fake_rumps) -> None:
    from mitm_tracker.tray_app import Status, _format_status_line

    line = _format_status_line(Status.CRASHED, {"pid": 9999})

    assert "9999" in line
    assert "Crashed" in line
