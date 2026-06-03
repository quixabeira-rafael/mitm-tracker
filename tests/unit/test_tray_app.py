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


def test_set_accessory_activation_policy_calls_appkit(monkeypatch, fake_rumps) -> None:
    fake_appkit = MagicMock()
    fake_appkit.NSApplicationActivationPolicyAccessory = 1
    monkeypatch.setitem(sys.modules, "AppKit", fake_appkit)

    monkeypatch.delitem(sys.modules, "mitm_tracker.tray_app", raising=False)
    from mitm_tracker.tray_app import _set_accessory_activation_policy

    _set_accessory_activation_policy()

    fake_appkit.NSApplication.sharedApplication.return_value.setActivationPolicy_.assert_called_once_with(
        1
    )


def test_set_accessory_activation_policy_silent_when_appkit_missing(monkeypatch, fake_rumps) -> None:
    monkeypatch.setitem(sys.modules, "AppKit", None)

    monkeypatch.delitem(sys.modules, "mitm_tracker.tray_app", raising=False)
    from mitm_tracker.tray_app import _set_accessory_activation_policy

    _set_accessory_activation_policy()  # should not raise


def test_format_status_line_crashed_mentions_pid(tmp_path: Path, fake_rumps) -> None:
    from mitm_tracker.tray_app import Status, _format_status_line

    line = _format_status_line(Status.CRASHED, {"pid": 9999})

    assert "9999" in line
    assert "Crashed" in line


def test_format_status_line_shows_device_lan(tmp_path: Path, fake_rumps) -> None:
    from mitm_tracker.tray_app import Status, _format_status_line

    line = _format_status_line(
        Status.RUNNING,
        {"pid": 1234, "port": 8080, "listen_host": "0.0.0.0", "lan_ip": "192.168.1.7"},
    )

    assert "192.168.1.7" in line
    assert "8080" in line
    assert "device" in line.lower()


def test_device_help_url_only_for_lan_session(tmp_path: Path, fake_rumps) -> None:
    from mitm_tracker.tray_app import Status, _device_help_url

    lan_state = {
        "listen_host": "0.0.0.0",
        "lan_ip": "192.168.1.7",
        "help_port": 8888,
    }
    assert _device_help_url(Status.RUNNING, lan_state) == "http://192.168.1.7:8888/"
    assert _device_help_url(Status.STOPPED, lan_state) is None
    assert (
        _device_help_url(Status.RUNNING, {"listen_host": "127.0.0.1", "port": 8080})
        is None
    )


def test_warnings_submenu_lists_warnings_non_actionable(tmp_path: Path, monkeypatch) -> None:
    rumps = pytest.importorskip("rumps")
    monkeypatch.delitem(sys.modules, "mitm_tracker.tray_app", raising=False)
    import mitm_tracker.tray_app as tray_app
    from mitm_tracker import doctor

    fake_results = [
        doctor.CheckResult(name="Alpha", status=doctor.STATUS_OK, detail="fine"),
        doctor.CheckResult(name="Beta", status=doctor.STATUS_WARN, detail="be careful"),
        doctor.CheckResult(name="Gamma", status=doctor.STATUS_ERROR, detail="broken"),
    ]
    monkeypatch.setattr(tray_app.doctor, "run_all_checks", lambda: fake_results)

    ws = Workspace(root=tmp_path)
    ws.ensure()
    app = tray_app.TrayApp(ws)

    assert "(2)" in app._warnings_item.title
    children = list(app._warnings_item.values())
    titles = [c.title for c in children]
    assert any("Beta" in t for t in titles)
    assert any("be careful" in t for t in titles)
    assert any("Gamma" in t for t in titles)
    assert all(c._menuitem.action() is None for c in children)
    assert not any("Alpha" in t for t in titles)


def test_warnings_submenu_none_when_clean(tmp_path: Path, monkeypatch) -> None:
    rumps = pytest.importorskip("rumps")
    monkeypatch.delitem(sys.modules, "mitm_tracker.tray_app", raising=False)
    import mitm_tracker.tray_app as tray_app
    from mitm_tracker import doctor

    monkeypatch.setattr(
        tray_app.doctor,
        "run_all_checks",
        lambda: [doctor.CheckResult(name="Alpha", status=doctor.STATUS_OK, detail="fine")],
    )

    ws = Workspace(root=tmp_path)
    ws.ensure()
    app = tray_app.TrayApp(ws)

    assert "none" in app._warnings_item.title.lower()


def test_warnings_submenu_no_duplication_on_reopen(tmp_path: Path, monkeypatch) -> None:
    pytest.importorskip("rumps")
    monkeypatch.delitem(sys.modules, "mitm_tracker.tray_app", raising=False)
    import mitm_tracker.tray_app as tray_app
    from mitm_tracker import doctor

    monkeypatch.setattr(
        tray_app.doctor,
        "run_all_checks",
        lambda: [
            doctor.CheckResult(name="Beta", status=doctor.STATUS_WARN, detail="careful"),
            doctor.CheckResult(name="Gamma", status=doctor.STATUS_ERROR, detail="broken"),
        ],
    )

    ws = Workspace(root=tmp_path)
    ws.ensure()
    app = tray_app.TrayApp(ws)

    baseline = len(list(app._warnings_item.values()))
    assert baseline == 4
    for _ in range(5):
        app._render_warnings()
    assert len(list(app._warnings_item.values())) == baseline
    app._compute_warnings_snapshot()
    app._render_warnings()
    assert len(list(app._warnings_item.values())) == baseline
