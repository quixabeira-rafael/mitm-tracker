from __future__ import annotations

import json
from pathlib import Path

import pytest

from mitm_tracker.config import Workspace
from mitm_tracker.session_manager import SessionManager, SessionManagerError


def _make_manager(tmp_path: Path, *, pid_alive=lambda pid: True) -> SessionManager:
    ws = Workspace(root=tmp_path)
    ws.ensure()
    return SessionManager(ws, pid_alive=pid_alive, clock=lambda: "2026-04-28T14:30:22+00:00")


def test_is_running_false_when_no_state(tmp_path: Path) -> None:
    sm = _make_manager(tmp_path)
    assert sm.is_running() is False


def test_start_writes_state_and_marks_running(tmp_path: Path) -> None:
    sm = _make_manager(tmp_path)
    state = sm.start(
        pid=1234,
        mode="all",
        port=8080,
        session_db=Path(".mitm-tracker/captures/x.db"),
        proxy_service="Wi-Fi",
    )
    assert state["running"] is True
    assert state["pid"] == 1234
    assert state["session_db"].endswith("x.db")
    assert state["active_session"] == state["session_db"]

    saved = json.loads(sm.workspace.state_path.read_text())
    assert saved["pid"] == 1234


def test_is_running_uses_pid_alive(tmp_path: Path) -> None:
    sm = _make_manager(tmp_path, pid_alive=lambda pid: pid == 9999)
    sm.start(
        pid=9999,
        mode="all",
        port=8080,
        session_db=Path("x.db"),
        proxy_service="Wi-Fi",
    )
    assert sm.is_running() is True

    sm = _make_manager(tmp_path, pid_alive=lambda pid: False)
    assert sm.is_running() is False
    assert sm.detect_crashed() is True


def test_stop_clears_running_flag_and_pid(tmp_path: Path) -> None:
    sm = _make_manager(tmp_path)
    sm.start(
        pid=1234,
        mode="all",
        port=8080,
        session_db=Path("x.db"),
        proxy_service="Wi-Fi",
    )
    state = sm.stop()
    assert state["running"] is False
    assert state["pid"] is None
    assert "stopped_at" in state


def test_set_and_get_active_session(tmp_path: Path) -> None:
    sm = _make_manager(tmp_path)
    sm.start(
        pid=1,
        mode="all",
        port=8080,
        session_db=Path("first.db"),
        proxy_service=None,
    )
    sm.set_active_session(Path("second.db"))
    active = sm.active_session_db()
    assert active is not None
    assert active.name == "second.db"


def test_list_sessions_returns_db_files_sorted_desc(tmp_path: Path) -> None:
    ws = Workspace(root=tmp_path)
    ws.ensure()
    (ws.captures_dir / "2026-01-01.db").touch()
    (ws.captures_dir / "2026-04-28.db").touch()
    sm = SessionManager(ws)
    sessions = sm.list_sessions()
    assert [p.name for p in sessions] == ["2026-04-28.db", "2026-01-01.db"]


def test_pid_round_trip(tmp_path: Path) -> None:
    sm = _make_manager(tmp_path)
    sm.write_pid(4242)
    assert sm.read_pid() == 4242
    sm.clear_pid()
    assert sm.read_pid() is None


def test_start_preserves_active_profile_and_other_keys(tmp_path: Path) -> None:
    sm = _make_manager(tmp_path)
    sm.write_state({"active_profile": "sun-ios", "custom": "kept"})
    sm.start(
        pid=1,
        mode="all",
        port=8080,
        session_db=Path("x.db"),
        proxy_service=None,
    )
    state = sm.read_state()
    assert state["active_profile"] == "sun-ios"
    assert state["custom"] == "kept"
    assert state["running"] is True


def test_corrupt_state_raises(tmp_path: Path) -> None:
    sm = _make_manager(tmp_path)
    sm.workspace.state_path.write_text("{not json")
    with pytest.raises(SessionManagerError):
        sm.read_state()


def test_read_pid_returns_none_when_unparseable(tmp_path: Path) -> None:
    sm = _make_manager(tmp_path)
    sm.workspace.pid_path.write_text("not a number")
    assert sm.read_pid() is None
