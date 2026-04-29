from __future__ import annotations

import json
from pathlib import Path
from typing import Sequence

import pytest

from mitm_tracker import session_manager as session_module
from mitm_tracker.cli import main
from mitm_tracker.commands import record as record_module
from mitm_tracker.config import workspace_for
from mitm_tracker.output import (
    EXIT_INVALID_STATE,
    EXIT_OK,
    EXIT_SYSTEM,
)
from mitm_tracker.proxy_manager import ProxyManager, ProxyState


class FakeProcess:
    def __init__(self, pid: int = 5555) -> None:
        self.pid = pid


@pytest.fixture
def patched_environment(tmp_repo: Path, monkeypatch):
    monkeypatch.setattr(record_module, "_find_mitmdump", lambda: "/usr/bin/mitmdump")
    monkeypatch.setattr(session_module, "_default_pid_alive", lambda pid: True)

    captured_cmd: list[list[str]] = []

    def fake_spawn(cmd, **kwargs):
        captured_cmd.append(list(cmd))
        return FakeProcess(pid=4242)

    monkeypatch.setattr(record_module, "_spawn_default", fake_spawn)

    runner_calls: list[list[str]] = []

    def fake_runner(args: Sequence[str]):
        runner_calls.append(list(args))
        import subprocess

        if args[:2] == ["networksetup", "-listallnetworkservices"]:
            return subprocess.CompletedProcess(args=args, returncode=0, stdout="Header\nWi-Fi\n", stderr="")
        if args[:2] == ["networksetup", "-getwebproxy"]:
            return subprocess.CompletedProcess(
                args=args, returncode=0, stdout="Enabled: No\nServer: \nPort: 0\n", stderr=""
            )
        if args[:2] == ["networksetup", "-getsecurewebproxy"]:
            return subprocess.CompletedProcess(
                args=args, returncode=0, stdout="Enabled: No\nServer: \nPort: 0\n", stderr=""
            )
        return subprocess.CompletedProcess(args=args, returncode=0, stdout="", stderr="")

    privileged_invocations: list[tuple[list[list[str]], str]] = []

    def fake_privileged(commands, prompt):
        import subprocess

        privileged_invocations.append(([list(c) for c in commands], prompt))
        return subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")

    original_init = ProxyManager.__init__

    def patched_init(self, *_a, **_kw):
        original_init(self, runner=fake_runner, privileged_runner=fake_privileged)

    monkeypatch.setattr(ProxyManager, "__init__", patched_init)

    return {
        "captured_cmd": captured_cmd,
        "runner_calls": runner_calls,
        "privileged_invocations": privileged_invocations,
        "tmp_repo": tmp_repo,
    }


def test_start_creates_session_and_writes_state(
    patched_environment, capsys, tmp_repo: Path
) -> None:
    rc = main(["record", "start", "--mode", "all", "--port", "8123", "--json"])
    out = json.loads(capsys.readouterr().out)
    assert rc == EXIT_OK
    assert out["started"] is True
    assert out["pid"] == 4242
    assert out["port"] == 8123
    assert out["mode"] == "all"
    assert out["session_db"].endswith(".db")

    workspace = workspace_for(tmp_repo)
    state_path = workspace.state_path
    assert state_path.exists()
    state = json.loads(state_path.read_text())
    assert state["running"] is True
    assert state["pid"] == 4242

    cmd = patched_environment["captured_cmd"][0]
    assert cmd[0] == "/usr/bin/mitmdump"
    joined = " ".join(cmd)
    assert "tracker_db_path=" in joined
    assert "tracker_mode=all" in joined
    assert "tracker_no_cache=true" in joined
    assert out["no_cache"] is True


def test_keep_cache_disables_no_cache(patched_environment, capsys, tmp_repo: Path) -> None:
    rc = main(["record", "start", "--keep-cache", "--port", "8123", "--json"])
    out = json.loads(capsys.readouterr().out)
    assert rc == EXIT_OK
    assert out["no_cache"] is False
    cmd = patched_environment["captured_cmd"][-1]
    joined = " ".join(cmd)
    assert "tracker_no_cache=false" in joined


def test_start_idempotent_when_already_running(
    patched_environment, capsys, tmp_repo: Path
) -> None:
    main(["record", "start", "--json"])
    capsys.readouterr()
    rc = main(["record", "start", "--json"])
    out = json.loads(capsys.readouterr().out)
    assert rc == EXIT_OK
    assert out.get("already_running") is True


def test_start_fails_when_mitmdump_missing(monkeypatch, tmp_repo: Path, capsys) -> None:
    monkeypatch.setattr(record_module, "_find_mitmdump", lambda: None)
    rc = main(["record", "start", "--json", "--no-system-proxy"])
    err = capsys.readouterr().err
    assert rc == EXIT_SYSTEM
    payload = json.loads(err)
    assert payload["error"] == "mitmproxy_missing"


def test_start_includes_ignore_hosts_when_ssl_list_present(
    patched_environment, capsys, tmp_repo: Path
) -> None:
    main(["ssl", "add", "api.example.com"])
    capsys.readouterr()
    rc = main(["record", "start", "--json", "--no-system-proxy"])
    capsys.readouterr()
    assert rc == EXIT_OK
    cmd = patched_environment["captured_cmd"][-1]
    joined = " ".join(cmd)
    assert "--allow-hosts" in joined


def test_status_reflects_running_state(patched_environment, capsys, tmp_repo: Path) -> None:
    main(["record", "start", "--json"])
    capsys.readouterr()
    rc = main(["record", "status", "--json"])
    out = json.loads(capsys.readouterr().out)
    assert rc == EXIT_OK
    assert out["pid"] == 4242
    assert out["running"] is True


def test_stop_without_active_session_returns_invalid_state(tmp_repo: Path, capsys) -> None:
    rc = main(["record", "stop", "--json"])
    err = capsys.readouterr().err
    assert rc == EXIT_INVALID_STATE
    payload = json.loads(err)
    assert payload["error"] == "not_running"


def test_stop_marks_state_stopped(
    patched_environment, monkeypatch, capsys, tmp_repo: Path
) -> None:
    main(["record", "start", "--json"])
    capsys.readouterr()

    monkeypatch.setattr(record_module.os, "kill", lambda pid, sig: None)
    monkeypatch.setattr(session_module, "_default_pid_alive", lambda pid: False)

    rc = main(["record", "stop", "--json"])
    out = json.loads(capsys.readouterr().out)
    assert rc == EXIT_OK
    assert out["stopped"] is True

    workspace = workspace_for(tmp_repo)
    state = json.loads(workspace.state_path.read_text())
    assert state["running"] is False
    assert state["pid"] is None


def test_stop_returns_error_when_proxy_restore_fails(
    patched_environment, monkeypatch, capsys, tmp_repo: Path
) -> None:
    main(["record", "start", "--json"])
    capsys.readouterr()

    monkeypatch.setattr(record_module.os, "kill", lambda pid, sig: None)
    monkeypatch.setattr(session_module, "_default_pid_alive", lambda pid: False)

    # Re-patch ProxyManager so the privileged restore returns non-zero,
    # simulating the silent failure observed in the field (sudo/Touch ID/
    # networksetup combination returning an error).
    from mitm_tracker.proxy_manager import ProxyManager

    def failing_privileged(commands, prompt):
        import subprocess

        return subprocess.CompletedProcess(
            args=[], returncode=1, stdout="", stderr="sudo: a password is required"
        )

    def patched_init(self, *_a, **_kw):
        self._runner = lambda args: subprocess.CompletedProcess(args=args, returncode=0, stdout="", stderr="")
        self._privileged_runner = failing_privileged

    monkeypatch.setattr(ProxyManager, "__init__", patched_init)

    rc = main(["record", "stop", "--json"])
    captured = capsys.readouterr()
    out = json.loads(captured.out)

    assert rc != EXIT_OK
    # Daemon shutdown still happened: state moved to stopped, payload has stopped=true.
    assert out["stopped"] is True
    assert out["proxy_restored"] is False
    assert out["proxy_error"]
    # Error surfaced on stderr in JSON form so the tray can show a rumps.alert.
    json_lines = [
        json.loads(line)
        for line in captured.err.splitlines()
        if line.strip().startswith("{")
    ]
    assert any(payload.get("error") == "proxy_restore_failed" for payload in json_lines)
    # Backup file is preserved so a follow-up restore attempt can read it.
    workspace = workspace_for(tmp_repo)
    assert workspace.proxy_backup_path.exists()


def test_logs_returns_no_logs_message_when_missing(tmp_repo: Path, capsys) -> None:
    rc = main(["record", "logs"])
    out = capsys.readouterr().out
    assert rc == EXIT_OK
    assert "no logs" in out


def test_logs_tails_existing_file(patched_environment, capsys, tmp_repo: Path) -> None:
    workspace = workspace_for(tmp_repo)
    workspace.runtime_dir.mkdir(parents=True, exist_ok=True)
    workspace.log_path.write_text("line1\nline2\nline3\nline4\n")
    rc = main(["record", "logs", "--tail", "2"])
    out = capsys.readouterr().out
    assert rc == EXIT_OK
    assert "line3" in out
    assert "line4" in out
    assert "line1" not in out
