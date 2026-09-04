from __future__ import annotations

import json
from pathlib import Path
from typing import Sequence

import pytest

from mitm_tracker import instance
from mitm_tracker import session_manager as session_module
from mitm_tracker import tray_launch_agent
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
    monkeypatch.setattr(instance, "pid_alive", lambda pid: True)

    captured_cmd: list[list[str]] = []

    def fake_spawn(cmd, **kwargs):
        captured_cmd.append(list(cmd))
        return FakeProcess(pid=4242)

    monkeypatch.setattr(record_module, "_spawn_default", fake_spawn)

    tray_spawns: list[list[str]] = []

    def fake_tray_spawn(cmd, **kwargs):
        tray_spawns.append(list(cmd))
        return FakeProcess(pid=4343)

    monkeypatch.setattr(record_module, "_spawn_tray", fake_tray_spawn)

    runner_calls: list[list[str]] = []

    def fake_runner(args: Sequence[str]):
        runner_calls.append(list(args))
        import subprocess

        if args[:2] == ["/usr/sbin/networksetup", "-listallnetworkservices"]:
            return subprocess.CompletedProcess(args=args, returncode=0, stdout="Header\nWi-Fi\n", stderr="")
        if args[:2] == ["/usr/sbin/networksetup", "-getwebproxy"]:
            return subprocess.CompletedProcess(
                args=args, returncode=0, stdout="Enabled: No\nServer: \nPort: 0\n", stderr=""
            )
        if args[:2] == ["/usr/sbin/networksetup", "-getsecurewebproxy"]:
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
        "tray_spawns": tray_spawns,
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


def test_start_without_delay_omits_addon_options(
    patched_environment, capsys, tmp_repo: Path
) -> None:
    rc = main(["record", "start", "--port", "8123", "--json"])
    out = json.loads(capsys.readouterr().out)
    assert rc == EXIT_OK
    assert out["delay_ms"] == 0
    assert out["delay_jitter_ms"] == 0
    joined = " ".join(patched_environment["captured_cmd"][-1])
    assert "tracker_delay_ms" not in joined


def test_start_with_delay_and_jitter_sets_addon_options(
    patched_environment, capsys, tmp_repo: Path
) -> None:
    rc = main(
        [
            "record",
            "start",
            "--port",
            "8123",
            "--delay",
            "1.5s",
            "--delay-jitter",
            "200ms",
            "--json",
        ]
    )
    out = json.loads(capsys.readouterr().out)
    assert rc == EXIT_OK
    assert out["delay_ms"] == 1500
    assert out["delay_jitter_ms"] == 200
    joined = " ".join(patched_environment["captured_cmd"][-1])
    assert "tracker_delay_ms=1500" in joined
    assert "tracker_delay_jitter_ms=200" in joined

    workspace = workspace_for(tmp_repo)
    state = json.loads(workspace.state_path.read_text())
    assert state["delay_ms"] == 1500
    assert state["delay_jitter_ms"] == 200


def test_start_rejects_invalid_delay(patched_environment, capsys, tmp_repo: Path) -> None:
    rc = main(["record", "start", "--delay", "later", "--json"])
    out = json.loads(capsys.readouterr().err)
    assert rc == EXIT_INVALID_STATE
    assert out["error"] == "invalid_delay"
    assert patched_environment["captured_cmd"] == []


def test_start_rejects_jitter_without_delay(
    patched_environment, capsys, tmp_repo: Path
) -> None:
    rc = main(["record", "start", "--delay-jitter", "200ms", "--json"])
    out = json.loads(capsys.readouterr().err)
    assert rc == EXIT_INVALID_STATE
    assert out["error"] == "invalid_delay"


def test_status_reports_the_session_delay(
    patched_environment, capsys, tmp_repo: Path
) -> None:
    main(["record", "start", "--delay", "800ms", "--delay-jitter", "200ms", "--json"])
    capsys.readouterr()

    rc = main(["record", "status", "--json"])
    out = json.loads(capsys.readouterr().out)
    assert rc == EXIT_OK
    assert out["delay_ms"] == 800
    assert out["delay_jitter_ms"] == 200


def test_status_text_shows_delay_window(
    patched_environment, capsys, tmp_repo: Path
) -> None:
    main(["record", "start", "--delay", "800ms", "--delay-jitter", "200ms"])
    capsys.readouterr()

    rc = main(["record", "status"])
    assert rc == EXIT_OK
    assert "delay: 800ms +/-200ms (600-1000ms)" in capsys.readouterr().out


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


def test_start_passes_impossible_regex_when_ssl_list_empty(
    patched_environment, capsys, tmp_repo: Path
) -> None:
    """Critical safety check: an empty SSL list must still pass --allow-hosts
    with a regex that matches nothing — otherwise mitmproxy decrypts every
    HTTPS connection by default and the macOS host (which doesn't trust the
    mitmproxy CA) loses internet access."""
    rc = main(["record", "start", "--json"])
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert rc == EXIT_OK
    assert payload["ssl_decryption_active"] is False
    assert payload["ssl_list_count"] == 0
    cmd = patched_environment["captured_cmd"][-1]
    # The exact impossible regex from ssl_list.py.
    assert "--allow-hosts" in cmd
    idx = cmd.index("--allow-hosts")
    assert cmd[idx + 1] == "(?!.*)"
    # And the warning is on stderr.
    assert "SSL list is empty" in captured.err


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


def test_build_mitmdump_command_wireguard_mode(tmp_path: Path) -> None:
    keyfile = tmp_path / "wireguard.conf"
    cmd = record_module._build_mitmdump_command(
        mitmdump_bin="/usr/bin/mitmdump",
        listen_host="0.0.0.0",
        listen_port=51820,
        db_path=tmp_path / "s.db",
        mode="all",
        allow_regex="^$",
        proxy_mode="wireguard",
        wireguard_keyfile=keyfile,
    )
    assert "--mode" in cmd
    assert f"wireguard:{keyfile}" in cmd
    # WireGuard mode must NOT pass --listen-host
    assert "--listen-host" not in cmd
    assert "--listen-port" in cmd and "51820" in cmd


def test_build_mitmdump_command_regular_mode_uses_listen_host(tmp_path: Path) -> None:
    cmd = record_module._build_mitmdump_command(
        mitmdump_bin="/usr/bin/mitmdump",
        listen_host="127.0.0.1",
        listen_port=8080,
        db_path=tmp_path / "s.db",
        mode="all",
        allow_regex="^$",
    )
    assert "--listen-host" in cmd
    assert "--mode" not in cmd


def test_build_mitmdump_command_wireguard_requires_keyfile(tmp_path: Path) -> None:
    with pytest.raises(record_module.ProxyLaunchError) as exc:
        record_module._build_mitmdump_command(
            mitmdump_bin="/usr/bin/mitmdump",
            listen_host="0.0.0.0",
            listen_port=51820,
            db_path=tmp_path / "s.db",
            mode="all",
            allow_regex="^$",
            proxy_mode="wireguard",
            wireguard_keyfile=None,
        )
    assert exc.value.error == "wireguard_keyfile_missing"


def test_stop_terminates_both_proxy_and_help_pids(tmp_repo: Path, monkeypatch, capsys) -> None:
    from mitm_tracker.session_manager import SessionManager

    workspace = workspace_for(tmp_repo)
    workspace.ensure()
    sm = SessionManager(workspace)
    sm.start(
        pid=1111,
        mode="all",
        port=51820,
        session_db=workspace.captures_dir / "s.db",
        proxy_service=None,
        listen_host="0.0.0.0",
        proxy_mode="wireguard",
    )
    sm.set_device_help(help_pid=2222, help_port=8888, lan_ip="192.168.1.44")

    killed: list[int] = []
    # Alive until the signal lands, then dead — so _terminate_pid signals once
    # and its wait loop exits immediately (no 5s SIGKILL fallback delay).
    monkeypatch.setattr(
        session_module,
        "_default_pid_alive",
        lambda pid: pid in (1111, 2222) and pid not in killed,
    )

    import argparse

    rc = record_module.cmd_stop(
        argparse.Namespace(json_mode=True), kill=lambda pid, sig: killed.append(pid)
    )
    capsys.readouterr()
    assert rc == EXIT_OK
    # Both the proxy pid and the help-server pid must receive a signal.
    assert 1111 in killed
    assert 2222 in killed


def test_start_registers_a_machine_wide_instance(
    patched_environment, capsys, tmp_repo: Path
) -> None:
    rc = main(["record", "start", "--port", "8123", "--json"])
    capsys.readouterr()
    assert rc == EXIT_OK

    current = instance.live(instance.KIND_PROXY, alive=lambda pid: True)
    assert current is not None
    assert current.pid == 4242
    assert current.port == 8123
    assert current.workspace == tmp_repo.resolve()


def test_start_refuses_when_another_workspace_owns_the_proxy(
    patched_environment, capsys, tmp_repo: Path
) -> None:
    other = tmp_repo / "other-project"
    other.mkdir()
    instance.acquire(
        instance.KIND_PROXY, pid=7777, workspace=other, port=8080, alive=lambda pid: True
    )

    rc = main(["record", "start", "--port", "8123", "--json"])
    err = capsys.readouterr().err
    assert rc == EXIT_INVALID_STATE
    assert "already_running" in err
    assert str(other) in err
    assert patched_environment["captured_cmd"] == []


def test_stop_releases_the_machine_wide_instance(
    patched_environment, capsys, tmp_repo: Path
) -> None:
    main(["record", "start", "--port", "8123", "--json"])
    capsys.readouterr()

    rc = main(["record", "stop", "--json"])
    capsys.readouterr()
    assert rc == EXIT_OK
    assert instance.live(instance.KIND_PROXY, alive=lambda pid: True) is None


def test_start_opens_the_tray(patched_environment, capsys, tmp_repo: Path) -> None:
    rc = main(["record", "start", "--port", "8123", "--json"])
    capsys.readouterr()
    assert rc == EXIT_OK
    assert patched_environment["tray_spawns"] == [
        [str(tray_launch_agent.resolve_binary()), "tray", "run"]
    ]


def test_start_skips_the_tray_with_no_tray(
    patched_environment, capsys, tmp_repo: Path
) -> None:
    rc = main(["record", "start", "--port", "8123", "--no-tray", "--json"])
    capsys.readouterr()
    assert rc == EXIT_OK
    assert patched_environment["tray_spawns"] == []


def test_start_does_not_open_a_second_tray(
    patched_environment, capsys, tmp_repo: Path
) -> None:
    instance.acquire(
        instance.KIND_TRAY, pid=8888, workspace=tmp_repo, alive=lambda pid: True
    )
    rc = main(["record", "start", "--port", "8123", "--json"])
    capsys.readouterr()
    assert rc == EXIT_OK
    assert patched_environment["tray_spawns"] == []
