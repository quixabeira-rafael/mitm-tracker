from __future__ import annotations

import argparse
import json
from pathlib import Path
from unittest.mock import patch

import pytest

from mitm_tracker import auth_setup, tray_launch_agent
from mitm_tracker.commands import setup as setup_commands
from mitm_tracker.output import EXIT_INVALID_STATE, EXIT_OK


def _install_args(
    *,
    workspace: str | None = None,
    skip_touch_id: bool = False,
    skip_sudo_cache: bool = False,
    skip_tray: bool = False,
    skip_skill: bool = True,  # default in tests: don't try to install the Claude skill
    with_skill: bool = False,
    json_mode: bool = True,
) -> argparse.Namespace:
    return argparse.Namespace(
        workspace=workspace,
        skip_touch_id=skip_touch_id,
        skip_sudo_cache=skip_sudo_cache,
        skip_tray=skip_tray,
        skip_skill=skip_skill,
        with_skill=with_skill,
        json_mode=json_mode,
    )


def _simple_args(json_mode: bool = True) -> argparse.Namespace:
    return argparse.Namespace(json_mode=json_mode)


def _stub_install_result() -> auth_setup.InstallResult:
    return auth_setup.InstallResult(
        touch_id=auth_setup.TouchIdInstallResult(
            pam_local_path=Path("/etc/pam.d/sudo_local"),
            line_added=True,
            already_present=False,
        ),
        sudo_cache=auth_setup.SudoCacheInstallResult(
            sudoers_path=Path("/etc/sudoers.d/mitm-tracker"),
            written=True,
            already_present=False,
            validated=True,
        ),
        invoked_privileged=True,
    )


def _stub_uninstall_result() -> auth_setup.UninstallResult:
    return auth_setup.UninstallResult(
        pam_local_path=Path("/etc/pam.d/sudo_local"),
        sudoers_path=Path("/etc/sudoers.d/mitm-tracker"),
        pam_local_removed=True,
        pam_local_line_stripped=False,
        sudoers_removed=True,
        sudoers_skipped_unmanaged=False,
    )


def _stub_tray_install_result(workspace: Path) -> tray_launch_agent.InstallResult:
    return tray_launch_agent.InstallResult(
        plist_path=Path("/Users/test/Library/LaunchAgents/com.mitm-tracker.tray.plist"),
        workspace=workspace,
        binary=Path("/usr/local/bin/mitm-tracker"),
        log_path=Path("/Users/test/Library/Logs/mitm-tracker-tray.log"),
        replaced_existing=False,
        loaded=True,
    )


def _stub_tray_uninstall_result() -> tray_launch_agent.UninstallResult:
    return tray_launch_agent.UninstallResult(
        plist_path=Path("/Users/test/Library/LaunchAgents/com.mitm-tracker.tray.plist"),
        plist_removed=True,
        was_loaded=True,
    )


def test_register_install_uninstall_status() -> None:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command")
    setup_commands.register(sub)

    install = parser.parse_args(["setup", "install", "--skip-touch-id", "--workspace", "/tmp/ws"])
    assert install.func is setup_commands.cmd_install
    assert install.skip_touch_id is True
    assert install.workspace == "/tmp/ws"

    uninstall = parser.parse_args(["setup", "uninstall"])
    assert uninstall.func is setup_commands.cmd_uninstall

    status = parser.parse_args(["setup", "status"])
    assert status.func is setup_commands.cmd_status


def test_cmd_install_orchestrates_tray_then_auth(tmp_path: Path, monkeypatch, capsys) -> None:
    workspace = tmp_path / "ws"
    workspace.mkdir()
    binary = tmp_path / "bin" / "mitm-tracker"
    binary.parent.mkdir()
    binary.touch()
    monkeypatch.setattr(tray_launch_agent, "resolve_binary", lambda: binary)

    call_order: list[str] = []

    def tray_install(workspace_path, *, binary):
        call_order.append("tray")
        return _stub_tray_install_result(workspace_path)

    def auth_install(*, privileged_runner, tmpdir, skip_touch_id=False, skip_sudo_cache=False):
        call_order.append("auth")
        return _stub_install_result()

    with patch.object(tray_launch_agent, "install", side_effect=tray_install), \
         patch.object(auth_setup, "install", side_effect=auth_install):
        rc = setup_commands.cmd_install(_install_args(workspace=str(workspace)))

    assert rc == EXIT_OK
    assert call_order == ["tray", "auth"]
    payload = json.loads(capsys.readouterr().out)
    assert payload["tray"] is not None
    assert payload["auth_setup"]["invoked_privileged"] is True


def test_cmd_install_all_skipped_returns_invalid_state(capsys) -> None:
    rc = setup_commands.cmd_install(
        _install_args(skip_touch_id=True, skip_sudo_cache=True, skip_tray=True)
    )
    assert rc == EXIT_INVALID_STATE
    err = capsys.readouterr().err
    assert "nothing_to_do" in err


def test_cmd_install_skip_tray(tmp_path: Path, monkeypatch, capsys) -> None:
    workspace = tmp_path / "ws"
    workspace.mkdir()
    monkeypatch.chdir(workspace)

    with patch.object(tray_launch_agent, "install") as mock_tray, \
         patch.object(auth_setup, "install", return_value=_stub_install_result()):
        rc = setup_commands.cmd_install(_install_args(skip_tray=True))

    assert rc == EXIT_OK
    mock_tray.assert_not_called()
    payload = json.loads(capsys.readouterr().out)
    assert payload["tray"] is None
    assert payload["auth_setup"] is not None


def test_cmd_install_skip_auth(tmp_path: Path, monkeypatch, capsys) -> None:
    workspace = tmp_path / "ws"
    workspace.mkdir()
    binary = tmp_path / "bin" / "mitm-tracker"
    binary.parent.mkdir()
    binary.touch()
    monkeypatch.setattr(tray_launch_agent, "resolve_binary", lambda: binary)

    with patch.object(tray_launch_agent, "install", return_value=_stub_tray_install_result(workspace)) as mock_tray, \
         patch.object(auth_setup, "install") as mock_auth:
        rc = setup_commands.cmd_install(
            _install_args(workspace=str(workspace), skip_touch_id=True, skip_sudo_cache=True)
        )

    assert rc == EXIT_OK
    mock_tray.assert_called_once()
    mock_auth.assert_not_called()
    payload = json.loads(capsys.readouterr().out)
    assert payload["auth_setup"] is None


def test_cmd_install_workspace_not_found(tmp_path: Path, capsys) -> None:
    rc = setup_commands.cmd_install(_install_args(workspace=str(tmp_path / "nope")))
    assert rc == EXIT_INVALID_STATE
    err = capsys.readouterr().err
    assert "workspace_not_found" in err


def test_cmd_uninstall(capsys) -> None:
    with patch.object(tray_launch_agent, "uninstall", return_value=_stub_tray_uninstall_result()), \
         patch.object(auth_setup, "uninstall", return_value=_stub_uninstall_result()), \
         patch.object(setup_commands, "_cleanup_artifacts", return_value={
             "log_path": "/dev/null",
             "log_removed": True,
             "tmpdir_path": "/dev/null",
             "tmpdir_removed": True,
             "mitmproxy_dir_path": "/dev/null",
             "mitmproxy_dir_removed": True,
         }):
        rc = setup_commands.cmd_uninstall(_simple_args())

    assert rc == EXIT_OK
    payload = json.loads(capsys.readouterr().out)
    assert payload["tray"]["plist_removed"] is True
    assert payload["auth_setup"]["sudoers_removed"] is True
    assert payload["cleanup"]["log_removed"] is True
    assert payload["cleanup"]["tmpdir_removed"] is True
    assert payload["cleanup"]["mitmproxy_dir_removed"] is True


def test_cleanup_artifacts_removes_existing_files(tmp_path: Path) -> None:
    (tmp_path / "Library" / "Logs").mkdir(parents=True)
    log = tmp_path / "Library" / "Logs" / "mitm-tracker-tray.log"
    log.write_text("some log content")

    setup_tmp = tmp_path / ".mitm-tracker-setup-tmp"
    setup_tmp.mkdir()
    (setup_tmp / "askpass.sh").write_text("#!/bin/bash")

    mitmproxy = tmp_path / ".mitmproxy"
    mitmproxy.mkdir()
    (mitmproxy / "mitmproxy-ca.pem").write_text("CERT")

    result = setup_commands._cleanup_artifacts(home=tmp_path)

    assert result["log_removed"] is True
    assert result["tmpdir_removed"] is True
    assert result["mitmproxy_dir_removed"] is True
    assert not log.exists()
    assert not setup_tmp.exists()
    assert not mitmproxy.exists()


def test_cleanup_artifacts_no_op_when_nothing_present(tmp_path: Path) -> None:
    result = setup_commands._cleanup_artifacts(home=tmp_path)

    assert result["log_removed"] is False
    assert result["tmpdir_removed"] is False
    assert result["mitmproxy_dir_removed"] is False


def test_cmd_status(tmp_path: Path, capsys) -> None:
    auth_status = auth_setup.SetupStatus(
        pam_local_path=Path("/etc/pam.d/sudo_local"),
        sudoers_path=Path("/etc/sudoers.d/mitm-tracker"),
        touch_id_configured=True,
        sudo_cache_configured=True,
    )
    tray_status = tray_launch_agent.StatusResult(
        plist_path=Path("/p"),
        installed=True,
        loaded=True,
        pid=999,
        workspace=tmp_path,
    )
    with patch.object(auth_setup, "status", return_value=auth_status), \
         patch.object(tray_launch_agent, "status", return_value=tray_status):
        rc = setup_commands.cmd_status(_simple_args())

    assert rc == EXIT_OK
    payload = json.loads(capsys.readouterr().out)
    assert payload["auth_setup"]["touch_id_configured"] is True
    assert payload["tray"]["pid"] == 999
