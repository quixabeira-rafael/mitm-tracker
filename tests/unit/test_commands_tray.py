from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from mitm_tracker import tray_launch_agent as tla
from mitm_tracker.commands import tray as tray_commands
from mitm_tracker.config import Workspace
from mitm_tracker.output import EXIT_INVALID_STATE, EXIT_OK, EXIT_SYSTEM


def _run_args(json_mode: bool = True) -> argparse.Namespace:
    return argparse.Namespace(interval=2.0, json_mode=json_mode)


def _install_args(workspace: str | None = None, binary: str | None = None, json_mode: bool = True) -> argparse.Namespace:
    return argparse.Namespace(workspace=workspace, binary=binary, json_mode=json_mode)


def _simple_args(json_mode: bool = True) -> argparse.Namespace:
    return argparse.Namespace(json_mode=json_mode)


def test_cmd_run_no_workspace(tmp_path: Path, monkeypatch, capsys) -> None:
    monkeypatch.chdir(tmp_path)

    rc = tray_commands.cmd_run(_run_args())

    assert rc == EXIT_INVALID_STATE
    err = capsys.readouterr().err
    assert "no_workspace" in err


def test_cmd_run_rumps_missing(tmp_path: Path, monkeypatch, capsys) -> None:
    ws = Workspace(root=tmp_path)
    ws.ensure()
    monkeypatch.chdir(tmp_path)
    monkeypatch.setitem(sys.modules, "rumps", None)

    rc = tray_commands.cmd_run(_run_args())

    assert rc == EXIT_SYSTEM
    err = capsys.readouterr().err
    assert "rumps_missing" in err


def test_register_supports_run_subcommand() -> None:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command")
    tray_commands.register(sub)
    args = parser.parse_args(["tray", "run", "--interval", "5"])
    assert args.command == "tray"
    assert args.tray_action == "run"
    assert args.interval == pytest.approx(5.0)
    assert args.func is tray_commands.cmd_run


def test_register_defaults_to_run_when_no_action() -> None:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command")
    tray_commands.register(sub)
    args = parser.parse_args(["tray"])
    assert args.tray_action is None
    assert args.func is tray_commands.cmd_run
    assert args.interval == pytest.approx(2.0)


def test_register_supports_install_subcommand() -> None:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command")
    tray_commands.register(sub)
    args = parser.parse_args(["tray", "install", "--workspace", "/tmp/ws"])
    assert args.tray_action == "install"
    assert args.workspace == "/tmp/ws"
    assert args.func is tray_commands.cmd_install


def test_register_supports_uninstall_and_status() -> None:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command")
    tray_commands.register(sub)
    uninstall = parser.parse_args(["tray", "uninstall"])
    assert uninstall.func is tray_commands.cmd_uninstall
    status = parser.parse_args(["tray", "status"])
    assert status.func is tray_commands.cmd_status


def test_cmd_install_writes_plist_and_returns_ok(tmp_path: Path, monkeypatch, capsys) -> None:
    workspace = tmp_path / "ws"
    workspace.mkdir()
    binary = tmp_path / "bin" / "mitm-tracker"
    binary.parent.mkdir()
    binary.touch()

    fake_paths = tla.LaunchAgentPaths.for_user(home=tmp_path)

    expected_result = tla.InstallResult(
        plist_path=fake_paths.plist,
        workspace=workspace,
        binary=binary,
        log_path=fake_paths.log,
        replaced_existing=False,
        loaded=True,
    )
    with patch.object(tla, "install", return_value=expected_result) as mock_install:
        rc = tray_commands.cmd_install(_install_args(workspace=str(workspace), binary=str(binary)))

    assert rc == EXIT_OK
    out = capsys.readouterr().out
    payload = json.loads(out)
    assert payload["loaded"] is True
    assert payload["replaced_existing"] is False
    mock_install.assert_called_once()


def test_cmd_install_rejects_missing_workspace(tmp_path: Path, capsys) -> None:
    rc = tray_commands.cmd_install(_install_args(workspace=str(tmp_path / "does-not-exist")))

    assert rc == EXIT_INVALID_STATE
    err = capsys.readouterr().err
    assert "workspace_not_found" in err


def test_cmd_install_rejects_missing_binary(tmp_path: Path, capsys) -> None:
    workspace = tmp_path / "ws"
    workspace.mkdir()

    rc = tray_commands.cmd_install(
        _install_args(workspace=str(workspace), binary=str(tmp_path / "no-bin"))
    )

    assert rc == EXIT_SYSTEM
    err = capsys.readouterr().err
    assert "binary_not_found" in err


def test_cmd_uninstall(tmp_path: Path, capsys) -> None:
    expected = tla.UninstallResult(
        plist_path=tmp_path / "ag.plist",
        plist_removed=True,
        was_loaded=True,
    )
    with patch.object(tla, "uninstall", return_value=expected):
        rc = tray_commands.cmd_uninstall(_simple_args())

    assert rc == EXIT_OK
    out = capsys.readouterr().out
    payload = json.loads(out)
    assert payload["plist_removed"] is True
    assert payload["was_loaded"] is True


def test_cmd_status(tmp_path: Path, capsys) -> None:
    expected = tla.StatusResult(
        plist_path=tmp_path / "ag.plist",
        installed=True,
        loaded=True,
        pid=12345,
        workspace=tmp_path / "ws",
    )
    with patch.object(tla, "status", return_value=expected):
        rc = tray_commands.cmd_status(_simple_args())

    assert rc == EXIT_OK
    out = capsys.readouterr().out
    payload = json.loads(out)
    assert payload["installed"] is True
    assert payload["loaded"] is True
    assert payload["pid"] == 12345
