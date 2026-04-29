from __future__ import annotations

import plistlib
import subprocess
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from mitm_tracker import tray_launch_agent as tla


def _result(returncode: int = 0, stdout: str = "", stderr: str = "") -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr=stderr)


def _paths(tmp_path: Path) -> tla.LaunchAgentPaths:
    return tla.LaunchAgentPaths.for_user(home=tmp_path)


def test_generate_plist_data_includes_workspace_and_binary(tmp_path: Path) -> None:
    workspace = tmp_path / "ws"
    workspace.mkdir()
    binary = tmp_path / "bin" / "mitm-tracker"
    binary.parent.mkdir()
    binary.touch()
    log_path = tmp_path / "log.txt"

    data = tla.generate_plist_data(workspace, binary, log_path)

    assert data["Label"] == "com.mitm-tracker.tray"
    assert data["ProgramArguments"] == [str(binary), "tray", "run"]
    assert data["WorkingDirectory"] == str(workspace)
    assert data["StandardOutPath"] == str(log_path)
    assert data["StandardErrorPath"] == str(log_path)
    assert data["RunAtLoad"] is True
    assert "PATH" in data["EnvironmentVariables"]


def test_write_plist_round_trip(tmp_path: Path) -> None:
    plist = tmp_path / "ag.plist"
    data = tla.generate_plist_data(tmp_path, tmp_path / "bin", tmp_path / "log")

    tla.write_plist(plist, data)

    with plist.open("rb") as fh:
        loaded = plistlib.load(fh)
    assert loaded["Label"] == "com.mitm-tracker.tray"
    assert loaded["ProgramArguments"][1] == "tray"
    assert loaded["ProgramArguments"][2] == "run"


def test_is_installed_reflects_plist_presence(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    assert tla.is_installed(paths) is False
    paths.plist.parent.mkdir(parents=True, exist_ok=True)
    paths.plist.touch()
    assert tla.is_installed(paths) is True


def test_is_loaded_true_when_launchctl_succeeds() -> None:
    runner = MagicMock(return_value=_result(returncode=0, stdout="ok"))
    assert tla.is_loaded(runner) is True


def test_is_loaded_false_when_launchctl_fails() -> None:
    runner = MagicMock(return_value=_result(returncode=3))
    assert tla.is_loaded(runner) is False


def test_loaded_pid_parses_value() -> None:
    stdout = '{\n\t"LimitLoadToSessionType" = "Aqua";\n\t"PID" = 12345;\n\t"Label" = "com.mitm-tracker.tray";\n}\n'
    runner = MagicMock(return_value=_result(returncode=0, stdout=stdout))
    assert tla.loaded_pid(runner) == 12345


def test_loaded_pid_none_when_not_loaded() -> None:
    runner = MagicMock(return_value=_result(returncode=3))
    assert tla.loaded_pid(runner) is None


def test_install_writes_plist_and_loads(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    workspace = tmp_path / "ws"
    workspace.mkdir()
    binary = tmp_path / "bin" / "mitm-tracker"
    binary.parent.mkdir()
    binary.touch()

    list_results = iter(
        [
            _result(returncode=3),  # is_loaded before write -> False
            _result(returncode=0),  # is_loaded after load -> True
        ]
    )
    runner = MagicMock(side_effect=lambda cmd: next(list_results) if cmd[0:2] == ["launchctl", "list"] else _result())

    result = tla.install(workspace, binary=binary, paths=paths, runner=runner)

    assert paths.plist.exists()
    with paths.plist.open("rb") as fh:
        loaded = plistlib.load(fh)
    assert loaded["WorkingDirectory"] == str(workspace)
    assert result.replaced_existing is False
    assert result.loaded is True


def test_install_unloads_existing_plist(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    paths.plist.parent.mkdir(parents=True, exist_ok=True)
    paths.plist.write_bytes(b"<plist></plist>")
    workspace = tmp_path / "ws"
    workspace.mkdir()

    calls: list[list[str]] = []

    def runner(cmd: list[str]) -> subprocess.CompletedProcess:
        calls.append(cmd)
        if cmd[0:2] == ["launchctl", "list"]:
            return _result(returncode=0)
        return _result()

    result = tla.install(workspace, binary=Path("/usr/bin/true"), paths=paths, runner=runner)

    assert result.replaced_existing is True
    assert any(cmd[0:2] == ["launchctl", "unload"] for cmd in calls)
    assert any(cmd[0:3] == ["launchctl", "load", "-w"] for cmd in calls)


def test_uninstall_removes_plist_and_unloads(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    paths.plist.parent.mkdir(parents=True, exist_ok=True)
    paths.plist.write_bytes(b"<plist></plist>")

    calls: list[list[str]] = []

    def runner(cmd: list[str]) -> subprocess.CompletedProcess:
        calls.append(cmd)
        if cmd[0:2] == ["launchctl", "list"]:
            return _result(returncode=0)
        return _result()

    result = tla.uninstall(paths=paths, runner=runner)

    assert result.was_loaded is True
    assert result.plist_removed is True
    assert not paths.plist.exists()
    assert any(cmd[0:2] == ["launchctl", "unload"] for cmd in calls)


def test_uninstall_when_nothing_installed(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    runner = MagicMock(return_value=_result(returncode=3))

    result = tla.uninstall(paths=paths, runner=runner)

    assert result.was_loaded is False
    assert result.plist_removed is False


def test_status_returns_workspace_when_installed(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    workspace = tmp_path / "ws"
    workspace.mkdir()
    paths.plist.parent.mkdir(parents=True, exist_ok=True)
    data = tla.generate_plist_data(workspace, tmp_path / "bin", tmp_path / "log")
    tla.write_plist(paths.plist, data)

    stdout = '{\n\t"PID" = 999;\n}\n'
    runner = MagicMock(return_value=_result(returncode=0, stdout=stdout))

    result = tla.status(paths=paths, runner=runner)

    assert result.installed is True
    assert result.loaded is True
    assert result.pid == 999
    assert result.workspace == workspace


def test_status_when_not_installed(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    runner = MagicMock(return_value=_result(returncode=3))

    result = tla.status(paths=paths, runner=runner)

    assert result.installed is False
    assert result.loaded is False
    assert result.pid is None
    assert result.workspace is None
