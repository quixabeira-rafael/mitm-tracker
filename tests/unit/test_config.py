from __future__ import annotations

from pathlib import Path

import pytest

from mitm_tracker.config import (
    DEFAULT_PROFILE_NAME,
    Workspace,
    is_valid_profile_name,
    workspace_for,
)


def test_workspace_for_uses_cwd_when_none(tmp_repo: Path) -> None:
    ws = workspace_for()
    assert ws.root == tmp_repo.resolve()


def test_workspace_paths_are_relative_to_root(tmp_path: Path) -> None:
    ws = Workspace(root=tmp_path)
    assert ws.base == tmp_path / ".mitm-tracker"
    assert ws.runtime_dir == tmp_path / ".mitm-tracker" / "runtime"
    assert ws.captures_dir == tmp_path / ".mitm-tracker" / "captures"
    assert ws.profiles_dir == tmp_path / ".mitm-tracker" / "profiles"
    assert ws.profile_dir("foo") == tmp_path / ".mitm-tracker" / "profiles" / "foo"
    assert ws.ssl_path("foo") == tmp_path / ".mitm-tracker" / "profiles" / "foo" / "ssl.json"
    assert ws.pid_path == tmp_path / ".mitm-tracker" / "runtime" / "mitmproxy.pid"
    assert ws.log_path == tmp_path / ".mitm-tracker" / "runtime" / "mitmproxy.log"
    assert ws.state_path == tmp_path / ".mitm-tracker" / "runtime" / "state.json"
    assert ws.proxy_backup_path == tmp_path / ".mitm-tracker" / "runtime" / "proxy_backup.json"


def test_workspace_ensure_creates_directories_and_default_profile(tmp_path: Path) -> None:
    ws = Workspace(root=tmp_path)
    ws.ensure()
    assert ws.base.is_dir()
    assert ws.runtime_dir.is_dir()
    assert ws.captures_dir.is_dir()
    assert ws.profiles_dir.is_dir()
    assert ws.profile_dir(DEFAULT_PROFILE_NAME).is_dir()


@pytest.mark.parametrize("name", ["default", "sun-ios", "Foo_Bar", "abc123", "a"])
def test_valid_profile_names(name: str) -> None:
    assert is_valid_profile_name(name) is True


@pytest.mark.parametrize(
    "name", ["", "-foo", "_bar", "foo bar", "foo/bar", "foo.bar", "x" * 100]
)
def test_invalid_profile_names(name: str) -> None:
    assert is_valid_profile_name(name) is False
