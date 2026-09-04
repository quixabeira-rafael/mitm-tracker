from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from mitm_tracker.config import (
    DEFAULT_PROFILE_NAME,
    WORKSPACE_DIRNAME,
    WORKSPACE_ROOT_ENV,
    Workspace,
    is_valid_profile_name,
    resolve_workspace_root,
    workspace_for,
)


def _git(cwd: Path, *args: str) -> None:
    subprocess.run(
        ["git", *args],
        cwd=str(cwd),
        check=True,
        capture_output=True,
        text=True,
    )


@pytest.fixture
def git_repo_with_worktree(tmp_path: Path) -> tuple[Path, Path]:
    main = tmp_path / "main"
    main.mkdir()
    _git(main, "init", "-q")
    _git(main, "config", "user.email", "test@example.com")
    _git(main, "config", "user.name", "test")
    (main / "README.md").write_text("hello\n", encoding="utf-8")
    _git(main, "add", "README.md")
    _git(main, "commit", "-qm", "init")
    worktree = tmp_path / "wt"
    _git(main, "worktree", "add", "-q", "-b", "feature", str(worktree))
    return main.resolve(), worktree.resolve()


def test_workspace_for_uses_cwd_when_none(tmp_repo: Path) -> None:
    ws = workspace_for()
    assert ws.root == tmp_repo.resolve()


def test_worktree_resolves_to_the_main_repository(
    git_repo_with_worktree: tuple[Path, Path], monkeypatch
) -> None:
    main, worktree = git_repo_with_worktree
    monkeypatch.chdir(worktree)
    assert workspace_for().root == main


def test_subdirectory_resolves_to_the_main_repository(
    git_repo_with_worktree: tuple[Path, Path], monkeypatch
) -> None:
    main, _ = git_repo_with_worktree
    nested = main / "src" / "deep"
    nested.mkdir(parents=True)
    monkeypatch.chdir(nested)
    assert workspace_for().root == main


def test_explicit_cwd_still_resolves_to_the_main_repository(
    git_repo_with_worktree: tuple[Path, Path]
) -> None:
    main, worktree = git_repo_with_worktree
    assert resolve_workspace_root(worktree) == main


def test_env_override_sets_the_starting_directory(
    git_repo_with_worktree: tuple[Path, Path], tmp_path: Path, monkeypatch
) -> None:
    main, worktree = git_repo_with_worktree
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv(WORKSPACE_ROOT_ENV, str(worktree))
    assert workspace_for().root == main


def test_falls_back_to_the_nearest_existing_workspace(tmp_path: Path, monkeypatch) -> None:
    project = tmp_path / "project"
    nested = project / "a" / "b"
    nested.mkdir(parents=True)
    (project / WORKSPACE_DIRNAME).mkdir()
    monkeypatch.chdir(nested)
    assert workspace_for().root == project.resolve()


def test_falls_back_to_cwd_outside_a_repository(tmp_repo: Path) -> None:
    assert resolve_workspace_root() == tmp_repo.resolve()


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
