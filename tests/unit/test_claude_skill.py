from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from mitm_tracker import claude_skill


def _paths(tmp_path: Path) -> claude_skill.ClaudeSkillPaths:
    return claude_skill.ClaudeSkillPaths.for_user(home=tmp_path)


def _make_source(tmp_path: Path) -> Path:
    src = tmp_path / "src" / ".claude" / "skills" / "mitm-tracker" / "SKILL.md"
    src.parent.mkdir(parents=True, exist_ok=True)
    src.write_text("# fake skill\n")
    return src


def test_claude_code_present_true_when_dir_exists(tmp_path: Path) -> None:
    (tmp_path / ".claude").mkdir()
    assert claude_skill.claude_code_present(home=tmp_path) is True


def test_claude_code_present_false_when_missing(tmp_path: Path) -> None:
    assert claude_skill.claude_code_present(home=tmp_path) is False


def test_install_creates_symlink(tmp_path: Path) -> None:
    src = _make_source(tmp_path)
    paths = _paths(tmp_path)

    result = claude_skill.install(paths=paths, source=src)

    assert result.installed is True
    assert result.replaced_existing is False
    assert paths.user_skill_file.is_symlink()
    assert paths.user_skill_file.resolve() == src.resolve()


def test_install_replaces_existing_symlink(tmp_path: Path) -> None:
    src = _make_source(tmp_path)
    paths = _paths(tmp_path)
    # Pre-create a stale symlink to a different target
    paths.user_skill_dir.mkdir(parents=True)
    other = tmp_path / "other.md"
    other.write_text("stale")
    paths.user_skill_file.symlink_to(other)

    result = claude_skill.install(paths=paths, source=src)

    assert result.replaced_existing is True
    assert paths.user_skill_file.resolve() == src.resolve()


def test_install_skipped_when_source_missing(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    nonexistent = tmp_path / "nope" / "SKILL.md"

    result = claude_skill.install(paths=paths, source=nonexistent)

    assert result.installed is False
    assert result.skipped_reason is not None
    assert not paths.user_skill_file.exists()


def test_uninstall_removes_managed_symlink(tmp_path: Path) -> None:
    src = _make_source(tmp_path)
    paths = _paths(tmp_path)
    claude_skill.install(paths=paths, source=src)
    assert paths.user_skill_file.is_symlink()

    result = claude_skill.uninstall(paths=paths, source=src)

    assert result.removed is True
    assert result.skipped_unmanaged is False
    assert not paths.user_skill_file.exists()


def test_uninstall_skips_unmanaged_symlink(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    other = tmp_path / "other.md"
    other.write_text("custom")
    paths.user_skill_dir.mkdir(parents=True)
    paths.user_skill_file.symlink_to(other)
    src = _make_source(tmp_path)

    result = claude_skill.uninstall(paths=paths, source=src)

    assert result.removed is False
    assert result.skipped_unmanaged is True
    assert paths.user_skill_file.is_symlink()  # untouched


def test_uninstall_skips_unmanaged_regular_file(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    paths.user_skill_dir.mkdir(parents=True)
    paths.user_skill_file.write_text("# personal copy")
    src = _make_source(tmp_path)

    result = claude_skill.uninstall(paths=paths, source=src)

    assert result.removed is False
    assert result.skipped_unmanaged is True
    assert paths.user_skill_file.exists()


def test_uninstall_no_op_when_nothing_present(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    src = _make_source(tmp_path)

    result = claude_skill.uninstall(paths=paths, source=src)

    assert result.removed is False
    assert result.skipped_unmanaged is False


def test_status_reports_managed_symlink(tmp_path: Path) -> None:
    src = _make_source(tmp_path)
    paths = _paths(tmp_path)
    claude_skill.install(paths=paths, source=src)

    s = claude_skill.status(paths=paths, source=src)

    assert s.installed is True
    assert s.is_symlink is True
    assert s.is_managed_symlink is True
    assert s.points_to is not None


def test_status_flags_unmanaged(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    paths.user_skill_dir.mkdir(parents=True)
    paths.user_skill_file.write_text("# personal copy")
    src = _make_source(tmp_path)

    s = claude_skill.status(paths=paths, source=src)

    assert s.installed is True
    assert s.is_symlink is False
    assert s.is_managed_symlink is False


def test_status_when_not_installed(tmp_path: Path) -> None:
    paths = _paths(tmp_path)

    s = claude_skill.status(paths=paths, source=None)

    assert s.installed is False
    assert s.is_managed_symlink is False
