from __future__ import annotations

import argparse
import json
from pathlib import Path
from unittest.mock import patch

import pytest

from mitm_tracker import claude_skill
from mitm_tracker.commands import skill as skill_commands
from mitm_tracker.output import EXIT_OK, EXIT_SYSTEM


def _args(json_mode: bool = True) -> argparse.Namespace:
    return argparse.Namespace(json_mode=json_mode)


def test_register_supports_subcommands() -> None:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command")
    skill_commands.register(sub)
    install = parser.parse_args(["skill", "install"])
    assert install.func is skill_commands.cmd_install
    uninstall = parser.parse_args(["skill", "uninstall"])
    assert uninstall.func is skill_commands.cmd_uninstall
    status = parser.parse_args(["skill", "status"])
    assert status.func is skill_commands.cmd_status


def test_cmd_install_emits_payload(capsys) -> None:
    stub = claude_skill.InstallResult(
        skill_file=Path("/h/.claude/skills/mitm-tracker/SKILL.md"),
        source_file=Path("/repo/.claude/skills/mitm-tracker/SKILL.md"),
        installed=True,
        replaced_existing=False,
        skipped_reason=None,
    )
    with patch.object(claude_skill, "install", return_value=stub):
        rc = skill_commands.cmd_install(_args())
    assert rc == EXIT_OK
    payload = json.loads(capsys.readouterr().out)
    assert payload["installed"] is True


def test_cmd_install_returns_system_when_skipped(capsys) -> None:
    stub = claude_skill.InstallResult(
        skill_file=Path("/h/.claude/skills/mitm-tracker/SKILL.md"),
        source_file=None,
        installed=False,
        replaced_existing=False,
        skipped_reason="source SKILL.md not found",
    )
    with patch.object(claude_skill, "install", return_value=stub):
        rc = skill_commands.cmd_install(_args())
    assert rc == EXIT_SYSTEM
    err = json.loads(capsys.readouterr().err)
    assert err["error"] == "skill_install_skipped"


def test_cmd_uninstall_payload(capsys) -> None:
    stub = claude_skill.UninstallResult(
        skill_file=Path("/h/.claude/skills/mitm-tracker/SKILL.md"),
        removed=True,
        skipped_unmanaged=False,
    )
    with patch.object(claude_skill, "uninstall", return_value=stub):
        rc = skill_commands.cmd_uninstall(_args())
    assert rc == EXIT_OK
    payload = json.loads(capsys.readouterr().out)
    assert payload["removed"] is True


def test_cmd_status_payload(tmp_path: Path, capsys) -> None:
    stub = claude_skill.SkillStatus(
        skill_file=tmp_path / "SKILL.md",
        source_file=tmp_path / "src.md",
        installed=True,
        is_symlink=True,
        is_managed_symlink=True,
        points_to=tmp_path / "src.md",
    )
    with patch.object(claude_skill, "status", return_value=stub):
        rc = skill_commands.cmd_status(_args())
    assert rc == EXIT_OK
    payload = json.loads(capsys.readouterr().out)
    assert payload["is_managed_symlink"] is True
