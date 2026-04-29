from __future__ import annotations

import argparse
import json
from unittest.mock import patch

import pytest

from mitm_tracker import doctor
from mitm_tracker.commands import doctor as doctor_commands
from mitm_tracker.output import EXIT_INVALID_STATE, EXIT_OK, EXIT_SYSTEM


def _args(json_mode: bool = True) -> argparse.Namespace:
    return argparse.Namespace(json_mode=json_mode)


def _stub_results() -> list[doctor.CheckResult]:
    return [
        doctor.CheckResult(name="macOS", status=doctor.STATUS_OK, detail="14.5", group="system"),
        doctor.CheckResult(name="Python", status=doctor.STATUS_OK, detail="3.13", group="system"),
        doctor.CheckResult(name="mitmdump", status=doctor.STATUS_OK, detail="12.0", group="tools"),
    ]


def test_register_adds_doctor_subcommand() -> None:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command")
    doctor_commands.register(sub)
    args = parser.parse_args(["doctor", "--json"])
    assert args.command == "doctor"
    assert args.json_mode is True
    assert args.func is doctor_commands.cmd_doctor


def test_cmd_doctor_returns_ok_when_all_green(capsys) -> None:
    with patch.object(doctor, "run_all_checks", return_value=_stub_results()):
        rc = doctor_commands.cmd_doctor(_args())
    assert rc == EXIT_OK
    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == doctor.STATUS_OK
    assert len(payload["checks"]) == 3


def test_cmd_doctor_returns_invalid_state_on_warn(capsys) -> None:
    results = [
        doctor.CheckResult(name="macOS", status=doctor.STATUS_OK, detail="14.5", group="system"),
        doctor.CheckResult(name="xcrun", status=doctor.STATUS_WARN, detail="missing", group="tools"),
    ]
    with patch.object(doctor, "run_all_checks", return_value=results):
        rc = doctor_commands.cmd_doctor(_args())
    assert rc == EXIT_INVALID_STATE
    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == doctor.STATUS_WARN


def test_cmd_doctor_returns_system_on_error(capsys) -> None:
    results = [
        doctor.CheckResult(name="macOS", status=doctor.STATUS_ERROR, detail="too old", group="system"),
    ]
    with patch.object(doctor, "run_all_checks", return_value=results):
        rc = doctor_commands.cmd_doctor(_args())
    assert rc == EXIT_SYSTEM
    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == doctor.STATUS_ERROR


def test_cmd_doctor_text_mode_renders_groups_and_summary(capsys) -> None:
    results = [
        doctor.CheckResult(name="macOS", status=doctor.STATUS_OK, detail="14.5", group="system"),
        doctor.CheckResult(name="xcrun", status=doctor.STATUS_WARN, detail="missing", fix="xcode-select --install", group="tools"),
        doctor.CheckResult(name="Workspace", status=doctor.STATUS_INFO, detail="/path", group="state"),
    ]
    with patch.object(doctor, "run_all_checks", return_value=results):
        rc = doctor_commands.cmd_doctor(_args(json_mode=False))
    out = capsys.readouterr().out
    assert "System:" in out
    assert "Required tools:" in out
    assert "Runtime state:" in out
    assert "fix: xcode-select --install" in out
    assert "Summary:" in out
    assert rc == EXIT_INVALID_STATE
