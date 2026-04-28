from __future__ import annotations

import argparse
import sys
from pathlib import Path

import pytest

from mitm_tracker.commands import tray as tray_commands
from mitm_tracker.config import Workspace
from mitm_tracker.output import EXIT_INVALID_STATE, EXIT_SYSTEM


def _args(json_mode: bool = True) -> argparse.Namespace:
    return argparse.Namespace(interval=2.0, json_mode=json_mode)


def test_cmd_tray_no_workspace(tmp_path: Path, monkeypatch, capsys) -> None:
    monkeypatch.chdir(tmp_path)

    rc = tray_commands.cmd_tray(_args())

    assert rc == EXIT_INVALID_STATE
    err = capsys.readouterr().err
    assert "no_workspace" in err


def test_cmd_tray_rumps_missing(tmp_path: Path, monkeypatch, capsys) -> None:
    ws = Workspace(root=tmp_path)
    ws.ensure()
    monkeypatch.chdir(tmp_path)
    monkeypatch.setitem(sys.modules, "rumps", None)

    rc = tray_commands.cmd_tray(_args())

    assert rc == EXIT_SYSTEM
    err = capsys.readouterr().err
    assert "rumps_missing" in err


def test_register_adds_tray_subcommand() -> None:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command")
    tray_commands.register(sub)
    args = parser.parse_args(["tray", "--interval", "5"])
    assert args.command == "tray"
    assert args.interval == pytest.approx(5.0)
    assert args.func is tray_commands.cmd_tray
