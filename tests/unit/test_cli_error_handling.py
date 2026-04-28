from __future__ import annotations

import errno
import json
from pathlib import Path

import pytest

from mitm_tracker.cli import main
from mitm_tracker.commands import record as record_module
from mitm_tracker.output import EXIT_SYSTEM


def test_permission_error_returns_structured_json(monkeypatch, tmp_repo: Path, capsys) -> None:
    def boom(args):
        raise PermissionError(13, "Permission denied", "/some/path")

    monkeypatch.setattr(record_module, "cmd_start", boom)
    rc = main(["record", "start", "--no-system-proxy", "--json"])
    err = capsys.readouterr().err
    payload = json.loads(err)
    assert rc == EXIT_SYSTEM
    assert payload["error"] == "permission_denied"
    assert "permission denied" in payload["message"].lower()


def test_file_not_found_returns_structured_json(monkeypatch, tmp_repo: Path, capsys) -> None:
    def boom(args):
        raise FileNotFoundError(2, "No such file", "/missing")

    monkeypatch.setattr(record_module, "cmd_start", boom)
    rc = main(["record", "start", "--no-system-proxy", "--json"])
    err = capsys.readouterr().err
    payload = json.loads(err)
    assert rc == EXIT_SYSTEM
    assert payload["error"] == "path_not_found"


def test_no_space_returns_structured_json(monkeypatch, tmp_repo: Path, capsys) -> None:
    def boom(args):
        raise OSError(errno.ENOSPC, "No space left on device", "/full")

    monkeypatch.setattr(record_module, "cmd_start", boom)
    rc = main(["record", "start", "--no-system-proxy", "--json"])
    err = capsys.readouterr().err
    payload = json.loads(err)
    assert rc == EXIT_SYSTEM
    assert payload["error"] == "no_space"


def test_generic_oserror_returns_filesystem_error(monkeypatch, tmp_repo: Path, capsys) -> None:
    def boom(args):
        raise OSError(5, "I/O error", "/dev/null")

    monkeypatch.setattr(record_module, "cmd_start", boom)
    rc = main(["record", "start", "--no-system-proxy", "--json"])
    err = capsys.readouterr().err
    payload = json.loads(err)
    assert rc == EXIT_SYSTEM
    assert payload["error"] == "filesystem_error"


def test_text_mode_writes_human_readable_error(monkeypatch, tmp_repo: Path, capsys) -> None:
    def boom(args):
        raise PermissionError(13, "Permission denied", "/locked")

    monkeypatch.setattr(record_module, "cmd_start", boom)
    rc = main(["record", "start", "--no-system-proxy"])
    err = capsys.readouterr().err
    assert rc == EXIT_SYSTEM
    assert "permission denied" in err.lower()
    assert err.startswith("error:") or "permission denied" in err.lower()


def test_real_permission_error_in_workspace_ensure(tmp_path: Path, monkeypatch, capsys) -> None:
    monkeypatch.chdir(tmp_path)
    tmp_path.chmod(0o555)
    try:
        rc = main(["record", "start", "--no-system-proxy", "--json"])
    finally:
        tmp_path.chmod(0o755)
    err = capsys.readouterr().err
    payload = json.loads(err)
    assert rc == EXIT_SYSTEM
    assert payload["error"] == "permission_denied"
