from __future__ import annotations

import json
from pathlib import Path

import pytest

from mitm_tracker.cli import main
from mitm_tracker.config import workspace_for
from mitm_tracker.output import EXIT_INVALID_STATE, EXIT_OK


def test_ssl_add_creates_file_and_returns_json(tmp_repo: Path, capsys) -> None:
    rc = main(["ssl", "add", "--json", "api.example.com"])
    assert rc == EXIT_OK
    out = json.loads(capsys.readouterr().out)
    assert out["added"] is True
    assert out["pattern"] == "api.example.com"
    assert out["count"] == 1

    workspace = workspace_for(tmp_repo)
    assert workspace.ssl_path("default").exists()
    data = json.loads(workspace.ssl_path("default").read_text())
    assert data["domains"][0]["pattern"] == "api.example.com"


def test_ssl_add_idempotent(tmp_repo: Path, capsys) -> None:
    main(["ssl", "add", "api.example.com"])
    capsys.readouterr()
    rc = main(["ssl", "add", "--json", "API.EXAMPLE.COM"])
    out = json.loads(capsys.readouterr().out)
    assert rc == EXIT_OK
    assert out["added"] is False
    assert out["count"] == 1


def test_ssl_remove_existing(tmp_repo: Path, capsys) -> None:
    main(["ssl", "add", "api.example.com"])
    capsys.readouterr()
    rc = main(["ssl", "remove", "--json", "api.example.com"])
    out = json.loads(capsys.readouterr().out)
    assert rc == EXIT_OK
    assert out["removed"] is True
    assert out["count"] == 0


def test_ssl_remove_missing(tmp_repo: Path, capsys) -> None:
    rc = main(["ssl", "remove", "--json", "api.example.com"])
    out = json.loads(capsys.readouterr().out)
    assert rc == EXIT_OK
    assert out["removed"] is False


def test_ssl_list_empty_json(tmp_repo: Path, capsys) -> None:
    rc = main(["ssl", "list", "--json"])
    out = json.loads(capsys.readouterr().out)
    assert rc == EXIT_OK
    assert out["count"] == 0
    assert out["patterns"] == []


def test_ssl_list_after_add(tmp_repo: Path, capsys) -> None:
    main(["ssl", "add", "api.example.com"])
    main(["ssl", "add", "*.cdn.example.com"])
    capsys.readouterr()
    rc = main(["ssl", "list", "--json"])
    out = json.loads(capsys.readouterr().out)
    assert rc == EXIT_OK
    assert out["count"] == 2
    patterns = [p["pattern"] for p in out["patterns"]]
    assert patterns == ["api.example.com", "*.cdn.example.com"]


def test_ssl_add_rejects_empty_pattern(tmp_repo: Path, capsys) -> None:
    rc = main(["ssl", "add", "--json", "   "])
    err = capsys.readouterr().err
    payload = json.loads(err)
    assert rc == EXIT_INVALID_STATE
    assert payload["error"] == "invalid_pattern"


def test_ssl_list_text_mode_renders_table(tmp_repo: Path, capsys) -> None:
    main(["ssl", "add", "api.example.com"])
    capsys.readouterr()
    rc = main(["ssl", "list"])
    out = capsys.readouterr().out
    assert rc == EXIT_OK
    assert "PATTERN" in out
    assert "api.example.com" in out


def test_ssl_list_text_mode_empty(tmp_repo: Path, capsys) -> None:
    rc = main(["ssl", "list"])
    out = capsys.readouterr().out
    assert rc == EXIT_OK
    assert "empty" in out
