from __future__ import annotations

import json
from pathlib import Path

import pytest

from mitm_tracker.cli import main
from mitm_tracker.config import workspace_for
from mitm_tracker.output import EXIT_INVALID_STATE, EXIT_OK


def test_profile_create_returns_json(tmp_repo: Path, capsys) -> None:
    rc = main(["profile", "create", "sun-ios", "--json"])
    out = json.loads(capsys.readouterr().out)
    assert rc == EXIT_OK
    assert out["created"] is True
    assert out["name"] == "sun-ios"
    assert out["active"] == "default"

    ws = workspace_for(tmp_repo)
    assert ws.profile_dir("sun-ios").is_dir()


def test_profile_create_with_use_activates(tmp_repo: Path, capsys) -> None:
    rc = main(["profile", "create", "sun-ios", "--use", "--json"])
    out = json.loads(capsys.readouterr().out)
    assert rc == EXIT_OK
    assert out["active"] == "sun-ios"


def test_profile_create_idempotent(tmp_repo: Path, capsys) -> None:
    main(["profile", "create", "alpha"])
    capsys.readouterr()
    rc = main(["profile", "create", "alpha", "--json"])
    out = json.loads(capsys.readouterr().out)
    assert rc == EXIT_OK
    assert out["created"] is False


def test_profile_use_unknown_returns_invalid_state(tmp_repo: Path, capsys) -> None:
    rc = main(["profile", "use", "missing", "--json"])
    err = capsys.readouterr().err
    payload = json.loads(err)
    assert rc == EXIT_INVALID_STATE
    assert payload["error"] == "invalid_profile"


def test_profile_list_includes_default_and_created(tmp_repo: Path, capsys) -> None:
    main(["profile", "create", "alpha"])
    main(["profile", "create", "beta", "--use"])
    capsys.readouterr()
    rc = main(["profile", "list", "--json"])
    out = json.loads(capsys.readouterr().out)
    assert rc == EXIT_OK
    assert out["active"] == "beta"
    names = [p["name"] for p in out["profiles"]]
    assert names == ["default", "alpha", "beta"]


def test_profile_show_describes_active(tmp_repo: Path, capsys) -> None:
    main(["profile", "create", "sun-ios", "--use"])
    capsys.readouterr()
    rc = main(["profile", "show", "--json"])
    out = json.loads(capsys.readouterr().out)
    assert rc == EXIT_OK
    assert out["name"] == "sun-ios"
    assert out["is_active"] is True
    assert out["ssl_count"] == 0


def test_profile_delete_clears_active(tmp_repo: Path, capsys) -> None:
    main(["profile", "create", "tmp", "--use"])
    capsys.readouterr()
    rc = main(["profile", "delete", "tmp", "--json"])
    out = json.loads(capsys.readouterr().out)
    assert rc == EXIT_OK
    assert out["deleted"] is True
    assert out["active"] == "default"


def test_profile_delete_default_is_forbidden(tmp_repo: Path, capsys) -> None:
    rc = main(["profile", "delete", "default", "--json"])
    err = capsys.readouterr().err
    payload = json.loads(err)
    assert rc == EXIT_INVALID_STATE
    assert payload["error"] == "invalid_profile"


def test_ssl_add_targets_active_profile(tmp_repo: Path, capsys) -> None:
    main(["profile", "create", "sun-ios", "--use"])
    capsys.readouterr()
    rc = main(["ssl", "add", "*.thesun.co.uk", "--json"])
    out = json.loads(capsys.readouterr().out)
    assert rc == EXIT_OK
    assert out["profile"] == "sun-ios"
    ws = workspace_for(tmp_repo)
    assert ws.ssl_path("sun-ios").exists()
    assert not ws.ssl_path("default").exists()


def test_ssl_lists_are_isolated_per_profile(tmp_repo: Path, capsys) -> None:
    main(["profile", "create", "alpha"])
    main(["profile", "create", "beta"])
    main(["ssl", "add", "alpha.com", "--profile", "alpha"])
    main(["ssl", "add", "beta.com", "--profile", "beta"])
    capsys.readouterr()

    rc = main(["ssl", "list", "--profile", "alpha", "--json"])
    out = json.loads(capsys.readouterr().out)
    assert rc == EXIT_OK
    assert [p["pattern"] for p in out["patterns"]] == ["alpha.com"]

    rc = main(["ssl", "list", "--profile", "beta", "--json"])
    out = json.loads(capsys.readouterr().out)
    assert [p["pattern"] for p in out["patterns"]] == ["beta.com"]


def test_ssl_add_rejects_unknown_profile(tmp_repo: Path, capsys) -> None:
    rc = main(["ssl", "add", "x.com", "--profile", "missing", "--json"])
    err = capsys.readouterr().err
    payload = json.loads(err)
    assert rc == EXIT_INVALID_STATE
    assert payload["error"] == "profile_not_found"
