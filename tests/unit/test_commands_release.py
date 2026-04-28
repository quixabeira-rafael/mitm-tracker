from __future__ import annotations

import json
import os
import time
from pathlib import Path

import pytest

from mitm_tracker.cli import main
from mitm_tracker.config import workspace_for
from mitm_tracker.output import EXIT_INVALID_STATE, EXIT_OK


def _seed(tmp_repo: Path, name: str, age_hours: float, size: int = 4096) -> Path:
    workspace = workspace_for(tmp_repo)
    workspace.ensure()
    path = workspace.captures_dir / name
    path.write_bytes(b"x" * size)
    timestamp = time.time() - age_hours * 3600.0
    os.utime(path, (timestamp, timestamp))
    return path


def test_release_deletes_old_files(tmp_repo: Path, capsys) -> None:
    old = _seed(tmp_repo, "old.db", age_hours=48)
    new = _seed(tmp_repo, "new.db", age_hours=2)

    rc = main(["release", "--older-than", "24h", "--json"])
    out = json.loads(capsys.readouterr().out)
    assert rc == EXIT_OK
    assert out["dry_run"] is False
    assert [d["name"] for d in out["deleted"]] == ["old.db"]
    assert out["freed_bytes"] == 4096
    assert not old.exists()
    assert new.exists()


def test_release_dry_run_keeps_files(tmp_repo: Path, capsys) -> None:
    p = _seed(tmp_repo, "old.db", age_hours=48)
    rc = main(["release", "--older-than", "24h", "--dry-run", "--json"])
    out = json.loads(capsys.readouterr().out)
    assert rc == EXIT_OK
    assert out["dry_run"] is True
    assert [d["name"] for d in out["deleted"]] == ["old.db"]
    assert p.exists()


def test_release_protects_active_session(tmp_repo: Path, capsys) -> None:
    workspace = workspace_for(tmp_repo)
    workspace.ensure()
    active = _seed(tmp_repo, "active.db", age_hours=72)
    workspace.runtime_dir.mkdir(parents=True, exist_ok=True)
    workspace.state_path.write_text(
        json.dumps(
            {
                "running": False,
                "active_session": str(active),
            }
        )
    )

    rc = main(["release", "--older-than", "24h", "--json"])
    out = json.loads(capsys.readouterr().out)
    assert rc == EXIT_OK
    assert out["deleted"] == []
    assert [s["name"] for s in out["skipped_active"]] == ["active.db"]
    assert active.exists()


def test_release_no_keep_active_flag_removes_active(tmp_repo: Path, capsys) -> None:
    workspace = workspace_for(tmp_repo)
    workspace.ensure()
    active = _seed(tmp_repo, "active.db", age_hours=72)
    workspace.runtime_dir.mkdir(parents=True, exist_ok=True)
    workspace.state_path.write_text(
        json.dumps({"running": False, "active_session": str(active)})
    )

    rc = main(
        ["release", "--older-than", "24h", "--no-keep-active", "--json"]
    )
    out = json.loads(capsys.readouterr().out)
    assert rc == EXIT_OK
    assert [d["name"] for d in out["deleted"]] == ["active.db"]
    assert not active.exists()


def test_release_protects_running_session(tmp_repo: Path, capsys) -> None:
    workspace = workspace_for(tmp_repo)
    workspace.ensure()
    running = _seed(tmp_repo, "running.db", age_hours=72)
    workspace.runtime_dir.mkdir(parents=True, exist_ok=True)
    workspace.state_path.write_text(
        json.dumps(
            {
                "running": True,
                "session_db": str(running),
                "active_session": str(running),
            }
        )
    )

    rc = main(
        ["release", "--older-than", "24h", "--no-keep-active", "--json"]
    )
    out = json.loads(capsys.readouterr().out)
    assert rc == EXIT_OK
    assert out["deleted"] == []
    assert [s["name"] for s in out["skipped_running"]] == ["running.db"]
    assert running.exists()


def test_release_invalid_age_returns_invalid_state(tmp_repo: Path, capsys) -> None:
    rc = main(["release", "--older-than", "abc", "--json"])
    err = capsys.readouterr().err
    payload = json.loads(err)
    assert rc == EXIT_INVALID_STATE
    assert payload["error"] == "invalid_age"


def test_release_text_mode_renders_nothing_to_delete(tmp_repo: Path, capsys) -> None:
    rc = main(["release", "--older-than", "24h"])
    out = capsys.readouterr().out
    assert rc == EXIT_OK
    assert "nothing to delete" in out


def test_release_text_mode_renders_table(tmp_repo: Path, capsys) -> None:
    _seed(tmp_repo, "old.db", age_hours=48)
    rc = main(["release", "--older-than", "24h"])
    out = capsys.readouterr().out
    assert rc == EXIT_OK
    assert "deleted 1 file(s)" in out
    assert "old.db" in out


def test_release_supports_days_unit(tmp_repo: Path, capsys) -> None:
    _seed(tmp_repo, "two-day.db", age_hours=49)
    _seed(tmp_repo, "twelve-hour.db", age_hours=12)
    rc = main(["release", "--older-than", "2d", "--json"])
    out = json.loads(capsys.readouterr().out)
    assert rc == EXIT_OK
    names = [d["name"] for d in out["deleted"]]
    assert names == ["two-day.db"]
