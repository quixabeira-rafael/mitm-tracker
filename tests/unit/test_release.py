from __future__ import annotations

import time
from pathlib import Path

import pytest

from mitm_tracker.config import Workspace
from mitm_tracker.release import (
    ReleaseError,
    execute,
    list_capture_files,
    parse_age_hours,
    plan,
)


def _workspace(tmp_path: Path) -> Workspace:
    ws = Workspace(root=tmp_path)
    ws.ensure()
    return ws


def _seed_capture(workspace: Workspace, name: str, *, age_hours: float, size: int = 4096) -> Path:
    path = workspace.captures_dir / name
    path.write_bytes(b"x" * size)
    age = age_hours * 3600.0
    timestamp = time.time() - age
    import os

    os.utime(path, (timestamp, timestamp))
    return path


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("24h", 24.0),
        ("48", 48.0),
        ("7d", 168.0),
        ("0.5h", 0.5),
        ("30m", 0.5),
        (12, 12.0),
        (1.5, 1.5),
    ],
)
def test_parse_age_hours_accepts_known_formats(raw, expected) -> None:
    assert parse_age_hours(raw) == expected


@pytest.mark.parametrize("raw", ["", "weeks", "abc", "-1", "10x", "  "])
def test_parse_age_hours_rejects_invalid(raw) -> None:
    with pytest.raises(ReleaseError):
        parse_age_hours(raw)


def test_parse_age_hours_rejects_negative_number() -> None:
    with pytest.raises(ReleaseError):
        parse_age_hours(-5)


def test_list_capture_files_empty_when_no_dir(tmp_path: Path) -> None:
    ws = Workspace(root=tmp_path)
    assert list_capture_files(ws) == []


def test_list_capture_files_returns_db_files(tmp_path: Path) -> None:
    ws = _workspace(tmp_path)
    (ws.captures_dir / "a.db").touch()
    (ws.captures_dir / "b.db").touch()
    (ws.captures_dir / "ignore.txt").touch()
    files = list_capture_files(ws)
    assert sorted(f.name for f in files) == ["a.db", "b.db"]


def test_plan_separates_old_and_recent(tmp_path: Path) -> None:
    ws = _workspace(tmp_path)
    _seed_capture(ws, "old.db", age_hours=48)
    _seed_capture(ws, "new.db", age_hours=2)

    report = plan(ws, age_hours=24.0)
    assert [c.path.name for c in report.deleted] == ["old.db"]
    assert [c.path.name for c in report.kept] == ["new.db"]
    assert report.dry_run is False
    assert report.freed_bytes == 4096


def test_plan_keeps_active_session_by_default(tmp_path: Path) -> None:
    ws = _workspace(tmp_path)
    active = _seed_capture(ws, "active.db", age_hours=48)
    _seed_capture(ws, "old.db", age_hours=72)

    report = plan(ws, age_hours=24.0, active_session=active)
    deleted = [c.path.name for c in report.deleted]
    skipped = [c.path.name for c in report.skipped_active]
    assert deleted == ["old.db"]
    assert skipped == ["active.db"]


def test_plan_can_remove_active_session_when_keep_active_disabled(tmp_path: Path) -> None:
    ws = _workspace(tmp_path)
    active = _seed_capture(ws, "active.db", age_hours=48)

    report = plan(ws, age_hours=24.0, keep_active=False, active_session=active)
    assert [c.path.name for c in report.deleted] == ["active.db"]
    assert report.skipped_active == []


def test_plan_always_skips_running_session(tmp_path: Path) -> None:
    ws = _workspace(tmp_path)
    running = _seed_capture(ws, "running.db", age_hours=72)

    report = plan(
        ws,
        age_hours=24.0,
        keep_active=False,
        running_session=running,
    )
    assert report.deleted == []
    assert [c.path.name for c in report.skipped_running] == ["running.db"]


def test_plan_with_zero_threshold_deletes_everything(tmp_path: Path) -> None:
    ws = _workspace(tmp_path)
    _seed_capture(ws, "a.db", age_hours=0.1)
    _seed_capture(ws, "b.db", age_hours=10)

    report = plan(ws, age_hours=0.0)
    assert sorted(c.path.name for c in report.deleted) == ["a.db", "b.db"]


def test_execute_actually_deletes_files(tmp_path: Path) -> None:
    ws = _workspace(tmp_path)
    p = _seed_capture(ws, "old.db", age_hours=48)
    report = plan(ws, age_hours=24.0)
    final = execute(report)
    assert not p.exists()
    assert [c.path.name for c in final.deleted] == ["old.db"]
    assert final.freed_bytes == 4096
    assert final.dry_run is False


def test_execute_dry_run_does_not_delete(tmp_path: Path) -> None:
    ws = _workspace(tmp_path)
    p = _seed_capture(ws, "old.db", age_hours=48)
    report = plan(ws, age_hours=24.0)
    final = execute(report, dry_run=True)
    assert p.exists()
    assert final.dry_run is True
    assert [c.path.name for c in final.deleted] == ["old.db"]


def test_execute_handles_missing_files(tmp_path: Path) -> None:
    ws = _workspace(tmp_path)
    p = _seed_capture(ws, "old.db", age_hours=48)
    report = plan(ws, age_hours=24.0)
    p.unlink()
    final = execute(report)
    assert final.deleted == []
    assert final.freed_bytes == 0


def test_to_dict_round_trip_shape(tmp_path: Path) -> None:
    ws = _workspace(tmp_path)
    _seed_capture(ws, "old.db", age_hours=48)
    _seed_capture(ws, "new.db", age_hours=1)
    report = plan(ws, age_hours=24.0)
    payload = report.to_dict()
    assert payload["age_threshold_hours"] == 24.0
    assert payload["dry_run"] is False
    assert isinstance(payload["deleted"], list)
    assert isinstance(payload["freed_bytes"], int)
