from __future__ import annotations

import re
import time
from dataclasses import dataclass
from pathlib import Path

from mitm_tracker.config import Workspace

DEFAULT_AGE_HOURS = 24.0


class ReleaseError(RuntimeError):
    pass


@dataclass(frozen=True)
class CandidateFile:
    path: Path
    size_bytes: int
    mtime: float
    age_seconds: float

    def to_dict(self) -> dict:
        return {
            "name": self.path.name,
            "path": str(self.path),
            "size_bytes": self.size_bytes,
            "age_hours": round(self.age_seconds / 3600.0, 2),
        }


@dataclass(frozen=True)
class ReleaseReport:
    deleted: list[CandidateFile]
    kept: list[CandidateFile]
    skipped_active: list[CandidateFile]
    skipped_running: list[CandidateFile]
    freed_bytes: int
    age_threshold_hours: float
    dry_run: bool
    keep_active: bool

    def to_dict(self) -> dict:
        return {
            "dry_run": self.dry_run,
            "age_threshold_hours": self.age_threshold_hours,
            "keep_active": self.keep_active,
            "deleted": [c.to_dict() for c in self.deleted],
            "kept": [c.to_dict() for c in self.kept],
            "skipped_active": [c.to_dict() for c in self.skipped_active],
            "skipped_running": [c.to_dict() for c in self.skipped_running],
            "freed_bytes": self.freed_bytes,
        }


def parse_age_hours(value: str | float | int) -> float:
    if isinstance(value, (int, float)):
        if value < 0:
            raise ReleaseError(f"age must be >= 0, got {value!r}")
        return float(value)
    text = str(value).strip().lower()
    if not text:
        raise ReleaseError("empty age value")
    match = re.match(r"^(\d+(?:\.\d+)?)\s*(h|hr|hrs|hour|hours|d|day|days|m|min|minutes)?$", text)
    if not match:
        raise ReleaseError(
            f"invalid age {value!r}: use formats like '24h', '7d', '30m', or a number of hours"
        )
    amount = float(match.group(1))
    unit = match.group(2) or "h"
    if unit in {"h", "hr", "hrs", "hour", "hours"}:
        return amount
    if unit in {"d", "day", "days"}:
        return amount * 24.0
    if unit in {"m", "min", "minutes"}:
        return amount / 60.0
    raise ReleaseError(f"unsupported age unit {unit!r}")


def list_capture_files(workspace: Workspace) -> list[Path]:
    captures_dir = workspace.captures_dir
    if not captures_dir.exists():
        return []
    return sorted(captures_dir.glob("*.db"))


def plan(
    workspace: Workspace,
    *,
    age_hours: float = DEFAULT_AGE_HOURS,
    keep_active: bool = True,
    active_session: Path | None = None,
    running_session: Path | None = None,
    now: float | None = None,
) -> ReleaseReport:
    if age_hours < 0:
        raise ReleaseError(f"age_hours must be >= 0, got {age_hours}")
    threshold_seconds = age_hours * 3600.0
    reference = now if now is not None else time.time()

    deleted: list[CandidateFile] = []
    kept: list[CandidateFile] = []
    skipped_active: list[CandidateFile] = []
    skipped_running: list[CandidateFile] = []

    active_resolved = _resolve(active_session)
    running_resolved = _resolve(running_session)

    for path in list_capture_files(workspace):
        try:
            stat = path.stat()
        except FileNotFoundError:
            continue
        age = max(reference - stat.st_mtime, 0.0)
        candidate = CandidateFile(
            path=path,
            size_bytes=stat.st_size,
            mtime=stat.st_mtime,
            age_seconds=age,
        )
        resolved = path.resolve()
        if running_resolved == resolved:
            skipped_running.append(candidate)
            continue
        if keep_active and active_resolved == resolved:
            skipped_active.append(candidate)
            continue
        if age >= threshold_seconds:
            deleted.append(candidate)
        else:
            kept.append(candidate)

    return ReleaseReport(
        deleted=deleted,
        kept=kept,
        skipped_active=skipped_active,
        skipped_running=skipped_running,
        freed_bytes=sum(c.size_bytes for c in deleted),
        age_threshold_hours=age_hours,
        dry_run=False,
        keep_active=keep_active,
    )


def execute(report: ReleaseReport, *, dry_run: bool = False) -> ReleaseReport:
    if dry_run:
        return ReleaseReport(
            deleted=report.deleted,
            kept=report.kept,
            skipped_active=report.skipped_active,
            skipped_running=report.skipped_running,
            freed_bytes=report.freed_bytes,
            age_threshold_hours=report.age_threshold_hours,
            dry_run=True,
            keep_active=report.keep_active,
        )
    actually_deleted: list[CandidateFile] = []
    freed = 0
    for candidate in report.deleted:
        try:
            candidate.path.unlink()
        except FileNotFoundError:
            continue
        actually_deleted.append(candidate)
        freed += candidate.size_bytes
        for sidecar_suffix in (".db-wal", ".db-shm", ".db-journal"):
            sidecar = candidate.path.with_name(candidate.path.name + sidecar_suffix.replace(".db", ""))
            sidecar.unlink(missing_ok=True)
    return ReleaseReport(
        deleted=actually_deleted,
        kept=report.kept,
        skipped_active=report.skipped_active,
        skipped_running=report.skipped_running,
        freed_bytes=freed,
        age_threshold_hours=report.age_threshold_hours,
        dry_run=False,
        keep_active=report.keep_active,
    )


def _resolve(path: Path | None) -> Path | None:
    if path is None:
        return None
    try:
        return Path(path).resolve()
    except OSError:
        return None
