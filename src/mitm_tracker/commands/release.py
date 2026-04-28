from __future__ import annotations

import argparse
from pathlib import Path

from mitm_tracker import release as release_module
from mitm_tracker.config import workspace_for
from mitm_tracker.output import (
    EXIT_INVALID_STATE,
    EXIT_OK,
    emit_error,
    emit_json,
    emit_text,
    render_table,
)
from mitm_tracker.release import ReleaseError, ReleaseReport
from mitm_tracker.session_manager import SessionManager


def register(subparsers: argparse._SubParsersAction) -> None:
    parser = subparsers.add_parser(
        "release",
        help="Delete capture databases older than a threshold to reclaim disk space.",
    )
    parser.add_argument(
        "--older-than",
        default="24h",
        help="Age threshold (e.g. 24h, 7d, 30m). Files older than this are deleted.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be deleted without actually removing files.",
    )
    parser.add_argument(
        "--no-keep-active",
        action="store_true",
        help="Allow deletion of the active session DB (default: protect it).",
    )
    parser.add_argument("--json", action="store_true", dest="json_mode")
    parser.set_defaults(func=cmd_release)


def cmd_release(args: argparse.Namespace) -> int:
    workspace = workspace_for()
    workspace.ensure()

    try:
        age_hours = release_module.parse_age_hours(args.older_than)
    except ReleaseError as exc:
        return emit_error(
            "invalid_age",
            str(exc),
            json_mode=args.json_mode,
            exit_code=EXIT_INVALID_STATE,
        )

    sm = SessionManager(workspace)
    state = sm.read_state()
    active_session = _path_or_none(state.get("active_session"))
    running_session = (
        _path_or_none(state.get("session_db")) if state.get("running") else None
    )

    plan = release_module.plan(
        workspace,
        age_hours=age_hours,
        keep_active=not args.no_keep_active,
        active_session=active_session,
        running_session=running_session,
    )
    report = release_module.execute(plan, dry_run=args.dry_run)

    if args.json_mode:
        emit_json(report.to_dict())
        return EXIT_OK

    _render_text(report)
    return EXIT_OK


def _path_or_none(value) -> Path | None:
    if not value:
        return None
    return Path(str(value))


def _render_text(report: ReleaseReport) -> None:
    label = "would delete" if report.dry_run else "deleted"
    if not report.deleted:
        if report.dry_run:
            emit_text("(no files would be deleted)")
        else:
            emit_text("(nothing to delete)")
    else:
        rows = [c.to_dict() for c in report.deleted]
        emit_text(
            f"{label} {len(report.deleted)} file(s), "
            f"{_format_bytes(report.freed_bytes)} freed:"
        )
        emit_text(
            render_table(
                rows,
                columns=[
                    ("name", "NAME"),
                    ("age_hours", "AGE_H"),
                    ("size_bytes", "BYTES"),
                ],
            )
        )

    if report.skipped_running:
        names = ", ".join(c.path.name for c in report.skipped_running)
        emit_text(f"skipped (running): {names}")
    if report.skipped_active:
        names = ", ".join(c.path.name for c in report.skipped_active)
        emit_text(f"skipped (active): {names}")
    if report.kept:
        emit_text(f"kept (within threshold): {len(report.kept)} file(s)")


def _format_bytes(num: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if num < 1024 or unit == "GB":
            return f"{num:.1f} {unit}" if unit != "B" else f"{num} {unit}"
        num /= 1024
    return f"{num:.1f} GB"
