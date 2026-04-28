from __future__ import annotations

import argparse

from mitm_tracker.config import workspace_for
from mitm_tracker.output import (
    EXIT_INVALID_STATE,
    EXIT_OK,
    EXIT_SYSTEM,
    emit_error,
)


def register(subparsers: argparse._SubParsersAction) -> None:
    parser = subparsers.add_parser(
        "tray",
        help="Show a macOS menu bar indicator (green=running, red=stopped, yellow=crashed).",
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=2.0,
        help="Polling interval in seconds (default: 2.0).",
    )
    parser.add_argument("--json", action="store_true", dest="json_mode")
    parser.set_defaults(func=cmd_tray)


def cmd_tray(args: argparse.Namespace) -> int:
    workspace = workspace_for()
    if not workspace.base.exists():
        return emit_error(
            "no_workspace",
            f"no workspace at {workspace.base}; run `mitm-tracker record start` or any "
            "other command to bootstrap one first",
            json_mode=args.json_mode,
            exit_code=EXIT_INVALID_STATE,
        )

    try:
        import rumps  # noqa: F401
    except ImportError:
        return emit_error(
            "rumps_missing",
            "rumps is not installed; install with: pipx inject mitm-tracker rumps",
            json_mode=args.json_mode,
            exit_code=EXIT_SYSTEM,
        )

    from mitm_tracker.tray_app import TrayApp

    TrayApp(workspace, interval=args.interval).run()
    return EXIT_OK
