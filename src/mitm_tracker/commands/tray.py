from __future__ import annotations

import argparse
from pathlib import Path

from mitm_tracker import tray_launch_agent
from mitm_tracker.config import workspace_for
from mitm_tracker.output import (
    EXIT_INVALID_STATE,
    EXIT_OK,
    EXIT_SYSTEM,
    emit_error,
    emit_json,
    emit_text,
)


def register(subparsers: argparse._SubParsersAction) -> None:
    parser = subparsers.add_parser(
        "tray",
        help="macOS menu bar indicator (green=running, red=stopped, yellow=crashed).",
    )
    sub = parser.add_subparsers(dest="tray_action", metavar="ACTION")
    sub.required = False

    run_p = sub.add_parser("run", help="Open the menu bar indicator (default action).")
    run_p.add_argument(
        "--interval",
        type=float,
        default=2.0,
        help="Polling interval in seconds (default: 2.0).",
    )
    run_p.add_argument("--json", action="store_true", dest="json_mode")
    run_p.set_defaults(func=cmd_run)

    install_p = sub.add_parser(
        "install",
        help="Install a LaunchAgent so the tray opens automatically on login.",
    )
    install_p.add_argument(
        "--workspace",
        help="Workspace path the tray should monitor (default: current working directory).",
    )
    install_p.add_argument(
        "--binary",
        help="Absolute path to the mitm-tracker binary (default: resolved from PATH).",
    )
    install_p.add_argument("--json", action="store_true", dest="json_mode")
    install_p.set_defaults(func=cmd_install)

    uninstall_p = sub.add_parser(
        "uninstall",
        help="Remove the LaunchAgent (the tray will no longer auto-start on login).",
    )
    uninstall_p.add_argument("--json", action="store_true", dest="json_mode")
    uninstall_p.set_defaults(func=cmd_uninstall)

    status_p = sub.add_parser(
        "status",
        help="Show whether the LaunchAgent is installed and loaded.",
    )
    status_p.add_argument("--json", action="store_true", dest="json_mode")
    status_p.set_defaults(func=cmd_status)

    parser.set_defaults(
        func=cmd_run,
        interval=2.0,
        json_mode=False,
    )


def cmd_run(args: argparse.Namespace) -> int:
    workspace = workspace_for()
    workspace.ensure()

    try:
        import rumps  # noqa: F401
    except ImportError:
        return emit_error(
            "rumps_missing",
            "rumps is not installed; install with: pipx install -e \".[tray]\" --force",
            json_mode=args.json_mode,
            exit_code=EXIT_SYSTEM,
        )

    from mitm_tracker.tray_app import TrayApp

    TrayApp(workspace, interval=args.interval).run()
    return EXIT_OK


def cmd_install(args: argparse.Namespace) -> int:
    workspace_path = Path(args.workspace).expanduser().resolve() if args.workspace else Path.cwd()
    if not workspace_path.is_dir():
        return emit_error(
            "workspace_not_found",
            f"workspace path is not a directory: {workspace_path}",
            json_mode=args.json_mode,
            exit_code=EXIT_INVALID_STATE,
        )

    binary = Path(args.binary).expanduser().resolve() if args.binary else tray_launch_agent.resolve_binary()
    if not binary.exists():
        return emit_error(
            "binary_not_found",
            f"mitm-tracker binary not found: {binary}",
            json_mode=args.json_mode,
            exit_code=EXIT_SYSTEM,
        )

    result = tray_launch_agent.install(workspace_path, binary=binary)

    if args.json_mode:
        emit_json(result.to_dict())
    else:
        verb = "replaced" if result.replaced_existing else "installed"
        emit_text(
            f"{verb} LaunchAgent at {result.plist_path}\n"
            f"  workspace: {result.workspace}\n"
            f"  binary:    {result.binary}\n"
            f"  log:       {result.log_path}\n"
            f"  loaded:    {result.loaded}"
        )
    return EXIT_OK


def cmd_uninstall(args: argparse.Namespace) -> int:
    result = tray_launch_agent.uninstall()

    if args.json_mode:
        emit_json(result.to_dict())
    else:
        if not result.plist_removed and not result.was_loaded:
            emit_text("LaunchAgent not installed; nothing to do")
        else:
            emit_text(
                f"removed LaunchAgent at {result.plist_path}\n"
                f"  was_loaded: {result.was_loaded}\n"
                f"  removed:    {result.plist_removed}"
            )
    return EXIT_OK


def cmd_status(args: argparse.Namespace) -> int:
    result = tray_launch_agent.status()

    if args.json_mode:
        emit_json(result.to_dict())
    else:
        emit_text(
            f"plist:     {result.plist_path}\n"
            f"installed: {result.installed}\n"
            f"loaded:    {result.loaded}\n"
            f"pid:       {result.pid if result.pid is not None else '-'}\n"
            f"workspace: {result.workspace if result.workspace else '-'}"
        )
    return EXIT_OK
