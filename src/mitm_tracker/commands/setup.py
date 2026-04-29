from __future__ import annotations

import argparse
from pathlib import Path

from mitm_tracker import auth_setup, tray_launch_agent
from mitm_tracker.config import workspace_for
from mitm_tracker.output import (
    EXIT_INVALID_STATE,
    EXIT_OK,
    EXIT_SYSTEM,
    emit_error,
    emit_json,
    emit_text,
)
from mitm_tracker.proxy_manager import _default_privileged_runner

_TMPDIR = Path.home() / ".mitm-tracker-setup-tmp"


def register(subparsers: argparse._SubParsersAction) -> None:
    parser = subparsers.add_parser(
        "setup",
        help="Configure Touch ID, extend the sudo cache, and install the tray LaunchAgent.",
    )
    sub = parser.add_subparsers(dest="setup_action", metavar="ACTION")
    sub.required = True

    install_p = sub.add_parser(
        "install",
        help="Configure Touch ID + sudo cache + tray. One auth, then Touch ID for everything else.",
    )
    install_p.add_argument(
        "--workspace",
        help="Workspace path the tray should monitor (default: current working directory).",
    )
    install_p.add_argument("--skip-touch-id", action="store_true")
    install_p.add_argument("--skip-sudo-cache", action="store_true")
    install_p.add_argument("--skip-tray", action="store_true")
    install_p.add_argument("--json", action="store_true", dest="json_mode")
    install_p.set_defaults(func=cmd_install)

    uninstall_p = sub.add_parser(
        "uninstall",
        help="Revert Touch ID, sudo cache, and tray LaunchAgent.",
    )
    uninstall_p.add_argument("--json", action="store_true", dest="json_mode")
    uninstall_p.set_defaults(func=cmd_uninstall)

    status_p = sub.add_parser(
        "status",
        help="Show whether Touch ID, sudo cache, and tray are configured.",
    )
    status_p.add_argument("--json", action="store_true", dest="json_mode")
    status_p.set_defaults(func=cmd_status)


def cmd_install(args: argparse.Namespace) -> int:
    if args.skip_touch_id and args.skip_sudo_cache and args.skip_tray:
        return emit_error(
            "nothing_to_do",
            "all components were skipped via --skip-* flags",
            json_mode=args.json_mode,
            exit_code=EXIT_INVALID_STATE,
        )

    payload: dict = {"tray": None, "auth_setup": None}

    if not args.skip_tray:
        workspace_path = (
            Path(args.workspace).expanduser().resolve()
            if args.workspace
            else Path.cwd()
        )
        if not workspace_path.is_dir():
            return emit_error(
                "workspace_not_found",
                f"workspace path is not a directory: {workspace_path}",
                json_mode=args.json_mode,
                exit_code=EXIT_INVALID_STATE,
            )
        binary = tray_launch_agent.resolve_binary()
        if not binary.exists():
            return emit_error(
                "binary_not_found",
                f"mitm-tracker binary not found: {binary}",
                json_mode=args.json_mode,
                exit_code=EXIT_SYSTEM,
            )
        tray_result = tray_launch_agent.install(workspace_path, binary=binary)
        payload["tray"] = tray_result.to_dict()

    if not (args.skip_touch_id and args.skip_sudo_cache):
        try:
            auth_result = auth_setup.install(
                privileged_runner=_default_privileged_runner,
                tmpdir=_TMPDIR,
                skip_touch_id=args.skip_touch_id,
                skip_sudo_cache=args.skip_sudo_cache,
            )
        except auth_setup.AuthSetupError as exc:
            return emit_error(
                "auth_setup_failed",
                str(exc),
                json_mode=args.json_mode,
                exit_code=EXIT_SYSTEM,
            )
        payload["auth_setup"] = auth_result.to_dict()

    if args.json_mode:
        emit_json(payload)
    else:
        _render_install_text(payload)
    return EXIT_OK


def cmd_uninstall(args: argparse.Namespace) -> int:
    payload: dict = {"tray": None, "auth_setup": None}

    tray_result = tray_launch_agent.uninstall()
    payload["tray"] = tray_result.to_dict()

    try:
        auth_result = auth_setup.uninstall(
            privileged_runner=_default_privileged_runner,
            tmpdir=_TMPDIR,
        )
    except auth_setup.AuthSetupError as exc:
        return emit_error(
            "auth_setup_failed",
            str(exc),
            json_mode=args.json_mode,
            exit_code=EXIT_SYSTEM,
        )
    payload["auth_setup"] = auth_result.to_dict()

    if args.json_mode:
        emit_json(payload)
    else:
        _render_uninstall_text(payload)
    return EXIT_OK


def cmd_status(args: argparse.Namespace) -> int:
    auth_status = auth_setup.status()
    tray_status = tray_launch_agent.status()
    payload = {
        "auth_setup": auth_status.to_dict(),
        "tray": tray_status.to_dict(),
    }
    if args.json_mode:
        emit_json(payload)
    else:
        emit_text(
            f"Touch ID:        {auth_status.touch_id_configured}\n"
            f"sudo cache:      {auth_status.sudo_cache_configured}\n"
            f"tray installed:  {tray_status.installed}\n"
            f"tray loaded:     {tray_status.loaded}\n"
            f"tray pid:        {tray_status.pid if tray_status.pid is not None else '-'}\n"
            f"tray workspace:  {tray_status.workspace if tray_status.workspace else '-'}"
        )
    return EXIT_OK


def _render_install_text(payload: dict) -> None:
    tray = payload.get("tray")
    auth = payload.get("auth_setup")
    lines: list[str] = []
    if tray is not None:
        verb = "replaced" if tray["replaced_existing"] else "installed"
        lines.append(f"tray:       {verb} ({tray['plist_path']}, loaded={tray['loaded']})")
    if auth is not None:
        if auth["invoked_privileged"]:
            ti = auth["touch_id"]
            sc = auth["sudo_cache"]
            lines.append(
                f"touch_id:   line_added={ti['line_added']} (already_present={ti['already_present']})"
            )
            lines.append(
                f"sudo_cache: written={sc['written']} validated={sc['validated']} "
                f"(already_present={sc['already_present']})"
            )
        else:
            lines.append("touch_id + sudo_cache: already configured (no changes)")
    emit_text("\n".join(lines))


def _render_uninstall_text(payload: dict) -> None:
    tray = payload.get("tray") or {}
    auth = payload.get("auth_setup") or {}
    lines = [
        f"tray:       removed={tray.get('plist_removed', False)} (was_loaded={tray.get('was_loaded', False)})",
        f"touch_id:   removed={auth.get('pam_local_removed', False)} stripped={auth.get('pam_local_line_stripped', False)}",
        f"sudo_cache: removed={auth.get('sudoers_removed', False)} skipped_unmanaged={auth.get('sudoers_skipped_unmanaged', False)}",
    ]
    emit_text("\n".join(lines))
