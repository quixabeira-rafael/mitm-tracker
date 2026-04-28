from __future__ import annotations

import argparse

from mitm_tracker.config import Workspace, workspace_for
from mitm_tracker.output import (
    EXIT_INVALID_STATE,
    EXIT_OK,
    emit_error,
    emit_json,
    emit_text,
    render_table,
)
from mitm_tracker.profile_manager import ProfileError, ProfileManager
from mitm_tracker.ssl_list import SslList, SslListError


def register(subparsers: argparse._SubParsersAction) -> None:
    ssl_parser = subparsers.add_parser("ssl", help="Manage the SSL decryption list.")
    ssl_sub = ssl_parser.add_subparsers(dest="ssl_command", metavar="ACTION")
    ssl_sub.required = True

    add_p = ssl_sub.add_parser("add", help="Add a domain pattern to the SSL list.")
    add_p.add_argument("pattern")
    add_p.add_argument("--profile", help="Operate on this profile (default: active).")
    add_p.add_argument("--json", action="store_true", dest="json_mode")
    add_p.set_defaults(func=cmd_add)

    rm_p = ssl_sub.add_parser("remove", help="Remove a pattern from the SSL list.")
    rm_p.add_argument("pattern")
    rm_p.add_argument("--profile", help="Operate on this profile (default: active).")
    rm_p.add_argument("--json", action="store_true", dest="json_mode")
    rm_p.set_defaults(func=cmd_remove)

    list_p = ssl_sub.add_parser("list", help="List SSL patterns.")
    list_p.add_argument("--profile", help="Operate on this profile (default: active).")
    list_p.add_argument("--json", action="store_true", dest="json_mode")
    list_p.set_defaults(func=cmd_list)


def _resolve_profile(workspace: Workspace, requested: str | None) -> tuple[ProfileManager, str] | int:
    pm = ProfileManager(workspace)
    target = requested or pm.active_name()
    if not pm.exists(target):
        try:
            pm.create(target)
        except ProfileError:
            return EXIT_INVALID_STATE
    return pm, target


def _load(workspace: Workspace, profile: str) -> SslList:
    workspace.ensure()
    return SslList.load(workspace.ssl_path(profile))


def cmd_add(args: argparse.Namespace) -> int:
    workspace = workspace_for()
    workspace.ensure()
    pm = ProfileManager(workspace)
    profile = args.profile or pm.active_name()
    if not pm.exists(profile):
        return emit_error(
            "profile_not_found",
            f"profile {profile!r} does not exist; create it with `mitm-tracker profile create {profile}`",
            json_mode=args.json_mode,
            exit_code=EXIT_INVALID_STATE,
        )
    try:
        sl = _load(workspace, profile)
        added = sl.add(args.pattern)
    except SslListError as exc:
        return emit_error(
            "invalid_pattern", str(exc), json_mode=args.json_mode, exit_code=EXIT_INVALID_STATE
        )
    sl.save()
    payload = {
        "added": added,
        "pattern": args.pattern.strip().lower(),
        "count": len(sl.entries),
        "profile": profile,
        "ssl_path": str(workspace.ssl_path(profile)),
    }
    if args.json_mode:
        emit_json(payload)
    else:
        msg = "added" if added else "already present"
        emit_text(
            f"[{profile}] {msg}: {payload['pattern']} ({payload['count']} total)"
        )
    return EXIT_OK


def cmd_remove(args: argparse.Namespace) -> int:
    workspace = workspace_for()
    workspace.ensure()
    pm = ProfileManager(workspace)
    profile = args.profile or pm.active_name()
    if not pm.exists(profile):
        return emit_error(
            "profile_not_found",
            f"profile {profile!r} does not exist",
            json_mode=args.json_mode,
            exit_code=EXIT_INVALID_STATE,
        )
    try:
        sl = _load(workspace, profile)
    except SslListError as exc:
        return emit_error(
            "invalid_state", str(exc), json_mode=args.json_mode, exit_code=EXIT_INVALID_STATE
        )
    removed = sl.remove(args.pattern)
    if removed:
        sl.save()
    payload = {
        "removed": removed,
        "pattern": args.pattern.strip().lower(),
        "count": len(sl.entries),
        "profile": profile,
        "ssl_path": str(workspace.ssl_path(profile)),
    }
    if args.json_mode:
        emit_json(payload)
    else:
        msg = "removed" if removed else "not found"
        emit_text(
            f"[{profile}] {msg}: {payload['pattern']} ({payload['count']} total)"
        )
    return EXIT_OK


def cmd_list(args: argparse.Namespace) -> int:
    workspace = workspace_for()
    workspace.ensure()
    pm = ProfileManager(workspace)
    profile = args.profile or pm.active_name()
    if not pm.exists(profile):
        return emit_error(
            "profile_not_found",
            f"profile {profile!r} does not exist",
            json_mode=args.json_mode,
            exit_code=EXIT_INVALID_STATE,
        )
    try:
        sl = _load(workspace, profile)
    except SslListError as exc:
        return emit_error(
            "invalid_state", str(exc), json_mode=args.json_mode, exit_code=EXIT_INVALID_STATE
        )
    entries = [e.to_dict() for e in sl.entries]
    if args.json_mode:
        emit_json(
            {
                "profile": profile,
                "ssl_path": str(workspace.ssl_path(profile)),
                "count": len(entries),
                "patterns": entries,
            }
        )
    elif not entries:
        emit_text(f"[{profile}] (empty)")
    else:
        emit_text(
            f"[{profile}]\n"
            + render_table(
                entries,
                columns=[("pattern", "PATTERN"), ("added_at", "ADDED")],
            )
        )
    return EXIT_OK
