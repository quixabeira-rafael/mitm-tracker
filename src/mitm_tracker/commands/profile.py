from __future__ import annotations

import argparse

from mitm_tracker.config import workspace_for
from mitm_tracker.output import (
    EXIT_INVALID_STATE,
    EXIT_OK,
    emit_error,
    emit_json,
    emit_text,
    render_table,
)
from mitm_tracker.profile_manager import ProfileError, ProfileManager


def register(subparsers: argparse._SubParsersAction) -> None:
    profile_parser = subparsers.add_parser(
        "profile", help="Manage capture profiles (each has its own SSL list)."
    )
    sub = profile_parser.add_subparsers(dest="profile_command", metavar="ACTION")
    sub.required = True

    create_p = sub.add_parser("create", help="Create a new profile.")
    create_p.add_argument("name")
    create_p.add_argument("--use", action="store_true", help="Activate after creating.")
    create_p.add_argument("--json", action="store_true", dest="json_mode")
    create_p.set_defaults(func=cmd_create)

    use_p = sub.add_parser("use", help="Switch the active profile.")
    use_p.add_argument("name")
    use_p.add_argument("--json", action="store_true", dest="json_mode")
    use_p.set_defaults(func=cmd_use)

    list_p = sub.add_parser("list", help="List all profiles.")
    list_p.add_argument("--json", action="store_true", dest="json_mode")
    list_p.set_defaults(func=cmd_list)

    show_p = sub.add_parser("show", help="Show details of the active or named profile.")
    show_p.add_argument("name", nargs="?")
    show_p.add_argument("--json", action="store_true", dest="json_mode")
    show_p.set_defaults(func=cmd_show)

    delete_p = sub.add_parser("delete", help="Delete a profile (cannot be 'default').")
    delete_p.add_argument("name")
    delete_p.add_argument("--json", action="store_true", dest="json_mode")
    delete_p.set_defaults(func=cmd_delete)


def _manager() -> ProfileManager:
    workspace = workspace_for()
    workspace.ensure()
    return ProfileManager(workspace)


def cmd_create(args: argparse.Namespace) -> int:
    pm = _manager()
    try:
        created = pm.create(args.name)
    except ProfileError as exc:
        return emit_error(
            "invalid_profile", str(exc), json_mode=args.json_mode, exit_code=EXIT_INVALID_STATE
        )
    if args.use:
        try:
            pm.set_active(args.name)
        except ProfileError as exc:
            return emit_error(
                "invalid_profile",
                str(exc),
                json_mode=args.json_mode,
                exit_code=EXIT_INVALID_STATE,
            )
    payload = {
        "created": created,
        "name": args.name,
        "active": pm.active_name(),
    }
    if args.json_mode:
        emit_json(payload)
    else:
        msg = "created" if created else "already exists"
        emit_text(
            f"{msg}: {args.name}"
            + (f" (active: {payload['active']})" if args.use else "")
        )
    return EXIT_OK


def cmd_use(args: argparse.Namespace) -> int:
    pm = _manager()
    try:
        pm.set_active(args.name)
    except ProfileError as exc:
        return emit_error(
            "invalid_profile", str(exc), json_mode=args.json_mode, exit_code=EXIT_INVALID_STATE
        )
    payload = {"active": pm.active_name()}
    if args.json_mode:
        emit_json(payload)
    else:
        emit_text(f"active profile: {payload['active']}")
    return EXIT_OK


def cmd_list(args: argparse.Namespace) -> int:
    pm = _manager()
    profiles = [p.to_dict() for p in pm.describe_all()]
    if args.json_mode:
        emit_json({"active": pm.active_name(), "profiles": profiles})
    elif not profiles:
        emit_text("(no profiles)")
    else:
        rows = [
            {
                "name": p["name"],
                "active": "yes" if p["is_active"] else "no",
                "ssl_count": p["ssl_count"],
            }
            for p in profiles
        ]
        emit_text(
            render_table(
                rows,
                columns=[
                    ("name", "NAME"),
                    ("active", "ACTIVE"),
                    ("ssl_count", "SSL HOSTS"),
                ],
            )
        )
    return EXIT_OK


def cmd_show(args: argparse.Namespace) -> int:
    pm = _manager()
    try:
        info = pm.describe(args.name)
    except ProfileError as exc:
        return emit_error(
            "profile_not_found",
            str(exc),
            json_mode=args.json_mode,
            exit_code=EXIT_INVALID_STATE,
        )
    if args.json_mode:
        emit_json(info.to_dict())
    else:
        marker = " (active)" if info.is_active else ""
        emit_text(
            f"{info.name}{marker}\n"
            f"ssl hosts: {info.ssl_count}"
        )
    return EXIT_OK


def cmd_delete(args: argparse.Namespace) -> int:
    pm = _manager()
    try:
        deleted = pm.delete(args.name)
    except ProfileError as exc:
        return emit_error(
            "invalid_profile",
            str(exc),
            json_mode=args.json_mode,
            exit_code=EXIT_INVALID_STATE,
        )
    payload = {
        "deleted": deleted,
        "name": args.name,
        "active": pm.active_name(),
    }
    if args.json_mode:
        emit_json(payload)
    else:
        msg = "deleted" if deleted else "not found"
        emit_text(f"{msg}: {args.name}")
    return EXIT_OK
