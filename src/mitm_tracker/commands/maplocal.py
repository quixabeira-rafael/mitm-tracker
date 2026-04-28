from __future__ import annotations

import argparse
import json
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from mitm_tracker.config import workspace_for
from mitm_tracker.maplocal import (
    MapLocalError,
    MapLocalRule,
    MapLocalSource,
    MapLocalStore,
)
from mitm_tracker.output import (
    EXIT_INVALID_STATE,
    EXIT_OK,
    EXIT_SYSTEM,
    emit_error,
    emit_json,
    emit_text,
    render_table,
)
from mitm_tracker.profile_manager import ProfileManager
from mitm_tracker.session_manager import SessionManager
from mitm_tracker.store import FlowStore
from mitm_tracker.url_matcher import (
    ALL_QUERY_MODES,
    QUERY_MODE_IGNORE,
)


def register(subparsers: argparse._SubParsersAction) -> None:
    parser = subparsers.add_parser(
        "maplocal",
        help="Override responses with local files (Charles Proxy-style Map Local).",
    )
    sub = parser.add_subparsers(dest="maplocal_command", metavar="ACTION")
    sub.required = True

    add_p = sub.add_parser("add", help="Create a new map local rule (manual).")
    add_p.add_argument("url_pattern", help="URL pattern, e.g. https://api.example.com/users/*")
    add_p.add_argument("--status", type=int, default=200)
    add_p.add_argument(
        "--header",
        action="append",
        default=[],
        help="Response header in form 'Key: Value' (repeatable).",
    )
    add_p.add_argument(
        "--body-file",
        help="Path to a file whose contents become the response body.",
    )
    add_p.add_argument(
        "--query-mode",
        choices=ALL_QUERY_MODES,
        default=QUERY_MODE_IGNORE,
    )
    add_p.add_argument("--description")
    add_p.add_argument("--profile", help="Profile (default: active).")
    add_p.add_argument("--json", action="store_true", dest="json_mode")
    add_p.set_defaults(func=cmd_add)

    from_p = sub.add_parser(
        "from-flow",
        help="Create a rule by copying the response of a captured flow.",
    )
    from_p.add_argument("seq", type=int)
    from_p.add_argument(
        "--query-mode",
        choices=ALL_QUERY_MODES,
        default=QUERY_MODE_IGNORE,
    )
    from_p.add_argument("--description")
    from_p.add_argument("--profile", help="Profile (default: active).")
    from_p.add_argument("--json", action="store_true", dest="json_mode")
    from_p.set_defaults(func=cmd_from_flow)

    list_p = sub.add_parser("list", help="List rules in the active profile.")
    list_p.add_argument("--profile", help="Profile (default: active).")
    list_p.add_argument("--json", action="store_true", dest="json_mode")
    list_p.set_defaults(func=cmd_list)

    show_p = sub.add_parser("show", help="Show details of a rule.")
    show_p.add_argument("rule_id")
    show_p.add_argument("--profile")
    show_p.add_argument("--json", action="store_true", dest="json_mode")
    show_p.set_defaults(func=cmd_show)

    edit_p = sub.add_parser(
        "edit",
        help="Open the body or headers file in $EDITOR for the given rule.",
    )
    edit_p.add_argument("rule_id")
    edit_p.add_argument(
        "--headers",
        action="store_true",
        help="Edit the headers JSON file instead of the body.",
    )
    edit_p.add_argument("--profile")
    edit_p.add_argument("--json", action="store_true", dest="json_mode")
    edit_p.set_defaults(func=cmd_edit)

    enable_p = sub.add_parser("enable", help="Enable a rule.")
    enable_p.add_argument("rule_id")
    enable_p.add_argument("--profile")
    enable_p.add_argument("--json", action="store_true", dest="json_mode")
    enable_p.set_defaults(func=cmd_enable)

    disable_p = sub.add_parser("disable", help="Disable a rule.")
    disable_p.add_argument("rule_id")
    disable_p.add_argument("--profile")
    disable_p.add_argument("--json", action="store_true", dest="json_mode")
    disable_p.set_defaults(func=cmd_disable)

    rm_p = sub.add_parser("remove", help="Delete a rule (and its body/headers files).")
    rm_p.add_argument("rule_id")
    rm_p.add_argument(
        "--keep-files",
        action="store_true",
        help="Keep the body and headers files on disk.",
    )
    rm_p.add_argument("--profile")
    rm_p.add_argument("--json", action="store_true", dest="json_mode")
    rm_p.set_defaults(func=cmd_remove)


def _resolve_profile(json_mode: bool, requested: str | None):
    workspace = workspace_for()
    workspace.ensure()
    pm = ProfileManager(workspace)
    profile = requested or pm.active_name()
    if not pm.exists(profile):
        return None, emit_error(
            "profile_not_found",
            f"profile {profile!r} does not exist",
            json_mode=json_mode,
            exit_code=EXIT_INVALID_STATE,
        )
    return (workspace, profile), EXIT_OK


def _store(workspace, profile: str) -> MapLocalStore:
    store = MapLocalStore(profile_dir=workspace.profile_dir(profile))
    store.ensure()
    return store


def _parse_header_args(values: list[str]) -> list[tuple[str, str]]:
    headers: list[tuple[str, str]] = []
    for raw in values:
        if ":" not in raw:
            raise MapLocalError(
                f"invalid --header {raw!r}: expected 'Name: Value'"
            )
        name, _, value = raw.partition(":")
        headers.append((name.strip(), value.strip()))
    return headers


def cmd_add(args: argparse.Namespace) -> int:
    resolved, rc = _resolve_profile(args.json_mode, args.profile)
    if resolved is None:
        return rc
    workspace, profile = resolved
    store = _store(workspace, profile)

    body = b""
    if args.body_file:
        body_path = Path(args.body_file)
        if not body_path.exists():
            return emit_error(
                "body_file_missing",
                f"body file not found: {body_path}",
                json_mode=args.json_mode,
                exit_code=EXIT_INVALID_STATE,
            )
        body = body_path.read_bytes()

    try:
        headers = _parse_header_args(args.header)
        rule = store.add(
            url_pattern=args.url_pattern,
            query_mode=args.query_mode,
            status=args.status,
            headers=headers,
            body=body,
            description=args.description,
        )
    except MapLocalError as exc:
        return emit_error(
            "invalid_rule", str(exc), json_mode=args.json_mode, exit_code=EXIT_INVALID_STATE
        )

    payload = _rule_payload(store, rule, profile)
    if args.json_mode:
        emit_json(payload)
    else:
        emit_text(_render_added(rule, payload))
    return EXIT_OK


def cmd_from_flow(args: argparse.Namespace) -> int:
    resolved, rc = _resolve_profile(args.json_mode, args.profile)
    if resolved is None:
        return rc
    workspace, profile = resolved

    sm = SessionManager(workspace)
    db_path = sm.active_session_db()
    if db_path is None or not Path(db_path).exists():
        return emit_error(
            "no_session",
            "no active session DB found; run a record first or `query use <session>`",
            json_mode=args.json_mode,
            exit_code=EXIT_INVALID_STATE,
        )
    if not Path(db_path).is_absolute():
        db_path = workspace.root / db_path

    flow_store = FlowStore(Path(db_path), read_only=True)
    try:
        flow = flow_store.query_show_raw(args.seq)
    finally:
        flow_store.close()
    if flow is None:
        return emit_error(
            "flow_not_found",
            f"flow with seq={args.seq} not found in active session",
            json_mode=args.json_mode,
            exit_code=EXIT_INVALID_STATE,
        )
    if flow.get("response_status_code") is None:
        return emit_error(
            "flow_has_no_response",
            f"flow seq={args.seq} has no response yet (still pending or errored)",
            json_mode=args.json_mode,
            exit_code=EXIT_INVALID_STATE,
        )

    body = flow.get("response_body") or b""
    if isinstance(body, str):
        body = body.encode("utf-8")
    elif isinstance(body, dict) and "__bytes_b64__" in body:
        import base64

        body = base64.b64decode(body["__bytes_b64__"])

    headers_raw = flow.get("response_headers")
    headers: list[tuple[str, str]] = []
    if headers_raw:
        try:
            decoded = json.loads(
                headers_raw if isinstance(headers_raw, str) else headers_raw.decode("utf-8")
            )
            headers = [(str(k), str(v)) for k, v in decoded]
        except (json.JSONDecodeError, UnicodeDecodeError, TypeError):
            headers = []

    source = MapLocalSource(
        from_flow=int(args.seq),
        session_db=str(db_path),
        captured_at=datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
    )

    store = _store(workspace, profile)
    try:
        rule = store.add(
            url_pattern=str(flow.get("full_url") or ""),
            query_mode=args.query_mode,
            status=int(flow.get("response_status_code") or 200),
            headers=headers,
            body=body if isinstance(body, bytes) else b"",
            description=args.description
            or f"Copied from flow seq={args.seq} ({flow.get('host')}{flow.get('path')})",
            source=source,
        )
    except MapLocalError as exc:
        return emit_error(
            "invalid_rule", str(exc), json_mode=args.json_mode, exit_code=EXIT_INVALID_STATE
        )

    payload = _rule_payload(store, rule, profile)
    payload["next_step"] = (
        f"Edit {payload['body_path']} (and optionally {payload['headers_path']}) "
        "in your editor, then start record."
    )
    if args.json_mode:
        emit_json(payload)
    else:
        emit_text(
            f"[{profile}] created rule {rule.id} from flow seq={args.seq}\n"
            f"  url:     {rule.url_pattern}\n"
            f"  status:  {rule.status}\n"
            f"  body:    {payload['body_path']}\n"
            f"  headers: {payload['headers_path']}\n"
            f"  next:    edit the body file, then run `mitm-tracker record start`"
        )
    return EXIT_OK


def cmd_list(args: argparse.Namespace) -> int:
    resolved, rc = _resolve_profile(args.json_mode, args.profile)
    if resolved is None:
        return rc
    workspace, profile = resolved
    store = _store(workspace, profile)
    try:
        rules = store.load()
    except MapLocalError as exc:
        return emit_error(
            "invalid_state", str(exc), json_mode=args.json_mode, exit_code=EXIT_INVALID_STATE
        )

    payloads = [_rule_payload(store, r, profile) for r in rules]
    if args.json_mode:
        emit_json({"profile": profile, "count": len(payloads), "rules": payloads})
        return EXIT_OK

    if not payloads:
        emit_text(f"[{profile}] (no map local rules)")
        return EXIT_OK

    rows = [
        {
            "id": p["id"],
            "enabled": "yes" if p["enabled"] else "no",
            "status": p["status"],
            "query_mode": p["query_mode"],
            "url": p["url_pattern"],
        }
        for p in payloads
    ]
    emit_text(f"[{profile}]")
    emit_text(
        render_table(
            rows,
            columns=[
                ("id", "ID"),
                ("enabled", "ENABLED"),
                ("status", "STATUS"),
                ("query_mode", "QUERY"),
                ("url", "URL"),
            ],
        )
    )
    return EXIT_OK


def cmd_show(args: argparse.Namespace) -> int:
    resolved, rc = _resolve_profile(args.json_mode, args.profile)
    if resolved is None:
        return rc
    workspace, profile = resolved
    store = _store(workspace, profile)
    rule = store.find(args.rule_id)
    if rule is None:
        return emit_error(
            "rule_not_found",
            f"rule {args.rule_id!r} not found in profile {profile!r}",
            json_mode=args.json_mode,
            exit_code=EXIT_INVALID_STATE,
        )
    payload = _rule_payload(store, rule, profile)
    payload["headers"] = [list(h) for h in store.read_headers(rule.id)]
    payload["body_size_bytes"] = store.body_path(rule.id).stat().st_size if store.body_path(rule.id).exists() else 0
    if args.json_mode:
        emit_json(payload)
    else:
        emit_text(
            f"[{profile}] {rule.id}\n"
            f"  enabled:    {rule.enabled}\n"
            f"  url:        {rule.url_pattern}\n"
            f"  query_mode: {rule.query_mode}\n"
            f"  status:     {rule.status}\n"
            f"  body:       {payload['body_path']} ({payload['body_size_bytes']} bytes)\n"
            f"  headers:    {payload['headers_path']}\n"
            f"  desc:       {rule.description or ''}"
        )
    return EXIT_OK


def cmd_edit(args: argparse.Namespace) -> int:
    resolved, rc = _resolve_profile(args.json_mode, args.profile)
    if resolved is None:
        return rc
    workspace, profile = resolved
    store = _store(workspace, profile)
    rule = store.find(args.rule_id)
    if rule is None:
        return emit_error(
            "rule_not_found",
            f"rule {args.rule_id!r} not found",
            json_mode=args.json_mode,
            exit_code=EXIT_INVALID_STATE,
        )
    target = store.headers_path(rule.id) if args.headers else store.body_path(rule.id)
    editor = os.environ.get("EDITOR") or "vi"
    try:
        result = subprocess.run([editor, str(target)])
    except FileNotFoundError:
        return emit_error(
            "editor_not_found",
            f"$EDITOR {editor!r} not found",
            json_mode=args.json_mode,
            exit_code=EXIT_SYSTEM,
        )
    payload = {"rule_id": rule.id, "edited": str(target), "exit_code": result.returncode}
    if args.json_mode:
        emit_json(payload)
    else:
        emit_text(f"edited {target} (exit {result.returncode})")
    return EXIT_OK


def cmd_enable(args: argparse.Namespace) -> int:
    return _set_enabled(args, True)


def cmd_disable(args: argparse.Namespace) -> int:
    return _set_enabled(args, False)


def _set_enabled(args: argparse.Namespace, enabled: bool) -> int:
    resolved, rc = _resolve_profile(args.json_mode, args.profile)
    if resolved is None:
        return rc
    workspace, profile = resolved
    store = _store(workspace, profile)
    if not store.set_enabled(args.rule_id, enabled):
        return emit_error(
            "rule_not_found",
            f"rule {args.rule_id!r} not found",
            json_mode=args.json_mode,
            exit_code=EXIT_INVALID_STATE,
        )
    payload = {"rule_id": args.rule_id, "enabled": enabled, "profile": profile}
    if args.json_mode:
        emit_json(payload)
    else:
        emit_text(f"[{profile}] rule {args.rule_id}: {'enabled' if enabled else 'disabled'}")
    return EXIT_OK


def cmd_remove(args: argparse.Namespace) -> int:
    resolved, rc = _resolve_profile(args.json_mode, args.profile)
    if resolved is None:
        return rc
    workspace, profile = resolved
    store = _store(workspace, profile)
    removed = store.remove(args.rule_id, keep_files=args.keep_files)
    payload = {
        "rule_id": args.rule_id,
        "removed": removed,
        "kept_files": bool(args.keep_files),
        "profile": profile,
    }
    if args.json_mode:
        emit_json(payload)
    else:
        msg = "removed" if removed else "not found"
        emit_text(f"[{profile}] rule {args.rule_id}: {msg}")
    return EXIT_OK


def _rule_payload(store: MapLocalStore, rule: MapLocalRule, profile: str) -> dict[str, Any]:
    return {
        "id": rule.id,
        "enabled": rule.enabled,
        "url_pattern": rule.url_pattern,
        "query_mode": rule.query_mode,
        "status": rule.status,
        "description": rule.description,
        "profile": profile,
        "body_path": str(store.body_path(rule.id)),
        "headers_path": str(store.headers_path(rule.id)),
        "source": rule.source.to_dict(),
    }


def _render_added(rule: MapLocalRule, payload: dict[str, Any]) -> str:
    return (
        f"[{payload['profile']}] created {rule.id}\n"
        f"  url:     {rule.url_pattern}\n"
        f"  status:  {rule.status}\n"
        f"  body:    {payload['body_path']}\n"
        f"  headers: {payload['headers_path']}"
    )
