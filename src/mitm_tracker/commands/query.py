from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

from mitm_tracker.config import workspace_for
from mitm_tracker.curl_export import export_request
from mitm_tracker.output import (
    EXIT_INVALID_STATE,
    EXIT_OK,
    EXIT_SYSTEM,
    emit_error,
    emit_json,
    emit_text,
    render_table,
)
from mitm_tracker.session_manager import SessionManager
from mitm_tracker.store import FlowStore, ReadOnlyQueryError


def register(subparsers: argparse._SubParsersAction) -> None:
    query_parser = subparsers.add_parser(
        "query", help="Inspect captured flows from a session database."
    )
    sub = query_parser.add_subparsers(dest="query_command", metavar="ACTION")
    sub.required = True

    common = {"add_help": True}

    recent_p = sub.add_parser("recent", help="Show the most recent flows.")
    recent_p.add_argument("--limit", type=int, default=20)
    recent_p.add_argument("--host")
    recent_p.add_argument("--reverse", action="store_true")
    recent_p.add_argument("--json", action="store_true", dest="json_mode")
    recent_p.set_defaults(func=cmd_recent)

    fail_p = sub.add_parser("failures", help="Show flows with 4xx/5xx status or errors.")
    fail_p.add_argument("--limit", type=int, default=20)
    fail_p.add_argument("--json", action="store_true", dest="json_mode")
    fail_p.set_defaults(func=cmd_failures)

    slow_p = sub.add_parser("slow", help="Show flows slower than a threshold.")
    slow_p.add_argument("--threshold-ms", type=float, default=1000.0)
    slow_p.add_argument("--limit", type=int, default=20)
    slow_p.add_argument("--json", action="store_true", dest="json_mode")
    slow_p.set_defaults(func=cmd_slow)

    hosts_p = sub.add_parser("hosts", help="Aggregate captured flows by host.")
    hosts_p.add_argument("--json", action="store_true", dest="json_mode")
    hosts_p.set_defaults(func=cmd_hosts)

    show_p = sub.add_parser("show", help="Show a single flow by seq.")
    show_p.add_argument("seq", type=int)
    show_p.add_argument("--json", action="store_true", dest="json_mode")
    show_p.set_defaults(func=cmd_show)

    sql_p = sub.add_parser("sql", help="Run a read-only SELECT query against flows.")
    sql_p.add_argument("statement")
    sql_p.add_argument("--json", action="store_true", dest="json_mode")
    sql_p.set_defaults(func=cmd_sql)

    sessions_p = sub.add_parser("sessions", help="List recorded session databases.")
    sessions_p.add_argument("--json", action="store_true", dest="json_mode")
    sessions_p.set_defaults(func=cmd_sessions)

    use_p = sub.add_parser("use", help="Set the active session database.")
    use_p.add_argument("session", help="A session filename or absolute path.")
    use_p.add_argument("--json", action="store_true", dest="json_mode")
    use_p.set_defaults(func=cmd_use)

    curl_p = sub.add_parser(
        "curl",
        help="Reproduce the request as a curl command (rigorous, all headers preserved).",
    )
    curl_p.add_argument("seq", type=int)
    curl_p.add_argument(
        "--single-line",
        action="store_true",
        help="Render as a single line instead of multiline with backslashes.",
    )
    curl_p.add_argument(
        "--body-dir",
        help="Directory to write binary body files (default: current directory).",
    )
    curl_p.add_argument("--json", action="store_true", dest="json_mode")
    curl_p.set_defaults(func=cmd_curl)


def _open_active_store(json_mode: bool) -> tuple[FlowStore | None, int, str | None]:
    workspace = workspace_for()
    sm = SessionManager(workspace)
    db = sm.active_session_db()
    if db is None:
        sessions = sm.list_sessions()
        if not sessions:
            return None, emit_error(
                "no_sessions",
                "no record sessions found; run `mitm-tracker record start` first",
                json_mode=json_mode,
                exit_code=EXIT_INVALID_STATE,
            ), None
        db = sessions[0]
    if not db.is_absolute():
        db = (workspace.root / db).resolve()
    if not db.exists():
        return None, emit_error(
            "session_not_found",
            f"session db not found: {db}",
            json_mode=json_mode,
            exit_code=EXIT_INVALID_STATE,
        ), None
    try:
        store = FlowStore(db, read_only=True)
    except Exception as exc:
        return None, emit_error(
            "open_failed",
            f"failed to open {db}: {exc}",
            json_mode=json_mode,
            exit_code=EXIT_SYSTEM,
        ), None
    return store, EXIT_OK, str(db)


def _render_flow_row(flow: dict[str, Any]) -> dict[str, Any]:
    return {
        "seq": flow.get("seq"),
        "method": flow.get("method"),
        "host": flow.get("host"),
        "path": flow.get("path"),
        "status": flow.get("response_status_code"),
        "duration_ms": flow.get("duration_total_ms"),
        "tls_decrypted": bool(flow.get("tls_decrypted")),
        "pending": flow.get("response_status_code") is None
        and flow.get("error_msg") is None,
    }


def _emit_flow_table(rows: list[dict[str, Any]]) -> None:
    if not rows:
        emit_text("(no flows)")
        return
    rendered = [_render_flow_row(r) for r in rows]
    emit_text(
        render_table(
            rendered,
            columns=[
                ("seq", "SEQ"),
                ("method", "METHOD"),
                ("status", "STATUS"),
                ("host", "HOST"),
                ("path", "PATH"),
                ("duration_ms", "MS"),
                ("pending", "PEND"),
            ],
        )
    )


def cmd_recent(args: argparse.Namespace) -> int:
    store, rc, db_path = _open_active_store(args.json_mode)
    if store is None:
        return rc
    try:
        rows = store.query_recent(limit=args.limit, host=args.host, reverse=args.reverse)
    finally:
        store.close()
    payload = {
        "session": db_path,
        "count": len(rows),
        "flows": [_render_flow_row(r) for r in rows],
    }
    if args.json_mode:
        emit_json(payload)
    else:
        _emit_flow_table(rows)
    return EXIT_OK


def cmd_failures(args: argparse.Namespace) -> int:
    store, rc, db_path = _open_active_store(args.json_mode)
    if store is None:
        return rc
    try:
        rows = store.query_failures(limit=args.limit)
    finally:
        store.close()
    payload = {
        "session": db_path,
        "count": len(rows),
        "flows": [_render_flow_row(r) for r in rows],
    }
    if args.json_mode:
        emit_json(payload)
    else:
        _emit_flow_table(rows)
    return EXIT_OK


def cmd_slow(args: argparse.Namespace) -> int:
    store, rc, db_path = _open_active_store(args.json_mode)
    if store is None:
        return rc
    try:
        rows = store.query_slow(threshold_ms=args.threshold_ms, limit=args.limit)
    finally:
        store.close()
    payload = {
        "session": db_path,
        "threshold_ms": args.threshold_ms,
        "count": len(rows),
        "flows": [_render_flow_row(r) for r in rows],
    }
    if args.json_mode:
        emit_json(payload)
    else:
        _emit_flow_table(rows)
    return EXIT_OK


def cmd_hosts(args: argparse.Namespace) -> int:
    store, rc, db_path = _open_active_store(args.json_mode)
    if store is None:
        return rc
    try:
        rows = store.query_hosts()
    finally:
        store.close()
    payload = {"session": db_path, "count": len(rows), "hosts": rows}
    if args.json_mode:
        emit_json(payload)
    elif rows:
        emit_text(
            render_table(
                rows,
                columns=[
                    ("host", "HOST"),
                    ("count", "COUNT"),
                    ("decrypted", "DECRYPTED"),
                    ("failures", "FAILURES"),
                ],
            )
        )
    else:
        emit_text("(no flows)")
    return EXIT_OK


def cmd_show(args: argparse.Namespace) -> int:
    store, rc, db_path = _open_active_store(args.json_mode)
    if store is None:
        return rc
    try:
        flow = store.query_show(args.seq)
    finally:
        store.close()
    if flow is None:
        return emit_error(
            "not_found",
            f"flow with seq={args.seq} not found",
            json_mode=args.json_mode,
            exit_code=EXIT_INVALID_STATE,
        )
    if args.json_mode:
        emit_json({"session": db_path, "flow": flow})
    else:
        for key in sorted(flow.keys()):
            emit_text(f"{key}: {flow[key]}")
    return EXIT_OK


def cmd_sql(args: argparse.Namespace) -> int:
    store, rc, db_path = _open_active_store(args.json_mode)
    if store is None:
        return rc
    try:
        rows = store.query_sql(args.statement)
    except ReadOnlyQueryError as exc:
        store.close()
        return emit_error(
            "invalid_query", str(exc), json_mode=args.json_mode, exit_code=EXIT_INVALID_STATE
        )
    finally:
        store.close()
    if args.json_mode:
        emit_json({"session": db_path, "count": len(rows), "rows": rows})
    elif rows:
        columns = [(k, k.upper()) for k in rows[0].keys()]
        emit_text(render_table(rows, columns=columns))
    else:
        emit_text("(no rows)")
    return EXIT_OK


def cmd_sessions(args: argparse.Namespace) -> int:
    workspace = workspace_for()
    sm = SessionManager(workspace)
    sessions = sm.list_sessions()
    active = sm.active_session_db()
    rows = []
    for path in sessions:
        rows.append(
            {
                "name": path.name,
                "path": str(path),
                "size_bytes": path.stat().st_size if path.exists() else 0,
                "active": active is not None and Path(active).resolve() == path.resolve(),
            }
        )
    if args.json_mode:
        emit_json({"count": len(rows), "sessions": rows})
    elif not rows:
        emit_text("(no sessions)")
    else:
        emit_text(
            render_table(
                rows,
                columns=[
                    ("name", "NAME"),
                    ("size_bytes", "BYTES"),
                    ("active", "ACTIVE"),
                ],
            )
        )
    return EXIT_OK


def cmd_curl(args: argparse.Namespace) -> int:
    store, rc, db_path = _open_active_store(args.json_mode)
    if store is None:
        return rc
    try:
        flow = store.query_show_raw(args.seq)
    finally:
        store.close()
    if flow is None:
        return emit_error(
            "not_found",
            f"flow with seq={args.seq} not found",
            json_mode=args.json_mode,
            exit_code=EXIT_INVALID_STATE,
        )

    body_dir = Path(args.body_dir) if args.body_dir else None
    if body_dir is not None:
        body_dir.mkdir(parents=True, exist_ok=True)

    export = export_request(
        flow,
        body_dir=body_dir,
        single_line=bool(args.single_line),
    )

    if args.json_mode:
        emit_json({"session": db_path, **export.to_dict()})
    else:
        emit_text(export.command)
    return EXIT_OK


def cmd_use(args: argparse.Namespace) -> int:
    workspace = workspace_for()
    sm = SessionManager(workspace)
    candidate = Path(args.session)
    if not candidate.is_absolute():
        candidate = workspace.captures_dir / candidate.name
    if not candidate.exists():
        return emit_error(
            "session_not_found",
            f"session not found: {candidate}",
            json_mode=args.json_mode,
            exit_code=EXIT_INVALID_STATE,
        )
    workspace.runtime_dir.mkdir(parents=True, exist_ok=True)
    sm.set_active_session(candidate)
    payload = {"active_session": str(candidate)}
    if args.json_mode:
        emit_json(payload)
    else:
        emit_text(f"active session: {candidate}")
    return EXIT_OK
