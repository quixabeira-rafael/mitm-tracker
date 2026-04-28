from __future__ import annotations

import json
from pathlib import Path

import pytest

from mitm_tracker.cli import main
from mitm_tracker.config import workspace_for
from mitm_tracker.output import EXIT_INVALID_STATE, EXIT_OK
from mitm_tracker.session_manager import SessionManager
from mitm_tracker.store import FlowStore


def _request_payload(*, seq: int, flow_uuid: str, **overrides) -> dict:
    base = {
        "seq": seq,
        "flow_uuid": flow_uuid,
        "type": "http",
        "intercepted": 0,
        "flow_created_at": 1_700_000_000.0 + seq,
        "request_started_at": 1_700_000_000.0 + seq,
        "request_ended_at": 1_700_000_000.001 + seq,
        "method": "GET",
        "scheme": "https",
        "host": "api.example.com",
        "port": 443,
        "path": "/users",
        "query_string": "",
        "full_url": "https://api.example.com/users",
        "request_http_version": "HTTP/1.1",
        "request_headers": json.dumps([["Host", "api.example.com"]]),
        "request_body_size": 0,
        "request_body_truncated": 0,
        "tls_decrypted": 1,
    }
    base.update(overrides)
    return base


def _populate_session(tmp_repo: Path) -> Path:
    workspace = workspace_for(tmp_repo)
    workspace.ensure()
    db = workspace.captures_dir / "session.db"
    store = FlowStore.init_session(
        db, mode="all", listen_host="127.0.0.1", listen_port=8080
    )
    for seq in range(1, 4):
        store.insert_request(_request_payload(seq=seq, flow_uuid=f"u{seq}"))
        store.update_response(
            f"u{seq}",
            {
                "response_status_code": 200 if seq != 2 else 500,
                "response_reason": "OK" if seq != 2 else "Bad",
                "response_started_at": 1_700_000_000.05 + seq,
                "response_ended_at": 1_700_000_000.10 + seq,
                "duration_total_ms": 100.0 + seq * 200,
            },
        )
    store.close()
    return db


def test_query_recent_returns_rows_in_seq_order(tmp_repo: Path, capsys) -> None:
    _populate_session(tmp_repo)
    rc = main(["query", "recent", "--json"])
    out = json.loads(capsys.readouterr().out)
    assert rc == EXIT_OK
    assert out["count"] == 3
    assert [f["seq"] for f in out["flows"]] == [1, 2, 3]


def test_query_recent_filters_by_host(tmp_repo: Path, capsys) -> None:
    _populate_session(tmp_repo)
    rc = main(["query", "recent", "--host", "missing.com", "--json"])
    out = json.loads(capsys.readouterr().out)
    assert rc == EXIT_OK
    assert out["count"] == 0


def test_query_failures_returns_only_4xx_5xx(tmp_repo: Path, capsys) -> None:
    _populate_session(tmp_repo)
    rc = main(["query", "failures", "--json"])
    out = json.loads(capsys.readouterr().out)
    assert rc == EXIT_OK
    seqs = sorted(f["seq"] for f in out["flows"])
    assert seqs == [2]


def test_query_slow_filters_by_threshold(tmp_repo: Path, capsys) -> None:
    _populate_session(tmp_repo)
    rc = main(["query", "slow", "--threshold-ms", "500", "--json"])
    out = json.loads(capsys.readouterr().out)
    assert rc == EXIT_OK
    seqs = sorted(f["seq"] for f in out["flows"])
    assert seqs == [2, 3]


def test_query_hosts_aggregates(tmp_repo: Path, capsys) -> None:
    _populate_session(tmp_repo)
    rc = main(["query", "hosts", "--json"])
    out = json.loads(capsys.readouterr().out)
    assert rc == EXIT_OK
    assert out["count"] == 1
    assert out["hosts"][0]["host"] == "api.example.com"
    assert out["hosts"][0]["count"] == 3


def test_query_show_returns_flow(tmp_repo: Path, capsys) -> None:
    _populate_session(tmp_repo)
    rc = main(["query", "show", "2", "--json"])
    out = json.loads(capsys.readouterr().out)
    assert rc == EXIT_OK
    assert out["flow"]["seq"] == 2
    assert out["flow"]["response_status_code"] == 500


def test_query_show_unknown_returns_invalid_state(tmp_repo: Path, capsys) -> None:
    _populate_session(tmp_repo)
    rc = main(["query", "show", "999", "--json"])
    err = capsys.readouterr().err
    assert rc == EXIT_INVALID_STATE
    payload = json.loads(err)
    assert payload["error"] == "not_found"


def test_query_sql_select_only(tmp_repo: Path, capsys) -> None:
    _populate_session(tmp_repo)
    rc = main(["query", "sql", "SELECT seq FROM flows", "--json"])
    out = json.loads(capsys.readouterr().out)
    assert rc == EXIT_OK
    assert out["count"] == 3
    assert sorted(r["seq"] for r in out["rows"]) == [1, 2, 3]


def test_query_sql_rejects_writes(tmp_repo: Path, capsys) -> None:
    _populate_session(tmp_repo)
    rc = main(["query", "sql", "DELETE FROM flows", "--json"])
    err = capsys.readouterr().err
    assert rc == EXIT_INVALID_STATE
    payload = json.loads(err)
    assert payload["error"] == "invalid_query"


def test_query_no_session_returns_invalid_state(tmp_repo: Path, capsys) -> None:
    rc = main(["query", "recent", "--json"])
    err = capsys.readouterr().err
    assert rc == EXIT_INVALID_STATE
    payload = json.loads(err)
    assert payload["error"] == "no_sessions"


def test_query_sessions_lists_all(tmp_repo: Path, capsys) -> None:
    _populate_session(tmp_repo)
    rc = main(["query", "sessions", "--json"])
    out = json.loads(capsys.readouterr().out)
    assert rc == EXIT_OK
    assert out["count"] == 1
    assert out["sessions"][0]["name"] == "session.db"


def test_query_use_changes_active_session(tmp_repo: Path, capsys) -> None:
    db = _populate_session(tmp_repo)
    rc = main(["query", "use", db.name, "--json"])
    out = json.loads(capsys.readouterr().out)
    assert rc == EXIT_OK
    workspace = workspace_for(tmp_repo)
    sm = SessionManager(workspace)
    active = sm.active_session_db()
    assert active is not None
    assert active.name == db.name


def test_query_use_unknown_returns_invalid_state(tmp_repo: Path, capsys) -> None:
    rc = main(["query", "use", "missing.db", "--json"])
    err = capsys.readouterr().err
    assert rc == EXIT_INVALID_STATE
    payload = json.loads(err)
    assert payload["error"] == "session_not_found"


def test_query_curl_renders_basic_command(tmp_repo: Path, capsys) -> None:
    _populate_session(tmp_repo)
    rc = main(["query", "curl", "1", "--json"])
    out = json.loads(capsys.readouterr().out)
    assert rc == EXIT_OK
    assert out["seq"] == 1
    assert out["method"] == "GET"
    assert "curl" in out["curl"]
    assert "https://api.example.com/users" in out["curl"]
    assert "-X GET" in out["curl"]


def test_query_curl_text_mode_outputs_command_only(tmp_repo: Path, capsys) -> None:
    _populate_session(tmp_repo)
    rc = main(["query", "curl", "1"])
    out = capsys.readouterr().out
    assert rc == EXIT_OK
    assert out.startswith("curl")
    assert "https://api.example.com/users" in out


def test_query_curl_unknown_returns_invalid_state(tmp_repo: Path, capsys) -> None:
    _populate_session(tmp_repo)
    rc = main(["query", "curl", "999", "--json"])
    err = capsys.readouterr().err
    payload = json.loads(err)
    assert rc == EXIT_INVALID_STATE
    assert payload["error"] == "not_found"


def test_query_curl_single_line(tmp_repo: Path, capsys) -> None:
    _populate_session(tmp_repo)
    rc = main(["query", "curl", "1", "--single-line"])
    out = capsys.readouterr().out
    assert rc == EXIT_OK
    assert " \\\n" not in out
