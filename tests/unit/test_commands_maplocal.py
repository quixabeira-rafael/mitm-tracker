from __future__ import annotations

import json
from pathlib import Path

import pytest

from mitm_tracker.cli import main
from mitm_tracker.config import workspace_for
from mitm_tracker.maplocal import MapLocalStore
from mitm_tracker.output import EXIT_INVALID_STATE, EXIT_OK
from mitm_tracker.session_manager import SessionManager
from mitm_tracker.store import FlowStore


def _populate_session(tmp_repo: Path) -> Path:
    workspace = workspace_for(tmp_repo)
    workspace.ensure()
    db = workspace.captures_dir / "session.db"
    store = FlowStore.init_session(
        db, mode="all", listen_host="127.0.0.1", listen_port=8080
    )
    store.insert_request(
        {
            "seq": 1,
            "flow_uuid": "u1",
            "type": "http",
            "intercepted": 0,
            "flow_created_at": 1.0,
            "request_started_at": 1.0,
            "method": "GET",
            "scheme": "https",
            "host": "api.example.com",
            "port": 443,
            "path": "/users/42",
            "full_url": "https://api.example.com/users/42",
            "request_http_version": "HTTP/1.1",
            "request_headers": json.dumps([]),
            "request_body_size": 0,
            "request_body_truncated": 0,
            "tls_decrypted": 1,
        }
    )
    store.update_response(
        "u1",
        {
            "response_status_code": 200,
            "response_reason": "OK",
            "response_headers": json.dumps([["Content-Type", "application/json"]]),
            "response_body": b'{"id":42,"name":"Foo"}',
            "response_body_size": 23,
            "response_body_truncated": 0,
            "response_started_at": 1.05,
            "response_ended_at": 1.10,
            "duration_total_ms": 100.0,
        },
    )
    store.close()

    sm = SessionManager(workspace)
    sm.write_state({"active_session": str(db), "active_profile": "default"})
    return db


def test_maplocal_add_creates_rule(tmp_repo: Path, capsys) -> None:
    rc = main(
        [
            "maplocal",
            "add",
            "https://api.example.com/users/*",
            "--status",
            "200",
            "--header",
            "Content-Type: application/json",
            "--description",
            "test mock",
            "--json",
        ]
    )
    out = json.loads(capsys.readouterr().out)
    assert rc == EXIT_OK
    assert out["status"] == 200
    assert out["url_pattern"] == "https://api.example.com/users/*"
    assert out["enabled"] is True
    assert "/maplocal-bodies/" in out["body_path"]


def test_maplocal_add_with_body_file(tmp_repo: Path, capsys, tmp_path: Path) -> None:
    body_file = tmp_path / "body.json"
    body_file.write_text('{"hello":"world"}')
    rc = main(
        [
            "maplocal",
            "add",
            "https://api.example.com/x",
            "--body-file",
            str(body_file),
            "--json",
        ]
    )
    out = json.loads(capsys.readouterr().out)
    assert rc == EXIT_OK
    assert Path(out["body_path"]).read_bytes() == b'{"hello":"world"}'


def test_maplocal_add_invalid_url(tmp_repo: Path, capsys) -> None:
    rc = main(["maplocal", "add", "not-a-url", "--json"])
    err = capsys.readouterr().err
    payload = json.loads(err)
    assert rc == EXIT_INVALID_STATE
    assert payload["error"] == "invalid_rule"


def test_maplocal_add_invalid_header_format(tmp_repo: Path, capsys) -> None:
    rc = main(
        ["maplocal", "add", "https://api.example.com/x", "--header", "noColonHere", "--json"]
    )
    err = capsys.readouterr().err
    payload = json.loads(err)
    assert rc == EXIT_INVALID_STATE
    assert payload["error"] == "invalid_rule"


def test_maplocal_add_missing_body_file(tmp_repo: Path, capsys) -> None:
    rc = main(
        [
            "maplocal",
            "add",
            "https://api.example.com/x",
            "--body-file",
            "/nonexistent/path",
            "--json",
        ]
    )
    err = capsys.readouterr().err
    payload = json.loads(err)
    assert rc == EXIT_INVALID_STATE
    assert payload["error"] == "body_file_missing"


def test_maplocal_list_empty(tmp_repo: Path, capsys) -> None:
    rc = main(["maplocal", "list", "--json"])
    out = json.loads(capsys.readouterr().out)
    assert rc == EXIT_OK
    assert out["count"] == 0
    assert out["rules"] == []


def test_maplocal_list_after_add(tmp_repo: Path, capsys) -> None:
    main(["maplocal", "add", "https://api.example.com/a"])
    main(["maplocal", "add", "https://api.example.com/b"])
    capsys.readouterr()
    rc = main(["maplocal", "list", "--json"])
    out = json.loads(capsys.readouterr().out)
    assert rc == EXIT_OK
    assert out["count"] == 2
    urls = sorted(r["url_pattern"] for r in out["rules"])
    assert urls == ["https://api.example.com/a", "https://api.example.com/b"]


def test_maplocal_show_unknown(tmp_repo: Path, capsys) -> None:
    rc = main(["maplocal", "show", "missing", "--json"])
    err = capsys.readouterr().err
    payload = json.loads(err)
    assert rc == EXIT_INVALID_STATE
    assert payload["error"] == "rule_not_found"


def _first_rule_id(capsys) -> str:
    main(["maplocal", "list", "--json"])
    payload = json.loads(capsys.readouterr().out)
    return payload["rules"][0]["id"]


def test_maplocal_show_includes_headers_and_body_size(tmp_repo: Path, capsys) -> None:
    main(
        [
            "maplocal",
            "add",
            "https://api.example.com/x",
            "--header",
            "X-A: 1",
            "--header",
            "X-B: 2",
        ]
    )
    capsys.readouterr()
    rule_id = _first_rule_id(capsys)

    rc = main(["maplocal", "show", rule_id, "--json"])
    out = json.loads(capsys.readouterr().out)
    assert rc == EXIT_OK
    assert out["headers"] == [["X-A", "1"], ["X-B", "2"]]


def test_maplocal_disable_then_enable(tmp_repo: Path, capsys) -> None:
    main(["maplocal", "add", "https://api.example.com/x"])
    capsys.readouterr()
    rule_id = _first_rule_id(capsys)

    rc = main(["maplocal", "disable", rule_id, "--json"])
    out = json.loads(capsys.readouterr().out)
    assert rc == EXIT_OK
    assert out["enabled"] is False

    rc = main(["maplocal", "enable", rule_id, "--json"])
    out = json.loads(capsys.readouterr().out)
    assert rc == EXIT_OK
    assert out["enabled"] is True


def test_maplocal_disable_unknown(tmp_repo: Path, capsys) -> None:
    rc = main(["maplocal", "disable", "missing", "--json"])
    err = capsys.readouterr().err
    payload = json.loads(err)
    assert rc == EXIT_INVALID_STATE
    assert payload["error"] == "rule_not_found"


def test_maplocal_remove_deletes_files(tmp_repo: Path, capsys) -> None:
    main(["maplocal", "add", "https://api.example.com/x"])
    capsys.readouterr()
    main(["maplocal", "list", "--json"])
    payload = json.loads(capsys.readouterr().out)
    rule = payload["rules"][0]
    body_path = Path(rule["body_path"])
    headers_path = Path(rule["headers_path"])
    assert body_path.exists()

    rc = main(["maplocal", "remove", rule["id"], "--json"])
    out = json.loads(capsys.readouterr().out)
    assert rc == EXIT_OK
    assert out["removed"] is True
    assert not body_path.exists()
    assert not headers_path.exists()


def test_maplocal_remove_keep_files(tmp_repo: Path, capsys) -> None:
    main(["maplocal", "add", "https://api.example.com/x"])
    capsys.readouterr()
    main(["maplocal", "list", "--json"])
    rules = json.loads(capsys.readouterr().out)["rules"]
    rule = rules[0]
    body_path = Path(rule["body_path"])

    rc = main(["maplocal", "remove", rule["id"], "--keep-files", "--json"])
    out = json.loads(capsys.readouterr().out)
    assert rc == EXIT_OK
    assert out["removed"] is True
    assert body_path.exists()


def test_maplocal_from_flow_copies_response(tmp_repo: Path, capsys) -> None:
    _populate_session(tmp_repo)

    rc = main(["maplocal", "from-flow", "1", "--json"])
    out = json.loads(capsys.readouterr().out)
    assert rc == EXIT_OK
    assert out["status"] == 200
    assert out["url_pattern"] == "https://api.example.com/users/42"
    assert out["source"]["from_flow"] == 1

    body = Path(out["body_path"]).read_bytes()
    assert body == b'{"id":42,"name":"Foo"}'


def test_maplocal_from_flow_unknown_seq(tmp_repo: Path, capsys) -> None:
    _populate_session(tmp_repo)
    rc = main(["maplocal", "from-flow", "999", "--json"])
    err = capsys.readouterr().err
    payload = json.loads(err)
    assert rc == EXIT_INVALID_STATE
    assert payload["error"] == "flow_not_found"


def test_maplocal_from_flow_no_session(tmp_repo: Path, capsys) -> None:
    rc = main(["maplocal", "from-flow", "1", "--json"])
    err = capsys.readouterr().err
    payload = json.loads(err)
    assert rc == EXIT_INVALID_STATE
    assert payload["error"] == "no_session"


def test_maplocal_uses_active_profile_isolation(tmp_repo: Path, capsys) -> None:
    main(["profile", "create", "alpha"])
    main(["profile", "create", "beta"])
    main(["maplocal", "add", "https://api.example.com/a", "--profile", "alpha"])
    main(["maplocal", "add", "https://api.example.com/b", "--profile", "beta"])
    capsys.readouterr()

    rc = main(["maplocal", "list", "--profile", "alpha", "--json"])
    out = json.loads(capsys.readouterr().out)
    assert [r["url_pattern"] for r in out["rules"]] == ["https://api.example.com/a"]

    rc = main(["maplocal", "list", "--profile", "beta", "--json"])
    out = json.loads(capsys.readouterr().out)
    assert [r["url_pattern"] for r in out["rules"]] == ["https://api.example.com/b"]
