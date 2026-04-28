from __future__ import annotations

import json
from pathlib import Path

import pytest

from mitm_tracker.store import FlowStore, ReadOnlyQueryError, StoreError


def _request_payload(
    *,
    seq: int,
    flow_uuid: str,
    method: str = "GET",
    host: str = "api.example.com",
    path: str = "/users",
    started_at: float = 1_700_000_000.0,
    request_body: bytes | None = b"",
) -> dict:
    return {
        "seq": seq,
        "flow_uuid": flow_uuid,
        "type": "http",
        "intercepted": 0,
        "flow_created_at": started_at,
        "request_started_at": started_at,
        "request_ended_at": started_at + 0.001,
        "method": method,
        "scheme": "https",
        "host": host,
        "port": 443,
        "path": path,
        "query_string": "",
        "full_url": f"https://{host}{path}",
        "request_http_version": "HTTP/1.1",
        "request_headers": json.dumps([["Host", host]]),
        "request_body": request_body,
        "request_body_size": len(request_body) if request_body else 0,
        "request_body_truncated": 0,
        "request_content_type": None,
        "tls_decrypted": 1,
    }


def _response_payload(
    *,
    status: int = 200,
    started_at: float = 1_700_000_000.05,
    ended_at: float = 1_700_000_000.10,
    duration_ms: float = 100.0,
    body: bytes | None = b"{}",
) -> dict:
    return {
        "response_status_code": status,
        "response_reason": "OK" if status < 400 else "Bad",
        "response_http_version": "HTTP/1.1",
        "response_headers": json.dumps([["Content-Type", "application/json"]]),
        "response_body": body,
        "response_body_size": len(body) if body else 0,
        "response_body_truncated": 0,
        "response_content_type": "application/json",
        "response_started_at": started_at,
        "response_ended_at": ended_at,
        "duration_total_ms": duration_ms,
        "duration_server_ms": 50.0,
    }


@pytest.fixture
def store(tmp_path: Path) -> FlowStore:
    db = tmp_path / "test.db"
    return FlowStore.init_session(
        db,
        mode="all",
        listen_host="127.0.0.1",
        listen_port=8080,
    )


def test_init_session_creates_session_row(store: FlowStore) -> None:
    info = store.session_info()
    assert info is not None
    assert info["mode"] == "all"
    assert info["listen_host"] == "127.0.0.1"
    assert info["listen_port"] == 8080
    assert info["profile"] == "default"
    assert info["schema_version"] >= 1
    assert info["ended_at"] is None


def test_end_session_sets_ended_at(store: FlowStore) -> None:
    store.end_session()
    info = store.session_info()
    assert info is not None
    assert info["ended_at"] is not None


def test_insert_request_persists_basic_fields(store: FlowStore) -> None:
    payload = _request_payload(seq=1, flow_uuid="uuid-1")
    store.insert_request(payload)

    rows = store.query_recent()
    assert len(rows) == 1
    row = rows[0]
    assert row["seq"] == 1
    assert row["host"] == "api.example.com"
    assert row["method"] == "GET"
    assert row["full_url"] == "https://api.example.com/users"
    assert row["response_status_code"] is None


def test_insert_request_rejects_missing_required_field(store: FlowStore) -> None:
    payload = _request_payload(seq=1, flow_uuid="uuid-1")
    del payload["host"]
    with pytest.raises(StoreError, match="host"):
        store.insert_request(payload)


def test_insert_request_rejects_missing_seq(store: FlowStore) -> None:
    payload = _request_payload(seq=1, flow_uuid="uuid-1")
    del payload["seq"]
    with pytest.raises(StoreError, match="seq"):
        store.insert_request(payload)


def test_seq_must_be_unique(store: FlowStore) -> None:
    store.insert_request(_request_payload(seq=1, flow_uuid="uuid-1"))
    with pytest.raises(Exception):
        store.insert_request(_request_payload(seq=1, flow_uuid="uuid-2"))


def test_flow_uuid_must_be_unique(store: FlowStore) -> None:
    store.insert_request(_request_payload(seq=1, flow_uuid="uuid-1"))
    with pytest.raises(Exception):
        store.insert_request(_request_payload(seq=2, flow_uuid="uuid-1"))


def test_update_response_fills_fields(store: FlowStore) -> None:
    store.insert_request(_request_payload(seq=1, flow_uuid="uuid-1"))
    rowcount = store.update_response("uuid-1", _response_payload(status=200))
    assert rowcount == 1

    row = store.query_show(1)
    assert row is not None
    assert row["response_status_code"] == 200
    assert row["response_content_type"] == "application/json"
    assert row["duration_total_ms"] == 100.0


def test_update_response_unknown_uuid_returns_zero(store: FlowStore) -> None:
    rowcount = store.update_response("missing", _response_payload())
    assert rowcount == 0


def test_update_error_records_message(store: FlowStore) -> None:
    store.insert_request(_request_payload(seq=1, flow_uuid="uuid-1"))
    rowcount = store.update_error("uuid-1", "connection refused", 1_700_000_000.5)
    assert rowcount == 1
    row = store.query_show(1)
    assert row is not None
    assert row["error_msg"] == "connection refused"
    assert row["error_timestamp"] == 1_700_000_000.5


def test_query_recent_orders_by_seq_ascending_by_default(store: FlowStore) -> None:
    for i in (1, 2, 3):
        store.insert_request(_request_payload(seq=i, flow_uuid=f"u{i}"))
    rows = store.query_recent()
    assert [r["seq"] for r in rows] == [1, 2, 3]


def test_query_recent_supports_reverse(store: FlowStore) -> None:
    for i in (1, 2, 3):
        store.insert_request(_request_payload(seq=i, flow_uuid=f"u{i}"))
    rows = store.query_recent(reverse=True)
    assert [r["seq"] for r in rows] == [3, 2, 1]


def test_query_recent_filters_by_host(store: FlowStore) -> None:
    store.insert_request(_request_payload(seq=1, flow_uuid="u1", host="a.com"))
    store.insert_request(_request_payload(seq=2, flow_uuid="u2", host="b.com"))
    store.insert_request(_request_payload(seq=3, flow_uuid="u3", host="a.com"))
    rows = store.query_recent(host="a.com")
    assert [r["seq"] for r in rows] == [1, 3]


def test_query_recent_respects_limit(store: FlowStore) -> None:
    for i in range(1, 6):
        store.insert_request(_request_payload(seq=i, flow_uuid=f"u{i}"))
    rows = store.query_recent(limit=2)
    assert len(rows) == 2


def test_query_failures_returns_4xx_5xx_and_errors(store: FlowStore) -> None:
    for seq, status in [(1, 200), (2, 404), (3, 500)]:
        store.insert_request(_request_payload(seq=seq, flow_uuid=f"u{seq}"))
        store.update_response(f"u{seq}", _response_payload(status=status))
    store.insert_request(_request_payload(seq=4, flow_uuid="u4"))
    store.update_error("u4", "boom", 1_700_000_001.0)

    rows = store.query_failures()
    seqs = sorted(r["seq"] for r in rows)
    assert seqs == [2, 3, 4]


def test_query_slow_filters_by_threshold(store: FlowStore) -> None:
    durations = [(1, 50.0), (2, 250.0), (3, 1500.0)]
    for seq, dur in durations:
        store.insert_request(_request_payload(seq=seq, flow_uuid=f"u{seq}"))
        store.update_response(f"u{seq}", _response_payload(duration_ms=dur))
    rows = store.query_slow(threshold_ms=200.0)
    seqs = sorted(r["seq"] for r in rows)
    assert seqs == [2, 3]
    assert rows[0]["duration_total_ms"] >= rows[-1]["duration_total_ms"]


def test_query_hosts_aggregates(store: FlowStore) -> None:
    store.insert_request(_request_payload(seq=1, flow_uuid="u1", host="a.com"))
    store.insert_request(_request_payload(seq=2, flow_uuid="u2", host="a.com"))
    store.update_response("u2", _response_payload(status=500))
    store.insert_request(_request_payload(seq=3, flow_uuid="u3", host="b.com"))

    rows = store.query_hosts()
    by_host = {row["host"]: row for row in rows}
    assert by_host["a.com"]["count"] == 2
    assert by_host["a.com"]["failures"] == 1
    assert by_host["b.com"]["count"] == 1
    assert by_host["b.com"]["failures"] == 0


def test_query_show_returns_full_row(store: FlowStore) -> None:
    store.insert_request(_request_payload(seq=42, flow_uuid="u42"))
    row = store.query_show(42)
    assert row is not None
    assert row["seq"] == 42
    assert row["flow_uuid"] == "u42"


def test_query_show_unknown_returns_none(store: FlowStore) -> None:
    assert store.query_show(999) is None


def test_query_sql_allows_select(store: FlowStore) -> None:
    store.insert_request(_request_payload(seq=1, flow_uuid="u1"))
    rows = store.query_sql("SELECT seq, host FROM flows")
    assert rows == [{"seq": 1, "host": "api.example.com"}]


def test_query_sql_allows_with(store: FlowStore) -> None:
    store.insert_request(_request_payload(seq=1, flow_uuid="u1"))
    rows = store.query_sql(
        "WITH x AS (SELECT seq FROM flows) SELECT seq FROM x"
    )
    assert rows == [{"seq": 1}]


@pytest.mark.parametrize(
    "sql",
    [
        "DELETE FROM flows",
        "INSERT INTO flows (seq) VALUES (1)",
        "UPDATE flows SET host='x'",
        "DROP TABLE flows",
        "PRAGMA journal_mode=DELETE",
        "ATTACH DATABASE 'x.db' AS x",
        "SELECT 1; DROP TABLE flows",
        "  ",
        "",
    ],
)
def test_query_sql_rejects_writes_and_pragmas(store: FlowStore, sql: str) -> None:
    with pytest.raises(ReadOnlyQueryError):
        store.query_sql(sql)


def test_max_seq_returns_zero_when_empty(store: FlowStore) -> None:
    assert store.max_seq() == 0


def test_max_seq_returns_largest(store: FlowStore) -> None:
    for i in (3, 1, 2):
        store.insert_request(_request_payload(seq=i, flow_uuid=f"u{i}"))
    assert store.max_seq() == 3


def test_count_reflects_insertions(store: FlowStore) -> None:
    assert store.count() == 0
    store.insert_request(_request_payload(seq=1, flow_uuid="u1"))
    store.insert_request(_request_payload(seq=2, flow_uuid="u2"))
    assert store.count() == 2


def test_read_only_mode_rejects_writes(tmp_path: Path) -> None:
    db = tmp_path / "ro.db"
    writer = FlowStore.init_session(
        db, mode="all", listen_host="127.0.0.1", listen_port=8080
    )
    writer.insert_request(_request_payload(seq=1, flow_uuid="u1"))
    writer.close()

    reader = FlowStore(db, read_only=True)
    rows = reader.query_recent()
    assert len(rows) == 1
    with pytest.raises(StoreError):
        reader.insert_request(_request_payload(seq=2, flow_uuid="u2"))
    reader.close()


def test_blob_decoded_as_utf8_when_possible(store: FlowStore) -> None:
    payload = _request_payload(seq=1, flow_uuid="u1", request_body=b"hello")
    store.insert_request(payload)
    row = store.query_show(1)
    assert row is not None
    assert row["request_body"] == "hello"


def test_blob_returns_base64_when_not_utf8(store: FlowStore) -> None:
    payload = _request_payload(seq=1, flow_uuid="u1", request_body=b"\xff\xfe\x00\x01")
    store.insert_request(payload)
    row = store.query_show(1)
    assert row is not None
    assert isinstance(row["request_body"], dict)
    assert "__bytes_b64__" in row["request_body"]
    assert row["request_body"]["size"] == 4
