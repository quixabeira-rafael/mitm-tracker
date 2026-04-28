from __future__ import annotations

import sqlite3

from mitm_tracker.schema import SCHEMA_VERSION, apply


def test_schema_version_is_positive_int() -> None:
    assert isinstance(SCHEMA_VERSION, int)
    assert SCHEMA_VERSION >= 1


def test_apply_creates_session_and_flows_tables(tmp_path) -> None:
    db = tmp_path / "schema.db"
    conn = sqlite3.connect(db)
    apply(conn)

    tables = {
        row[0]
        for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        )
    }
    assert {"session", "flows"}.issubset(tables)


def test_apply_creates_expected_indexes(tmp_path) -> None:
    db = tmp_path / "schema.db"
    conn = sqlite3.connect(db)
    apply(conn)

    indexes = {
        row[0]
        for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='index'"
        )
    }
    expected = {
        "idx_flows_seq",
        "idx_flows_host",
        "idx_flows_started",
        "idx_flows_status",
        "idx_flows_method_host",
    }
    assert expected.issubset(indexes)


def test_apply_is_idempotent(tmp_path) -> None:
    db = tmp_path / "schema.db"
    conn = sqlite3.connect(db)
    apply(conn)
    apply(conn)
    apply(conn)

    table_count = conn.execute(
        "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name IN ('session','flows')"
    ).fetchone()[0]
    assert table_count == 2
