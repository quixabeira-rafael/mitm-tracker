from __future__ import annotations

import json
import re
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator, Mapping

from mitm_tracker.schema import FLOW_COLUMNS, SCHEMA_VERSION, apply


class StoreError(RuntimeError):
    pass


class ReadOnlyQueryError(StoreError):
    pass


_FORBIDDEN_SQL_TOKENS = (
    "INSERT",
    "UPDATE",
    "DELETE",
    "DROP",
    "ALTER",
    "ATTACH",
    "DETACH",
    "REPLACE",
    "CREATE",
    "PRAGMA",
    "VACUUM",
)


_REQUEST_REQUIRED = (
    "flow_uuid",
    "flow_created_at",
    "request_started_at",
    "method",
    "scheme",
    "host",
    "port",
    "path",
    "full_url",
    "request_headers",
)


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _validate_select_only(sql: str) -> None:
    stripped = sql.strip().rstrip(";")
    if not stripped:
        raise ReadOnlyQueryError("empty query")
    upper = stripped.upper()
    if not upper.startswith("SELECT") and not upper.startswith("WITH"):
        raise ReadOnlyQueryError("only SELECT/WITH queries are allowed")
    if ";" in stripped:
        raise ReadOnlyQueryError("multiple statements are not allowed")
    tokens = re.findall(r"[A-Za-z_]+", upper)
    for forbidden in _FORBIDDEN_SQL_TOKENS:
        if forbidden in tokens:
            raise ReadOnlyQueryError(f"keyword not allowed in read-only query: {forbidden}")


class FlowStore:
    def __init__(self, db_path: Path, *, read_only: bool = False) -> None:
        self.db_path = Path(db_path)
        self._read_only = read_only
        if read_only:
            uri = f"file:{self.db_path}?mode=ro"
            self._conn = sqlite3.connect(uri, uri=True, isolation_level=None)
        else:
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            self._conn = sqlite3.connect(self.db_path, isolation_level=None)
        self._conn.row_factory = sqlite3.Row
        if not read_only:
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=NORMAL")
            self._conn.execute("PRAGMA foreign_keys=ON")
            apply(self._conn)

    @classmethod
    def init_session(
        cls,
        db_path: Path,
        *,
        mode: str,
        listen_host: str,
        listen_port: int,
        profile: str = "default",
        mitmproxy_version: str | None = None,
    ) -> FlowStore:
        store = cls(db_path)
        store._conn.execute(
            """
            INSERT INTO session (
                started_at, profile, mode, mitmproxy_version,
                listen_host, listen_port, schema_version
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                _now_iso(),
                profile,
                mode,
                mitmproxy_version,
                listen_host,
                listen_port,
                SCHEMA_VERSION,
            ),
        )
        return store

    def end_session(self) -> None:
        self._guard_writable()
        self._conn.execute(
            "UPDATE session SET ended_at = ? WHERE ended_at IS NULL",
            (_now_iso(),),
        )

    def session_info(self) -> dict[str, Any] | None:
        row = self._conn.execute(
            "SELECT * FROM session ORDER BY id DESC LIMIT 1"
        ).fetchone()
        return _row_to_dict(row) if row else None

    def insert_request(self, payload: Mapping[str, Any]) -> None:
        self._guard_writable()
        for required in _REQUEST_REQUIRED:
            if payload.get(required) is None:
                raise StoreError(f"missing required field: {required}")
        if payload.get("seq") is None:
            raise StoreError("missing required field: seq")

        columns = [c for c in FLOW_COLUMNS if c in payload]
        placeholders = ",".join("?" for _ in columns)
        values = [payload[c] for c in columns]
        sql = (
            f"INSERT INTO flows ({', '.join(columns)}) VALUES ({placeholders})"
        )
        self._conn.execute(sql, values)

    def update_response(self, flow_uuid: str, payload: Mapping[str, Any]) -> int:
        self._guard_writable()
        updatable = [c for c in FLOW_COLUMNS if c in payload and c not in {"seq", "flow_uuid"}]
        if not updatable:
            return 0
        assignments = ", ".join(f"{c} = ?" for c in updatable)
        values = [payload[c] for c in updatable]
        values.append(flow_uuid)
        cursor = self._conn.execute(
            f"UPDATE flows SET {assignments} WHERE flow_uuid = ?",
            values,
        )
        return cursor.rowcount

    def update_error(self, flow_uuid: str, msg: str, timestamp: float) -> int:
        self._guard_writable()
        cursor = self._conn.execute(
            "UPDATE flows SET error_msg = ?, error_timestamp = ? WHERE flow_uuid = ?",
            (msg, timestamp, flow_uuid),
        )
        return cursor.rowcount

    def count(self) -> int:
        row = self._conn.execute("SELECT COUNT(*) AS c FROM flows").fetchone()
        return int(row["c"])

    def query_recent(
        self,
        *,
        limit: int = 20,
        host: str | None = None,
        reverse: bool = False,
    ) -> list[dict[str, Any]]:
        sql = "SELECT * FROM flows"
        params: list[Any] = []
        if host:
            sql += " WHERE host = ?"
            params.append(host)
        order = "DESC" if reverse else "ASC"
        sql += f" ORDER BY seq {order} LIMIT ?"
        params.append(int(limit))
        rows = self._conn.execute(sql, params).fetchall()
        return [_row_to_dict(row) for row in rows]

    def query_failures(self, *, limit: int = 20) -> list[dict[str, Any]]:
        sql = (
            "SELECT * FROM flows "
            "WHERE response_status_code >= 400 OR error_msg IS NOT NULL "
            "ORDER BY seq ASC LIMIT ?"
        )
        rows = self._conn.execute(sql, (int(limit),)).fetchall()
        return [_row_to_dict(row) for row in rows]

    def query_slow(
        self,
        *,
        threshold_ms: float,
        limit: int = 20,
    ) -> list[dict[str, Any]]:
        sql = (
            "SELECT * FROM flows "
            "WHERE duration_total_ms IS NOT NULL AND duration_total_ms >= ? "
            "ORDER BY duration_total_ms DESC LIMIT ?"
        )
        rows = self._conn.execute(sql, (float(threshold_ms), int(limit))).fetchall()
        return [_row_to_dict(row) for row in rows]

    def query_hosts(self) -> list[dict[str, Any]]:
        sql = (
            "SELECT host, COUNT(*) AS count, "
            "SUM(CASE WHEN tls_decrypted = 1 THEN 1 ELSE 0 END) AS decrypted, "
            "SUM(CASE WHEN response_status_code >= 400 OR error_msg IS NOT NULL "
            "THEN 1 ELSE 0 END) AS failures "
            "FROM flows GROUP BY host ORDER BY count DESC"
        )
        rows = self._conn.execute(sql).fetchall()
        return [_row_to_dict(row) for row in rows]

    def query_show(self, seq: int) -> dict[str, Any] | None:
        row = self._conn.execute(
            "SELECT * FROM flows WHERE seq = ?", (int(seq),)
        ).fetchone()
        return _row_to_dict(row) if row else None

    def query_show_raw(self, seq: int) -> dict[str, Any] | None:
        row = self._conn.execute(
            "SELECT * FROM flows WHERE seq = ?", (int(seq),)
        ).fetchone()
        if row is None:
            return None
        return {key: row[key] for key in row.keys()}

    def query_sql(self, sql: str) -> list[dict[str, Any]]:
        _validate_select_only(sql)
        rows = self._conn.execute(sql).fetchall()
        return [_row_to_dict(row) for row in rows]

    def max_seq(self) -> int:
        row = self._conn.execute(
            "SELECT COALESCE(MAX(seq), 0) AS m FROM flows"
        ).fetchone()
        return int(row["m"])

    def close(self) -> None:
        self._conn.close()

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        try:
            self._conn.execute("BEGIN")
            yield self._conn
            self._conn.execute("COMMIT")
        except BaseException:
            self._conn.execute("ROLLBACK")
            raise

    def _guard_writable(self) -> None:
        if self._read_only:
            raise StoreError("store opened in read-only mode")


def _row_to_dict(row: sqlite3.Row | None) -> dict[str, Any]:
    if row is None:
        return {}
    out: dict[str, Any] = {}
    for key in row.keys():
        value = row[key]
        if isinstance(value, bytes):
            try:
                value = value.decode("utf-8")
            except UnicodeDecodeError:
                value = {"__bytes_b64__": _b64(value), "size": len(value)}
        out[key] = value
    return out


def _b64(data: bytes) -> str:
    import base64

    return base64.b64encode(data).decode("ascii")


def dump_headers(headers: list[tuple[str, str]] | None) -> str | None:
    if headers is None:
        return None
    return json.dumps(headers, ensure_ascii=False)
