from __future__ import annotations

import sqlite3

SCHEMA_VERSION = 1


_DDL_STATEMENTS: tuple[str, ...] = (
    """
    CREATE TABLE IF NOT EXISTS session (
        id INTEGER PRIMARY KEY,
        started_at TEXT NOT NULL,
        ended_at TEXT,
        profile TEXT NOT NULL DEFAULT 'default',
        mode TEXT NOT NULL,
        mitmproxy_version TEXT,
        listen_host TEXT,
        listen_port INTEGER,
        schema_version INTEGER NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS flows (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        seq INTEGER UNIQUE NOT NULL,
        flow_uuid TEXT UNIQUE NOT NULL,
        type TEXT NOT NULL DEFAULT 'http',
        is_replay TEXT,
        intercepted INTEGER NOT NULL DEFAULT 0,

        flow_created_at REAL NOT NULL,
        request_started_at REAL NOT NULL,
        request_ended_at REAL,
        response_started_at REAL,
        response_ended_at REAL,
        duration_total_ms REAL,
        duration_server_ms REAL,

        method TEXT NOT NULL,
        scheme TEXT NOT NULL,
        host TEXT NOT NULL,
        port INTEGER NOT NULL,
        authority TEXT,
        path TEXT NOT NULL,
        query_string TEXT,
        full_url TEXT NOT NULL,

        request_http_version TEXT,
        request_headers TEXT NOT NULL,
        request_trailers TEXT,
        request_body BLOB,
        request_body_size INTEGER,
        request_body_truncated INTEGER NOT NULL DEFAULT 0,
        request_content_type TEXT,
        request_cookies TEXT,

        response_status_code INTEGER,
        response_reason TEXT,
        response_http_version TEXT,
        response_headers TEXT,
        response_trailers TEXT,
        response_body BLOB,
        response_body_size INTEGER,
        response_body_truncated INTEGER NOT NULL DEFAULT 0,
        response_content_type TEXT,
        response_cookies TEXT,

        client_ip TEXT,
        client_port INTEGER,
        client_tls INTEGER NOT NULL DEFAULT 0,
        client_tls_version TEXT,
        client_cipher TEXT,
        client_sni TEXT,
        client_alpn TEXT,
        client_proxy_mode TEXT,

        server_address TEXT,
        server_ip TEXT,
        server_port INTEGER,
        server_tls INTEGER NOT NULL DEFAULT 0,
        server_tls_version TEXT,
        server_cipher TEXT,
        server_sni TEXT,
        server_alpn TEXT,
        server_via TEXT,

        tls_decrypted INTEGER NOT NULL DEFAULT 0,
        matched_rule TEXT,

        mocked INTEGER NOT NULL DEFAULT 0,
        mock_rule_id TEXT,
        mock_rule_description TEXT,

        error_msg TEXT,
        error_timestamp REAL
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_flows_seq ON flows(seq)",
    "CREATE INDEX IF NOT EXISTS idx_flows_host ON flows(host)",
    "CREATE INDEX IF NOT EXISTS idx_flows_started ON flows(request_started_at)",
    "CREATE INDEX IF NOT EXISTS idx_flows_status ON flows(response_status_code)",
    "CREATE INDEX IF NOT EXISTS idx_flows_method_host ON flows(method, host)",
)


def apply(conn: sqlite3.Connection) -> None:
    cursor = conn.cursor()
    for statement in _DDL_STATEMENTS:
        cursor.execute(statement)
    conn.commit()


FLOW_COLUMNS: tuple[str, ...] = (
    "seq",
    "flow_uuid",
    "type",
    "is_replay",
    "intercepted",
    "flow_created_at",
    "request_started_at",
    "request_ended_at",
    "response_started_at",
    "response_ended_at",
    "duration_total_ms",
    "duration_server_ms",
    "method",
    "scheme",
    "host",
    "port",
    "authority",
    "path",
    "query_string",
    "full_url",
    "request_http_version",
    "request_headers",
    "request_trailers",
    "request_body",
    "request_body_size",
    "request_body_truncated",
    "request_content_type",
    "request_cookies",
    "response_status_code",
    "response_reason",
    "response_http_version",
    "response_headers",
    "response_trailers",
    "response_body",
    "response_body_size",
    "response_body_truncated",
    "response_content_type",
    "response_cookies",
    "client_ip",
    "client_port",
    "client_tls",
    "client_tls_version",
    "client_cipher",
    "client_sni",
    "client_alpn",
    "client_proxy_mode",
    "server_address",
    "server_ip",
    "server_port",
    "server_tls",
    "server_tls_version",
    "server_cipher",
    "server_sni",
    "server_alpn",
    "server_via",
    "tls_decrypted",
    "matched_rule",
    "mocked",
    "mock_rule_id",
    "mock_rule_description",
    "error_msg",
    "error_timestamp",
)
