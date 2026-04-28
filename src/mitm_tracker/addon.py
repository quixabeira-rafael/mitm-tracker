from __future__ import annotations

import json
import logging
import threading
from pathlib import Path
from typing import Any

from mitmproxy import ctx
from mitmproxy import http as mitm_http
from mitmproxy.http import HTTPFlow

from mitm_tracker.maplocal import MapLocalRule, MapLocalStore
from mitm_tracker.store import FlowStore
from mitm_tracker.url_matcher import (
    CompiledPattern,
    UrlMatcherError,
    compile_pattern,
    matches as url_matches,
)

log = logging.getLogger("mitm_tracker.addon")

DEFAULT_BODY_LIMIT_BYTES = 5 * 1024 * 1024


class TrackerAddon:
    def __init__(self) -> None:
        self._seq = 0
        self._lock = threading.Lock()
        self._store: FlowStore | None = None
        self._mode: str = "all"
        self._body_limit: int = DEFAULT_BODY_LIMIT_BYTES
        self._tracked: set[str] = set()
        self._maplocal_store: MapLocalStore | None = None
        self._maplocal_compiled: list[tuple[MapLocalRule, CompiledPattern, bytes, list[tuple[str, str]]]] = []
        self._maplocal_dir: Path | None = None
        self._maplocal_signature: tuple = ()
        self._maplocal_reload_lock = threading.Lock()

    def load(self, loader) -> None:
        loader.add_option(
            name="tracker_db_path",
            typespec=str,
            default="",
            help="Path to the SQLite session database to write captures into.",
        )
        loader.add_option(
            name="tracker_mode",
            typespec=str,
            default="all",
            help="Capture mode: 'all' (everything) or 'listed' (record list, future use).",
        )
        loader.add_option(
            name="tracker_body_limit",
            typespec=int,
            default=DEFAULT_BODY_LIMIT_BYTES,
            help="Maximum body bytes stored inline; bodies larger are truncated.",
        )
        loader.add_option(
            name="tracker_maplocal_dir",
            typespec=str,
            default="",
            help="Path to the active profile directory holding maplocal.json.",
        )

    def configure(self, updates) -> None:
        if "tracker_db_path" in updates and ctx.options.tracker_db_path:
            db_path = Path(ctx.options.tracker_db_path)
            if self._store is not None:
                self._store.close()
            mode = ctx.options.tracker_mode if "tracker_mode" in updates else self._mode
            self._store = self._open_or_init_store(db_path, mode)
            existing = self._store.max_seq()
            with self._lock:
                self._seq = existing
        if "tracker_mode" in updates:
            self._mode = ctx.options.tracker_mode
        if "tracker_body_limit" in updates:
            self._body_limit = int(ctx.options.tracker_body_limit)
        if "tracker_maplocal_dir" in updates:
            value = ctx.options.tracker_maplocal_dir
            if value:
                self._maplocal_dir = Path(value)
                self._refresh_maplocal_rules(force=True)
            else:
                self._maplocal_dir = None
                self._maplocal_store = None
                self._maplocal_compiled = []
                self._maplocal_signature = ()

    def _refresh_maplocal_rules(self, *, force: bool = False) -> None:
        if self._maplocal_dir is None:
            return
        with self._maplocal_reload_lock:
            current = _maplocal_signature(self._maplocal_dir)
            if not force and current == self._maplocal_signature:
                return
            store = MapLocalStore(profile_dir=self._maplocal_dir)
            compiled: list[tuple[MapLocalRule, CompiledPattern, bytes, list[tuple[str, str]]]] = []
            try:
                for rule in store.load():
                    if not rule.enabled:
                        continue
                    try:
                        pattern = compile_pattern(rule.url_pattern, rule.query_mode)
                    except UrlMatcherError as exc:
                        log.warning(
                            "Skipping invalid map local rule %s: %s", rule.id, exc
                        )
                        continue
                    body = store.read_body(rule.id)
                    headers = store.read_headers(rule.id)
                    compiled.append((rule, pattern, body, headers))
            except Exception:
                log.exception(
                    "Failed to load map local rules from %s", self._maplocal_dir
                )
                return
            self._maplocal_store = store
            self._maplocal_compiled = compiled
            self._maplocal_signature = current
            log.info(
                "Loaded %d enabled map local rules%s",
                len(compiled),
                " (hot-reload)" if not force else "",
            )

    @staticmethod
    def _open_or_init_store(db_path: Path, mode: str) -> FlowStore:
        store = FlowStore(db_path)
        if store.session_info() is None:
            store.close()
            store = FlowStore.init_session(
                db_path,
                mode=mode,
                listen_host="",
                listen_port=0,
            )
        return store

    def request(self, flow: HTTPFlow) -> None:
        if not self._should_capture(flow):
            return
        if self._store is None:
            log.warning("TrackerAddon has no store configured; dropping request")
            return

        self._refresh_maplocal_rules()
        mock = self._find_mock(flow)

        with self._lock:
            self._seq += 1
            seq = self._seq

        try:
            payload = build_request_payload(flow, seq=seq, body_limit=self._body_limit)
            if mock is not None:
                rule, _pattern, body, headers = mock
                self._apply_mock(flow, rule, body, headers)
                response_payload = build_response_payload(flow, body_limit=self._body_limit)
                payload.update(response_payload)
                payload["mocked"] = 1
                payload["mock_rule_id"] = rule.id
                payload["mock_rule_description"] = rule.description
            self._store.insert_request(payload)
            self._tracked.add(flow.id)
        except Exception:
            log.exception("Failed to insert request flow=%s", flow.id)

    def _find_mock(self, flow: HTTPFlow):
        if not self._maplocal_compiled:
            return None
        url = flow.request.pretty_url
        for entry in self._maplocal_compiled:
            _rule, pattern, _body, _headers = entry
            if url_matches(pattern, url):
                return entry
        return None

    @staticmethod
    def _apply_mock(
        flow: HTTPFlow,
        rule: MapLocalRule,
        body: bytes,
        headers: list[tuple[str, str]],
    ) -> None:
        header_tuples = tuple(
            (k.encode("utf-8"), v.encode("utf-8")) for k, v in headers
        )
        response = mitm_http.Response.make(
            status_code=int(rule.status),
            content=body or b"",
            headers=header_tuples,
        )
        flow.response = response

    def response(self, flow: HTTPFlow) -> None:
        if flow.id not in self._tracked:
            return
        if self._store is None:
            return
        try:
            payload = build_response_payload(flow, body_limit=self._body_limit)
            self._store.update_response(flow.id, payload)
        except Exception:
            log.exception("Failed to update response flow=%s", flow.id)

    def error(self, flow: HTTPFlow) -> None:
        if flow.id not in self._tracked:
            return
        if self._store is None or flow.error is None:
            return
        try:
            self._store.update_error(
                flow.id,
                msg=str(flow.error),
                timestamp=float(flow.error.timestamp or 0.0),
            )
        except Exception:
            log.exception("Failed to update error flow=%s", flow.id)

    def done(self) -> None:
        if self._store is not None:
            try:
                self._store.end_session()
            finally:
                self._store.close()
                self._store = None

    def _should_capture(self, flow: HTTPFlow) -> bool:
        if self._mode == "all":
            return True
        if self._mode == "listed":
            return False
        return True


def build_request_payload(
    flow: HTTPFlow, *, seq: int, body_limit: int = DEFAULT_BODY_LIMIT_BYTES
) -> dict[str, Any]:
    request = flow.request
    raw_body = _safe_content(request)
    body, truncated = _truncate(raw_body, body_limit)

    client = flow.client_conn
    server = flow.server_conn

    return {
        "seq": seq,
        "flow_uuid": flow.id,
        "type": flow.type or "http",
        "is_replay": flow.is_replay,
        "intercepted": int(bool(flow.intercepted)),
        "flow_created_at": float(flow.timestamp_created or 0.0),
        "request_started_at": float(request.timestamp_start or 0.0),
        "request_ended_at": _opt_float(request.timestamp_end),
        "method": request.method,
        "scheme": request.scheme,
        "host": request.pretty_host,
        "port": int(request.port),
        "authority": request.authority or None,
        "path": request.path,
        "query_string": _query_string(request),
        "full_url": request.pretty_url,
        "request_http_version": request.http_version,
        "request_headers": _headers_to_json(request.headers.fields),
        "request_trailers": (
            _headers_to_json(request.trailers.fields) if request.trailers else None
        ),
        "request_body": body,
        "request_body_size": len(raw_body) if raw_body is not None else None,
        "request_body_truncated": int(truncated),
        "request_content_type": request.headers.get("content-type"),
        "request_cookies": _cookies_to_json(request.cookies),
        "client_ip": _peer_host(client.peername),
        "client_port": _peer_port(client.peername),
        "client_tls": int(bool(client.tls)),
        "client_tls_version": client.tls_version,
        "client_cipher": client.cipher,
        "client_sni": client.sni,
        "client_alpn": _alpn(client.alpn),
        "client_proxy_mode": _proxy_mode_str(getattr(client, "proxy_mode", None)),
        "server_address": _addr(server.address),
        "server_ip": _peer_host(server.peername),
        "server_port": _peer_port(server.peername) or _addr_port(server.address),
        "server_tls": int(bool(server.tls)),
        "server_tls_version": server.tls_version,
        "server_cipher": server.cipher,
        "server_sni": server.sni,
        "server_alpn": _alpn(server.alpn),
        "server_via": _addr(getattr(server, "via", None)),
        "tls_decrypted": int(bool(client.tls_established or server.tls_established)),
        "matched_rule": None,
    }


def build_response_payload(
    flow: HTTPFlow, *, body_limit: int = DEFAULT_BODY_LIMIT_BYTES
) -> dict[str, Any]:
    response = flow.response
    if response is None:
        return {}
    raw_body = _safe_content(response)
    body, truncated = _truncate(raw_body, body_limit)

    started = _opt_float(response.timestamp_start)
    ended = _opt_float(response.timestamp_end)
    request_ended = _opt_float(flow.request.timestamp_end)
    request_started = _opt_float(flow.request.timestamp_start)

    duration_total_ms = None
    if ended is not None and request_started is not None:
        duration_total_ms = (ended - request_started) * 1000.0

    duration_server_ms = None
    if started is not None and request_ended is not None:
        duration_server_ms = (started - request_ended) * 1000.0

    return {
        "response_status_code": int(response.status_code),
        "response_reason": response.reason,
        "response_http_version": response.http_version,
        "response_headers": _headers_to_json(response.headers.fields),
        "response_trailers": (
            _headers_to_json(response.trailers.fields) if response.trailers else None
        ),
        "response_body": body,
        "response_body_size": len(raw_body) if raw_body is not None else None,
        "response_body_truncated": int(truncated),
        "response_content_type": response.headers.get("content-type"),
        "response_cookies": _cookies_to_json(response.cookies),
        "response_started_at": started,
        "response_ended_at": ended,
        "duration_total_ms": duration_total_ms,
        "duration_server_ms": duration_server_ms,
    }


def _safe_content(message) -> bytes | None:
    try:
        return message.get_content(strict=False)
    except Exception:
        try:
            return message.raw_content
        except Exception:
            return None


def _truncate(data: bytes | None, limit: int) -> tuple[bytes | None, bool]:
    if data is None:
        return None, False
    if len(data) <= limit:
        return data, False
    return data[:limit], True


def _opt_float(value) -> float | None:
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _query_string(request) -> str | None:
    if "?" in request.path:
        return request.path.split("?", 1)[1]
    return None


def _headers_to_json(fields) -> str:
    out: list[list[str]] = []
    for k, v in fields:
        out.append([_to_text(k), _to_text(v)])
    return json.dumps(out, ensure_ascii=False)


def _cookies_to_json(cookies) -> str | None:
    try:
        items = list(cookies.items(multi=True))
    except Exception:
        try:
            items = list(cookies.items())
        except Exception:
            return None
    if not items:
        return None
    return json.dumps(
        [[_to_text(k), _serialize_cookie_value(v)] for k, v in items],
        ensure_ascii=False,
    )


def _serialize_cookie_value(value) -> Any:
    if isinstance(value, tuple):
        return [_serialize_cookie_value(part) for part in value]
    if isinstance(value, (bytes, str)):
        return _to_text(value)
    if isinstance(value, (bool, int, float)) or value is None:
        return value
    if isinstance(value, dict):
        return {_to_text(k): _serialize_cookie_value(v) for k, v in value.items()}
    try:
        items = value.items(multi=True)
    except Exception:
        try:
            items = value.items()
        except Exception:
            items = None
    if items is not None:
        try:
            return [[_to_text(k), _serialize_cookie_value(v)] for k, v in items]
        except Exception:
            pass
    return _to_text(value)


def _to_text(value) -> str:
    if isinstance(value, bytes):
        try:
            return value.decode("utf-8")
        except UnicodeDecodeError:
            return value.decode("latin-1")
    return str(value)


def _peer_host(peer) -> str | None:
    if not peer:
        return None
    return str(peer[0])


def _peer_port(peer) -> int | None:
    if not peer:
        return None
    try:
        return int(peer[1])
    except (TypeError, ValueError, IndexError):
        return None


def _addr(addr) -> str | None:
    if not addr:
        return None
    try:
        return f"{addr[0]}:{addr[1]}"
    except (TypeError, ValueError, IndexError):
        return str(addr)


def _addr_port(addr) -> int | None:
    if not addr:
        return None
    try:
        return int(addr[1])
    except (TypeError, ValueError, IndexError):
        return None


def _alpn(value) -> str | None:
    if not value:
        return None
    if isinstance(value, bytes):
        try:
            return value.decode("ascii")
        except UnicodeDecodeError:
            return value.hex()
    return str(value)


def _proxy_mode_str(value) -> str | None:
    if value is None:
        return None
    return getattr(value, "type_name", None) or str(value)


def _maplocal_signature(profile_dir: Path) -> tuple:
    """Cheap fingerprint to detect changes in map local files.

    Captures mtime+size of maplocal.json and every file under maplocal-bodies/.
    Two runs return the same tuple iff nothing changed on disk.
    """
    parts: list[tuple[str, float, int]] = []
    json_path = profile_dir / "maplocal.json"
    if json_path.exists():
        try:
            stat = json_path.stat()
            parts.append((str(json_path), stat.st_mtime, stat.st_size))
        except OSError:
            pass
    bodies_dir = profile_dir / "maplocal-bodies"
    if bodies_dir.exists():
        try:
            for entry in sorted(bodies_dir.iterdir()):
                try:
                    stat = entry.stat()
                except OSError:
                    continue
                parts.append((str(entry), stat.st_mtime, stat.st_size))
        except OSError:
            pass
    return tuple(parts)


addons = [TrackerAddon()]
