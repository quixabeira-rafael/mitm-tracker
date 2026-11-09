from __future__ import annotations

import fcntl
import json as _json
import os
import tempfile
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from mitmproxy import http
from mitmproxy.net.http.status_codes import RESPONSES

from mitm_tracker.url_matcher import QUERY_MODE_IGNORE, compile_pattern, matches


class FlowControl:
    """Per-flow decisions taken by a test case script."""

    def __init__(self) -> None:
        self.claimed = False
        self.responded = False
        self.aborted = False
        self.request_delay_ms = 0
        self.response_delay_ms = 0


class Request:
    def __init__(self, flow: http.HTTPFlow, control: FlowControl) -> None:
        self._flow = flow
        self._raw = flow.request
        self._control = control

    @property
    def method(self) -> str:
        return self._raw.method

    @method.setter
    def method(self, value: str) -> None:
        self._raw.method = str(value).upper()

    @property
    def url(self) -> str:
        return self._raw.pretty_url

    @property
    def scheme(self) -> str:
        return self._raw.scheme

    @property
    def host(self) -> str:
        return self._raw.pretty_host

    @host.setter
    def host(self, value: str) -> None:
        self._raw.host = value

    @property
    def port(self) -> int:
        return self._raw.port

    @property
    def path(self) -> str:
        return self._raw.path.split("?", 1)[0]

    @path.setter
    def path(self, value: str) -> None:
        parts = self._raw.path.split("?", 1)
        self._raw.path = value + ("?" + parts[1] if len(parts) > 1 else "")

    @property
    def query(self):
        return self._raw.query

    @property
    def headers(self):
        return self._raw.headers

    @property
    def body(self) -> bytes:
        return self._raw.get_content(strict=False) or b""

    @body.setter
    def body(self, value: bytes | str) -> None:
        self._raw.set_content(_to_bytes(value))

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")

    @text.setter
    def text(self, value: str) -> None:
        self.body = value

    @property
    def json(self) -> Any:
        return _json.loads(self.body) if self.body else None

    @json.setter
    def json(self, value: Any) -> None:
        self.body = _json.dumps(value)
        self._raw.headers["Content-Type"] = "application/json"

    @property
    def delay(self) -> int:
        return self._control.request_delay_ms

    @delay.setter
    def delay(self, value: int) -> None:
        self._control.request_delay_ms = max(0, int(value))

    def matches(self, pattern: str, query_mode: str = QUERY_MODE_IGNORE) -> bool:
        return matches(compile_pattern(pattern, query_mode), self.url)

    def claim(self) -> None:
        self._control.claimed = True

    def respond(
        self,
        status: int = 200,
        *,
        headers: dict[str, str] | None = None,
        body: bytes | str | None = None,
        json: Any = None,
        delay: int = 0,
    ) -> None:
        all_headers = {str(k): str(v) for k, v in (headers or {}).items()}
        if json is not None:
            content = _json.dumps(json).encode("utf-8")
            if not any(k.lower() == "content-type" for k in all_headers):
                all_headers["Content-Type"] = "application/json"
        else:
            content = _to_bytes(body) if body is not None else b""
        self._flow.response = http.Response.make(int(status), content, all_headers)
        self._control.responded = True
        self._control.claimed = True
        self._control.response_delay_ms = max(0, int(delay))

    def abort(self) -> None:
        self._control.aborted = True
        self._control.claimed = True


class Response:
    def __init__(self, flow: http.HTTPFlow, control: FlowControl) -> None:
        self._raw = flow.response
        self._control = control

    @property
    def status(self) -> int:
        return self._raw.status_code

    @status.setter
    def status(self, value: int) -> None:
        code = int(value)
        self._raw.status_code = code
        self._raw.reason = RESPONSES.get(code, "")

    @property
    def headers(self):
        return self._raw.headers

    @property
    def body(self) -> bytes:
        return self._raw.get_content(strict=False) or b""

    @body.setter
    def body(self, value: bytes | str) -> None:
        self._raw.set_content(_to_bytes(value))

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")

    @text.setter
    def text(self, value: str) -> None:
        self.body = value

    @property
    def json(self) -> Any:
        return _json.loads(self.body) if self.body else None

    @json.setter
    def json(self, value: Any) -> None:
        self.body = _json.dumps(value)
        self._raw.headers["Content-Type"] = "application/json"

    @property
    def delay(self) -> int:
        return self._control.response_delay_ms

    @delay.setter
    def delay(self, value: int) -> None:
        self._control.response_delay_ms = max(0, int(value))


class StateStore:
    """JSON-file key/value store shared by every case of a test plan.

    Every operation holds an in-process lock plus an exclusive flock on a
    sidecar lock file, so the proxy and the CLI never interleave writes.
    """

    def __init__(self, path: Path) -> None:
        self._path = Path(path)
        self._lock_path = self._path.with_name(self._path.name + ".lock")
        self._lock = threading.RLock()

    @property
    def path(self) -> Path:
        return self._path

    def get(self, key: str, default: Any = None) -> Any:
        with self._locked():
            return self._read().get(key, default)

    def set(self, key: str, value: Any) -> None:
        with self._locked():
            data = self._read()
            data[key] = value
            self._write(data)

    def incr(self, key: str, by: int = 1) -> int:
        with self._locked():
            data = self._read()
            current = data.get(key, 0)
            if not isinstance(current, int) or isinstance(current, bool):
                raise TypeError(f"store key {key!r} holds a non-integer value")
            data[key] = current + int(by)
            self._write(data)
            return data[key]

    def delete(self, key: str) -> bool:
        with self._locked():
            data = self._read()
            if key not in data:
                return False
            del data[key]
            self._write(data)
            return True

    def clear(self) -> None:
        with self._locked():
            self._write({})

    def all(self) -> dict[str, Any]:
        with self._locked():
            return self._read()

    @contextmanager
    def _locked(self) -> Iterator[None]:
        with self._lock:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            with self._lock_path.open("a") as handle:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
                try:
                    yield
                finally:
                    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)

    def _read(self) -> dict[str, Any]:
        if not self._path.is_file():
            return {}
        text = self._path.read_text(encoding="utf-8")
        if not text.strip():
            return {}
        data = _json.loads(text)
        if not isinstance(data, dict):
            raise ValueError(f"{self._path} must hold a JSON object")
        return data

    def _write(self, data: dict[str, Any]) -> None:
        text = _json.dumps(data, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
        fd, tmp = tempfile.mkstemp(
            dir=str(self._path.parent), prefix=f".{self._path.name}.", suffix=".tmp"
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fp:
                fp.write(text)
            os.replace(tmp, self._path)
        except BaseException:
            Path(tmp).unlink(missing_ok=True)
            raise


def _to_bytes(value: bytes | str) -> bytes:
    if isinstance(value, str):
        return value.encode("utf-8")
    return bytes(value)
