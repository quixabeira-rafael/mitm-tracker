from __future__ import annotations

import base64
import json
import shlex
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class CurlExport:
    seq: int
    method: str
    url: str
    http_version: str | None
    command: str
    body_file: Path | None

    def to_dict(self) -> dict:
        return {
            "seq": self.seq,
            "method": self.method,
            "url": self.url,
            "http_version": self.http_version,
            "curl": self.command,
            "body_file": str(self.body_file) if self.body_file else None,
        }


def export_request(
    flow: dict[str, Any],
    *,
    body_dir: Path | None = None,
    single_line: bool = False,
) -> CurlExport:
    method = (flow.get("method") or "GET").upper()
    url = flow.get("full_url") or ""
    http_version = flow.get("request_http_version")
    headers = _decode_headers(flow.get("request_headers"))
    body_value = flow.get("request_body")
    body_size = flow.get("request_body_size") or 0
    body_truncated = bool(flow.get("request_body_truncated"))

    parts: list[list[str]] = []
    parts.append(["curl"])
    parts.append(["-X", method])

    http_flag = _http_version_flag(http_version)
    if http_flag:
        parts.append([http_flag])

    for name, value in headers:
        parts.append(["--header", f"{name}: {value}"])

    body_file: Path | None = None
    body_bytes = _coerce_body_bytes(body_value)
    if body_bytes is not None and body_bytes != b"":
        if _is_safe_inline_text(body_bytes):
            parts.append(["--data-binary", body_bytes.decode("utf-8")])
        else:
            if body_dir is None:
                body_dir = Path.cwd()
            body_file = body_dir / f"flow_{flow.get('seq')}.body.bin"
            body_file.write_bytes(body_bytes)
            parts.append(["--data-binary", f"@{body_file}"])

    parts.append([url])

    if body_truncated:
        comment = (
            "# WARNING: original request body was truncated by mitm-tracker "
            f"(captured {body_size} bytes; mitm-tracker stored only a prefix). "
            "Re-record with a higher tracker_body_limit to reproduce exactly."
        )
        if single_line:
            command = comment + "\n" + " ".join(shlex.quote(t) for tokens in parts for t in tokens)
        else:
            command = comment + "\n" + _format_multiline(parts)
    else:
        command = _format_command(parts, single_line=single_line)

    return CurlExport(
        seq=int(flow.get("seq") or 0),
        method=method,
        url=url,
        http_version=http_version,
        command=command,
        body_file=body_file,
    )


def _format_command(parts: list[list[str]], *, single_line: bool) -> str:
    if single_line:
        return " ".join(shlex.quote(token) for group in parts for token in group)
    return _format_multiline(parts)


def _format_multiline(parts: list[list[str]]) -> str:
    rendered_groups: list[str] = []
    for group in parts:
        rendered_groups.append(" ".join(shlex.quote(token) for token in group))
    indent = "  "
    if len(rendered_groups) == 1:
        return rendered_groups[0]
    head, *tail = rendered_groups
    lines = [head + " \\"]
    for i, line in enumerate(tail):
        suffix = " \\" if i < len(tail) - 1 else ""
        lines.append(f"{indent}{line}{suffix}")
    return "\n".join(lines)


def _http_version_flag(version: str | None) -> str | None:
    if not version:
        return None
    text = version.strip().upper()
    if text in {"HTTP/1.0"}:
        return "--http1.0"
    if text in {"HTTP/1.1"}:
        return "--http1.1"
    if text.startswith("HTTP/2"):
        return "--http2"
    if text.startswith("HTTP/3"):
        return "--http3"
    return None


def _decode_headers(raw: Any) -> list[tuple[str, str]]:
    if raw is None:
        return []
    if isinstance(raw, list):
        return [(str(k), str(v)) for k, v in raw]
    if isinstance(raw, str):
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return []
        if isinstance(data, list):
            return [(str(k), str(v)) for k, v in data]
    return []


def _coerce_body_bytes(value: Any) -> bytes | None:
    if value is None:
        return None
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return value.encode("utf-8")
    if isinstance(value, dict) and "__bytes_b64__" in value:
        try:
            return base64.b64decode(value["__bytes_b64__"])
        except Exception:
            return None
    return None


def _is_safe_inline_text(data: bytes) -> bool:
    if b"\x00" in data:
        return False
    try:
        data.decode("utf-8")
    except UnicodeDecodeError:
        return False
    if len(data) > 100_000:
        return False
    return True
