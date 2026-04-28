from __future__ import annotations

import json
from pathlib import Path

import pytest

from mitm_tracker.curl_export import export_request


def _flow(
    *,
    seq: int = 1,
    method: str = "GET",
    url: str = "https://api.example.com/users",
    http_version: str = "HTTP/1.1",
    headers: list[tuple[str, str]] | None = None,
    body: bytes | None = None,
    truncated: bool = False,
) -> dict:
    return {
        "seq": seq,
        "method": method,
        "full_url": url,
        "request_http_version": http_version,
        "request_headers": json.dumps(headers or []),
        "request_body": body,
        "request_body_size": len(body) if body else 0,
        "request_body_truncated": int(truncated),
    }


def test_export_basic_get_with_no_body() -> None:
    export = export_request(_flow(headers=[("Host", "api.example.com")]))
    assert "curl" in export.command
    assert "-X GET" in export.command
    assert "--header 'Host: api.example.com'" in export.command
    assert "https://api.example.com/users" in export.command
    assert "--http1.1" in export.command


def test_export_preserves_all_headers_including_sensitive() -> None:
    flow = _flow(
        headers=[
            ("Host", "api.example.com"),
            ("Authorization", "Bearer secret-token"),
            ("User-Agent", "MyApp/1.0"),
            ("X-Custom-Trace", "abc123"),
            ("Cookie", "session=abc; theme=dark"),
        ]
    )
    cmd = export_request(flow).command
    assert "Authorization: Bearer secret-token" in cmd
    assert "User-Agent: MyApp/1.0" in cmd
    assert "X-Custom-Trace: abc123" in cmd
    assert "Cookie: session=abc; theme=dark" in cmd


def test_export_preserves_duplicate_headers() -> None:
    flow = _flow(
        headers=[
            ("Set-Cookie", "a=1"),
            ("Set-Cookie", "b=2"),
            ("X-Forwarded-For", "10.0.0.1"),
            ("X-Forwarded-For", "10.0.0.2"),
        ]
    )
    cmd = export_request(flow).command
    assert cmd.count("Set-Cookie: a=1") == 1
    assert cmd.count("Set-Cookie: b=2") == 1
    assert cmd.count("X-Forwarded-For: 10.0.0.1") == 1
    assert cmd.count("X-Forwarded-For: 10.0.0.2") == 1


def test_export_post_with_inline_text_body() -> None:
    flow = _flow(
        method="POST",
        headers=[("Content-Type", "application/json")],
        body=b'{"name":"foo"}',
    )
    cmd = export_request(flow).command
    assert "-X POST" in cmd
    assert '--data-binary' in cmd
    assert '{"name":"foo"}' in cmd


def test_export_binary_body_writes_file(tmp_path: Path) -> None:
    binary = bytes(range(256))
    flow = _flow(method="POST", body=binary)
    export = export_request(flow, body_dir=tmp_path)
    assert export.body_file is not None
    assert export.body_file.exists()
    assert export.body_file.read_bytes() == binary
    assert f"@{export.body_file}" in export.command


def test_export_body_with_null_byte_uses_file(tmp_path: Path) -> None:
    flow = _flow(method="POST", body=b"hello\x00world")
    export = export_request(flow, body_dir=tmp_path)
    assert export.body_file is not None


def test_export_handles_base64_blob_from_store(tmp_path: Path) -> None:
    import base64

    raw = bytes([0xff, 0xfe, 0x00, 0x01, 0x02])
    flow = {
        "seq": 1,
        "method": "POST",
        "full_url": "https://x.example.com",
        "request_http_version": "HTTP/1.1",
        "request_headers": "[]",
        "request_body": {"__bytes_b64__": base64.b64encode(raw).decode("ascii"), "size": 5},
    }
    export = export_request(flow, body_dir=tmp_path)
    assert export.body_file is not None
    assert export.body_file.read_bytes() == raw


def test_export_http_version_flags() -> None:
    for ver, flag in [
        ("HTTP/1.0", "--http1.0"),
        ("HTTP/1.1", "--http1.1"),
        ("HTTP/2", "--http2"),
        ("HTTP/2.0", "--http2"),
        ("HTTP/3", "--http3"),
    ]:
        cmd = export_request(_flow(http_version=ver)).command
        assert flag in cmd


def test_export_unknown_http_version_omits_flag() -> None:
    cmd = export_request(_flow(http_version="SPDY/3.1")).command
    assert "--http" not in cmd


def test_export_method_options_preserved() -> None:
    cmd = export_request(_flow(method="OPTIONS")).command
    assert "-X OPTIONS" in cmd


def test_export_method_patch_preserved() -> None:
    cmd = export_request(_flow(method="PATCH")).command
    assert "-X PATCH" in cmd


def test_single_line_renders_without_backslashes() -> None:
    flow = _flow(headers=[("X-A", "1"), ("X-B", "2")])
    cmd = export_request(flow, single_line=True).command
    assert "\\\n" not in cmd
    assert "X-A: 1" in cmd
    assert "X-B: 2" in cmd


def test_multiline_uses_backslash_continuation() -> None:
    flow = _flow(headers=[("X-A", "1"), ("X-B", "2")])
    cmd = export_request(flow, single_line=False).command
    assert " \\\n" in cmd


def test_truncated_body_emits_warning_comment() -> None:
    flow = _flow(method="POST", body=b"prefix-only", truncated=True)
    flow["request_body_size"] = 99999
    export = export_request(flow)
    assert export.command.startswith("# WARNING:")
    assert "truncated" in export.command


def test_url_with_query_string_preserved() -> None:
    url = "https://api.example.com/search?q=hello%20world&page=2"
    cmd = export_request(_flow(url=url)).command
    assert url in cmd


def test_special_characters_in_header_values_quoted() -> None:
    """Single quotes get shell-escaped to '"'"'; double quotes pass through."""
    flow = _flow(headers=[("X-Weird", "value with 'single' and \"double\" quotes")])
    cmd = export_request(flow).command
    assert "X-Weird:" in cmd
    assert "double" in cmd
    assert "single" in cmd
    import shlex

    tokens = shlex.split(cmd.replace("\\\n", " "))
    header_token = next(t for t in tokens if t.startswith("X-Weird:"))
    assert header_token == "X-Weird: value with 'single' and \"double\" quotes"


def test_to_dict_shape() -> None:
    export = export_request(_flow(headers=[("Host", "x")]))
    payload = export.to_dict()
    assert payload["seq"] == 1
    assert payload["method"] == "GET"
    assert payload["url"] == "https://api.example.com/users"
    assert payload["http_version"] == "HTTP/1.1"
    assert "curl" in payload["curl"]
    assert payload["body_file"] is None


def test_no_body_omits_data_binary() -> None:
    cmd = export_request(_flow()).command
    assert "--data-binary" not in cmd


def test_empty_body_omits_data_binary() -> None:
    cmd = export_request(_flow(body=b"")).command
    assert "--data-binary" not in cmd
