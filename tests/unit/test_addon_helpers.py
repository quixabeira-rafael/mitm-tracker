from __future__ import annotations

import json

from mitm_tracker.addon import _cookies_to_json, _serialize_cookie_value


class _CookieAttrsLike:
    """Mimics mitmproxy.coretypes.multidict.CookieAttrs (an object, not dict)."""

    def __init__(self, pairs: list[tuple[str, str]]) -> None:
        self._pairs = list(pairs)

    def items(self, multi: bool = False):
        return list(self._pairs)


def test_serialize_cookie_value_with_string() -> None:
    assert _serialize_cookie_value("session") == "session"


def test_serialize_cookie_value_with_bytes() -> None:
    assert _serialize_cookie_value(b"session") == "session"


def test_serialize_cookie_value_with_tuple_string_and_dict() -> None:
    out = _serialize_cookie_value(("session-id", {"path": "/", "secure": True}))
    assert out == ["session-id", {"path": "/", "secure": True}]


def test_serialize_cookie_value_with_tuple_string_and_cookie_attrs_object() -> None:
    attrs = _CookieAttrsLike([("path", "/"), ("Secure", "")])
    out = _serialize_cookie_value(("session-id", attrs))
    assert out[0] == "session-id"
    assert out[1] == [["path", "/"], ["Secure", ""]]


def test_cookies_to_json_handles_set_cookie_with_cookie_attrs() -> None:
    class _CookiesContainer:
        def __init__(self) -> None:
            self._items = [
                ("__cf_bm", ("abc.def", _CookieAttrsLike([("path", "/"), ("HttpOnly", "")]))),
                ("session", ("xyz", _CookieAttrsLike([("path", "/"), ("Secure", "")]))),
            ]

        def items(self, multi: bool = False):
            return list(self._items)

    result = _cookies_to_json(_CookiesContainer())
    assert result is not None
    decoded = json.loads(result)
    assert decoded[0][0] == "__cf_bm"
    assert decoded[0][1][0] == "abc.def"
    assert decoded[0][1][1] == [["path", "/"], ["HttpOnly", ""]]


def test_cookies_to_json_returns_none_when_empty() -> None:
    class _Empty:
        def items(self, multi: bool = False):
            return []

    assert _cookies_to_json(_Empty()) is None


def test_cookies_to_json_falls_back_to_str_when_unserializable() -> None:
    class _Weird:
        def __str__(self) -> str:
            return "weird-token"

    class _C:
        def items(self, multi: bool = False):
            return [("k", _Weird())]

    out = _cookies_to_json(_C())
    assert out is not None
    decoded = json.loads(out)
    assert decoded == [["k", "weird-token"]]
