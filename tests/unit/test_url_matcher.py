from __future__ import annotations

import pytest

from mitm_tracker.url_matcher import (
    QUERY_MODE_CONTAINS,
    QUERY_MODE_EQUALS,
    QUERY_MODE_EXACT,
    QUERY_MODE_IGNORE,
    UrlMatcherError,
    compile_pattern,
    matches,
    parse_url,
)


def test_parse_url_basic() -> None:
    p = parse_url("https://api.example.com/users?foo=bar")
    assert p.scheme == "https"
    assert p.host == "api.example.com"
    assert p.path == "/users"
    assert p.query_raw == "foo=bar"


def test_parse_url_lowercases_host() -> None:
    p = parse_url("https://API.EXAMPLE.COM/X")
    assert p.host == "api.example.com"
    assert p.path == "/X"


def test_parse_url_missing_scheme_raises() -> None:
    with pytest.raises(UrlMatcherError):
        parse_url("api.example.com/users")


def test_parse_url_missing_host_raises() -> None:
    with pytest.raises(UrlMatcherError):
        parse_url("https:///path")


def test_parse_url_default_path_is_slash() -> None:
    p = parse_url("https://example.com")
    assert p.path == "/"


@pytest.mark.parametrize(
    "pattern,target,expected",
    [
        ("https://api.example.com/users", "https://api.example.com/users", True),
        ("https://api.example.com/users", "https://api.example.com/users/", False),
        ("https://api.example.com/users", "https://api.example.com/posts", False),
        ("https://api.example.com/users", "https://OTHER.example.com/users", False),
        ("https://api.example.com/users", "http://api.example.com/users", False),
        ("https://api.example.com/users/*", "https://api.example.com/users/abc", True),
        ("https://api.example.com/users/*", "https://api.example.com/users/abc/posts", False),
        ("https://api.example.com/users/**", "https://api.example.com/users/abc/posts", True),
        ("https://api.example.com/users/**", "https://api.example.com/users/", True),
        ("https://api.example.com/users/*/posts/*", "https://api.example.com/users/42/posts/9", True),
        ("https://api.example.com/users/*/posts/*", "https://api.example.com/users/42/posts/9/comments", False),
        ("https://*.example.com/x", "https://api.example.com/x", True),
        ("https://*.example.com/x", "https://v1.api.example.com/x", True),
        ("https://*.example.com/x", "https://example.com/x", False),
    ],
)
def test_path_and_host_matching(pattern: str, target: str, expected: bool) -> None:
    compiled = compile_pattern(pattern)
    assert matches(compiled, target) is expected


def test_query_mode_ignore_matches_any_query() -> None:
    pat = compile_pattern("https://api.example.com/users", QUERY_MODE_IGNORE)
    assert matches(pat, "https://api.example.com/users") is True
    assert matches(pat, "https://api.example.com/users?foo=1") is True
    assert matches(pat, "https://api.example.com/users?a=1&b=2&c=3") is True


def test_query_mode_exact_requires_byte_for_byte() -> None:
    pat = compile_pattern(
        "https://api.example.com/users?foo=1&bar=2", QUERY_MODE_EXACT
    )
    assert matches(pat, "https://api.example.com/users?foo=1&bar=2") is True
    assert matches(pat, "https://api.example.com/users?bar=2&foo=1") is False
    assert matches(pat, "https://api.example.com/users?foo=1&bar=2&extra=3") is False


def test_query_mode_contains_allows_extra_params() -> None:
    pat = compile_pattern(
        "https://api.example.com/users?foo=1", QUERY_MODE_CONTAINS
    )
    assert matches(pat, "https://api.example.com/users?foo=1") is True
    assert matches(pat, "https://api.example.com/users?foo=1&bar=2") is True
    assert matches(pat, "https://api.example.com/users?bar=2&foo=1") is True
    assert matches(pat, "https://api.example.com/users") is False


def test_query_mode_contains_rejects_when_param_missing() -> None:
    pat = compile_pattern(
        "https://api.example.com/users?foo=1&bar=2", QUERY_MODE_CONTAINS
    )
    assert matches(pat, "https://api.example.com/users?foo=1") is False
    assert matches(pat, "https://api.example.com/users?bar=2") is False


def test_query_mode_equals_requires_same_multiset() -> None:
    pat = compile_pattern(
        "https://api.example.com/users?a=1&b=2&c=3", QUERY_MODE_EQUALS
    )
    assert matches(pat, "https://api.example.com/users?a=1&b=2&c=3") is True
    assert matches(pat, "https://api.example.com/users?c=3&a=1&b=2") is True
    assert matches(pat, "https://api.example.com/users?a=1&b=2") is False
    assert matches(pat, "https://api.example.com/users?a=1&b=2&c=3&d=4") is False


def test_query_value_wildcard_in_contains() -> None:
    pat = compile_pattern(
        "https://api.example.com/users?token=*", QUERY_MODE_CONTAINS
    )
    assert matches(pat, "https://api.example.com/users?token=abc") is True
    assert matches(pat, "https://api.example.com/users?token=") is True
    assert matches(pat, "https://api.example.com/users") is False


def test_query_value_partial_wildcard() -> None:
    pat = compile_pattern(
        "https://api.example.com/users?id=42*", QUERY_MODE_CONTAINS
    )
    assert matches(pat, "https://api.example.com/users?id=42") is True
    assert matches(pat, "https://api.example.com/users?id=4200") is True
    assert matches(pat, "https://api.example.com/users?id=43") is False


def test_query_repeated_param_multiset_in_equals() -> None:
    pat = compile_pattern(
        "https://api.example.com/x?tag=a&tag=b&tag=c", QUERY_MODE_EQUALS
    )
    assert matches(pat, "https://api.example.com/x?tag=a&tag=b&tag=c") is True
    assert matches(pat, "https://api.example.com/x?tag=c&tag=a&tag=b") is True
    assert matches(pat, "https://api.example.com/x?tag=a&tag=b") is False
    assert matches(pat, "https://api.example.com/x?tag=a&tag=b&tag=c&tag=d") is False


def test_query_mode_invalid_raises() -> None:
    with pytest.raises(UrlMatcherError):
        compile_pattern("https://api.example.com/x", "totallybogus")


def test_url_with_port_matches_when_pattern_has_no_port() -> None:
    pat = compile_pattern("https://api.example.com/x")
    assert matches(pat, "https://api.example.com:443/x") is True


def test_invalid_target_url_returns_false() -> None:
    pat = compile_pattern("https://api.example.com/x")
    assert matches(pat, "not a url") is False


def test_case_insensitive_host_match() -> None:
    pat = compile_pattern("https://API.example.com/x")
    assert matches(pat, "https://api.example.com/x") is True
    assert matches(pat, "https://API.EXAMPLE.COM/x") is True


def test_path_with_special_regex_chars_is_literal() -> None:
    pat = compile_pattern("https://api.example.com/users.json")
    assert matches(pat, "https://api.example.com/users.json") is True
    assert matches(pat, "https://api.example.com/usersXjson") is False


def test_path_query_combined() -> None:
    pat = compile_pattern(
        "https://api.example.com/users/*?include=posts", QUERY_MODE_CONTAINS
    )
    assert matches(pat, "https://api.example.com/users/42?include=posts&limit=10") is True
    assert matches(pat, "https://api.example.com/users/42?limit=10") is False
    assert matches(pat, "https://api.example.com/posts/42?include=posts") is False


def test_blank_value_param_is_preserved() -> None:
    pat = compile_pattern(
        "https://api.example.com/x?empty=", QUERY_MODE_CONTAINS
    )
    assert matches(pat, "https://api.example.com/x?empty=") is True
    assert matches(pat, "https://api.example.com/x?empty=foo") is False
