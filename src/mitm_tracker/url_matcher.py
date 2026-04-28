from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable
from urllib.parse import parse_qsl, urlsplit


QueryMode = str

QUERY_MODE_IGNORE = "ignore"
QUERY_MODE_EXACT = "exact"
QUERY_MODE_CONTAINS = "contains"
QUERY_MODE_EQUALS = "equals"

ALL_QUERY_MODES = (
    QUERY_MODE_IGNORE,
    QUERY_MODE_EXACT,
    QUERY_MODE_CONTAINS,
    QUERY_MODE_EQUALS,
)


class UrlMatcherError(ValueError):
    pass


@dataclass(frozen=True)
class ParsedUrl:
    scheme: str
    host: str
    port: int | None
    path: str
    query_raw: str

    @property
    def query_pairs(self) -> list[tuple[str, str]]:
        if not self.query_raw:
            return []
        return list(parse_qsl(self.query_raw, keep_blank_values=True))


def parse_url(value: str) -> ParsedUrl:
    if not value or "://" not in value:
        raise UrlMatcherError(
            f"invalid URL {value!r}: must include scheme (e.g. https://)"
        )
    parts = urlsplit(value)
    if not parts.hostname:
        raise UrlMatcherError(f"invalid URL {value!r}: missing host")
    return ParsedUrl(
        scheme=parts.scheme.lower(),
        host=parts.hostname.lower(),
        port=parts.port,
        path=parts.path or "/",
        query_raw=parts.query or "",
    )


@dataclass(frozen=True)
class CompiledPattern:
    raw: str
    scheme: str | None
    host_regex: re.Pattern
    path_regex: re.Pattern
    query_mode: QueryMode
    query_pairs: tuple[tuple[str, str], ...]
    query_raw: str


def compile_pattern(url_pattern: str, query_mode: QueryMode = QUERY_MODE_IGNORE) -> CompiledPattern:
    if query_mode not in ALL_QUERY_MODES:
        raise UrlMatcherError(
            f"invalid query_mode {query_mode!r}: choose from {ALL_QUERY_MODES}"
        )
    parsed = parse_url(url_pattern)
    host_regex = _compile_host_glob(parsed.host)
    path_regex = _compile_path_glob(parsed.path or "/")
    query_pairs = tuple(parsed.query_pairs)
    return CompiledPattern(
        raw=url_pattern,
        scheme=parsed.scheme,
        host_regex=host_regex,
        path_regex=path_regex,
        query_mode=query_mode,
        query_pairs=query_pairs,
        query_raw=parsed.query_raw,
    )


def matches(pattern: CompiledPattern, url: str) -> bool:
    try:
        target = parse_url(url)
    except UrlMatcherError:
        return False
    if pattern.scheme and pattern.scheme != target.scheme:
        return False
    if not pattern.host_regex.fullmatch(target.host):
        return False
    if not pattern.path_regex.fullmatch(target.path or "/"):
        return False
    return _query_matches(pattern, target)


def _query_matches(pattern: CompiledPattern, target: ParsedUrl) -> bool:
    mode = pattern.query_mode
    if mode == QUERY_MODE_IGNORE:
        return True
    if mode == QUERY_MODE_EXACT:
        return pattern.query_raw == target.query_raw
    actual = target.query_pairs
    expected = list(pattern.query_pairs)
    if mode == QUERY_MODE_CONTAINS:
        return _multiset_contains(actual, expected)
    if mode == QUERY_MODE_EQUALS:
        return _multiset_equals(actual, expected)
    return False


def _multiset_contains(
    actual: list[tuple[str, str]],
    expected: list[tuple[str, str]],
) -> bool:
    remaining = list(actual)
    for key, value_pattern in expected:
        idx = _find_match(remaining, key, value_pattern)
        if idx is None:
            return False
        remaining.pop(idx)
    return True


def _multiset_equals(
    actual: list[tuple[str, str]],
    expected: list[tuple[str, str]],
) -> bool:
    if len(actual) != len(expected):
        return False
    return _multiset_contains(actual, expected)


def _find_match(
    items: list[tuple[str, str]], key: str, value_pattern: str
) -> int | None:
    regex = _compile_value_glob(value_pattern)
    for idx, (k, v) in enumerate(items):
        if k == key and regex.fullmatch(v):
            return idx
    return None


def _compile_host_glob(value: str) -> re.Pattern:
    if value.startswith("*."):
        suffix = re.escape(value[2:])
        return re.compile(rf"(?:[^.]+\.)+{suffix}", re.IGNORECASE)
    return re.compile(re.escape(value), re.IGNORECASE)


def _compile_path_glob(value: str) -> re.Pattern:
    parts: list[str] = []
    i = 0
    while i < len(value):
        ch = value[i]
        if ch == "*":
            if i + 1 < len(value) and value[i + 1] == "*":
                parts.append(".*")
                i += 2
            else:
                parts.append("[^/]*")
                i += 1
        else:
            parts.append(re.escape(ch))
            i += 1
    return re.compile("".join(parts))


def _compile_value_glob(value: str) -> re.Pattern:
    parts: list[str] = []
    for ch in value:
        if ch == "*":
            parts.append(".*")
        else:
            parts.append(re.escape(ch))
    return re.compile("".join(parts))


def first_matching_index(
    patterns: Iterable[CompiledPattern], url: str
) -> int | None:
    for idx, pattern in enumerate(patterns):
        if matches(pattern, url):
            return idx
    return None
