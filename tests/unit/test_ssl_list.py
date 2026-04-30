from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from mitm_tracker.ssl_list import SslList, SslListError


def test_load_missing_file_returns_empty_list(tmp_path: Path) -> None:
    sl = SslList.load(tmp_path / "ssl.json")
    assert sl.entries == []
    assert sl.patterns() == []


def test_save_writes_versioned_json(tmp_path: Path) -> None:
    path = tmp_path / "ssl.json"
    sl = SslList(path=path)
    sl.add("api.example.com")
    sl.save()
    data = json.loads(path.read_text())
    assert data["version"] == 1
    assert data["domains"][0]["pattern"] == "api.example.com"
    assert "added_at" in data["domains"][0]


def test_round_trip_preserves_patterns(tmp_path: Path) -> None:
    path = tmp_path / "ssl.json"
    sl = SslList(path=path)
    sl.add("api.example.com")
    sl.add("*.cdn.example.com")
    sl.save()
    reloaded = SslList.load(path)
    assert reloaded.patterns() == ["api.example.com", "*.cdn.example.com"]


def test_add_dedupes(tmp_path: Path) -> None:
    sl = SslList(path=tmp_path / "ssl.json")
    assert sl.add("api.example.com") is True
    assert sl.add("api.example.com") is False
    assert sl.add("API.EXAMPLE.COM") is False
    assert sl.patterns() == ["api.example.com"]


def test_add_rejects_empty(tmp_path: Path) -> None:
    sl = SslList(path=tmp_path / "ssl.json")
    with pytest.raises(SslListError):
        sl.add("   ")


def test_remove_returns_false_when_missing(tmp_path: Path) -> None:
    sl = SslList(path=tmp_path / "ssl.json")
    assert sl.remove("nope.com") is False


def test_remove_returns_true_when_present(tmp_path: Path) -> None:
    sl = SslList(path=tmp_path / "ssl.json")
    sl.add("api.example.com")
    assert sl.remove("api.example.com") is True
    assert sl.patterns() == []


def test_matches_exact(tmp_path: Path) -> None:
    sl = SslList(path=tmp_path / "ssl.json")
    sl.add("api.example.com")
    assert sl.matches("api.example.com") == "api.example.com"
    assert sl.matches("v1.api.example.com") is None
    assert sl.matches("example.com") is None


def test_matches_wildcard_subdomain(tmp_path: Path) -> None:
    sl = SslList(path=tmp_path / "ssl.json")
    sl.add("*.cdn.example.com")
    assert sl.matches("cdn.example.com") == "*.cdn.example.com"
    assert sl.matches("v1.cdn.example.com") == "*.cdn.example.com"
    assert sl.matches("v1.v2.cdn.example.com") == "*.cdn.example.com"
    assert sl.matches("example.com") is None


def test_matches_is_case_insensitive(tmp_path: Path) -> None:
    sl = SslList(path=tmp_path / "ssl.json")
    sl.add("api.example.com")
    assert sl.matches("API.example.com") == "api.example.com"


def test_to_allow_hosts_regex_when_empty_returns_impossible_match(tmp_path: Path) -> None:
    """An empty SSL list must return a regex that matches NO host, so mitmproxy
    falls back to TLS passthrough for everything (instead of decrypting all
    HTTPS by default — which would break the whole machine since the macOS
    host doesn't trust the mitmproxy CA)."""
    sl = SslList(path=tmp_path / "ssl.json")
    regex = sl.to_allow_hosts_regex()
    assert regex is not None
    pattern = re.compile(regex)
    # No real host should match this regex.
    for sample in ["api.example.com", "google.com", "127.0.0.1", "localhost", "example.com:443"]:
        assert pattern.search(sample) is None, f"impossible regex matched {sample!r}"


def test_allow_hosts_regex_includes_listed_hosts(tmp_path: Path) -> None:
    sl = SslList(path=tmp_path / "ssl.json")
    sl.add("api.example.com")
    sl.add("*.cdn.example.com")
    regex = sl.to_allow_hosts_regex()
    assert regex is not None
    pattern = re.compile(regex)

    assert pattern.search("api.example.com") is not None
    assert pattern.search("api.example.com:443") is not None
    assert pattern.search("v1.cdn.example.com") is not None
    assert pattern.search("cdn.example.com") is not None
    assert pattern.search("v1.cdn.example.com:443") is not None

    assert pattern.search("google.com") is None
    assert pattern.search("v1.api.example.com") is None
    assert pattern.search("example.com") is None


def test_load_rejects_invalid_json(tmp_path: Path) -> None:
    path = tmp_path / "ssl.json"
    path.write_text("{invalid")
    with pytest.raises(SslListError):
        SslList.load(path)


def test_load_rejects_invalid_shape(tmp_path: Path) -> None:
    path = tmp_path / "ssl.json"
    path.write_text(json.dumps({"domains": "not-a-list"}))
    with pytest.raises(SslListError):
        SslList.load(path)


def test_load_rejects_entries_without_pattern(tmp_path: Path) -> None:
    path = tmp_path / "ssl.json"
    path.write_text(json.dumps({"version": 1, "domains": [{"added_at": "x"}]}))
    with pytest.raises(SslListError):
        SslList.load(path)
