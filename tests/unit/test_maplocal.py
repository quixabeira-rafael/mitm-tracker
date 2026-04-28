from __future__ import annotations

import json
from pathlib import Path

import pytest

from mitm_tracker.maplocal import (
    MapLocalError,
    MapLocalSource,
    MapLocalStore,
)


def _store(tmp_path: Path) -> MapLocalStore:
    return MapLocalStore(profile_dir=tmp_path / "profiles" / "test")


def test_load_empty_when_file_absent(tmp_path: Path) -> None:
    s = _store(tmp_path)
    assert s.load() == []


def test_add_creates_files_and_returns_rule(tmp_path: Path) -> None:
    s = _store(tmp_path)
    rule = s.add(
        url_pattern="https://api.example.com/users",
        status=200,
        headers=[("Content-Type", "application/json")],
        body=b'{"x":1}',
    )
    assert rule.url_pattern == "https://api.example.com/users"
    assert rule.status == 200
    assert s.body_path(rule.id).read_bytes() == b'{"x":1}'
    assert s.headers_path(rule.id).exists()
    assert s.json_path.exists()


def test_add_persists_in_json(tmp_path: Path) -> None:
    s = _store(tmp_path)
    rule = s.add(
        url_pattern="https://api.example.com/x",
        body=b"hi",
    )
    payload = json.loads(s.json_path.read_text())
    assert payload["version"] == 1
    assert len(payload["rules"]) == 1
    assert payload["rules"][0]["id"] == rule.id


def test_add_round_trip(tmp_path: Path) -> None:
    s = _store(tmp_path)
    s.add(url_pattern="https://api.example.com/a", body=b"a")
    s.add(url_pattern="https://api.example.com/b", body=b"b")
    rules = s.load()
    assert [r.url_pattern for r in rules] == [
        "https://api.example.com/a",
        "https://api.example.com/b",
    ]


def test_add_validates_url_pattern(tmp_path: Path) -> None:
    s = _store(tmp_path)
    with pytest.raises(MapLocalError):
        s.add(url_pattern="not a url", body=b"")


def test_add_validates_query_mode(tmp_path: Path) -> None:
    s = _store(tmp_path)
    with pytest.raises(MapLocalError):
        s.add(
            url_pattern="https://api.example.com/x",
            query_mode="bogus",
            body=b"",
        )


def test_remove_existing_clears_files(tmp_path: Path) -> None:
    s = _store(tmp_path)
    rule = s.add(url_pattern="https://api.example.com/x", body=b"hi")
    body_path = s.body_path(rule.id)
    headers_path = s.headers_path(rule.id)
    assert body_path.exists()
    assert s.remove(rule.id) is True
    assert s.find(rule.id) is None
    assert not body_path.exists()
    assert not headers_path.exists()


def test_remove_keep_files(tmp_path: Path) -> None:
    s = _store(tmp_path)
    rule = s.add(url_pattern="https://api.example.com/x", body=b"hi")
    s.remove(rule.id, keep_files=True)
    assert s.body_path(rule.id).exists()
    assert s.headers_path(rule.id).exists()


def test_remove_unknown_returns_false(tmp_path: Path) -> None:
    s = _store(tmp_path)
    assert s.remove("missing") is False


def test_set_enabled_toggles(tmp_path: Path) -> None:
    s = _store(tmp_path)
    rule = s.add(url_pattern="https://api.example.com/x", body=b"")
    assert rule.enabled is True
    s.set_enabled(rule.id, False)
    assert s.find(rule.id).enabled is False
    s.set_enabled(rule.id, True)
    assert s.find(rule.id).enabled is True


def test_set_enabled_unknown_returns_false(tmp_path: Path) -> None:
    s = _store(tmp_path)
    assert s.set_enabled("missing", True) is False


def test_read_body_and_headers(tmp_path: Path) -> None:
    s = _store(tmp_path)
    rule = s.add(
        url_pattern="https://api.example.com/x",
        body=b"hello",
        headers=[("X-A", "1"), ("X-B", "2")],
    )
    assert s.read_body(rule.id) == b"hello"
    assert s.read_headers(rule.id) == [("X-A", "1"), ("X-B", "2")]


def test_write_body_overrides(tmp_path: Path) -> None:
    s = _store(tmp_path)
    rule = s.add(url_pattern="https://api.example.com/x", body=b"hi")
    s.write_body(rule.id, b"updated")
    assert s.read_body(rule.id) == b"updated"


def test_write_headers_overrides(tmp_path: Path) -> None:
    s = _store(tmp_path)
    rule = s.add(url_pattern="https://api.example.com/x", body=b"")
    s.write_headers(rule.id, [("X-Replaced", "1")])
    assert s.read_headers(rule.id) == [("X-Replaced", "1")]


def test_source_round_trip(tmp_path: Path) -> None:
    s = _store(tmp_path)
    src = MapLocalSource(from_flow=42, session_db="x.db", captured_at="now")
    rule = s.add(
        url_pattern="https://api.example.com/x",
        body=b"",
        source=src,
    )
    reloaded = s.find(rule.id)
    assert reloaded.source.from_flow == 42
    assert reloaded.source.session_db == "x.db"


def test_load_corrupt_raises(tmp_path: Path) -> None:
    s = _store(tmp_path)
    s.ensure()
    s.json_path.write_text("{not json")
    with pytest.raises(MapLocalError):
        s.load()


def test_load_invalid_shape_raises(tmp_path: Path) -> None:
    s = _store(tmp_path)
    s.ensure()
    s.json_path.write_text(json.dumps({"rules": "not a list"}))
    with pytest.raises(MapLocalError):
        s.load()


def test_ids_are_unique(tmp_path: Path) -> None:
    s = _store(tmp_path)
    ids = {
        s.add(url_pattern=f"https://api.example.com/{i}", body=b"").id
        for i in range(20)
    }
    assert len(ids) == 20
