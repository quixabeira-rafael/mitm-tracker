from __future__ import annotations

import json
from pathlib import Path

import pytest

from mitm_tracker.config import DEFAULT_PROFILE_NAME, Workspace
from mitm_tracker.profile_manager import ProfileError, ProfileManager


def _workspace(tmp_path: Path) -> Workspace:
    ws = Workspace(root=tmp_path)
    ws.ensure()
    return ws


def test_default_is_implicit_when_listing(tmp_path: Path) -> None:
    pm = ProfileManager(_workspace(tmp_path))
    assert pm.list() == [DEFAULT_PROFILE_NAME]


def test_create_persists_directory(tmp_path: Path) -> None:
    ws = _workspace(tmp_path)
    pm = ProfileManager(ws)
    assert pm.create("sun-ios") is True
    assert ws.profile_dir("sun-ios").is_dir()
    assert pm.exists("sun-ios") is True


def test_create_is_idempotent(tmp_path: Path) -> None:
    pm = ProfileManager(_workspace(tmp_path))
    assert pm.create("staging") is True
    assert pm.create("staging") is False


def test_create_rejects_invalid_names(tmp_path: Path) -> None:
    pm = ProfileManager(_workspace(tmp_path))
    with pytest.raises(ProfileError):
        pm.create("foo bar")
    with pytest.raises(ProfileError):
        pm.create("")
    with pytest.raises(ProfileError):
        pm.create(".hidden")


def test_active_defaults_to_default_profile(tmp_path: Path) -> None:
    pm = ProfileManager(_workspace(tmp_path))
    assert pm.active_name() == DEFAULT_PROFILE_NAME


def test_set_active_persists(tmp_path: Path) -> None:
    pm = ProfileManager(_workspace(tmp_path))
    pm.create("sun-ios")
    pm.set_active("sun-ios")
    assert pm.active_name() == "sun-ios"

    pm2 = ProfileManager(_workspace(tmp_path))
    assert pm2.active_name() == "sun-ios"


def test_set_active_rejects_unknown(tmp_path: Path) -> None:
    pm = ProfileManager(_workspace(tmp_path))
    with pytest.raises(ProfileError):
        pm.set_active("missing")


def test_set_active_rejects_invalid_name(tmp_path: Path) -> None:
    pm = ProfileManager(_workspace(tmp_path))
    with pytest.raises(ProfileError):
        pm.set_active("foo bar")


def test_delete_removes_directory_and_falls_back_to_default(tmp_path: Path) -> None:
    ws = _workspace(tmp_path)
    pm = ProfileManager(ws)
    pm.create("temp")
    pm.set_active("temp")
    (ws.ssl_path("temp")).write_text(
        json.dumps({"version": 1, "domains": [{"pattern": "x", "added_at": "y"}]}),
        encoding="utf-8",
    )

    assert pm.delete("temp") is True
    assert not ws.profile_dir("temp").exists()
    assert pm.active_name() == DEFAULT_PROFILE_NAME


def test_delete_default_is_forbidden(tmp_path: Path) -> None:
    pm = ProfileManager(_workspace(tmp_path))
    with pytest.raises(ProfileError):
        pm.delete(DEFAULT_PROFILE_NAME)


def test_delete_unknown_returns_false(tmp_path: Path) -> None:
    pm = ProfileManager(_workspace(tmp_path))
    assert pm.delete("missing") is False


def test_describe_includes_ssl_count(tmp_path: Path) -> None:
    ws = _workspace(tmp_path)
    pm = ProfileManager(ws)
    pm.create("api")
    ws.ssl_path("api").write_text(
        json.dumps(
            {
                "version": 1,
                "domains": [
                    {"pattern": "*.example.com", "added_at": "x"},
                    {"pattern": "api.example.com", "added_at": "x"},
                ],
            }
        ),
        encoding="utf-8",
    )
    info = pm.describe("api")
    assert info.name == "api"
    assert info.ssl_count == 2
    assert info.is_active is False


def test_describe_active_marks_is_active(tmp_path: Path) -> None:
    pm = ProfileManager(_workspace(tmp_path))
    info = pm.describe()
    assert info.name == DEFAULT_PROFILE_NAME
    assert info.is_active is True
    assert info.ssl_count == 0


def test_describe_unknown_raises(tmp_path: Path) -> None:
    pm = ProfileManager(_workspace(tmp_path))
    with pytest.raises(ProfileError):
        pm.describe("missing")


def test_describe_all_lists_in_order(tmp_path: Path) -> None:
    pm = ProfileManager(_workspace(tmp_path))
    pm.create("zeta")
    pm.create("alpha")
    pm.set_active("alpha")
    descriptions = pm.describe_all()
    names = [p.name for p in descriptions]
    assert names == [DEFAULT_PROFILE_NAME, "alpha", "zeta"]
    actives = [p.name for p in descriptions if p.is_active]
    assert actives == ["alpha"]
