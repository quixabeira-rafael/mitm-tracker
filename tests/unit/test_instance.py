from __future__ import annotations

from pathlib import Path

import pytest

from mitm_tracker import instance


def test_registry_path_follows_home_env(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv(instance.HOME_ENV, str(tmp_path))
    assert instance.registry_path() == tmp_path / instance.REGISTRY_FILENAME


def test_live_is_none_without_registry() -> None:
    assert instance.live(instance.KIND_PROXY) is None


def test_acquire_then_live_roundtrip(tmp_path: Path) -> None:
    entry = instance.acquire(
        instance.KIND_PROXY, pid=111, workspace=tmp_path, port=8080, alive=lambda pid: True
    )
    assert entry.pid == 111
    assert entry.port == 8080

    current = instance.live(instance.KIND_PROXY, alive=lambda pid: True)
    assert current is not None
    assert current.workspace == tmp_path
    assert current.port == 8080


def test_acquire_rejects_a_second_live_instance(tmp_path: Path) -> None:
    instance.acquire(
        instance.KIND_PROXY, pid=111, workspace=tmp_path, alive=lambda pid: True
    )
    with pytest.raises(instance.InstanceBusyError) as excinfo:
        instance.acquire(
            instance.KIND_PROXY,
            pid=222,
            workspace=tmp_path / "other",
            alive=lambda pid: True,
        )
    assert excinfo.value.current.pid == 111


def test_acquire_is_idempotent_for_the_same_pid(tmp_path: Path) -> None:
    instance.acquire(
        instance.KIND_PROXY, pid=111, workspace=tmp_path, alive=lambda pid: True
    )
    again = instance.acquire(
        instance.KIND_PROXY, pid=111, workspace=tmp_path, port=9090, alive=lambda pid: True
    )
    assert again.port == 9090


def test_dead_entries_are_pruned(tmp_path: Path) -> None:
    instance.acquire(
        instance.KIND_PROXY, pid=111, workspace=tmp_path, alive=lambda pid: True
    )
    assert instance.live(instance.KIND_PROXY, alive=lambda pid: False) is None
    assert instance.registry_path().read_text(encoding="utf-8").strip() == "{}"


def test_kinds_are_tracked_independently(tmp_path: Path) -> None:
    instance.acquire(
        instance.KIND_PROXY, pid=111, workspace=tmp_path, alive=lambda pid: True
    )
    instance.acquire(
        instance.KIND_TRAY, pid=222, workspace=tmp_path, alive=lambda pid: True
    )
    assert instance.live(instance.KIND_PROXY, alive=lambda pid: True).pid == 111
    assert instance.live(instance.KIND_TRAY, alive=lambda pid: True).pid == 222


def test_adopt_pid_hands_the_reservation_to_the_child(tmp_path: Path) -> None:
    instance.acquire(
        instance.KIND_PROXY, pid=111, workspace=tmp_path, alive=lambda pid: True
    )
    adopted = instance.adopt_pid(instance.KIND_PROXY, expected_pid=111, pid=999)
    assert adopted is not None
    assert adopted.pid == 999
    assert instance.live(instance.KIND_PROXY, alive=lambda pid: True).pid == 999


def test_adopt_pid_ignores_a_mismatched_reservation(tmp_path: Path) -> None:
    instance.acquire(
        instance.KIND_PROXY, pid=111, workspace=tmp_path, alive=lambda pid: True
    )
    assert instance.adopt_pid(instance.KIND_PROXY, expected_pid=222, pid=999) is None
    assert instance.live(instance.KIND_PROXY, alive=lambda pid: True).pid == 111


def test_release_only_drops_a_matching_pid(tmp_path: Path) -> None:
    instance.acquire(
        instance.KIND_PROXY, pid=111, workspace=tmp_path, alive=lambda pid: True
    )
    instance.release(instance.KIND_PROXY, pid=222)
    assert instance.live(instance.KIND_PROXY, alive=lambda pid: True) is not None
    instance.release(instance.KIND_PROXY, pid=111)
    assert instance.live(instance.KIND_PROXY, alive=lambda pid: True) is None


def test_corrupt_registry_is_treated_as_empty(tmp_path: Path) -> None:
    instance.registry_path().parent.mkdir(parents=True, exist_ok=True)
    instance.registry_path().write_text("{not json", encoding="utf-8")
    assert instance.live(instance.KIND_PROXY) is None
