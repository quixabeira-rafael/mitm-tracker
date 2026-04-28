from __future__ import annotations

import json
import subprocess
from typing import Sequence

import pytest

from mitm_tracker.simulators import (
    Simulator,
    SimulatorError,
    list_booted,
    list_simulators,
    find_by_name,
    find_by_udid,
)


def _completed(stdout: str = "", stderr: str = "", code: int = 0) -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(
        args=["xcrun", "simctl", "list", "devices", "--json"],
        returncode=code,
        stdout=stdout,
        stderr=stderr,
    )


def _runner_for(payload: dict, code: int = 0):
    def runner(_args: Sequence[str]) -> subprocess.CompletedProcess:
        return _completed(json.dumps(payload), code=code)

    return runner


def test_list_simulators_parses_runtime_and_state() -> None:
    payload = {
        "devices": {
            "com.apple.CoreSimulator.SimRuntime.iOS-17-4": [
                {
                    "udid": "ABC-123",
                    "name": "iPhone 15 Pro",
                    "state": "Booted",
                    "isAvailable": True,
                },
                {
                    "udid": "DEF-456",
                    "name": "iPhone 14",
                    "state": "Shutdown",
                    "isAvailable": True,
                },
            ],
        }
    }
    sims = list_simulators(runner=_runner_for(payload))
    assert len(sims) == 2
    assert sims[0].udid == "ABC-123"
    assert sims[0].name == "iPhone 15 Pro"
    assert sims[0].runtime == "iOS 17 4"
    assert sims[0].is_booted is True
    assert sims[1].is_booted is False


def test_list_simulators_skips_unavailable() -> None:
    payload = {
        "devices": {
            "com.apple.CoreSimulator.SimRuntime.iOS-17-4": [
                {
                    "udid": "GONE",
                    "name": "iPhone 8",
                    "state": "Shutdown",
                    "isAvailable": False,
                },
                {
                    "udid": "OK",
                    "name": "iPhone 15",
                    "state": "Shutdown",
                    "isAvailable": True,
                },
            ],
        }
    }
    sims = list_simulators(runner=_runner_for(payload))
    assert [s.udid for s in sims] == ["OK"]


def test_list_simulators_handles_empty_payload() -> None:
    sims = list_simulators(runner=_runner_for({"devices": {}}))
    assert sims == []


def test_list_booted_filters_only_booted() -> None:
    payload = {
        "devices": {
            "com.apple.CoreSimulator.SimRuntime.iOS-17-4": [
                {"udid": "A", "name": "1", "state": "Booted", "isAvailable": True},
                {"udid": "B", "name": "2", "state": "Shutdown", "isAvailable": True},
            ],
        }
    }
    sims = list_booted(runner=_runner_for(payload))
    assert [s.udid for s in sims] == ["A"]


def test_find_by_udid_case_insensitive() -> None:
    payload = {
        "devices": {
            "com.apple.CoreSimulator.SimRuntime.iOS-17-4": [
                {"udid": "ABC-123", "name": "Phone", "state": "Booted", "isAvailable": True},
            ],
        }
    }
    runner = _runner_for(payload)
    assert find_by_udid("abc-123", runner=runner).udid == "ABC-123"
    assert find_by_udid("missing", runner=runner) is None


def test_find_by_name_returns_all_matches() -> None:
    payload = {
        "devices": {
            "com.apple.CoreSimulator.SimRuntime.iOS-17-4": [
                {"udid": "A", "name": "iPhone 15", "state": "Booted", "isAvailable": True},
            ],
            "com.apple.CoreSimulator.SimRuntime.iOS-16-4": [
                {"udid": "B", "name": "iPhone 15", "state": "Shutdown", "isAvailable": True},
            ],
        }
    }
    runner = _runner_for(payload)
    matches = find_by_name("iPhone 15", runner=runner)
    assert {m.udid for m in matches} == {"A", "B"}

    booted_only = find_by_name("iPhone 15", runner=runner, only_booted=True)
    assert {m.udid for m in booted_only} == {"A"}


def test_runner_failure_raises() -> None:
    def runner(_args: Sequence[str]):
        return _completed(stdout="", stderr="boom", code=1)

    with pytest.raises(SimulatorError):
        list_simulators(runner=runner)


def test_runner_invalid_json_raises() -> None:
    def runner(_args: Sequence[str]):
        return _completed(stdout="not json", code=0)

    with pytest.raises(SimulatorError):
        list_simulators(runner=runner)


def test_simulator_dict_round_trip() -> None:
    s = Simulator(udid="X", name="Y", runtime="Z", state="Booted")
    assert s.to_dict() == {"udid": "X", "name": "Y", "runtime": "Z", "state": "Booted"}
