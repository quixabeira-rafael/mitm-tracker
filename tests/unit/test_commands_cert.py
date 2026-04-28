from __future__ import annotations

import json
from pathlib import Path
from typing import Sequence

import pytest

from mitm_tracker import cert_manager, simulators
from mitm_tracker.cert_manager import InstallResult
from mitm_tracker.cli import main
from mitm_tracker.output import EXIT_INVALID_STATE, EXIT_OK, EXIT_SYSTEM
from mitm_tracker.simulators import Simulator


@pytest.fixture
def simulator_set(monkeypatch):
    booted = [
        Simulator(udid="A1", name="iPhone 15 Pro", runtime="iOS 17.4", state="Booted"),
        Simulator(udid="B2", name="iPad Air", runtime="iOS 17.4", state="Booted"),
    ]
    shutdown = [
        Simulator(udid="C3", name="iPhone 14", runtime="iOS 16.4", state="Shutdown"),
    ]
    all_sims = [*booted, *shutdown]
    monkeypatch.setattr(simulators, "list_simulators", lambda: list(all_sims))
    monkeypatch.setattr(simulators, "list_booted", lambda: list(booted))
    return booted


def test_cert_simulators_lists_all(simulator_set, capsys, tmp_repo: Path) -> None:
    rc = main(["cert", "simulators", "--json"])
    out = json.loads(capsys.readouterr().out)
    assert rc == EXIT_OK
    assert out["count"] == 3


def test_cert_simulators_booted_only(simulator_set, capsys, tmp_repo: Path) -> None:
    rc = main(["cert", "simulators", "--booted-only", "--json"])
    out = json.loads(capsys.readouterr().out)
    assert rc == EXIT_OK
    assert out["count"] == 2
    assert all(s["state"] == "Booted" for s in out["simulators"])


def test_cert_status_includes_install_flag(
    simulator_set, monkeypatch, capsys, tmp_repo: Path
) -> None:
    monkeypatch.setattr(
        cert_manager, "is_installed", lambda sim: sim.udid == "A1"
    )
    rc = main(["cert", "status", "--json"])
    out = json.loads(capsys.readouterr().out)
    assert rc == EXIT_OK
    by_udid = {s["udid"]: s["cert_installed"] for s in out["simulators"]}
    assert by_udid == {"A1": True, "B2": False}


def test_cert_install_requires_disambiguation_when_multiple_booted(
    simulator_set, capsys, tmp_repo: Path
) -> None:
    rc = main(["cert", "install", "--json"])
    err = capsys.readouterr().err
    assert rc == EXIT_INVALID_STATE
    payload = json.loads(err)
    assert payload["error"] == "invalid_state"


def test_cert_install_all_booted_runs_for_each(
    simulator_set, monkeypatch, capsys, tmp_repo: Path
) -> None:
    calls: list[str] = []

    def fake_install(sim, **_):
        calls.append(sim.udid)
        return InstallResult(udid=sim.udid, name=sim.name, installed=True)

    monkeypatch.setattr(cert_manager, "install", fake_install)
    rc = main(["cert", "install", "--all-booted", "--json"])
    out = json.loads(capsys.readouterr().out)
    assert rc == EXIT_OK
    assert sorted(calls) == ["A1", "B2"]
    assert len(out["installed"]) == 2
    assert out["errors"] == []


def test_cert_install_by_udid(
    simulator_set, monkeypatch, capsys, tmp_repo: Path
) -> None:
    calls: list[str] = []

    def fake_install(sim, **_):
        calls.append(sim.udid)
        return InstallResult(udid=sim.udid, name=sim.name, installed=True)

    monkeypatch.setattr(cert_manager, "install", fake_install)
    rc = main(["cert", "install", "--udid", "A1", "--json"])
    out = json.loads(capsys.readouterr().out)
    assert rc == EXIT_OK
    assert calls == ["A1"]
    assert len(out["installed"]) == 1


def test_cert_install_by_unknown_udid_returns_invalid_state(
    simulator_set, capsys, tmp_repo: Path
) -> None:
    rc = main(["cert", "install", "--udid", "XX", "--json"])
    err = capsys.readouterr().err
    assert rc == EXIT_INVALID_STATE
    payload = json.loads(err)
    assert payload["error"] == "invalid_state"


def test_cert_install_no_booted_returns_invalid_state(monkeypatch, tmp_repo: Path, capsys) -> None:
    monkeypatch.setattr(simulators, "list_simulators", lambda: [])
    monkeypatch.setattr(simulators, "list_booted", lambda: [])
    rc = main(["cert", "install", "--json"])
    err = capsys.readouterr().err
    payload = json.loads(err)
    assert rc == EXIT_INVALID_STATE
    assert payload["error"] == "no_simulators"


def test_cert_install_aggregates_errors(
    simulator_set, monkeypatch, capsys, tmp_repo: Path
) -> None:
    def fake_install(sim, **_):
        if sim.udid == "B2":
            raise cert_manager.CertManagerError("simctl boom")
        return InstallResult(udid=sim.udid, name=sim.name, installed=True)

    monkeypatch.setattr(cert_manager, "install", fake_install)
    rc = main(["cert", "install", "--all-booted", "--json"])
    out = json.loads(capsys.readouterr().out)
    assert rc == EXIT_SYSTEM
    assert len(out["errors"]) == 1
    assert out["errors"][0]["udid"] == "B2"
