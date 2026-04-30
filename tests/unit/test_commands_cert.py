from __future__ import annotations

import json
from pathlib import Path
from typing import Sequence
from unittest.mock import patch

import pytest

from mitm_tracker import cert_manager, host_ca, simulators
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


# --- cert host tests ---------------------------------------------------------


def _stub_install_result(
    pem: Path,
    *,
    invoked_privileged: bool = True,
    replaced_existing: bool = False,
    verified_trusted: bool = True,
    stale_removed: list[str] | None = None,
) -> host_ca.HostCaInstallResult:
    return host_ca.HostCaInstallResult(
        ca_path=pem,
        ca_sha1_hex="AABBCC",
        ca_sha1_colons="AA:BB:CC",
        system_keychain_path=host_ca.SYSTEM_KEYCHAIN,
        replaced_existing=replaced_existing,
        stale_removed=stale_removed or [],
        invoked_privileged=invoked_privileged,
        verified_trusted=verified_trusted,
    )


def _stub_uninstall_result() -> host_ca.HostCaUninstallResult:
    return host_ca.HostCaUninstallResult(
        system_keychain_path=host_ca.SYSTEM_KEYCHAIN,
        removed_shas=["AABBCC"],
        skipped_unmanaged_shas=[],
        invoked_privileged=True,
    )


def _stub_status_result(installed: bool = True, trusted: bool = True) -> host_ca.HostCaStatusResult:
    return host_ca.HostCaStatusResult(
        ca_path=Path("/tmp/ca.pem"),
        current_sha1_hex="AABBCC",
        current_sha1_colons="AA:BB:CC",
        system_keychain_path=host_ca.SYSTEM_KEYCHAIN,
        installed_current=installed,
        trusted_current=trusted,
        matching_cn=[],
    )


def test_register_cert_host_subcommands(tmp_repo: Path) -> None:
    """Make sure `cert host {install,uninstall,status}` parses."""
    from mitm_tracker.cli import build_parser

    parser = build_parser()
    args = parser.parse_args(["cert", "host", "install", "--yes", "--force", "--json"])
    assert args.cert_command == "host"
    assert args.cert_host_command == "install"
    assert args.yes is True
    assert args.force is True

    args = parser.parse_args(["cert", "host", "uninstall", "--json"])
    assert args.cert_host_command == "uninstall"

    args = parser.parse_args(["cert", "host", "status"])
    assert args.cert_host_command == "status"


def test_cmd_cert_host_install_skips_prompt_in_json_mode(
    tmp_repo: Path, monkeypatch, capsys
) -> None:
    pem = tmp_repo / "ca.pem"
    pem.write_text("-----BEGIN CERTIFICATE-----\nA\n-----END CERTIFICATE-----\n")
    monkeypatch.setattr(cert_manager, "ca_path", lambda *a, **kw: pem)
    monkeypatch.setattr(host_ca, "validate_pem_is_root_ca", lambda *_a, **_kw: (True, None))
    monkeypatch.setattr(host_ca, "current_ca_sha1", lambda *_a: ("AA", "AA"))
    # input() should never be called
    monkeypatch.setattr("builtins.input", lambda *_a: pytest.fail("prompt should be skipped in --json"))

    with patch.object(host_ca, "install", return_value=_stub_install_result(pem)):
        rc = main(["cert", "host", "install", "--json"])

    assert rc == EXIT_OK
    out = capsys.readouterr().out
    payload = json.loads(out)
    assert payload["verified_trusted"] is True


def test_cmd_cert_host_install_aborts_on_negative_prompt(
    tmp_repo: Path, monkeypatch, capsys
) -> None:
    pem = tmp_repo / "ca.pem"
    pem.write_text("-----BEGIN CERTIFICATE-----\nA\n-----END CERTIFICATE-----\n")
    monkeypatch.setattr(cert_manager, "ca_path", lambda *a, **kw: pem)
    monkeypatch.setattr(host_ca, "validate_pem_is_root_ca", lambda *_a, **_kw: (True, None))
    monkeypatch.setattr(host_ca, "current_ca_sha1", lambda *_a: ("AA", "AA"))
    monkeypatch.setattr("builtins.input", lambda *_a: "n")
    with patch.object(host_ca, "install") as mock_install:
        rc = main(["cert", "host", "install"])

    assert rc == EXIT_INVALID_STATE
    err = capsys.readouterr().err
    assert "cancelled by user" in err
    mock_install.assert_not_called()


def test_cmd_cert_host_install_passes_force_through(
    tmp_repo: Path, monkeypatch
) -> None:
    pem = tmp_repo / "ca.pem"
    pem.write_text("-----BEGIN CERTIFICATE-----\nA\n-----END CERTIFICATE-----\n")
    monkeypatch.setattr(cert_manager, "ca_path", lambda *a, **kw: pem)
    monkeypatch.setattr(host_ca, "validate_pem_is_root_ca", lambda *_a, **_kw: (True, None))
    monkeypatch.setattr(host_ca, "current_ca_sha1", lambda *_a: ("AA", "AA"))

    with patch.object(host_ca, "install", return_value=_stub_install_result(pem)) as mock_install:
        rc = main(["cert", "host", "install", "--yes", "--force", "--json"])

    assert rc == EXIT_OK
    kwargs = mock_install.call_args.kwargs
    assert kwargs.get("force") is True


def test_cmd_cert_host_install_returns_system_when_verify_fails(
    tmp_repo: Path, monkeypatch, capsys
) -> None:
    pem = tmp_repo / "ca.pem"
    pem.write_text("-----BEGIN CERTIFICATE-----\nA\n-----END CERTIFICATE-----\n")
    monkeypatch.setattr(cert_manager, "ca_path", lambda *a, **kw: pem)
    monkeypatch.setattr(host_ca, "validate_pem_is_root_ca", lambda *_a, **_kw: (True, None))
    monkeypatch.setattr(host_ca, "current_ca_sha1", lambda *_a: ("AA", "AA"))

    bad_result = _stub_install_result(pem, verified_trusted=False)
    with patch.object(host_ca, "install", return_value=bad_result):
        rc = main(["cert", "host", "install", "--yes", "--json"])

    assert rc == EXIT_SYSTEM
    err = capsys.readouterr().err
    assert "verify_failed" in err


def test_cmd_cert_host_install_aborts_on_missing_pem(tmp_repo: Path, monkeypatch, capsys) -> None:
    missing = tmp_repo / "no.pem"
    monkeypatch.setattr(cert_manager, "ca_path", lambda *a, **kw: missing)
    rc = main(["cert", "host", "install", "--yes", "--json"])
    assert rc == EXIT_INVALID_STATE
    err = capsys.readouterr().err
    assert "ca_missing" in err


def test_cmd_cert_host_install_rejects_invalid_pem(tmp_repo: Path, monkeypatch, capsys) -> None:
    pem = tmp_repo / "ca.pem"
    pem.write_text("-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n")
    monkeypatch.setattr(cert_manager, "ca_path", lambda *a, **kw: pem)
    monkeypatch.setattr(
        host_ca, "validate_pem_is_root_ca",
        lambda *_a, **_kw: (False, "PEM is not a CA certificate"),
    )
    rc = main(["cert", "host", "install", "--yes", "--json"])
    assert rc == EXIT_INVALID_STATE
    err = capsys.readouterr().err
    assert "ca_invalid" in err


def test_cmd_cert_host_uninstall_no_prompt(tmp_repo: Path, capsys) -> None:
    """Uninstall is a recovery operation; never prompts for confirmation."""
    with patch.object(host_ca, "uninstall", return_value=_stub_uninstall_result()):
        rc = main(["cert", "host", "uninstall", "--json"])
    assert rc == EXIT_OK
    out = json.loads(capsys.readouterr().out)
    assert out["removed_shas"] == ["AABBCC"]


def test_cmd_cert_host_status_returns_payload(tmp_repo: Path, capsys) -> None:
    with patch.object(host_ca, "status", return_value=_stub_status_result()):
        rc = main(["cert", "host", "status", "--json"])
    assert rc == EXIT_OK
    payload = json.loads(capsys.readouterr().out)
    assert payload["installed_current"] is True
    assert payload["trusted_current"] is True
