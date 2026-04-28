from __future__ import annotations

import base64
import hashlib
import sqlite3
import subprocess
from pathlib import Path
from typing import Sequence

import pytest

from mitm_tracker.cert_manager import (
    CertManagerError,
    InstallResult,
    ensure_ca_exists,
    fingerprint,
    install,
    is_installed,
)
from mitm_tracker.simulators import Simulator


_DUMMY_DER = b"\x30\x82\x01\x00DUMMY-CERT-BODY"
_DUMMY_PEM = (
    "-----BEGIN CERTIFICATE-----\n"
    + base64.b64encode(_DUMMY_DER).decode("ascii")
    + "\n-----END CERTIFICATE-----\n"
)


def _completed(stdout: str = "", stderr: str = "", code: int = 0) -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(
        args=[], returncode=code, stdout=stdout, stderr=stderr
    )


def _make_simulator(udid: str = "TEST-UDID", state: str = "Booted") -> Simulator:
    return Simulator(udid=udid, name="iPhone Test", runtime="iOS 17.4", state=state)


def _write_pem(tmp_path: Path) -> Path:
    pem = tmp_path / "ca.pem"
    pem.write_text(_DUMMY_PEM, encoding="ascii")
    return pem


def _seed_trust_store(tmp_home: Path, simulator: Simulator, sha1: bytes | None) -> Path:
    truststore = (
        tmp_home
        / "Library"
        / "Developer"
        / "CoreSimulator"
        / "Devices"
        / simulator.udid
        / "data"
        / "Library"
        / "Keychains"
        / "TrustStore.sqlite3"
    )
    truststore.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(truststore)
    conn.execute(
        "CREATE TABLE tsettings (sha1 BLOB PRIMARY KEY, subj BLOB, tset BLOB, data BLOB)"
    )
    if sha1 is not None:
        conn.execute("INSERT INTO tsettings (sha1) VALUES (?)", (sha1,))
    conn.commit()
    conn.close()
    return truststore


def _seed_trustd_store(tmp_home: Path, simulator: Simulator, sha256: bytes | None) -> Path:
    truststore = (
        tmp_home
        / "Library"
        / "Developer"
        / "CoreSimulator"
        / "Devices"
        / simulator.udid
        / "data"
        / "private"
        / "var"
        / "protected"
        / "trustd"
        / "private"
        / "TrustStore.sqlite3"
    )
    truststore.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(truststore)
    conn.execute(
        "CREATE TABLE tsettings (sha256 BLOB NOT NULL DEFAULT '', "
        "subj BLOB NOT NULL DEFAULT '', tset BLOB, data BLOB, "
        "uuid BLOB NOT NULL DEFAULT '', UNIQUE(sha256, uuid))"
    )
    if sha256 is not None:
        conn.execute("INSERT INTO tsettings (sha256) VALUES (?)", (sha256,))
    conn.commit()
    conn.close()
    return truststore


def test_fingerprint_matches_sha1_of_der(tmp_path: Path) -> None:
    pem = _write_pem(tmp_path)
    expected = hashlib.sha1(_DUMMY_DER).digest()
    assert fingerprint(pem) == expected


def test_ensure_ca_exists_returns_existing(tmp_path: Path) -> None:
    pem = _write_pem(tmp_path)
    runner_called = []

    def runner(args: Sequence[str]) -> subprocess.CompletedProcess:
        runner_called.append(args)
        return _completed()

    result = ensure_ca_exists(pem, runner=runner)
    assert result == pem
    assert runner_called == []


def test_ensure_ca_exists_invokes_runner_when_missing(tmp_path: Path) -> None:
    pem = tmp_path / "ca.pem"
    runner_called = []

    def runner(args: Sequence[str]) -> subprocess.CompletedProcess:
        runner_called.append(list(args))
        pem.write_text(_DUMMY_PEM, encoding="ascii")
        return _completed()

    result = ensure_ca_exists(pem, runner=runner)
    assert result == pem
    assert runner_called and runner_called[0][0] == "mitmdump"


def test_ensure_ca_exists_raises_if_runner_fails_to_create(tmp_path: Path) -> None:
    pem = tmp_path / "ca.pem"

    def runner(args: Sequence[str]) -> subprocess.CompletedProcess:
        return _completed()

    with pytest.raises(CertManagerError):
        ensure_ca_exists(pem, runner=runner)


def test_is_installed_true_when_sha1_present(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    pem = _write_pem(tmp_path)
    sim = _make_simulator()
    sha1 = hashlib.sha1(_DUMMY_DER).digest()
    _seed_trust_store(tmp_path, sim, sha1)

    assert is_installed(sim, ca_pem=pem) is True


def test_is_installed_false_when_sha1_absent(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    pem = _write_pem(tmp_path)
    sim = _make_simulator()
    _seed_trust_store(tmp_path, sim, b"\x00" * 20)

    assert is_installed(sim, ca_pem=pem) is False


def test_is_installed_true_when_sha256_present_in_trustd_store(
    monkeypatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    pem = _write_pem(tmp_path)
    sim = _make_simulator()
    sha256 = hashlib.sha256(_DUMMY_DER).digest()
    _seed_trustd_store(tmp_path, sim, sha256)

    assert is_installed(sim, ca_pem=pem) is True


def test_is_installed_prefers_trustd_path_when_present(
    monkeypatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    pem = _write_pem(tmp_path)
    sim = _make_simulator()
    sha256 = hashlib.sha256(_DUMMY_DER).digest()
    _seed_trustd_store(tmp_path, sim, sha256)
    _seed_trust_store(tmp_path, sim, b"\x00" * 20)

    assert is_installed(sim, ca_pem=pem) is True


def test_is_installed_false_when_sha256_absent(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    pem = _write_pem(tmp_path)
    sim = _make_simulator()
    _seed_trustd_store(tmp_path, sim, b"\x00" * 32)

    assert is_installed(sim, ca_pem=pem) is False


def test_is_installed_false_when_no_truststore(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    pem = _write_pem(tmp_path)
    sim = _make_simulator()
    assert is_installed(sim, ca_pem=pem) is False


def test_is_installed_false_when_pem_missing(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    sim = _make_simulator()
    assert is_installed(sim, ca_pem=tmp_path / "missing.pem") is False


def test_install_skips_when_simulator_not_booted(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    pem = _write_pem(tmp_path)
    sim = _make_simulator(state="Shutdown")

    def runner(args: Sequence[str]) -> subprocess.CompletedProcess:
        return _completed()

    result = install(sim, ca_pem=pem, runner=runner)
    assert isinstance(result, InstallResult)
    assert result.installed is False
    assert result.skipped_reason == "not_booted"


def test_install_skips_when_already_installed(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    pem = _write_pem(tmp_path)
    sim = _make_simulator()
    sha1 = hashlib.sha1(_DUMMY_DER).digest()
    _seed_trust_store(tmp_path, sim, sha1)

    runner_called = []

    def runner(args: Sequence[str]) -> subprocess.CompletedProcess:
        runner_called.append(list(args))
        return _completed()

    result = install(sim, ca_pem=pem, runner=runner)
    assert result.installed is True
    assert result.skipped_reason == "already_installed"
    assert runner_called == []


def test_install_calls_simctl_when_not_yet_installed(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    pem = _write_pem(tmp_path)
    sim = _make_simulator()
    _seed_trust_store(tmp_path, sim, None)

    captured: list[list[str]] = []

    def runner(args: Sequence[str]) -> subprocess.CompletedProcess:
        captured.append(list(args))
        return _completed(stdout="ok")

    result = install(sim, ca_pem=pem, runner=runner)
    assert result.installed is True
    assert result.skipped_reason is None
    assert captured == [
        ["xcrun", "simctl", "keychain", sim.udid, "add-root-cert", str(pem)]
    ]


def test_install_raises_on_simctl_failure(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    pem = _write_pem(tmp_path)
    sim = _make_simulator()
    _seed_trust_store(tmp_path, sim, None)

    def runner(args: Sequence[str]) -> subprocess.CompletedProcess:
        return _completed(stderr="boom", code=1)

    with pytest.raises(CertManagerError):
        install(sim, ca_pem=pem, runner=runner)
