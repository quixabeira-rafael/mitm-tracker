from __future__ import annotations

import json
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from mitm_tracker import host_ca


def _result(returncode: int = 0, stdout: str = "", stderr: str = "") -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr=stderr)


_OPENSSL_TEXT_VALID = """\
        Subject: O = mitmproxy, CN = mitmproxy
        X509v3 Basic Constraints: critical
            CA:TRUE
"""

_OPENSSL_TEXT_NOT_CA = """\
        Subject: O = mitmproxy, CN = mitmproxy
        X509v3 Basic Constraints: critical
            CA:FALSE
"""

_OPENSSL_TEXT_WRONG_CN = """\
        Subject: O = otherproxy, CN = otherproxy
        X509v3 Basic Constraints: critical
            CA:TRUE
"""


def _make_pem(tmp_path: Path) -> Path:
    pem = tmp_path / "ca.pem"
    pem.write_text(
        "-----BEGIN CERTIFICATE-----\n"
        + ("A" * 64 + "\n") * 4
        + "-----END CERTIFICATE-----\n"
    )
    return pem


def test_validate_pem_is_root_ca_accepts_real_pem(tmp_path: Path) -> None:
    pem = _make_pem(tmp_path)
    runner = MagicMock(return_value=_result(stdout=_OPENSSL_TEXT_VALID))
    ok, reason = host_ca.validate_pem_is_root_ca(pem, runner=runner)
    assert ok is True
    assert reason is None


def test_validate_pem_is_root_ca_rejects_leaf_cert(tmp_path: Path) -> None:
    pem = _make_pem(tmp_path)
    runner = MagicMock(return_value=_result(stdout=_OPENSSL_TEXT_NOT_CA))
    ok, reason = host_ca.validate_pem_is_root_ca(pem, runner=runner)
    assert ok is False
    assert "CA:TRUE" in reason


def test_validate_pem_is_root_ca_rejects_wrong_cn(tmp_path: Path) -> None:
    pem = _make_pem(tmp_path)
    runner = MagicMock(return_value=_result(stdout=_OPENSSL_TEXT_WRONG_CN))
    ok, reason = host_ca.validate_pem_is_root_ca(pem, runner=runner)
    assert ok is False
    assert "mitmproxy" in reason


def test_validate_pem_is_root_ca_rejects_missing_pem(tmp_path: Path) -> None:
    ok, reason = host_ca.validate_pem_is_root_ca(tmp_path / "nope.pem")
    assert ok is False
    assert "not found" in reason


def test_enumerate_keychain_matches_parses_output() -> None:
    sample_stdout = """\
SHA-1 hash: AABBCCDDEEFF00112233445566778899AABBCCDD
SHA-256 hash: 0011...
keychain: "/Library/Keychains/System.keychain"
SHA-1 hash: 1122334455667788990011223344556677889900
SHA-256 hash: 1122...
keychain: "/Library/Keychains/System.keychain"
"""
    runner = MagicMock(return_value=_result(stdout=sample_stdout))
    matches = host_ca.enumerate_keychain_matches(runner=runner)
    assert len(matches) == 2
    assert matches[0]["sha1_hex"] == "AABBCCDDEEFF00112233445566778899AABBCCDD"
    assert "AA:BB:CC" in matches[0]["sha1_colons"]


def test_enumerate_keychain_matches_empty_when_security_fails() -> None:
    runner = MagicMock(return_value=_result(returncode=44))
    matches = host_ca.enumerate_keychain_matches(runner=runner)
    assert matches == []


def test_enumerate_keychain_matches_dedupes_repeats() -> None:
    sample = "SHA-1 hash: AABBCCDDEEFF00112233445566778899AABBCCDD\n" * 2
    runner = MagicMock(return_value=_result(stdout=sample))
    assert len(host_ca.enumerate_keychain_matches(runner=runner)) == 1


def test_is_trusted_uses_verify_cert(tmp_path: Path) -> None:
    pem = _make_pem(tmp_path)
    runner = MagicMock(return_value=_result(returncode=0))
    assert host_ca.is_trusted(pem, runner=runner) is True
    runner.assert_called_once()
    args = runner.call_args[0][0]
    assert args[:2] == [host_ca.SECURITY_BIN, "verify-cert"]
    assert "ssl" in args


def test_is_trusted_false_when_pem_missing(tmp_path: Path) -> None:
    runner = MagicMock()
    assert host_ca.is_trusted(tmp_path / "nope.pem", runner=runner) is False
    runner.assert_not_called()


def test_log_round_trip(tmp_path: Path, monkeypatch) -> None:
    log_path = tmp_path / "host_installed_shas.json"
    monkeypatch.setattr(host_ca, "INSTALLED_LOG", log_path)
    assert host_ca.read_installed_log() == set()
    host_ca.write_installed_log({"AAA111", "bbb222"})
    assert host_ca.read_installed_log() == {"AAA111", "BBB222"}


def test_log_returns_empty_on_corrupt_json(tmp_path: Path, monkeypatch) -> None:
    log_path = tmp_path / "host_installed_shas.json"
    log_path.write_text("{not json")
    monkeypatch.setattr(host_ca, "INSTALLED_LOG", log_path)
    assert host_ca.read_installed_log() == set()


def test_extract_pem_for_sha_writes_file(tmp_path: Path) -> None:
    pem_text = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"
    runner = MagicMock(return_value=_result(stdout=pem_text))
    dest = tmp_path / "out.pem"
    assert host_ca.extract_pem_for_sha("AABB", dest, runner=runner) is True
    assert dest.read_text() == pem_text
    args = runner.call_args[0][0]
    assert args == [
        host_ca.SECURITY_BIN,
        "find-certificate",
        "-Z",
        "AABB",
        "-p",
        host_ca.SYSTEM_KEYCHAIN,
    ]


def test_extract_pem_for_sha_returns_false_on_invalid_output(tmp_path: Path) -> None:
    runner = MagicMock(return_value=_result(stdout="garbage"))
    assert host_ca.extract_pem_for_sha("AA", tmp_path / "out.pem", runner=runner) is False


def test_build_install_commands_no_stale(tmp_path: Path) -> None:
    pem = _make_pem(tmp_path)
    cmds = host_ca.build_install_commands(pem, stale_pairs=[])
    assert len(cmds) == 1
    assert cmds[0][:5] == [
        host_ca.SECURITY_BIN,
        "add-trusted-cert",
        "-d",
        "-r",
        "trustRoot",
    ]
    assert cmds[0][-2:] == [host_ca.SYSTEM_KEYCHAIN, str(pem)]


def test_build_install_commands_with_stale_first(tmp_path: Path) -> None:
    pem = _make_pem(tmp_path)
    stale_pem = tmp_path / "stale.pem"
    stale_pem.write_text("stale")
    cmds = host_ca.build_install_commands(pem, stale_pairs=[("ABCD", stale_pem)])
    # remove-trusted-cert + delete-certificate happen BEFORE add-trusted-cert
    assert cmds[0][:3] == [host_ca.SECURITY_BIN, "remove-trusted-cert", "-d"]
    assert cmds[0][-1] == str(stale_pem)
    assert cmds[1][:3] == [host_ca.SECURITY_BIN, "delete-certificate", "-Z"]
    assert cmds[1][3] == "ABCD"
    assert cmds[1][-1] == host_ca.SYSTEM_KEYCHAIN
    assert cmds[2][1] == "add-trusted-cert"


def test_build_install_commands_always_targets_system_keychain(tmp_path: Path) -> None:
    pem = _make_pem(tmp_path)
    stale_pem = tmp_path / "s.pem"
    stale_pem.write_text("x")
    cmds = host_ca.build_install_commands(pem, stale_pairs=[("AA", stale_pem)])
    # delete-certificate must point at SYSTEM_KEYCHAIN
    delete_cmd = next(c for c in cmds if c[1] == "delete-certificate")
    assert delete_cmd[-1] == host_ca.SYSTEM_KEYCHAIN
    add_cmd = next(c for c in cmds if c[1] == "add-trusted-cert")
    assert host_ca.SYSTEM_KEYCHAIN in add_cmd


def test_install_skips_when_already_trusted(tmp_path: Path, monkeypatch) -> None:
    pem = _make_pem(tmp_path)
    sha_no_colons, _ = host_ca.current_ca_sha1(pem)
    runner = MagicMock(side_effect=[
        _result(stdout=_OPENSSL_TEXT_VALID),               # validate_pem_is_root_ca → openssl
        _result(stdout=f"SHA-1 hash: {sha_no_colons}\n"),  # enumerate_keychain_matches
        _result(returncode=0),                              # is_trusted → verify-cert
    ])
    privileged = MagicMock()
    monkeypatch.setattr(host_ca, "INSTALLED_LOG", tmp_path / "log.json")

    result = host_ca.install(
        ca_path=pem, runner=runner, privileged_runner=privileged
    )
    assert result.invoked_privileged is False
    assert result.replaced_existing is False
    assert result.verified_trusted is True
    privileged.assert_not_called()


def test_install_replaces_stale_sha(tmp_path: Path, monkeypatch) -> None:
    pem = _make_pem(tmp_path)
    sha_no_colons, _ = host_ca.current_ca_sha1(pem)
    other_sha = "1122334455667788990011223344556677889900"

    enum_stdout = f"SHA-1 hash: {other_sha}\n"
    extract_stdout = "-----BEGIN CERTIFICATE-----\nXXXX\n-----END CERTIFICATE-----\n"

    runner = MagicMock(side_effect=[
        _result(stdout=_OPENSSL_TEXT_VALID),       # validate_pem_is_root_ca
        _result(stdout=enum_stdout),               # enumerate (only stale)
        _result(stdout=extract_stdout),            # extract pem for stale
        _result(returncode=0),                     # is_trusted post-install
    ])
    privileged = MagicMock(return_value=_result(returncode=0))
    monkeypatch.setattr(host_ca, "INSTALLED_LOG", tmp_path / "log.json")

    result = host_ca.install(
        ca_path=pem,
        runner=runner,
        privileged_runner=privileged,
        tmpdir=tmp_path / "work",
    )

    assert result.invoked_privileged is True
    assert result.stale_removed == [other_sha]
    assert result.verified_trusted is True
    cmds_passed, _prompt = privileged.call_args[0]
    # Must include the stale removal AND the add-trusted-cert
    actions = [c[1] for c in cmds_passed]
    assert "remove-trusted-cert" in actions
    assert "delete-certificate" in actions
    assert "add-trusted-cert" in actions
    # add-trusted-cert is the last command
    assert cmds_passed[-1][1] == "add-trusted-cert"


def test_install_aborts_when_pem_missing(tmp_path: Path) -> None:
    privileged = MagicMock()
    with pytest.raises(host_ca.HostCaError, match="not found"):
        host_ca.install(ca_path=tmp_path / "nope.pem", privileged_runner=privileged)
    privileged.assert_not_called()


def test_install_aborts_when_pem_not_root_ca(tmp_path: Path) -> None:
    pem = _make_pem(tmp_path)
    runner = MagicMock(return_value=_result(stdout=_OPENSSL_TEXT_NOT_CA))
    privileged = MagicMock()
    with pytest.raises(host_ca.HostCaError, match="CA:TRUE"):
        host_ca.install(ca_path=pem, runner=runner, privileged_runner=privileged)
    privileged.assert_not_called()


def test_install_log_persists_sha(tmp_path: Path, monkeypatch) -> None:
    pem = _make_pem(tmp_path)
    sha_no_colons, _ = host_ca.current_ca_sha1(pem)
    runner = MagicMock(side_effect=[
        _result(stdout=_OPENSSL_TEXT_VALID),
        _result(returncode=44),                  # enumerate empty
        _result(returncode=0),                   # is_trusted post-install
    ])
    privileged = MagicMock(return_value=_result(returncode=0))
    log_path = tmp_path / "log.json"
    monkeypatch.setattr(host_ca, "INSTALLED_LOG", log_path)

    host_ca.install(
        ca_path=pem, runner=runner, privileged_runner=privileged, tmpdir=tmp_path / "work"
    )

    assert log_path.exists()
    saved = json.loads(log_path.read_text())
    assert sha_no_colons in saved


def test_uninstall_managed_only(tmp_path: Path, monkeypatch) -> None:
    pem = _make_pem(tmp_path)
    sha_a, _ = host_ca.current_ca_sha1(pem)
    sha_b = "11223344556677889900AABBCCDDEEFF00112233"

    log_path = tmp_path / "log.json"
    log_path.write_text(json.dumps([sha_a]))
    monkeypatch.setattr(host_ca, "INSTALLED_LOG", log_path)

    enum_stdout = f"SHA-1 hash: {sha_a}\nSHA-1 hash: {sha_b}\n"
    extract_stdout = "-----BEGIN CERTIFICATE-----\nA\n-----END CERTIFICATE-----\n"

    runner = MagicMock(side_effect=[
        _result(stdout=enum_stdout),
        _result(stdout=extract_stdout),  # extract pem for sha_a
    ])
    privileged = MagicMock(return_value=_result(returncode=0))

    result = host_ca.uninstall(
        ca_path=pem,
        runner=runner,
        privileged_runner=privileged,
        tmpdir=tmp_path / "work",
    )

    assert result.removed_shas == [sha_a]
    assert result.skipped_unmanaged_shas == [sha_b]
    assert result.invoked_privileged is True


def test_uninstall_falls_back_to_current_sha_when_log_missing(
    tmp_path: Path, monkeypatch
) -> None:
    pem = _make_pem(tmp_path)
    sha, _ = host_ca.current_ca_sha1(pem)
    log_path = tmp_path / "log.json"  # absent
    monkeypatch.setattr(host_ca, "INSTALLED_LOG", log_path)

    extract_stdout = "-----BEGIN CERTIFICATE-----\nA\n-----END CERTIFICATE-----\n"
    runner = MagicMock(side_effect=[
        _result(stdout=f"SHA-1 hash: {sha}\n"),
        _result(stdout=extract_stdout),
    ])
    privileged = MagicMock(return_value=_result(returncode=0))

    result = host_ca.uninstall(
        ca_path=pem,
        runner=runner,
        privileged_runner=privileged,
        tmpdir=tmp_path / "work",
    )

    assert result.removed_shas == [sha]


def test_uninstall_no_op_when_nothing_to_remove(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(host_ca, "INSTALLED_LOG", tmp_path / "log.json")
    runner = MagicMock(return_value=_result(returncode=44))
    privileged = MagicMock()
    result = host_ca.uninstall(
        ca_path=tmp_path / "missing.pem",
        runner=runner,
        privileged_runner=privileged,
        tmpdir=tmp_path / "work",
    )
    assert result.removed_shas == []
    assert result.invoked_privileged is False
    privileged.assert_not_called()


def test_status_marks_current_correctly(tmp_path: Path, monkeypatch) -> None:
    pem = _make_pem(tmp_path)
    sha, _ = host_ca.current_ca_sha1(pem)
    other_sha = "0011223344556677889900112233445566778899"
    enum_stdout = f"SHA-1 hash: {sha}\nSHA-1 hash: {other_sha}\n"
    runner = MagicMock(side_effect=[
        _result(stdout=enum_stdout),
        _result(returncode=0),  # is_trusted
    ])
    monkeypatch.setattr(host_ca, "INSTALLED_LOG", tmp_path / "log.json")

    result = host_ca.status(ca_path=pem, runner=runner)
    assert result.installed_current is True
    assert result.trusted_current is True
    by_sha = {m.sha1_hex: m for m in result.matching_cn}
    assert by_sha[sha].is_current is True
    assert by_sha[sha].is_trusted is True
    assert by_sha[other_sha].is_current is False
    assert by_sha[other_sha].is_trusted is False


def test_status_when_pem_missing(tmp_path: Path, monkeypatch) -> None:
    runner = MagicMock(return_value=_result(returncode=44))
    monkeypatch.setattr(host_ca, "INSTALLED_LOG", tmp_path / "log.json")
    result = host_ca.status(ca_path=tmp_path / "missing.pem", runner=runner)
    assert result.ca_path is None
    assert result.installed_current is False
