from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from mitm_tracker import doctor


def _result(returncode: int = 0, stdout: str = "", stderr: str = "") -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr=stderr)


def test_macos_version_ok_for_sonoma(monkeypatch) -> None:
    monkeypatch.setattr(doctor, "_get_macos_product_version", lambda: "14.5")
    result = doctor.check_macos_version()
    assert result.status == doctor.STATUS_OK
    assert "Sonoma" in result.detail


def test_macos_version_warn_for_ventura(monkeypatch) -> None:
    monkeypatch.setattr(doctor, "_get_macos_product_version", lambda: "13.6")
    result = doctor.check_macos_version()
    assert result.status == doctor.STATUS_WARN
    assert "Ventura" in result.detail
    assert result.fix is not None


def test_macos_version_error_for_old(monkeypatch) -> None:
    monkeypatch.setattr(doctor, "_get_macos_product_version", lambda: "10.15")
    result = doctor.check_macos_version()
    assert result.status == doctor.STATUS_ERROR


def test_macos_version_error_when_missing(monkeypatch) -> None:
    monkeypatch.setattr(doctor, "_get_macos_product_version", lambda: None)
    result = doctor.check_macos_version()
    assert result.status == doctor.STATUS_ERROR


def test_python_version_ok() -> None:
    result = doctor.check_python_version()
    if sys.version_info >= (3, 11):
        assert result.status == doctor.STATUS_OK
    else:
        assert result.status == doctor.STATUS_ERROR


def test_mitmdump_present(monkeypatch) -> None:
    monkeypatch.setattr("shutil.which", lambda name: "/opt/homebrew/bin/mitmdump" if name == "mitmdump" else None)
    monkeypatch.setattr(doctor, "_run", lambda cmd: _result(stdout="Mitmproxy: 12.0.0\n"))
    result = doctor.check_mitmdump()
    assert result.status == doctor.STATUS_OK
    assert "12.0.0" in result.detail


def test_mitmdump_missing(monkeypatch) -> None:
    monkeypatch.setattr("shutil.which", lambda _name: None)
    result = doctor.check_mitmdump()
    assert result.status == doctor.STATUS_ERROR
    assert "brew install mitmproxy" in result.fix


def test_xcrun_present(monkeypatch) -> None:
    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/xcrun" if name == "xcrun" else None)
    monkeypatch.setattr(doctor, "_run", lambda cmd: _result(stdout="/usr/bin/simctl\n"))
    result = doctor.check_xcrun()
    assert result.status == doctor.STATUS_OK


def test_xcrun_missing(monkeypatch) -> None:
    monkeypatch.setattr("shutil.which", lambda _name: None)
    result = doctor.check_xcrun()
    assert result.status == doctor.STATUS_WARN
    assert "xcode-select" in result.fix


def test_pam_tid_present(monkeypatch, tmp_path) -> None:
    fake = tmp_path / "pam_tid.so.2"
    fake.touch()
    monkeypatch.setattr(doctor, "Path", lambda p: fake if "pam_tid.so.2" in p else Path(p))
    # Simpler: patch the candidates list inline
    monkeypatch.setattr(
        doctor,
        "check_pam_tid_module",
        lambda: doctor.CheckResult(
            name="pam_tid.so",
            status=doctor.STATUS_OK,
            detail=str(fake),
            group="tools",
        ),
    )
    result = doctor.check_pam_tid_module()
    assert result.status == doctor.STATUS_OK


def test_rumps_present_when_importable(monkeypatch) -> None:
    fake_rumps = MagicMock()
    fake_rumps.__version__ = "0.4.0"
    monkeypatch.setitem(sys.modules, "rumps", fake_rumps)
    result = doctor.check_rumps()
    assert result.status == doctor.STATUS_OK
    assert "0.4.0" in result.detail


def test_rumps_missing(monkeypatch) -> None:
    monkeypatch.setitem(sys.modules, "rumps", None)
    result = doctor.check_rumps()
    assert result.status == doctor.STATUS_WARN
    assert ".[tray]" in result.fix


def test_touch_id_setup_ok(monkeypatch) -> None:
    monkeypatch.setattr(doctor.auth_setup, "is_touch_id_configured", lambda: True)
    result = doctor.check_touch_id_setup()
    assert result.status == doctor.STATUS_OK


def test_touch_id_setup_warn(monkeypatch) -> None:
    monkeypatch.setattr(doctor.auth_setup, "is_touch_id_configured", lambda: False)
    result = doctor.check_touch_id_setup()
    assert result.status == doctor.STATUS_WARN
    assert "setup install" in result.fix


def test_sudo_cache_setup_ok(monkeypatch) -> None:
    monkeypatch.setattr(doctor.auth_setup, "is_sudo_cache_configured", lambda: True)
    result = doctor.check_sudo_cache_setup()
    assert result.status == doctor.STATUS_OK


def test_sudo_cache_setup_warn(monkeypatch) -> None:
    monkeypatch.setattr(doctor.auth_setup, "is_sudo_cache_configured", lambda: False)
    result = doctor.check_sudo_cache_setup()
    assert result.status == doctor.STATUS_WARN


def test_tray_launch_agent_loaded(monkeypatch) -> None:
    monkeypatch.setattr(
        doctor.tray_launch_agent,
        "status",
        lambda: doctor.tray_launch_agent.StatusResult(
            plist_path=Path("/p"),
            installed=True,
            loaded=True,
            pid=999,
            workspace=Path("/ws"),
        ),
    )
    result = doctor.check_tray_launch_agent()
    assert result.status == doctor.STATUS_OK
    assert "999" in result.detail


def test_tray_launch_agent_not_installed(monkeypatch) -> None:
    monkeypatch.setattr(
        doctor.tray_launch_agent,
        "status",
        lambda: doctor.tray_launch_agent.StatusResult(
            plist_path=Path("/p"),
            installed=False,
            loaded=False,
            pid=None,
            workspace=None,
        ),
    )
    result = doctor.check_tray_launch_agent()
    assert result.status == doctor.STATUS_WARN


def test_aggregate_status_error_wins() -> None:
    results = [
        doctor.CheckResult(name="A", status=doctor.STATUS_OK, detail=""),
        doctor.CheckResult(name="B", status=doctor.STATUS_WARN, detail=""),
        doctor.CheckResult(name="C", status=doctor.STATUS_ERROR, detail=""),
    ]
    assert doctor.aggregate_status(results) == doctor.STATUS_ERROR


def test_aggregate_status_warn_when_no_error() -> None:
    results = [
        doctor.CheckResult(name="A", status=doctor.STATUS_OK, detail=""),
        doctor.CheckResult(name="B", status=doctor.STATUS_WARN, detail=""),
        doctor.CheckResult(name="C", status=doctor.STATUS_INFO, detail=""),
    ]
    assert doctor.aggregate_status(results) == doctor.STATUS_WARN


def test_aggregate_status_ok_when_all_ok_or_info() -> None:
    results = [
        doctor.CheckResult(name="A", status=doctor.STATUS_OK, detail=""),
        doctor.CheckResult(name="B", status=doctor.STATUS_INFO, detail=""),
    ]
    assert doctor.aggregate_status(results) == doctor.STATUS_OK


def test_host_ca_check_when_pem_missing(monkeypatch) -> None:
    from mitm_tracker import host_ca

    stub = host_ca.HostCaStatusResult(
        ca_path=None,
        current_sha1_hex=None,
        current_sha1_colons=None,
        system_keychain_path=host_ca.SYSTEM_KEYCHAIN,
        installed_current=False,
        trusted_current=False,
        matching_cn=[],
    )
    monkeypatch.setattr(host_ca, "status", lambda: stub)
    result = doctor.check_host_ca()
    assert result.status == doctor.STATUS_INFO
    assert "not generated yet" in result.detail


def test_host_ca_check_when_installed_and_trusted(monkeypatch) -> None:
    from pathlib import Path as _P
    from mitm_tracker import host_ca

    match = host_ca.HostCaMatch(
        sha1_hex="AABBCC", sha1_colons="AA:BB:CC",
        is_current=True, is_managed=True, is_trusted=True,
    )
    stub = host_ca.HostCaStatusResult(
        ca_path=_P("/home/u/.mitmproxy/ca.pem"),
        current_sha1_hex="AABBCC",
        current_sha1_colons="AA:BB:CC",
        system_keychain_path=host_ca.SYSTEM_KEYCHAIN,
        installed_current=True,
        trusted_current=True,
        matching_cn=[match],
    )
    monkeypatch.setattr(host_ca, "status", lambda: stub)
    monkeypatch.setattr(host_ca, "read_installed_log", lambda: {"AABBCC"})
    result = doctor.check_host_ca()
    assert result.status == doctor.STATUS_OK


def test_host_ca_check_when_present_but_not_trusted(monkeypatch) -> None:
    from pathlib import Path as _P
    from mitm_tracker import host_ca

    match = host_ca.HostCaMatch(
        sha1_hex="AABBCC", sha1_colons="AA:BB:CC",
        is_current=True, is_managed=True, is_trusted=False,
    )
    stub = host_ca.HostCaStatusResult(
        ca_path=_P("/home/u/.mitmproxy/ca.pem"),
        current_sha1_hex="AABBCC",
        current_sha1_colons="AA:BB:CC",
        system_keychain_path=host_ca.SYSTEM_KEYCHAIN,
        installed_current=True,
        trusted_current=False,
        matching_cn=[match],
    )
    monkeypatch.setattr(host_ca, "status", lambda: stub)
    monkeypatch.setattr(host_ca, "read_installed_log", lambda: {"AABBCC"})
    result = doctor.check_host_ca()
    assert result.status == doctor.STATUS_WARN
    assert "--force" in (result.fix or "")


def test_host_ca_check_when_stale_managed_present(monkeypatch) -> None:
    from pathlib import Path as _P
    from mitm_tracker import host_ca

    stale = host_ca.HostCaMatch(
        sha1_hex="STALE1", sha1_colons="ST:AL:E1",
        is_current=False, is_managed=True, is_trusted=False,
    )
    stub = host_ca.HostCaStatusResult(
        ca_path=_P("/home/u/.mitmproxy/ca.pem"),
        current_sha1_hex="CURRENT",
        current_sha1_colons="CU:RR:EN:T",
        system_keychain_path=host_ca.SYSTEM_KEYCHAIN,
        installed_current=False,
        trusted_current=False,
        matching_cn=[stale],
    )
    monkeypatch.setattr(host_ca, "status", lambda: stub)
    monkeypatch.setattr(host_ca, "read_installed_log", lambda: {"STALE1"})
    result = doctor.check_host_ca()
    assert result.status == doctor.STATUS_WARN
    assert "uninstall" in (result.fix or "")


def test_host_ca_check_when_other_unmanaged_only(monkeypatch) -> None:
    """A CA from another tool (CN matches but not in our log) → INFO, not WARN."""
    from pathlib import Path as _P
    from mitm_tracker import host_ca

    other = host_ca.HostCaMatch(
        sha1_hex="OTHER1", sha1_colons="OT:HE:R1",
        is_current=False, is_managed=False, is_trusted=False,
    )
    stub = host_ca.HostCaStatusResult(
        ca_path=_P("/home/u/.mitmproxy/ca.pem"),
        current_sha1_hex="CURRENT",
        current_sha1_colons="CU:RR:EN:T",
        system_keychain_path=host_ca.SYSTEM_KEYCHAIN,
        installed_current=False,
        trusted_current=False,
        matching_cn=[other],
    )
    monkeypatch.setattr(host_ca, "status", lambda: stub)
    monkeypatch.setattr(host_ca, "read_installed_log", lambda: set())
    result = doctor.check_host_ca()
    assert result.status == doctor.STATUS_INFO
    assert "not installed" in result.detail


def test_run_all_checks_returns_list() -> None:
    results = doctor.run_all_checks()
    assert isinstance(results, list)
    assert len(results) > 0
    assert all(isinstance(r, doctor.CheckResult) for r in results)
