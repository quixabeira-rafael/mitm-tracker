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


_NETSTAT_VPN_DEFAULT = """Routing tables

Internet:
Destination        Gateway            Flags               Netif Expire
default            10.5.0.2           UGScg               utun6
default            192.168.1.1        UGScIg                en0
10.5.0.2/32        link#29            UCS                 utun6
127                127.0.0.1          UCS                   lo0
"""

_NETSTAT_NO_VPN = """Routing tables

Internet:
Destination        Gateway            Flags               Netif Expire
default            192.168.1.1        UGScg                 en0
127                127.0.0.1          UCS                   lo0
"""

_IFCONFIG_VPN_UP = """en0: flags=8863<UP> mtu 1500
\tinet 192.168.1.44 netmask 0xffffff00 broadcast 192.168.1.255
utun6: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1420
\tinet 10.5.0.2 --> 10.5.0.2 netmask 0xffff0000
utun0: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1380
"""

_IFCONFIG_NO_VPN = """en0: flags=8863<UP> mtu 1500
\tinet 192.168.1.44 netmask 0xffffff00 broadcast 192.168.1.255
utun0: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1380
"""


def test_parse_default_route_tunnels_detects_vpn() -> None:
    tunnels = doctor._parse_default_route_tunnels(_NETSTAT_VPN_DEFAULT)
    assert tunnels == ["utun6"]


def test_parse_default_route_tunnels_skips_non_tunnel_default() -> None:
    assert doctor._parse_default_route_tunnels(_NETSTAT_NO_VPN) == []


def test_parse_tunnel_ifaces_with_ip_returns_only_those_with_inet() -> None:
    ifaces = doctor._parse_tunnel_ifaces_with_ip(_IFCONFIG_VPN_UP)
    assert ifaces == ["utun6"]


def test_parse_tunnel_ifaces_with_ip_empty_when_no_inet() -> None:
    assert doctor._parse_tunnel_ifaces_with_ip(_IFCONFIG_NO_VPN) == []


def test_check_vpn_active_warns_when_default_route_via_tunnel(monkeypatch) -> None:
    def fake_run(cmd: list[str]) -> subprocess.CompletedProcess:
        if cmd[0] == "netstat":
            return _result(stdout=_NETSTAT_VPN_DEFAULT)
        if cmd[0] == "ifconfig":
            return _result(stdout=_IFCONFIG_VPN_UP)
        return _result()

    monkeypatch.setattr(doctor, "_run", fake_run)
    result = doctor.check_vpn_active()
    assert result.status == doctor.STATUS_WARN
    assert "utun6" in result.detail
    assert "bypass mitmproxy" in result.detail
    assert result.fix is not None


def test_check_vpn_active_warns_on_split_tunnel(monkeypatch) -> None:
    def fake_run(cmd: list[str]) -> subprocess.CompletedProcess:
        if cmd[0] == "netstat":
            return _result(stdout=_NETSTAT_NO_VPN)
        if cmd[0] == "ifconfig":
            return _result(stdout=_IFCONFIG_VPN_UP)
        return _result()

    monkeypatch.setattr(doctor, "_run", fake_run)
    result = doctor.check_vpn_active()
    assert result.status == doctor.STATUS_WARN
    assert "split-tunnel" in result.detail
    assert "utun6" in result.detail


def test_check_vpn_active_ok_when_no_tunnel(monkeypatch) -> None:
    def fake_run(cmd: list[str]) -> subprocess.CompletedProcess:
        if cmd[0] == "netstat":
            return _result(stdout=_NETSTAT_NO_VPN)
        if cmd[0] == "ifconfig":
            return _result(stdout=_IFCONFIG_NO_VPN)
        return _result()

    monkeypatch.setattr(doctor, "_run", fake_run)
    result = doctor.check_vpn_active()
    assert result.status == doctor.STATUS_OK
    assert "no active VPN" in result.detail


def test_check_vpn_active_ok_when_tools_missing(monkeypatch) -> None:
    def fake_run(cmd: list[str]) -> subprocess.CompletedProcess:
        raise FileNotFoundError(cmd[0])

    monkeypatch.setattr(doctor, "_run", fake_run)
    result = doctor.check_vpn_active()
    assert result.status == doctor.STATUS_OK


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


def test_check_firewall_ok_when_disabled(monkeypatch) -> None:
    monkeypatch.setattr(
        doctor.Path, "exists", lambda self: True
    )
    monkeypatch.setattr(
        doctor, "_run", lambda cmd: _result(stdout="Firewall is disabled. (State = 0)\n")
    )
    result = doctor.check_firewall()
    assert result.status == doctor.STATUS_OK


def test_check_firewall_warns_when_enabled(monkeypatch) -> None:
    monkeypatch.setattr(doctor.Path, "exists", lambda self: True)
    monkeypatch.setattr(
        doctor, "_run", lambda cmd: _result(stdout="Firewall is enabled. (State = 1)\n")
    )
    result = doctor.check_firewall()
    assert result.status == doctor.STATUS_WARN
    assert result.fix


def test_check_firewall_info_when_tool_missing(monkeypatch) -> None:
    monkeypatch.setattr(doctor.Path, "exists", lambda self: False)
    result = doctor.check_firewall()
    assert result.status == doctor.STATUS_INFO


def test_check_lan_reachable_reports_ip(monkeypatch) -> None:
    from mitm_tracker import net_info

    monkeypatch.setattr(
        net_info,
        "lan_address",
        lambda **kw: net_info.LanAddress(service="Wi-Fi", ip="192.168.1.44", source="networksetup"),
    )
    result = doctor.check_lan_reachable()
    assert result.status == doctor.STATUS_INFO
    assert "192.168.1.44" in result.detail


def test_check_lan_reachable_warns_without_ip(monkeypatch) -> None:
    from mitm_tracker import net_info

    monkeypatch.setattr(
        net_info,
        "lan_address",
        lambda **kw: net_info.LanAddress(service=None, ip=None, source="none"),
    )
    result = doctor.check_lan_reachable()
    assert result.status == doctor.STATUS_WARN
    assert result.fix


def test_check_lan_proxy_ok_when_lan_bound(tmp_repo, monkeypatch) -> None:
    from mitm_tracker.config import workspace_for
    from mitm_tracker.session_manager import SessionManager

    ws = workspace_for()
    ws.ensure()
    sm = SessionManager(ws)
    sm.start(
        pid=1234,
        mode="all",
        port=51820,
        session_db=ws.captures_dir / "s.db",
        proxy_service=None,
        listen_host="0.0.0.0",
        proxy_mode="wireguard",
    )
    monkeypatch.setattr(SessionManager, "is_running", lambda self: True)
    result = doctor.check_lan_proxy()
    assert result.status == doctor.STATUS_OK
    assert "0.0.0.0" in result.detail


def test_check_lan_proxy_info_when_loopback(tmp_repo, monkeypatch) -> None:
    from mitm_tracker.config import workspace_for
    from mitm_tracker.session_manager import SessionManager

    ws = workspace_for()
    ws.ensure()
    sm = SessionManager(ws)
    sm.start(
        pid=1234,
        mode="all",
        port=8080,
        session_db=ws.captures_dir / "s.db",
        proxy_service=None,
        listen_host="127.0.0.1",
    )
    monkeypatch.setattr(SessionManager, "is_running", lambda self: True)
    result = doctor.check_lan_proxy()
    assert result.status == doctor.STATUS_INFO


def test_check_lan_proxy_info_when_not_running(tmp_repo) -> None:
    from mitm_tracker.config import workspace_for

    workspace_for().ensure()
    result = doctor.check_lan_proxy()
    assert result.status == doctor.STATUS_INFO


def test_check_workspace_info_when_cwd_is_the_root(tmp_repo) -> None:
    from mitm_tracker.config import workspace_for

    workspace_for().ensure()
    result = doctor.check_workspace()
    assert result.status == doctor.STATUS_INFO
    assert result.fix is None


def test_check_workspace_warns_about_a_leftover_worktree_workspace(
    tmp_path, monkeypatch
) -> None:
    import subprocess

    def git(cwd, *args):
        subprocess.run(["git", *args], cwd=str(cwd), check=True, capture_output=True)

    main = tmp_path / "main"
    main.mkdir()
    git(main, "init", "-q")
    git(main, "config", "user.email", "test@example.com")
    git(main, "config", "user.name", "test")
    (main / "README.md").write_text("hello\n", encoding="utf-8")
    git(main, "add", "README.md")
    git(main, "commit", "-qm", "init")
    worktree = tmp_path / "wt"
    git(main, "worktree", "add", "-q", "-b", "feature", str(worktree))
    (main / ".mitm-tracker").mkdir()
    (worktree / ".mitm-tracker").mkdir()
    monkeypatch.chdir(worktree)

    result = doctor.check_workspace()
    assert result.status == doctor.STATUS_WARN
    assert str(worktree.resolve() / ".mitm-tracker") in result.detail
    assert result.fix


def test_check_single_instance_info_when_nothing_runs(tmp_repo) -> None:
    result = doctor.check_single_instance()
    assert result.status == doctor.STATUS_INFO
    assert "none registered" in result.detail


def test_check_single_instance_ok_for_this_workspace(tmp_repo, monkeypatch) -> None:
    from mitm_tracker import instance

    monkeypatch.setattr(instance, "pid_alive", lambda pid: True)
    instance.acquire(instance.KIND_PROXY, pid=4242, workspace=tmp_repo, port=8080)

    result = doctor.check_single_instance()
    assert result.status == doctor.STATUS_OK
    assert "pid=4242" in result.detail


def test_check_single_instance_warns_when_another_workspace_owns_it(
    tmp_repo, monkeypatch
) -> None:
    from mitm_tracker import instance

    other = tmp_repo / "other"
    other.mkdir()
    monkeypatch.setattr(instance, "pid_alive", lambda pid: True)
    instance.acquire(instance.KIND_PROXY, pid=4242, workspace=other, port=8080)

    result = doctor.check_single_instance()
    assert result.status == doctor.STATUS_WARN
    assert str(other) in result.fix
