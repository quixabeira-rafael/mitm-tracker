from __future__ import annotations

import subprocess

from mitm_tracker import net_info
from mitm_tracker.proxy_manager import ProxyManager, ProxyManagerError


def _completed(stdout: str, returncode: int = 0) -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr="")


def test_parse_ip_from_getinfo_extracts_ipv4():
    out = (
        "DHCP Configuration\n"
        "IP address: 192.168.1.42\n"
        "Subnet mask: 255.255.255.0\n"
        "Router: 192.168.1.1\n"
    )
    assert net_info._parse_ip_from_getinfo(out) == "192.168.1.42"


def test_parse_ip_from_getinfo_ignores_unset():
    out = "IP address: 0.0.0.0\nSubnet mask: 0.0.0.0\n"
    assert net_info._parse_ip_from_getinfo(out) is None


def test_lan_address_prefers_networksetup():
    class FakePM:
        def get_active_service(self) -> str:
            return "Wi-Fi"

    def runner(args):
        assert args == ["/usr/sbin/networksetup", "-getinfo", "Wi-Fi"]
        return _completed("IP address: 10.0.0.5\n")

    address = net_info.lan_address(proxy_manager=FakePM(), runner=runner)
    assert address.ip == "10.0.0.5"
    assert address.service == "Wi-Fi"
    assert address.source == "networksetup"


def test_lan_address_falls_back_to_socket(monkeypatch):
    class FakePM:
        def get_active_service(self) -> str:
            return "Wi-Fi"

    def runner(args):
        return _completed("IP address: 0.0.0.0\n")

    monkeypatch.setattr(net_info, "_ip_via_socket", lambda: "172.16.3.9")
    address = net_info.lan_address(proxy_manager=FakePM(), runner=runner)
    assert address.ip == "172.16.3.9"
    assert address.source == "socket"


def test_lan_address_handles_no_service(monkeypatch):
    class FakePM:
        def get_active_service(self) -> str:
            raise ProxyManagerError("no services")

    monkeypatch.setattr(net_info, "_ip_via_socket", lambda: None)
    address = net_info.lan_address(proxy_manager=FakePM(), runner=lambda a: _completed(""))
    assert address.ip is None
    assert address.source == "none"
    assert address.service is None
