from __future__ import annotations

import re
import socket
import subprocess
from dataclasses import dataclass
from typing import Callable, Sequence

from mitm_tracker.proxy_manager import ProxyManager, ProxyManagerError

_NETWORKSETUP = "/usr/sbin/networksetup"

Runner = Callable[[Sequence[str]], subprocess.CompletedProcess]


class NetInfoError(RuntimeError):
    pass


@dataclass(frozen=True)
class LanAddress:
    service: str | None
    ip: str | None
    source: str

    def to_dict(self) -> dict:
        return {
            "service": self.service,
            "ip": self.ip,
            "source": self.source,
        }


def _default_runner(args: Sequence[str]) -> subprocess.CompletedProcess:
    return subprocess.run(
        list(args),
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )


def _parse_ip_from_getinfo(stdout: str) -> str | None:
    for line in stdout.splitlines():
        match = re.match(r"^IP address:\s*(\d+\.\d+\.\d+\.\d+)\s*$", line.strip())
        if match:
            ip = match.group(1)
            if ip != "0.0.0.0":
                return ip
    return None


def _ip_via_networksetup(service: str, runner: Runner) -> str | None:
    try:
        proc = runner([_NETWORKSETUP, "-getinfo", service])
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0:
        return None
    return _parse_ip_from_getinfo(proc.stdout)


def _ip_via_socket() -> str | None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("8.8.8.8", 80))
        ip = sock.getsockname()[0]
    except OSError:
        return None
    finally:
        sock.close()
    if not ip or ip.startswith("127.") or ip == "0.0.0.0":
        return None
    return ip


def lan_address(
    *,
    proxy_manager: ProxyManager | None = None,
    runner: Runner | None = None,
) -> LanAddress:
    run = runner or _default_runner
    pm = proxy_manager or ProxyManager()

    service: str | None = None
    try:
        service = pm.get_active_service()
    except ProxyManagerError:
        service = None

    if service is not None:
        ip = _ip_via_networksetup(service, run)
        if ip:
            return LanAddress(service=service, ip=ip, source="networksetup")

    ip = _ip_via_socket()
    if ip:
        return LanAddress(service=service, ip=ip, source="socket")

    return LanAddress(service=service, ip=None, source="none")
