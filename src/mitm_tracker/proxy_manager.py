from __future__ import annotations

import re
import shlex
import subprocess
from dataclasses import asdict, dataclass
from typing import Callable, Sequence


class ProxyManagerError(RuntimeError):
    pass


class ProxyAuthorizationError(ProxyManagerError):
    pass


@dataclass
class ProxyState:
    enabled: bool
    server: str | None
    port: int | None

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "ProxyState":
        return cls(
            enabled=bool(data.get("enabled", False)),
            server=data.get("server"),
            port=data.get("port"),
        )


@dataclass
class ProxyBackup:
    service: str
    web: ProxyState
    secure: ProxyState

    def to_dict(self) -> dict:
        return {
            "service": self.service,
            "web": self.web.to_dict(),
            "secure": self.secure.to_dict(),
        }

    @classmethod
    def from_dict(cls, data: dict) -> "ProxyBackup":
        return cls(
            service=data["service"],
            web=ProxyState.from_dict(data.get("web") or {}),
            secure=ProxyState.from_dict(data.get("secure") or {}),
        )


Runner = Callable[[Sequence[str]], subprocess.CompletedProcess]
PrivilegedRunner = Callable[[list[list[str]], str], subprocess.CompletedProcess]


class ProxyManager:
    def __init__(
        self,
        *,
        runner: Runner | None = None,
        privileged_runner: PrivilegedRunner | None = None,
    ) -> None:
        self._runner = runner or _default_runner
        self._privileged_runner = privileged_runner or _default_privileged_runner

    def list_services(self) -> list[str]:
        proc = self._run(["networksetup", "-listallnetworkservices"])
        services: list[str] = []
        for line in proc.stdout.splitlines()[1:]:
            stripped = line.strip()
            if not stripped:
                continue
            if stripped.startswith("*"):
                continue
            services.append(stripped)
        return services

    def get_active_service(self) -> str:
        services = self.list_services()
        for preferred in ("Wi-Fi", "Ethernet", "Wi-Fi (en0)", "USB 10/100/1000 LAN"):
            if preferred in services:
                return preferred
        if services:
            return services[0]
        raise ProxyManagerError("no network services found via networksetup")

    def get_web_proxy(self, service: str) -> ProxyState:
        proc = self._run(["networksetup", "-getwebproxy", service])
        return _parse_state(proc.stdout)

    def get_secure_proxy(self, service: str) -> ProxyState:
        proc = self._run(["networksetup", "-getsecurewebproxy", service])
        return _parse_state(proc.stdout)

    def snapshot(self, service: str) -> ProxyBackup:
        return ProxyBackup(
            service=service,
            web=self.get_web_proxy(service),
            secure=self.get_secure_proxy(service),
        )

    def set_proxy(self, service: str, host: str, port: int) -> None:
        commands = [
            ["networksetup", "-setwebproxy", service, host, str(port)],
            ["networksetup", "-setsecurewebproxy", service, host, str(port)],
            ["networksetup", "-setwebproxystate", service, "on"],
            ["networksetup", "-setsecurewebproxystate", service, "on"],
        ]
        self._run_privileged_batch(
            commands,
            prompt="mitm-tracker needs to configure the macOS web proxy.",
        )

    def restore(self, backup: ProxyBackup) -> None:
        commands: list[list[str]] = []
        commands.extend(
            self._restore_commands(
                backup.service,
                backup.web,
                set_cmd="-setwebproxy",
                state_cmd="-setwebproxystate",
            )
        )
        commands.extend(
            self._restore_commands(
                backup.service,
                backup.secure,
                set_cmd="-setsecurewebproxy",
                state_cmd="-setsecurewebproxystate",
            )
        )
        if not commands:
            return
        self._run_privileged_batch(
            commands,
            prompt="mitm-tracker is restoring the original macOS web proxy.",
        )

    def _restore_commands(
        self,
        service: str,
        state: ProxyState,
        *,
        set_cmd: str,
        state_cmd: str,
    ) -> list[list[str]]:
        cmds: list[list[str]] = []
        if state.server and state.port:
            cmds.append(
                ["networksetup", set_cmd, service, state.server, str(state.port)]
            )
        cmds.append(
            ["networksetup", state_cmd, service, "on" if state.enabled else "off"]
        )
        return cmds

    def _run(self, args: Sequence[str]) -> subprocess.CompletedProcess:
        proc = self._runner(list(args))
        if proc.returncode != 0:
            raise ProxyManagerError(
                f"networksetup failed (exit {proc.returncode}): "
                f"{proc.stderr.strip() or proc.stdout.strip()}"
            )
        return proc

    def _run_privileged_batch(
        self, commands: list[list[str]], *, prompt: str
    ) -> None:
        if not commands:
            return
        proc = self._privileged_runner(commands, prompt)
        if proc.returncode != 0:
            raise _privilege_error_from(proc)


def _default_runner(args: Sequence[str]) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(
            list(args),
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
    except FileNotFoundError as exc:
        raise ProxyManagerError(f"command not found: {args[0]}") from exc
    except subprocess.TimeoutExpired as exc:
        raise ProxyManagerError(f"command timed out: {' '.join(args)}") from exc


def _default_privileged_runner(
    commands: list[list[str]], prompt: str
) -> subprocess.CompletedProcess:
    if _can_use_sudo_touch_id():
        try:
            return _default_sudo_runner(commands, prompt)
        except FileNotFoundError:
            pass
    return _default_osascript_runner(commands, prompt)


def _default_osascript_runner(
    commands: list[list[str]], prompt: str
) -> subprocess.CompletedProcess:
    shell_script = build_shell_script(commands)
    osascript = build_osascript(shell_script, prompt)
    try:
        return subprocess.run(
            ["osascript", "-e", osascript],
            capture_output=True,
            text=True,
            check=False,
            timeout=300,
        )
    except FileNotFoundError as exc:
        raise ProxyManagerError("osascript not found on PATH") from exc
    except subprocess.TimeoutExpired as exc:
        raise ProxyManagerError(
            "osascript timed out waiting for the authorization dialog (5 minutes)"
        ) from exc


def _can_use_sudo_touch_id() -> bool:
    try:
        from mitm_tracker import auth_setup
    except ImportError:
        return False
    try:
        return auth_setup.is_touch_id_configured()
    except Exception:
        return False


def _default_sudo_runner(
    commands: list[list[str]], prompt: str
) -> subprocess.CompletedProcess:
    shell_script = build_shell_script(commands)
    try:
        return subprocess.run(
            ["sudo", "-p", "", "/bin/bash", "-c", shell_script],
            capture_output=True,
            text=True,
            check=False,
            timeout=300,
        )
    except subprocess.TimeoutExpired as exc:
        raise ProxyManagerError(
            "sudo timed out waiting for authentication (5 minutes)"
        ) from exc


def build_shell_script(commands: list[list[str]]) -> str:
    if not commands:
        return ""
    pieces = [shlex.join(cmd) for cmd in commands]
    return " && ".join(pieces)


def build_osascript(shell_script: str, prompt: str) -> str:
    quoted_script = _applescript_string(shell_script)
    quoted_prompt = _applescript_string(prompt)
    return (
        f"do shell script {quoted_script} "
        f"with administrator privileges "
        f"with prompt {quoted_prompt}"
    )


def _applescript_string(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def _privilege_error_from(proc: subprocess.CompletedProcess) -> ProxyManagerError:
    stderr = (proc.stderr or "").strip()
    stdout = (proc.stdout or "").strip()
    message = stderr or stdout or f"privileged command failed with exit {proc.returncode}"
    if "User canceled" in message or "(-128)" in message:
        return ProxyAuthorizationError(
            "authorization dialog was cancelled by the user"
        )
    if "Touch ID cancelled" in message or "pam_tid: cancelled" in message:
        return ProxyAuthorizationError(
            "Touch ID prompt was cancelled by the user"
        )
    if "incorrect password attempts" in message or "a password is required" in message:
        return ProxyAuthorizationError(
            "sudo authentication failed (wrong password or Touch ID unavailable)"
        )
    return ProxyManagerError(message)


def _parse_state(stdout: str) -> ProxyState:
    enabled = False
    server: str | None = None
    port: int | None = None
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        if m := re.match(r"^Enabled:\s*(\S+)", line, re.IGNORECASE):
            enabled = m.group(1).lower() in {"yes", "true", "on", "1"}
        elif m := re.match(r"^Server:\s*(.*)$", line, re.IGNORECASE):
            value = m.group(1).strip()
            server = value or None
        elif m := re.match(r"^Port:\s*(\d+)", line, re.IGNORECASE):
            port = int(m.group(1))
    return ProxyState(enabled=enabled, server=server, port=port)
