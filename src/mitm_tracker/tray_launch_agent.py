from __future__ import annotations

import plistlib
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

LAUNCH_AGENT_LABEL = "com.mitm-tracker.tray"


def _default_path_env(home: Path | None = None) -> str:
    base = home or Path.home()
    return ":".join(
        [
            str(base / ".local" / "bin"),
            "/opt/homebrew/bin",
            "/usr/local/bin",
            "/usr/bin",
            "/bin",
        ]
    )


Runner = Callable[[list[str]], subprocess.CompletedProcess]


def _default_runner(cmd: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, check=False)


@dataclass(frozen=True)
class LaunchAgentPaths:
    plist: Path
    log: Path

    @classmethod
    def for_user(cls, home: Path | None = None) -> LaunchAgentPaths:
        base = home or Path.home()
        return cls(
            plist=base / "Library" / "LaunchAgents" / f"{LAUNCH_AGENT_LABEL}.plist",
            log=base / "Library" / "Logs" / "mitm-tracker-tray.log",
        )


def resolve_binary() -> Path:
    candidate = shutil.which("mitm-tracker")
    if candidate:
        return Path(candidate)
    fallback = Path(sys.argv[0]).resolve()
    return fallback


def generate_plist_data(
    workspace: Path,
    binary: Path,
    log_path: Path,
    *,
    path_env: str | None = None,
) -> dict:
    path_env = path_env or _default_path_env()
    return {
        "Label": LAUNCH_AGENT_LABEL,
        "ProgramArguments": [str(binary), "tray", "run"],
        "WorkingDirectory": str(workspace),
        "EnvironmentVariables": {"PATH": path_env},
        "RunAtLoad": True,
        "ProcessType": "Interactive",
        "StandardOutPath": str(log_path),
        "StandardErrorPath": str(log_path),
    }


def write_plist(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as fh:
        plistlib.dump(data, fh, sort_keys=False)


def is_installed(paths: LaunchAgentPaths) -> bool:
    return paths.plist.exists()


def is_loaded(runner: Runner | None = None) -> bool:
    runner = runner or _default_runner
    result = runner(["launchctl", "list", LAUNCH_AGENT_LABEL])
    return result.returncode == 0


def loaded_pid(runner: Runner | None = None) -> int | None:
    runner = runner or _default_runner
    result = runner(["launchctl", "list", LAUNCH_AGENT_LABEL])
    if result.returncode != 0:
        return None
    for line in result.stdout.splitlines():
        line = line.strip()
        if line.startswith('"PID"'):
            try:
                return int(line.split("=", 1)[1].strip().rstrip(";").strip())
            except ValueError:
                return None
    return None


@dataclass(frozen=True)
class InstallResult:
    plist_path: Path
    workspace: Path
    binary: Path
    log_path: Path
    replaced_existing: bool
    loaded: bool

    def to_dict(self) -> dict:
        return {
            "plist_path": str(self.plist_path),
            "workspace": str(self.workspace),
            "binary": str(self.binary),
            "log_path": str(self.log_path),
            "replaced_existing": self.replaced_existing,
            "loaded": self.loaded,
        }


def install(
    workspace: Path,
    *,
    binary: Path | None = None,
    paths: LaunchAgentPaths | None = None,
    runner: Runner | None = None,
) -> InstallResult:
    paths = paths or LaunchAgentPaths.for_user()
    binary = binary or resolve_binary()
    runner = runner or _default_runner

    replaced = paths.plist.exists()
    if is_loaded(runner):
        runner(["launchctl", "unload", str(paths.plist)])

    data = generate_plist_data(workspace, binary, paths.log)
    write_plist(paths.plist, data)

    runner(["launchctl", "load", "-w", str(paths.plist)])
    loaded = is_loaded(runner)

    return InstallResult(
        plist_path=paths.plist,
        workspace=workspace,
        binary=binary,
        log_path=paths.log,
        replaced_existing=replaced,
        loaded=loaded,
    )


@dataclass(frozen=True)
class UninstallResult:
    plist_path: Path
    plist_removed: bool
    was_loaded: bool

    def to_dict(self) -> dict:
        return {
            "plist_path": str(self.plist_path),
            "plist_removed": self.plist_removed,
            "was_loaded": self.was_loaded,
        }


def uninstall(
    *,
    paths: LaunchAgentPaths | None = None,
    runner: Runner | None = None,
) -> UninstallResult:
    paths = paths or LaunchAgentPaths.for_user()
    runner = runner or _default_runner

    was_loaded = is_loaded(runner)
    if was_loaded:
        runner(["launchctl", "unload", str(paths.plist)])

    plist_removed = False
    if paths.plist.exists():
        paths.plist.unlink()
        plist_removed = True

    return UninstallResult(
        plist_path=paths.plist,
        plist_removed=plist_removed,
        was_loaded=was_loaded,
    )


@dataclass(frozen=True)
class StatusResult:
    plist_path: Path
    installed: bool
    loaded: bool
    pid: int | None
    workspace: Path | None

    def to_dict(self) -> dict:
        return {
            "plist_path": str(self.plist_path),
            "installed": self.installed,
            "loaded": self.loaded,
            "pid": self.pid,
            "workspace": str(self.workspace) if self.workspace else None,
        }


def status(
    *,
    paths: LaunchAgentPaths | None = None,
    runner: Runner | None = None,
) -> StatusResult:
    paths = paths or LaunchAgentPaths.for_user()
    runner = runner or _default_runner

    installed = paths.plist.exists()
    loaded = is_loaded(runner)
    pid = loaded_pid(runner) if loaded else None

    workspace = None
    if installed:
        try:
            with paths.plist.open("rb") as fh:
                data = plistlib.load(fh)
            value = data.get("WorkingDirectory")
            if value:
                workspace = Path(value)
        except (OSError, plistlib.InvalidFileException):
            workspace = None

    return StatusResult(
        plist_path=paths.plist,
        installed=installed,
        loaded=loaded,
        pid=pid,
        workspace=workspace,
    )
