from __future__ import annotations

import os
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

WORKSPACE_DIRNAME = ".mitm-tracker"
WORKSPACE_ROOT_ENV = "MITM_TRACKER_ROOT"
RUNTIME_DIRNAME = "runtime"
CAPTURES_DIRNAME = "captures"
PROFILES_DIRNAME = "profiles"
SSL_FILENAME = "ssl.json"
PID_FILENAME = "mitmproxy.pid"
LOG_FILENAME = "mitmproxy.log"
STATE_FILENAME = "state.json"
PROXY_BACKUP_FILENAME = "proxy_backup.json"

DEFAULT_PROFILE_NAME = "default"
DEFAULT_PROXY_PORT = 8080
DEFAULT_LISTEN_HOST = "127.0.0.1"

LAN_LISTEN_HOST = "0.0.0.0"
DEFAULT_HELP_SERVER_PORT = 8888
DEFAULT_WIREGUARD_PORT = 51820
WIREGUARD_KEYFILE = "wireguard.conf"

_PROFILE_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$", re.IGNORECASE)


def is_valid_profile_name(name: str) -> bool:
    return bool(_PROFILE_NAME_RE.match(name or ""))


@dataclass(frozen=True)
class Workspace:
    root: Path

    @property
    def base(self) -> Path:
        return self.root / WORKSPACE_DIRNAME

    @property
    def runtime_dir(self) -> Path:
        return self.base / RUNTIME_DIRNAME

    @property
    def captures_dir(self) -> Path:
        return self.base / CAPTURES_DIRNAME

    @property
    def profiles_dir(self) -> Path:
        return self.base / PROFILES_DIRNAME

    def profile_dir(self, profile: str) -> Path:
        return self.profiles_dir / profile

    def ssl_path(self, profile: str) -> Path:
        return self.profile_dir(profile) / SSL_FILENAME

    @property
    def pid_path(self) -> Path:
        return self.runtime_dir / PID_FILENAME

    @property
    def log_path(self) -> Path:
        return self.runtime_dir / LOG_FILENAME

    @property
    def state_path(self) -> Path:
        return self.runtime_dir / STATE_FILENAME

    @property
    def proxy_backup_path(self) -> Path:
        return self.runtime_dir / PROXY_BACKUP_FILENAME

    @property
    def wireguard_keyfile(self) -> Path:
        return self.runtime_dir / WIREGUARD_KEYFILE

    def ensure(self) -> None:
        self.base.mkdir(parents=True, exist_ok=True)
        self.runtime_dir.mkdir(parents=True, exist_ok=True)
        self.captures_dir.mkdir(parents=True, exist_ok=True)
        self.profiles_dir.mkdir(parents=True, exist_ok=True)
        default_dir = self.profile_dir(DEFAULT_PROFILE_NAME)
        default_dir.mkdir(parents=True, exist_ok=True)


def workspace_for(cwd: Path | None = None) -> Workspace:
    return Workspace(root=resolve_workspace_root(cwd))


def resolve_workspace_root(cwd: Path | None = None) -> Path:
    """Resolve the single workspace root shared by every checkout of a project.

    Git worktrees each have their own directory, so a cwd-based workspace would
    give every worktree a private SSL list, profile set and runtime state. The
    main repository is the one place all worktrees agree on, so it owns the
    workspace and worktrees resolve to it.
    """
    start = _start_dir(cwd)
    return _main_repo_root(start) or _nearest_existing_workspace(start) or start


def _start_dir(cwd: Path | None) -> Path:
    if cwd is not None:
        return Path(cwd).expanduser().resolve()
    override = os.environ.get(WORKSPACE_ROOT_ENV)
    if override:
        return Path(override).expanduser().resolve()
    return Path.cwd().resolve()


def _main_repo_root(start: Path) -> Path | None:
    try:
        proc = subprocess.run(
            ["git", "rev-parse", "--git-common-dir"],
            cwd=str(start),
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0:
        return None
    raw = proc.stdout.strip()
    if not raw:
        return None
    common = Path(raw)
    if not common.is_absolute():
        common = start / common
    try:
        common = common.resolve()
    except OSError:
        return None
    root = common.parent if common.name == ".git" else common
    return root if root.is_dir() else None


def _nearest_existing_workspace(start: Path) -> Path | None:
    for candidate in (start, *start.parents):
        if (candidate / WORKSPACE_DIRNAME).is_dir():
            return candidate
    return None
