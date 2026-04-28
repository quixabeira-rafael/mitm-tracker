from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

WORKSPACE_DIRNAME = ".mitm-tracker"
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

    def ensure(self) -> None:
        self.base.mkdir(parents=True, exist_ok=True)
        self.runtime_dir.mkdir(parents=True, exist_ok=True)
        self.captures_dir.mkdir(parents=True, exist_ok=True)
        self.profiles_dir.mkdir(parents=True, exist_ok=True)
        default_dir = self.profile_dir(DEFAULT_PROFILE_NAME)
        default_dir.mkdir(parents=True, exist_ok=True)


def workspace_for(cwd: Path | None = None) -> Workspace:
    return Workspace(root=Path(cwd or Path.cwd()).resolve())
