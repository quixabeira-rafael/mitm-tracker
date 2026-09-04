from __future__ import annotations

import contextlib
import fcntl
import json
import os
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterator

HOME_DIRNAME = ".mitm-tracker"
HOME_ENV = "MITM_TRACKER_HOME"
REGISTRY_FILENAME = "instances.json"
LOCK_FILENAME = "instances.lock"

KIND_PROXY = "proxy"
KIND_TRAY = "tray"

PidChecker = Callable[[int], bool]


@dataclass(frozen=True)
class Instance:
    kind: str
    pid: int
    workspace: Path
    port: int | None
    started_at: str

    def to_dict(self) -> dict:
        return {
            "kind": self.kind,
            "pid": int(self.pid),
            "workspace": str(self.workspace),
            "port": int(self.port) if self.port else None,
            "started_at": self.started_at,
        }

    @classmethod
    def from_dict(cls, kind: str, data: dict) -> "Instance":
        return cls(
            kind=kind,
            pid=int(data.get("pid") or 0),
            workspace=Path(str(data.get("workspace") or "")),
            port=int(data["port"]) if data.get("port") else None,
            started_at=str(data.get("started_at") or ""),
        )

    def describe(self) -> str:
        parts = [f"pid={self.pid}"]
        if self.port:
            parts.append(f"port={self.port}")
        parts.append(f"workspace={self.workspace}")
        return " ".join(parts)


class InstanceBusyError(RuntimeError):
    def __init__(self, current: Instance) -> None:
        super().__init__(
            f"another mitm-tracker {current.kind} instance is already running "
            f"({current.describe()})"
        )
        self.current = current


def home_dir() -> Path:
    override = os.environ.get(HOME_ENV)
    if override:
        return Path(override).expanduser().resolve()
    return Path.home() / HOME_DIRNAME


def registry_path() -> Path:
    return home_dir() / REGISTRY_FILENAME


def pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def live(kind: str, *, alive: PidChecker | None = None) -> Instance | None:
    with _locked():
        return _live_locked(kind, alive or pid_alive)


def acquire(
    kind: str,
    *,
    pid: int,
    workspace: Path,
    port: int | None = None,
    alive: PidChecker | None = None,
) -> Instance:
    with _locked():
        current = _live_locked(kind, alive or pid_alive)
        if current is not None and current.pid != int(pid):
            raise InstanceBusyError(current)
        entry = Instance(
            kind=kind,
            pid=int(pid),
            workspace=Path(workspace),
            port=port,
            started_at=_now_iso(),
        )
        entries = _read_locked()
        entries[kind] = entry
        _write_locked(entries)
        return entry


def adopt_pid(kind: str, *, expected_pid: int, pid: int) -> Instance | None:
    """Hand a reservation held by `expected_pid` over to the spawned process."""
    with _locked():
        entries = _read_locked()
        entry = entries.get(kind)
        if entry is None or entry.pid != int(expected_pid):
            return None
        entries[kind] = replace(entry, pid=int(pid))
        _write_locked(entries)
        return entries[kind]


def release(kind: str, *, pid: int | None = None) -> None:
    with _locked():
        entries = _read_locked()
        entry = entries.get(kind)
        if entry is None:
            return
        if pid is not None and entry.pid != int(pid):
            return
        del entries[kind]
        _write_locked(entries)


def _live_locked(kind: str, alive: PidChecker) -> Instance | None:
    entries = _read_locked()
    entry = entries.get(kind)
    if entry is None:
        return None
    if alive(entry.pid):
        return entry
    del entries[kind]
    _write_locked(entries)
    return None


def _read_locked() -> dict[str, Instance]:
    path = registry_path()
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}
    if not isinstance(data, dict):
        return {}
    entries: dict[str, Instance] = {}
    for kind, raw in data.items():
        if isinstance(raw, dict):
            entries[str(kind)] = Instance.from_dict(str(kind), raw)
    return entries


def _write_locked(entries: dict[str, Instance]) -> None:
    path = registry_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {kind: entry.to_dict() for kind, entry in entries.items()}
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    tmp.replace(path)


@contextlib.contextmanager
def _locked() -> Iterator[None]:
    lock_path = home_dir() / LOCK_FILENAME
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    handle = lock_path.open("a+")
    try:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        yield
    finally:
        with contextlib.suppress(OSError):
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        handle.close()


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()
