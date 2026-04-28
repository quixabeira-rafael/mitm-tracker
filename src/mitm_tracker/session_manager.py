from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from mitm_tracker.config import Workspace


class SessionManagerError(RuntimeError):
    pass


PidChecker = Callable[[int], bool]


def _default_pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


class SessionManager:
    def __init__(
        self,
        workspace: Workspace,
        *,
        pid_alive: PidChecker | None = None,
        clock: Callable[[], str] | None = None,
    ) -> None:
        self._workspace = workspace
        self._pid_alive = pid_alive or _default_pid_alive
        self._clock = clock or _now_iso

    @property
    def workspace(self) -> Workspace:
        return self._workspace

    def is_running(self) -> bool:
        state = self.read_state()
        if not state.get("running"):
            return False
        pid = int(state.get("pid") or 0)
        return self._pid_alive(pid)

    def detect_crashed(self) -> bool:
        state = self.read_state()
        if not state.get("running"):
            return False
        pid = int(state.get("pid") or 0)
        return not self._pid_alive(pid)

    def start(
        self,
        *,
        pid: int,
        mode: str,
        port: int,
        session_db: Path,
        proxy_service: str | None,
    ) -> dict:
        state = self.read_state()
        state.update(
            {
                "running": True,
                "pid": int(pid),
                "mode": mode,
                "port": int(port),
                "started_at": self._clock(),
                "session_db": str(session_db),
                "active_session": str(session_db),
                "proxy_service": proxy_service,
                "stopped_at": None,
            }
        )
        self.write_state(state)
        return state

    def stop(self) -> dict:
        state = self.read_state()
        state["running"] = False
        state["pid"] = None
        state["stopped_at"] = self._clock()
        self.write_state(state)
        return state

    def set_active_session(self, session_db: Path) -> None:
        state = self.read_state()
        state["active_session"] = str(session_db)
        self.write_state(state)

    def active_session_db(self) -> Path | None:
        state = self.read_state()
        value = state.get("active_session")
        if not value:
            return None
        return Path(value)

    def list_sessions(self) -> list[Path]:
        if not self._workspace.captures_dir.exists():
            return []
        files = sorted(
            self._workspace.captures_dir.glob("*.db"),
            key=lambda p: p.name,
            reverse=True,
        )
        return list(files)

    def read_state(self) -> dict:
        path = self._workspace.state_path
        if not path.exists():
            return {}
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise SessionManagerError(f"corrupt state.json at {path}: {exc}") from exc

    def write_state(self, state: dict) -> None:
        self._workspace.runtime_dir.mkdir(parents=True, exist_ok=True)
        self._workspace.state_path.write_text(
            json.dumps(state, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    def write_pid(self, pid: int) -> None:
        self._workspace.runtime_dir.mkdir(parents=True, exist_ok=True)
        self._workspace.pid_path.write_text(str(int(pid)), encoding="utf-8")

    def read_pid(self) -> int | None:
        path = self._workspace.pid_path
        if not path.exists():
            return None
        try:
            return int(path.read_text(encoding="utf-8").strip())
        except ValueError:
            return None

    def clear_pid(self) -> None:
        self._workspace.pid_path.unlink(missing_ok=True)


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()
