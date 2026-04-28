from __future__ import annotations

import json
import shutil
import subprocess
from enum import Enum
from typing import Callable

import rumps

from mitm_tracker.config import Workspace
from mitm_tracker.profile_manager import ProfileError, ProfileManager
from mitm_tracker.session_manager import SessionManager, SessionManagerError


class Status(Enum):
    RUNNING = "running"
    STOPPED = "stopped"
    CRASHED = "crashed"


_TITLE_BY_STATUS = {
    Status.RUNNING: "🟢",
    Status.STOPPED: "🔴",
    Status.CRASHED: "🟡",
}


def compute_status(sm: SessionManager) -> Status:
    if sm.detect_crashed():
        return Status.CRASHED
    if sm.is_running():
        return Status.RUNNING
    return Status.STOPPED


class TrayApp(rumps.App):
    def __init__(
        self,
        workspace: Workspace,
        *,
        interval: float = 2.0,
        runner: Callable[[list[str], str], subprocess.CompletedProcess] | None = None,
    ) -> None:
        self._workspace = workspace
        self._sessions = SessionManager(workspace)
        self._profiles = ProfileManager(workspace)
        self._runner = runner or _default_runner
        super().__init__(name="mitm-tracker", title=_TITLE_BY_STATUS[Status.STOPPED], quit_button=None)

        self._status_item = rumps.MenuItem("Status: …")
        self._profile_item = rumps.MenuItem("Profile: …")
        self._workspace_item = rumps.MenuItem(f"Workspace: {workspace.root}")
        self._start_item = rumps.MenuItem("Start record", callback=self._on_start)
        self._stop_item = rumps.MenuItem("Stop record", callback=self._on_stop)
        self._open_captures_item = rumps.MenuItem(
            "Open captures folder", callback=self._on_open_captures
        )
        self._reveal_state_item = rumps.MenuItem(
            "Reveal state.json in Finder", callback=self._on_reveal_state
        )
        self._quit_item = rumps.MenuItem("Quit tray", callback=rumps.quit_application)

        self.menu = [
            self._status_item,
            self._profile_item,
            self._workspace_item,
            None,
            self._start_item,
            self._stop_item,
            None,
            self._open_captures_item,
            self._reveal_state_item,
            None,
            self._quit_item,
        ]

        self._timer = rumps.Timer(self._refresh, interval)
        self._refresh(None)
        self._timer.start()

    def _refresh(self, _sender) -> None:
        status = compute_status(self._sessions)
        self.title = _TITLE_BY_STATUS[status]

        try:
            state = self._sessions.read_state()
        except SessionManagerError:
            state = {}

        self._status_item.title = _format_status_line(status, state)
        self._profile_item.title = _format_profile_line(self._profiles)

        self._start_item.set_callback(self._on_start if status != Status.RUNNING else None)
        self._stop_item.set_callback(self._on_stop if status != Status.STOPPED else None)

    def _on_start(self, _sender) -> None:
        self._invoke_cli(["record", "start", "--json"])
        self._refresh(None)

    def _on_stop(self, _sender) -> None:
        self._invoke_cli(["record", "stop", "--json"])
        self._refresh(None)

    def _on_open_captures(self, _sender) -> None:
        path = self._workspace.captures_dir
        path.mkdir(parents=True, exist_ok=True)
        subprocess.run(["open", str(path)], check=False)

    def _on_reveal_state(self, _sender) -> None:
        path = self._workspace.state_path
        if not path.exists():
            rumps.alert("mitm-tracker", "state.json does not exist yet")
            return
        subprocess.run(["open", "-R", str(path)], check=False)

    def _invoke_cli(self, argv: list[str]) -> None:
        binary = shutil.which("mitm-tracker")
        if binary is None:
            rumps.alert("mitm-tracker", "binary not found on PATH")
            return
        try:
            result = self._runner([binary, *argv], str(self._workspace.root))
        except subprocess.TimeoutExpired:
            rumps.alert("mitm-tracker", f"`{' '.join(argv)}` timed out after 120s")
            return
        if result.returncode != 0:
            rumps.alert("mitm-tracker", _extract_error(result))


def _default_runner(cmd: list[str], cwd: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd,
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )


def _format_status_line(status: Status, state: dict) -> str:
    if status is Status.RUNNING:
        pid = state.get("pid")
        port = state.get("port")
        return f"Status: Running (PID {pid}, port {port})"
    if status is Status.CRASHED:
        pid = state.get("pid")
        return f"Status: Crashed (PID {pid} dead)"
    return "Status: Stopped"


def _format_profile_line(profiles: ProfileManager) -> str:
    try:
        profile = profiles.describe()
    except ProfileError:
        return f"Profile: {profiles.active_name()} (?)"
    return f"Profile: {profile.name} ({profile.ssl_count} hosts)"


def _extract_error(result: subprocess.CompletedProcess) -> str:
    for stream in (result.stderr, result.stdout):
        if not stream:
            continue
        for line in stream.strip().splitlines():
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(payload, dict) and payload.get("message"):
                return str(payload["message"])
        if stream.strip():
            return stream.strip()
    return f"command failed with exit code {result.returncode}"
