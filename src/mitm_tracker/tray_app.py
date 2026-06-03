from __future__ import annotations

import json
import shutil
import subprocess
import threading
from enum import Enum
from typing import Callable

import rumps

from mitm_tracker import doctor
from mitm_tracker.config import Workspace
from mitm_tracker.profile_manager import ProfileError, ProfileManager
from mitm_tracker.session_manager import SessionManager, SessionManagerError

_STATUS_GLYPH = {
    doctor.STATUS_WARN: "⚠️",
    doctor.STATUS_ERROR: "❌",
}


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
        self._copy_link_item = rumps.MenuItem(
            "Copy device setup link", callback=self._on_copy_device_link
        )
        self._open_page_item = rumps.MenuItem(
            "Open device setup page", callback=self._on_open_device_page
        )
        self._open_captures_item = rumps.MenuItem(
            "Open captures folder", callback=self._on_open_captures
        )
        self._reveal_state_item = rumps.MenuItem(
            "Reveal state.json in Finder", callback=self._on_reveal_state
        )
        self._warnings_item = rumps.MenuItem("Warnings")
        self._quit_item = rumps.MenuItem("Quit tray", callback=self._on_quit)

        self.menu = [
            self._status_item,
            self._profile_item,
            self._workspace_item,
            None,
            self._warnings_item,
            None,
            self._start_item,
            self._stop_item,
            None,
            self._copy_link_item,
            self._open_page_item,
            None,
            self._open_captures_item,
            self._reveal_state_item,
            None,
            self._quit_item,
        ]
        self._device_help_url: str | None = None
        self._warnings_snapshot: list[tuple[str, str]] = []
        self._warnings_rendered_key: tuple | None = None
        self._warnings_computing = False
        self._warnings_lock = threading.Lock()
        self._warnings_dirty = False

        self._compute_warnings_snapshot()
        self._render_warnings()

        self._timer = rumps.Timer(self._refresh, interval)
        self._refresh(None)
        self._timer.start()

    def run(self, **options) -> None:
        _set_accessory_activation_policy()
        super().run(**options)

    def _on_refresh_warnings(self, _sender) -> None:
        with self._warnings_lock:
            if self._warnings_computing:
                return
            self._warnings_computing = True
        self._warnings_item.title = "Warnings (refreshing…)"
        thread = threading.Thread(target=self._recompute_warnings_worker, daemon=True)
        thread.start()

    def _recompute_warnings_worker(self) -> None:
        try:
            title, snapshot = _build_warnings_snapshot()
        finally:
            with self._warnings_lock:
                self._warnings_computing = False
        self._apply_warnings_snapshot(title, snapshot)

    def _apply_warnings_snapshot(self, title: str, snapshot: list[tuple[str, str]]) -> None:
        def _on_main() -> None:
            self._warnings_title = title
            self._warnings_snapshot = snapshot
            self._render_warnings()

        try:
            from PyObjCTools import AppHelper
        except ImportError:
            # No way to hop to the main thread; stash the result and let the
            # next timer tick (which runs on the run loop) render it. Never
            # mutate the NSMenu from this worker thread.
            self._warnings_title = title
            self._warnings_snapshot = snapshot
            self._warnings_dirty = True
            return
        AppHelper.callAfter(_on_main)

    def _compute_warnings_snapshot(self) -> None:
        title, snapshot = _build_warnings_snapshot()
        self._warnings_title = title
        self._warnings_snapshot = snapshot

    def _render_warnings(self) -> None:
        self._warnings_item.title = self._warnings_title
        key = tuple(self._warnings_snapshot)
        if key == self._warnings_rendered_key:
            return
        self._warnings_rendered_key = key
        if len(self._warnings_item) > 0:
            self._warnings_item.clear()
        refresh = rumps.MenuItem("Refresh warnings", callback=self._on_refresh_warnings)
        self._warnings_item.add(refresh)
        self._warnings_item.add(rumps.separator)
        for title, detail in self._warnings_snapshot:
            head = rumps.MenuItem(title)
            head.set_callback(None)
            self._warnings_item.add(head)
            body = rumps.MenuItem(f"    {detail}")
            body.set_callback(None)
            self._warnings_item.add(body)

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

        self._device_help_url = _device_help_url(status, state)
        device_active = self._device_help_url is not None
        self._copy_link_item.set_callback(
            self._on_copy_device_link if device_active else None
        )
        self._open_page_item.set_callback(
            self._on_open_device_page if device_active else None
        )

        if self._warnings_dirty:
            self._warnings_dirty = False
            self._render_warnings()

    def _on_start(self, _sender) -> None:
        self._invoke_cli(["record", "start", "--json"])
        self._refresh(None)

    def _on_stop(self, _sender) -> None:
        self._invoke_cli(["record", "stop", "--json"])
        self._refresh(None)

    def _on_quit(self, _sender) -> None:
        status = compute_status(self._sessions)
        if status in (Status.RUNNING, Status.CRASHED):
            self._invoke_cli(["record", "stop", "--json"])
        rumps.quit_application()

    def _on_copy_device_link(self, _sender) -> None:
        url = self._device_help_url
        if not url:
            return
        try:
            proc = subprocess.run(["pbcopy"], input=url, text=True, check=False)
        except FileNotFoundError:
            rumps.alert("mitm-tracker", "pbcopy not found")
            return
        if proc.returncode == 0:
            rumps.notification("mitm-tracker", "Device setup link copied", url)

    def _on_open_device_page(self, _sender) -> None:
        url = self._device_help_url
        if not url:
            return
        subprocess.run(["open", url], check=False)

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


def _set_accessory_activation_policy() -> None:
    try:
        import AppKit
    except ImportError:
        return
    AppKit.NSApplication.sharedApplication().setActivationPolicy_(
        AppKit.NSApplicationActivationPolicyAccessory
    )


def _default_runner(cmd: list[str], cwd: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd,
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )


def _build_warnings_snapshot() -> tuple[str, list[tuple[str, str]]]:
    try:
        results = doctor.run_all_checks()
    except Exception as exc:
        return "Warnings (?)", [("Could not run checks", str(exc))]
    blocking = [
        r for r in results if r.status in (doctor.STATUS_WARN, doctor.STATUS_ERROR)
    ]
    if not blocking:
        return "Warnings (none)", [("No warnings", "everything looks healthy")]
    snapshot = [
        (f"{_STATUS_GLYPH.get(r.status, '')} {r.name}".strip(), r.detail)
        for r in blocking
    ]
    return f"Warnings ({len(blocking)})", snapshot


def _is_lan_session(state: dict) -> bool:
    return state.get("listen_host") in ("0.0.0.0", "::")


def _device_help_url(status: Status, state: dict) -> str | None:
    if status is not Status.RUNNING:
        return None
    if not _is_lan_session(state):
        return None
    lan_ip = state.get("lan_ip")
    help_port = state.get("help_port")
    if not lan_ip or not help_port:
        return None
    return f"http://{lan_ip}:{help_port}/"


def _format_status_line(status: Status, state: dict) -> str:
    if status is Status.RUNNING:
        pid = state.get("pid")
        port = state.get("port")
        if _is_lan_session(state) and state.get("lan_ip"):
            return f"Status: Running (device LAN {state['lan_ip']}:{port})"
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
