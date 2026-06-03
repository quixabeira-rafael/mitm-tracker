from __future__ import annotations

import argparse
import json
import os
import shutil
import signal
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from mitm_tracker.config import (
    DEFAULT_LISTEN_HOST,
    DEFAULT_PROXY_PORT,
    Workspace,
    workspace_for,
)
from mitm_tracker.output import (
    EXIT_INVALID_STATE,
    EXIT_OK,
    EXIT_SYSTEM,
    emit_error,
    emit_json,
    emit_text,
)
from mitm_tracker.profile_manager import ProfileManager
from mitm_tracker.proxy_manager import ProxyBackup, ProxyManager, ProxyManagerError
from mitm_tracker.session_manager import SessionManager
from mitm_tracker.ssl_list import SslList
from mitm_tracker.store import FlowStore


SpawnFn = Callable[..., subprocess.Popen]


def register(subparsers: argparse._SubParsersAction) -> None:
    record_parser = subparsers.add_parser(
        "record", help="Start, stop, and inspect a record session."
    )
    sub = record_parser.add_subparsers(dest="record_command", metavar="ACTION")
    sub.required = True

    start_p = sub.add_parser("start", help="Start a new record session.")
    start_p.add_argument("--mode", choices=["all", "listed"], default="all")
    start_p.add_argument("--port", type=int, default=DEFAULT_PROXY_PORT)
    start_p.add_argument("--listen-host", default=DEFAULT_LISTEN_HOST)
    start_p.add_argument(
        "--no-system-proxy",
        action="store_true",
        help="Skip configuring the macOS system proxy.",
    )
    start_p.add_argument(
        "--keep-cache",
        action="store_true",
        help="Preserve original Cache-Control headers (default: force no-cache like Charles).",
    )
    start_p.add_argument("--json", action="store_true", dest="json_mode")
    start_p.set_defaults(func=cmd_start)

    stop_p = sub.add_parser("stop", help="Stop the current record session.")
    stop_p.add_argument("--json", action="store_true", dest="json_mode")
    stop_p.set_defaults(func=cmd_stop)

    status_p = sub.add_parser("status", help="Show the current record session status.")
    status_p.add_argument("--json", action="store_true", dest="json_mode")
    status_p.set_defaults(func=cmd_status)

    logs_p = sub.add_parser("logs", help="Tail the mitmproxy log for the current session.")
    logs_p.add_argument("--tail", type=int, default=50)
    logs_p.add_argument("--follow", action="store_true")
    logs_p.set_defaults(func=cmd_logs)


class ProxyLaunchError(RuntimeError):
    def __init__(self, error: str, message: str, *, exit_code: int) -> None:
        super().__init__(message)
        self.error = error
        self.message = message
        self.exit_code = exit_code


@dataclass
class ProxyLaunchResult:
    pid: int
    mode: str
    port: int
    listen_host: str
    profile: str
    session_db: Path
    ssl_count: int
    proxy_service: str | None
    no_cache: bool


def launch_proxy(
    *,
    mode: str,
    port: int,
    listen_host: str,
    keep_cache: bool,
    configure_system_proxy: bool,
    spawn: SpawnFn | None = None,
) -> ProxyLaunchResult:
    workspace = workspace_for()
    workspace.ensure()
    sm = SessionManager(workspace)
    pm = ProfileManager(workspace)
    profile = pm.active_name()

    mitmdump_bin = _find_mitmdump()
    if not mitmdump_bin:
        raise ProxyLaunchError(
            "mitmproxy_missing",
            "mitmdump not found; ensure mitmproxy is installed in the same environment as mitm-tracker",
            exit_code=EXIT_SYSTEM,
        )

    db_path = _new_session_db(workspace, profile)
    FlowStore.init_session(
        db_path,
        mode=mode,
        listen_host=listen_host,
        listen_port=port,
        profile=profile,
    ).close()

    proxy_service: str | None = None
    if configure_system_proxy:
        try:
            proxy_mgr = ProxyManager()
            proxy_service = proxy_mgr.get_active_service()
            backup = proxy_mgr.snapshot(proxy_service)
            workspace.proxy_backup_path.write_text(
                json.dumps(backup.to_dict(), indent=2),
                encoding="utf-8",
            )
            proxy_mgr.set_proxy(proxy_service, "127.0.0.1", port)
        except ProxyManagerError as exc:
            raise ProxyLaunchError(
                "proxy_failed",
                f"failed to configure macOS proxy: {exc}",
                exit_code=EXIT_SYSTEM,
            ) from exc

    ssl_list = SslList.load(workspace.ssl_path(profile))
    allow_regex = ssl_list.to_allow_hosts_regex()
    ssl_count = len(ssl_list.entries)

    maplocal_dir = workspace.profile_dir(profile)

    no_cache = not keep_cache

    cmd = _build_mitmdump_command(
        mitmdump_bin=mitmdump_bin,
        listen_host=listen_host,
        listen_port=port,
        db_path=db_path,
        mode=mode,
        allow_regex=allow_regex,
        maplocal_dir=maplocal_dir,
        no_cache=no_cache,
    )
    log_handle = workspace.log_path.open("ab", buffering=0)
    log_handle.write(
        f"\n--- record start {_now_iso()} mode={mode} port={port} listen={listen_host} ---\n".encode()
    )

    spawn_fn = spawn or _spawn_default
    try:
        process = spawn_fn(
            cmd,
            stdout=log_handle,
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
            close_fds=True,
            start_new_session=True,
        )
    except Exception as exc:
        log_handle.close()
        raise ProxyLaunchError(
            "spawn_failed",
            f"failed to spawn mitmdump: {exc}",
            exit_code=EXIT_SYSTEM,
        ) from exc

    sm.write_pid(process.pid)
    state = sm.start(
        pid=process.pid,
        mode=mode,
        port=port,
        session_db=db_path,
        proxy_service=proxy_service,
        listen_host=listen_host,
    )
    log_handle.close()

    return ProxyLaunchResult(
        pid=state["pid"],
        mode=state["mode"],
        port=state["port"],
        listen_host=listen_host,
        profile=profile,
        session_db=Path(state["session_db"]),
        ssl_count=ssl_count,
        proxy_service=proxy_service,
        no_cache=no_cache,
    )


def cmd_start(args: argparse.Namespace, *, spawn: SpawnFn | None = None) -> int:
    workspace = workspace_for()
    sm = SessionManager(workspace)

    if sm.is_running():
        state = sm.read_state()
        if args.json_mode:
            emit_json({"already_running": True, **state})
        else:
            emit_text(f"already running (pid={state.get('pid')})")
        return EXIT_OK

    try:
        result = launch_proxy(
            mode=args.mode,
            port=args.port,
            listen_host=args.listen_host,
            keep_cache=args.keep_cache,
            configure_system_proxy=not args.no_system_proxy,
            spawn=spawn,
        )
    except ProxyLaunchError as exc:
        return emit_error(
            exc.error,
            exc.message,
            json_mode=args.json_mode,
            exit_code=exc.exit_code,
        )

    payload = {
        "started": True,
        "pid": result.pid,
        "mode": result.mode,
        "port": result.port,
        "profile": result.profile,
        "session_db": str(result.session_db),
        "ssl_decryption_active": result.ssl_count > 0,
        "ssl_list_count": result.ssl_count,
        "proxy_service": result.proxy_service,
        "no_cache": result.no_cache,
    }
    if args.json_mode:
        emit_json(payload)
    else:
        emit_text(
            "record started: pid={pid} port={port} mode={mode} db={db}".format(
                pid=payload["pid"],
                port=payload["port"],
                mode=payload["mode"],
                db=payload["session_db"],
            )
        )
    if result.ssl_count == 0:
        emit_text(
            "warning: SSL list is empty for profile '{p}'; HTTPS will pass "
            "through without decryption (no flow bodies will be captured). "
            "Add hosts with `mitm-tracker ssl add <pattern>` and restart record.".format(p=result.profile),
            stream=sys.stderr,
        )
    return EXIT_OK


def cmd_stop(args: argparse.Namespace, *, kill: Callable[[int, int], None] | None = None) -> int:
    workspace = workspace_for()
    sm = SessionManager(workspace)
    state = sm.read_state()
    if not state.get("running"):
        return emit_error(
            "not_running",
            "no active record session",
            json_mode=args.json_mode,
            exit_code=EXIT_INVALID_STATE,
        )

    pid = int(state.get("pid") or 0)
    killer = kill or os.kill
    _terminate_pid(sm, pid, killer)

    help_pid = int(state.get("help_pid") or 0)
    _terminate_pid(sm, help_pid, killer)

    proxy_service = state.get("proxy_service")
    backup_path = workspace.proxy_backup_path
    proxy_restored = True
    proxy_error: str | None = None
    if proxy_service and backup_path.exists():
        try:
            data = json.loads(backup_path.read_text(encoding="utf-8"))
            backup = ProxyBackup.from_dict(data)
            ProxyManager().restore(backup)
        except (ProxyManagerError, OSError, ValueError) as exc:
            proxy_restored = False
            proxy_error = str(exc)
            emit_text(
                f"warning: failed to restore proxy: {exc}",
                stream=__import__("sys").stderr,
            )
    if proxy_restored and backup_path.exists():
        backup_path.unlink()

    sm.clear_pid()
    final_state = sm.stop()

    payload = {
        "stopped": True,
        "session_db": final_state.get("session_db"),
        "stopped_at": final_state.get("stopped_at"),
        "proxy_restored": proxy_restored,
        "proxy_error": proxy_error,
    }
    if args.json_mode:
        emit_json(payload)
    else:
        emit_text(f"record stopped (db={payload['session_db']})")

    if not proxy_restored:
        return emit_error(
            "proxy_restore_failed",
            f"daemon stopped, but the system proxy could not be restored: "
            f"{proxy_error or 'unknown error'}. "
            f"Run `networksetup -setwebproxystate <service> off` to clean up.",
            json_mode=args.json_mode,
            exit_code=EXIT_SYSTEM,
        )
    return EXIT_OK


def cmd_status(args: argparse.Namespace) -> int:
    workspace = workspace_for()
    sm = SessionManager(workspace)
    state = sm.read_state()
    running = sm.is_running()
    crashed = sm.detect_crashed()

    captured = None
    db_path = state.get("session_db")
    if db_path:
        try:
            db = Path(db_path)
            if db.exists():
                store = FlowStore(db, read_only=True)
                captured = store.count()
                store.close()
        except Exception:
            captured = None

    payload = {
        "running": running,
        "crashed": crashed,
        "pid": state.get("pid"),
        "mode": state.get("mode"),
        "port": state.get("port"),
        "started_at": state.get("started_at"),
        "session_db": state.get("session_db"),
        "active_session": state.get("active_session"),
        "captured_count": captured,
        "proxy_service": state.get("proxy_service"),
        "listen_host": state.get("listen_host"),
    }
    if args.json_mode:
        emit_json(payload)
        return EXIT_OK

    if not state:
        emit_text("no record session has been started yet")
        return EXIT_OK
    label = "running" if running else ("crashed" if crashed else "stopped")
    emit_text(
        f"state: {label}\n"
        f"pid: {payload['pid']}\n"
        f"mode: {payload['mode']}\n"
        f"port: {payload['port']}\n"
        f"db: {payload['session_db']}\n"
        f"captured: {payload['captured_count']}"
    )
    return EXIT_OK


def cmd_logs(args: argparse.Namespace) -> int:
    workspace = workspace_for()
    log_path = workspace.log_path
    if not log_path.exists():
        emit_text("(no logs yet)")
        return EXIT_OK

    if args.follow:
        try:
            with log_path.open("r", encoding="utf-8", errors="replace") as fp:
                fp.seek(0, os.SEEK_END)
                while True:
                    line = fp.readline()
                    if not line:
                        time.sleep(0.2)
                        continue
                    print(line, end="")
        except KeyboardInterrupt:
            return EXIT_OK
        return EXIT_OK

    tail_n = max(int(args.tail), 1)
    lines = log_path.read_text(encoding="utf-8", errors="replace").splitlines()
    for line in lines[-tail_n:]:
        emit_text(line)
    return EXIT_OK


def _build_mitmdump_command(
    *,
    mitmdump_bin: str,
    listen_host: str,
    listen_port: int,
    db_path: Path,
    mode: str,
    allow_regex: str,
    maplocal_dir: Path | None = None,
    no_cache: bool = True,
) -> list[str]:
    addon_path = _addon_module_path()
    cmd = [
        mitmdump_bin,
        "-s",
        addon_path,
        "--listen-host",
        listen_host,
        "--listen-port",
        str(listen_port),
        "--set",
        f"tracker_db_path={db_path}",
        "--set",
        f"tracker_mode={mode}",
        "--set",
        f"tracker_no_cache={'true' if no_cache else 'false'}",
    ]
    if maplocal_dir is not None:
        cmd.extend(["--set", f"tracker_maplocal_dir={maplocal_dir}"])
    cmd.extend(["--allow-hosts", allow_regex])
    return cmd


def _find_mitmdump() -> str | None:
    candidate = Path(sys.executable).with_name("mitmdump")
    if candidate.exists() and os.access(candidate, os.X_OK):
        return str(candidate)
    return shutil.which("mitmdump")


def _addon_module_path() -> str:
    from mitm_tracker import addon as addon_module

    return addon_module.__file__


def _new_session_db(workspace: Workspace, profile: str) -> Path:
    workspace.captures_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d_%H%M%S")
    name = f"{stamp}_{profile}.db"
    return workspace.captures_dir / name


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _spawn_default(cmd, **kwargs) -> subprocess.Popen:
    return subprocess.Popen(cmd, **kwargs)


def _terminate_pid(sm: SessionManager, pid: int, killer: Callable[[int, int], None]) -> None:
    if not pid or not sm._pid_alive(pid):
        return
    try:
        killer(pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    deadline = time.time() + 5.0
    while time.time() < deadline:
        if not sm._pid_alive(pid):
            break
        time.sleep(0.1)
    if sm._pid_alive(pid):
        try:
            killer(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
