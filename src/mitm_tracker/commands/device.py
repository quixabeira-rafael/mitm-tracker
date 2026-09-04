from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

from mitm_tracker import cert_manager, device_server, device_wireguard, net_info
from mitm_tracker.cert_manager import CertManagerError
from mitm_tracker.commands import record as record_commands
from mitm_tracker.commands.record import ProxyLaunchError
from mitm_tracker.config import (
    DEFAULT_HELP_SERVER_PORT,
    DEFAULT_PROXY_PORT,
    DEFAULT_WIREGUARD_PORT,
    LAN_LISTEN_HOST,
    workspace_for,
)
from mitm_tracker.delay import DelayError
from mitm_tracker.output import (
    EXIT_INVALID_STATE,
    EXIT_OK,
    EXIT_SYSTEM,
    emit_error,
    emit_json,
    emit_text,
)
from mitm_tracker.session_manager import SessionManager


def register(subparsers: argparse._SubParsersAction) -> None:
    device_parser = subparsers.add_parser(
        "device",
        help="Route a physical iOS device through the proxy and serve its certificate.",
    )
    device_sub = device_parser.add_subparsers(dest="device_command", metavar="ACTION")
    device_sub.required = True

    start_p = device_sub.add_parser(
        "start",
        help="Listen on the LAN for a physical device and serve the setup page.",
    )
    start_p.add_argument("--mode", choices=["all", "listed"], default="all")
    start_p.add_argument(
        "--transport",
        choices=["wifi-proxy", "wireguard"],
        default="wifi-proxy",
        help="wifi-proxy (Safari/proxy-aware apps) or wireguard (every app, incl. QUIC).",
    )
    start_p.add_argument("--port", type=int, default=DEFAULT_PROXY_PORT)
    start_p.add_argument("--help-port", type=int, default=DEFAULT_HELP_SERVER_PORT)
    start_p.add_argument("--wireguard-port", type=int, default=DEFAULT_WIREGUARD_PORT)
    start_p.add_argument(
        "--keep-cache",
        action="store_true",
        help="Preserve original Cache-Control headers (default: force no-cache).",
    )
    record_commands.add_delay_arguments(start_p)
    record_commands.add_tray_arguments(start_p)
    start_p.add_argument("--json", action="store_true", dest="json_mode")
    start_p.set_defaults(func=cmd_start)

    status_p = device_sub.add_parser(
        "status", help="Show whether the LAN proxy is up and reachable."
    )
    status_p.add_argument("--json", action="store_true", dest="json_mode")
    status_p.set_defaults(func=cmd_status)

    stop_p = device_sub.add_parser(
        "stop", help="Stop the LAN proxy session and the setup page."
    )
    stop_p.add_argument("--json", action="store_true", dest="json_mode")
    stop_p.set_defaults(func=record_commands.cmd_stop)


def register_internal(subparsers: argparse._SubParsersAction) -> None:
    serve_p = subparsers.add_parser("_serve-device-page")
    serve_p.add_argument("--ca", required=True)
    serve_p.add_argument("--host", default=LAN_LISTEN_HOST)
    serve_p.add_argument("--help-port", type=int, required=True)
    serve_p.add_argument("--proxy-ip", required=True)
    serve_p.add_argument("--proxy-port", type=int, required=True)
    serve_p.add_argument("--page-mode", default="regular")
    serve_p.add_argument("--wg-conf")
    serve_p.set_defaults(func=cmd_serve_page)


def cmd_serve_page(args: argparse.Namespace) -> int:
    wireguard_conf = None
    if args.wg_conf:
        wireguard_conf = Path(args.wg_conf).read_text(encoding="utf-8")
    device_server.run_server(
        host=args.host,
        port=args.help_port,
        ca_pem_path=Path(args.ca),
        proxy_ip=args.proxy_ip,
        proxy_port=args.proxy_port,
        help_port=args.help_port,
        mode=args.page_mode,
        wireguard_conf=wireguard_conf,
    )
    return EXIT_OK


def _setup_steps_text(ip: str, port: int, help_url: str) -> str:
    return (
        "On the iPhone/iPad (same Wi-Fi):\n"
        f"  1. Settings > Wi-Fi > (your network) > Configure Proxy > Manual\n"
        f"     Server: {ip}   Port: {port}\n"
        f"  2. Open {help_url} (or http://mitm.it) in Safari and download the profile\n"
        "  3. Settings > General > VPN & Device Management > install the mitm-tracker CA\n"
        "  4. Settings > General > About > Certificate Trust Settings > enable full trust\n"
    )


def _find_self_binary() -> str | None:
    return shutil.which("mitm-tracker")


def _spawn_help_server(
    *,
    ca_pem: Path,
    help_port: int,
    proxy_ip: str,
    proxy_port: int,
    workspace_root: Path,
    page_mode: str = "regular",
    wg_conf_path: Path | None = None,
) -> int:
    binary = _find_self_binary()
    if binary is None:
        cmd = [
            sys.executable,
            "-m",
            "mitm_tracker.cli",
            "_serve-device-page",
        ]
    else:
        cmd = [binary, "_serve-device-page"]
    cmd += [
        "--ca",
        str(ca_pem),
        "--host",
        LAN_LISTEN_HOST,
        "--help-port",
        str(help_port),
        "--proxy-ip",
        proxy_ip,
        "--proxy-port",
        str(proxy_port),
        "--page-mode",
        page_mode,
    ]
    if wg_conf_path is not None:
        cmd += ["--wg-conf", str(wg_conf_path)]
    process = subprocess.Popen(
        cmd,
        cwd=str(workspace_root),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        stdin=subprocess.DEVNULL,
        close_fds=True,
        start_new_session=True,
    )
    return process.pid


def cmd_start(args: argparse.Namespace) -> int:
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
        ca_pem = cert_manager.ensure_ca_exists()
    except CertManagerError as exc:
        return emit_error(
            "ca_missing",
            str(exc),
            json_mode=args.json_mode,
            exit_code=EXIT_INVALID_STATE,
        )

    address = net_info.lan_address()
    if address.ip is None:
        return emit_error(
            "no_lan_ip",
            "could not determine this Mac's LAN IP address; connect to Wi-Fi/Ethernet "
            "and try again",
            json_mode=args.json_mode,
            exit_code=EXIT_INVALID_STATE,
        )

    wireguard = args.transport == "wireguard"
    proxy_mode = "wireguard" if wireguard else "regular"
    proxy_port = args.wireguard_port if wireguard else args.port

    wg_conf_text: str | None = None
    wg_conf_path: Path | None = None
    if wireguard:
        keyfile = device_wireguard.ensure_keyfile(workspace.wireguard_keyfile)
        wg_cfg = device_wireguard.client_config(
            keyfile, endpoint_host=address.ip, endpoint_port=proxy_port
        )
        wg_conf_text = wg_cfg.to_conf()
        wg_conf_path = device_wireguard.write_client_conf(
            workspace.runtime_dir / "wireguard-client.conf", wg_conf_text
        )

    try:
        delay = record_commands.delay_from_args(args)
    except DelayError as exc:
        return emit_error(
            "invalid_delay",
            str(exc),
            json_mode=args.json_mode,
            exit_code=EXIT_INVALID_STATE,
        )

    try:
        result = record_commands.launch_proxy(
            mode=args.mode,
            port=proxy_port,
            listen_host=LAN_LISTEN_HOST,
            keep_cache=args.keep_cache,
            configure_system_proxy=False,
            proxy_mode=proxy_mode,
            wireguard_keyfile=workspace.wireguard_keyfile if wireguard else None,
            delay=delay,
            start_tray=not getattr(args, "no_tray", False),
        )
    except ProxyLaunchError as exc:
        return emit_error(
            exc.error,
            exc.message,
            json_mode=args.json_mode,
            exit_code=exc.exit_code,
        )

    try:
        help_pid = _spawn_help_server(
            ca_pem=ca_pem,
            help_port=args.help_port,
            proxy_ip=address.ip,
            proxy_port=result.port,
            workspace_root=workspace.root,
            page_mode=proxy_mode,
            wg_conf_path=wg_conf_path,
        )
    except Exception as exc:
        _stop_session(args.json_mode)
        return emit_error(
            "help_server_failed",
            f"could not start the help server: {exc}",
            json_mode=args.json_mode,
            exit_code=EXIT_SYSTEM,
        )

    sm.set_device_help(help_pid=help_pid, help_port=args.help_port, lan_ip=address.ip)

    help_url = f"http://{address.ip}:{args.help_port}/"
    payload = {
        "started": True,
        "transport": "wireguard" if wireguard else "wifi-proxy",
        "pid": result.pid,
        "help_pid": help_pid,
        "proxy_ip": address.ip,
        "proxy_port": result.port,
        "listen_host": result.listen_host,
        "ip_source": address.source,
        "service": address.service,
        "help_url": help_url,
        "session_db": str(result.session_db),
        "ssl_list_count": result.ssl_count,
        **result.delay.to_dict(),
    }

    if args.json_mode:
        emit_json(payload)
        return EXIT_OK

    if wireguard:
        emit_text(
            "device WireGuard server listening on the LAN (captures every app).\n\n"
            f"Open the setup page on the device and scan the QR with the WireGuard app:\n"
            f"  {help_url}\n\n"
            "On the iPhone/iPad (same Wi-Fi):\n"
            "  1. Install the WireGuard app from the App Store\n"
            "  2. Open the setup page above, scan the QR (Add tunnel > from QR code)\n"
            "  3. Turn the tunnel on and allow the VPN prompt\n"
            "  4. Settings > General > VPN & Device Management > install the mitm-tracker CA\n"
            "  5. Settings > General > About > Certificate Trust Settings > enable full trust\n"
        )
    else:
        emit_text(
            "device proxy listening on the LAN.\n\n"
            f"Proxy:    {address.ip}:{result.port}\n"
            f"Help page: {help_url}\n\n"
            + _setup_steps_text(address.ip, result.port, help_url)
        )
    if result.ssl_count == 0:
        emit_text(
            f"warning: SSL list is empty for profile '{result.profile}'; HTTPS will "
            "pass through without decryption. Add hosts with `mitm-tracker ssl add "
            "<pattern>` and restart.",
        )
    emit_text("\nStop with `mitm-tracker device stop` (or the tray).")
    return EXIT_OK


def _stop_session(json_mode: bool) -> None:
    stop_args = argparse.Namespace(json_mode=json_mode)
    try:
        record_commands.cmd_stop(stop_args)
    except Exception as exc:
        emit_text(f"warning: failed to stop the session cleanly: {exc}", stream=sys.stderr)


def cmd_status(args: argparse.Namespace) -> int:
    workspace = workspace_for()
    sm = SessionManager(workspace)
    state = sm.read_state()
    running = sm.is_running()
    listen_host = state.get("listen_host")
    lan_bound = listen_host in ("0.0.0.0", "::")
    help_pid = state.get("help_pid")
    help_alive = bool(help_pid) and sm._pid_alive(int(help_pid))
    lan_ip = state.get("lan_ip")
    help_port = state.get("help_port")
    help_url = (
        f"http://{lan_ip}:{help_port}/" if lan_ip and help_port else None
    )

    proxy_mode = state.get("proxy_mode") or "regular"
    transport = "wireguard" if proxy_mode == "wireguard" else "wifi-proxy"

    payload = {
        "running": running,
        "transport": transport,
        "lan_bound": lan_bound,
        "listen_host": listen_host,
        "port": state.get("port"),
        "lan_ip": lan_ip,
        "help_port": help_port,
        "help_url": help_url,
        "help_server_running": help_alive,
    }

    if args.json_mode:
        emit_json(payload)
        return EXIT_OK

    if not state:
        emit_text("no device session has been started yet")
        return EXIT_OK

    label = "running" if running else "stopped"
    reach = f"{lan_ip}:{state.get('port')}" if lan_ip and state.get("port") else "-"
    emit_text(
        f"state: {label}\n"
        f"transport: {transport}\n"
        f"listen_host: {listen_host or '-'}\n"
        f"lan_bound: {lan_bound}\n"
        f"reachable_at: {reach}\n"
        f"help_url: {help_url or '-'}\n"
        f"help_server_running: {help_alive}"
    )
    return EXIT_OK
