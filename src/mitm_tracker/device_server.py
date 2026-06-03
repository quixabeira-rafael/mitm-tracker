from __future__ import annotations

import html
import threading
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from mitm_tracker import device_profile

PAGE_PATH = "/"
MOBILECONFIG_PATH = "/cert.mobileconfig"
PEM_PATH = "/cert.pem"


@dataclass(frozen=True)
class HelpPageContext:
    proxy_ip: str
    proxy_port: int
    help_ip: str
    help_port: int


def _deeplink_button(label: str, url: str) -> str:
    safe_url = html.escape(url, quote=True)
    safe_label = html.escape(label)
    return (
        f'<a class="deeplink" href="{safe_url}">{safe_label}</a>'
        '<span class="deeplink-note">may not work on iOS 17+</span>'
    )


def render_help_page(ctx: HelpPageContext) -> str:
    ip = html.escape(ctx.proxy_ip)
    port = ctx.proxy_port
    wifi_link = _deeplink_button("Open Wi-Fi settings", "prefs:root=WIFI")
    profiles_link = _deeplink_button(
        "Open VPN & Device Management",
        "prefs:root=General&path=ManagedConfigurationList",
    )
    trust_link = _deeplink_button(
        "Open Certificate Trust Settings",
        "prefs:root=General&path=About/CERT_TRUST_SETTINGS",
    )
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>mitm-tracker device setup</title>
<style>
  body {{ font-family: -apple-system, system-ui, sans-serif; margin: 0; padding: 1.5rem;
         color: #1d1d1f; background: #f5f5f7; line-height: 1.5; }}
  .card {{ max-width: 640px; margin: 0 auto; background: #fff; border-radius: 16px;
          padding: 1.5rem; box-shadow: 0 1px 4px rgba(0,0,0,.08); }}
  h1 {{ font-size: 1.4rem; margin: 0 0 .25rem; }}
  .lead {{ color: #6e6e73; margin: 0 0 1.5rem; }}
  .proxy {{ background: #f0f7ff; border: 1px solid #cfe4ff; border-radius: 12px;
           padding: 1rem; margin-bottom: 1.5rem; font-size: 1.05rem; }}
  .proxy code {{ font-size: 1.15rem; font-weight: 600; }}
  .download {{ display: block; text-align: center; background: #0071e3; color: #fff;
              text-decoration: none; padding: .9rem 1rem; border-radius: 12px;
              font-weight: 600; font-size: 1.1rem; margin: .5rem 0 .25rem; }}
  .download.secondary {{ background: #e8e8ed; color: #1d1d1f; font-weight: 500;
                        font-size: .95rem; }}
  ol {{ padding-left: 1.25rem; }}
  li {{ margin-bottom: .75rem; }}
  .step-title {{ font-weight: 600; }}
  .deeplink {{ display: inline-block; margin: .35rem .5rem .1rem 0; padding: .4rem .7rem;
              background: #e8e8ed; border-radius: 8px; text-decoration: none;
              color: #0071e3; font-size: .9rem; }}
  .deeplink-note {{ color: #a1a1a6; font-size: .8rem; }}
  .warn {{ background: #fff7e6; border: 1px solid #ffe0a3; border-radius: 12px;
          padding: .75rem 1rem; margin-top: 1.5rem; font-size: .9rem; color: #6e4b00; }}
</style>
</head>
<body>
<div class="card">
  <h1>Set up this device for mitm-tracker</h1>
  <p class="lead">Route this iPhone or iPad through the proxy and trust its certificate.</p>

  <div class="proxy">
    <div>Wi-Fi manual proxy:</div>
    <div>Server: <code>{ip}</code></div>
    <div>Port: <code>{port}</code></div>
  </div>

  <a class="download" href="{MOBILECONFIG_PATH}">Download certificate profile</a>
  <a class="download secondary" href="{PEM_PATH}">Download raw .pem instead</a>

  <h2>On-device steps</h2>
  <ol>
    <li>
      <span class="step-title">Point Wi-Fi at the proxy.</span><br>
      Settings &rarr; Wi-Fi &rarr; tap your network &rarr; Configure Proxy &rarr; Manual.
      Enter Server <code>{ip}</code> and Port <code>{port}</code>, then Save.<br>
      {wifi_link}
    </li>
    <li>
      <span class="step-title">Download &amp; install the profile.</span><br>
      Tap “Download certificate profile” above. iOS shows “Profile Downloaded”.
      Open Settings &rarr; General &rarr; VPN &amp; Device Management &rarr; tap the
      mitm-tracker CA profile &rarr; Install (enter passcode, tap Install twice).<br>
      {profiles_link}
    </li>
    <li>
      <span class="step-title">Enable full trust.</span><br>
      Settings &rarr; General &rarr; About &rarr; Certificate Trust Settings &rarr;
      turn ON full trust for the mitmproxy certificate. iOS does not do this
      automatically.<br>
      {trust_link}
    </li>
  </ol>

  <div class="warn">
    The “Open …” buttons are a best-effort shortcut. Apple restricts Settings
    deeplinks from Safari, so on iOS 17+ they may do nothing — follow the written
    steps in that case.
  </div>
</div>
</body>
</html>
"""


class _Handler(BaseHTTPRequestHandler):
    server_version = "mitm-tracker-device/1.0"

    def log_message(self, *args, **kwargs) -> None:  # noqa: D401
        return

    def _send(self, body: bytes, content_type: str, *, filename: str | None = None) -> None:
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        if filename:
            self.send_header(
                "Content-Disposition", f'attachment; filename="{filename}"'
            )
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        path = self.path.split("?", 1)[0]
        ctx = self.server.help_context
        ca_pem = self.server.ca_pem_path
        if path == PAGE_PATH:
            body = render_help_page(ctx).encode("utf-8")
            self._send(body, "text/html; charset=utf-8")
            return
        if path == MOBILECONFIG_PATH:
            try:
                body = device_profile.build_mobileconfig(ca_pem)
            except Exception:
                self.send_error(500, "could not build profile")
                return
            self._send(
                body,
                "application/x-apple-aspen-config",
                filename="mitm-tracker-ca.mobileconfig",
            )
            return
        if path == PEM_PATH:
            try:
                body = Path(ca_pem).read_bytes()
            except OSError:
                self.send_error(500, "could not read certificate")
                return
            self._send(body, "application/x-pem-file", filename="mitmproxy-ca-cert.pem")
            return
        self.send_error(404, "not found")


class DeviceHelpServer:
    def __init__(
        self,
        *,
        host: str,
        port: int,
        ca_pem_path: Path,
        help_context: HelpPageContext,
    ) -> None:
        self._httpd = ThreadingHTTPServer((host, port), _Handler)
        self._httpd.ca_pem_path = Path(ca_pem_path)
        self._httpd.help_context = help_context
        self._thread: threading.Thread | None = None

    @property
    def port(self) -> int:
        return self._httpd.server_address[1]

    def serve_forever(self) -> None:
        self._httpd.serve_forever()

    def start_background(self) -> None:
        self._thread = threading.Thread(target=self.serve_forever, daemon=True)
        self._thread.start()

    def shutdown(self) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()


def run_server(
    *,
    host: str,
    port: int,
    ca_pem_path: Path,
    proxy_ip: str,
    proxy_port: int,
    help_port: int,
) -> None:
    server = DeviceHelpServer(
        host=host,
        port=port,
        ca_pem_path=Path(ca_pem_path),
        help_context=HelpPageContext(
            proxy_ip=proxy_ip,
            proxy_port=proxy_port,
            help_ip=proxy_ip,
            help_port=help_port,
        ),
    )
    server.serve_forever()
