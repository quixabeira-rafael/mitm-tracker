from __future__ import annotations

import html
import threading
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from mitm_tracker import device_profile, device_wireguard

PAGE_PATH = "/"
MOBILECONFIG_PATH = "/cert.mobileconfig"
PEM_PATH = "/cert.pem"
WIREGUARD_CONF_PATH = "/mitm-tracker.conf"


@dataclass(frozen=True)
class HelpPageContext:
    proxy_ip: str
    proxy_port: int
    help_ip: str
    help_port: int
    mode: str = "regular"
    wireguard_conf: str | None = None


def _deeplink_button(label: str, url: str) -> str:
    safe_url = html.escape(url, quote=True)
    safe_label = html.escape(label)
    return (
        f'<a class="deeplink" href="{safe_url}">{safe_label}</a>'
        '<span class="deeplink-note">may not work on iOS 17+</span>'
    )


def _wireguard_section(ctx: HelpPageContext) -> str:
    if ctx.mode != "wireguard" or not ctx.wireguard_conf:
        return ""
    qr = device_wireguard.qr_svg(ctx.wireguard_conf)
    store_url = html.escape(device_wireguard.WIREGUARD_APP_STORE_URL, quote=True)
    return f"""
  <div class="wg">
    <h2>Capture every app (WireGuard)</h2>
    <p class="lead">This routes <strong>all</strong> traffic from this device through
    mitm-tracker — including native apps that ignore a Wi-Fi proxy. Recommended.</p>
    <ol>
      <li>
        <span class="step-title">Install the WireGuard app.</span><br>
        <a class="deeplink" href="{store_url}">Get WireGuard on the App Store</a>
      </li>
      <li>
        <span class="step-title">Add a tunnel from this QR code.</span><br>
        In WireGuard: <em>Add a tunnel &rarr; Create from QR code</em>, then scan:
        <div class="qr">{qr}</div>
        Or <a href="{WIREGUARD_CONF_PATH}">download the .conf file</a> and import it.
      </li>
      <li>
        <span class="step-title">Turn the tunnel on</span> and allow the VPN prompt.
        You should see the VPN icon in the status bar.
      </li>
      <li>
        <span class="step-title">Install the certificate.</span><br>
        <a class="dl-inline" href="{MOBILECONFIG_PATH}">Download certificate profile</a>,
        then Settings &rarr; General &rarr; VPN &amp; Device Management &rarr; tap the
        mitm-tracker CA &rarr; Install.
      </li>
      <li class="critical">
        <span class="step-title">⚠️ Enable FULL TRUST — this is the step everyone misses.</span><br>
        Settings &rarr; General &rarr; About &rarr; <strong>Certificate Trust Settings</strong>
        &rarr; turn ON the toggle for <strong>mitmproxy</strong>.<br>
        Without this, every HTTPS request fails the TLS handshake and apps show
        connection errors — the proxy is working, the device just doesn't trust it yet.
      </li>
    </ol>
  </div>
"""


def render_help_page(ctx: HelpPageContext) -> str:
    ip = html.escape(ctx.proxy_ip)
    port = ctx.proxy_port
    wireguard_section = _wireguard_section(ctx)
    wifi_section_title = (
        "Alternative: Wi-Fi proxy (Safari &amp; proxy-aware apps only)"
        if ctx.mode == "wireguard"
        else "On-device steps"
    )
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
  .field {{ display: flex; align-items: center; gap: .6rem; margin-top: .4rem; }}
  .field .label {{ min-width: 4.5rem; color: #6e6e73; }}
  .copy {{ margin-left: auto; border: 1px solid #cfe4ff; background: #fff; color: #0071e3;
          border-radius: 8px; padding: .3rem .7rem; font-size: .85rem; cursor: pointer; }}
  .copy:active {{ background: #e8e8ed; }}
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
  .wg {{ background: #f0fff4; border: 1px solid #b7e4c7; border-radius: 12px;
        padding: 1rem 1.25rem; margin-bottom: 1.5rem; }}
  .wg h2 {{ margin-top: 0; }}
  .qr {{ text-align: center; margin: .75rem 0; }}
  .qr svg {{ width: 220px; height: 220px; max-width: 100%; }}
  .critical {{ background: #fff7e6; border: 1px solid #ffe0a3; border-radius: 10px;
              padding: .6rem .8rem; list-style-position: inside; }}
  .dl-inline {{ color: #0071e3; text-decoration: underline; }}
</style>
</head>
<body>
<div class="card">
  <h1>Set up this device for mitm-tracker</h1>
  <p class="lead">Route this iPhone or iPad through the proxy and trust its certificate.</p>
{wireguard_section}
  <a class="download" href="{MOBILECONFIG_PATH}">Download certificate profile</a>
  <a class="download secondary" href="{PEM_PATH}">Download raw .pem instead</a>

  <h2>{wifi_section_title}</h2>

  <div class="proxy">
    <div>Wi-Fi manual proxy:</div>
    <div class="field">
      <span class="label">Server</span>
      <code id="proxy-ip">{ip}</code>
      <button class="copy" onclick="copyValue('{ip}', this)">Copy</button>
    </div>
    <div class="field">
      <span class="label">Port</span>
      <code id="proxy-port">{port}</code>
      <button class="copy" onclick="copyValue('{port}', this)">Copy</button>
    </div>
  </div>

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
<script>
  function copyValue(value, button) {{
    var done = function () {{
      var original = button.textContent;
      button.textContent = "Copied!";
      setTimeout(function () {{ button.textContent = original; }}, 1200);
    }};
    if (navigator.clipboard && navigator.clipboard.writeText) {{
      navigator.clipboard.writeText(value).then(done, function () {{ fallbackCopy(value, done); }});
    }} else {{
      fallbackCopy(value, done);
    }}
  }}
  function fallbackCopy(value, done) {{
    var area = document.createElement("textarea");
    area.value = value;
    area.style.position = "fixed";
    area.style.opacity = "0";
    document.body.appendChild(area);
    area.focus();
    area.select();
    try {{ document.execCommand("copy"); done(); }} catch (e) {{}}
    document.body.removeChild(area);
  }}
</script>
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
        if path == WIREGUARD_CONF_PATH:
            if not ctx.wireguard_conf:
                self.send_error(404, "not in WireGuard mode")
                return
            self._send(
                ctx.wireguard_conf.encode("utf-8"),
                "text/plain; charset=utf-8",
                filename="mitm-tracker.conf",
            )
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
    mode: str = "regular",
    wireguard_conf: str | None = None,
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
            mode=mode,
            wireguard_conf=wireguard_conf,
        ),
    )
    server.serve_forever()
