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


def _wireguard_tab(ctx: HelpPageContext) -> str:
    qr = device_wireguard.qr_svg(ctx.wireguard_conf)
    store_url = html.escape(device_wireguard.WIREGUARD_APP_STORE_URL, quote=True)
    return f"""
      <section class="tab-panel" data-panel="wireguard">
        <p class="lead">Routes <strong>all</strong> traffic from this device through
        mitm-tracker, including native apps and QUIC that ignore a Wi-Fi proxy.</p>
        <ol>
          <li>
            <span class="step-title">Install the WireGuard app.</span><br>
            <a class="btn" href="{store_url}">Get WireGuard on the App Store</a>
          </li>
          <li>
            <span class="step-title">Add a tunnel from this QR.</span><br>
            In WireGuard: <em>Add a tunnel &rarr; Create from QR code</em>, then scan:
            <div class="qr">{qr}</div>
            <a class="link" href="{WIREGUARD_CONF_PATH}">or download the .conf and import it</a>
          </li>
          <li>
            <span class="step-title">Turn the tunnel on</span> and allow the VPN prompt.
            Look for the VPN icon in the status bar.
          </li>
        </ol>
      </section>
"""


def _wifi_tab(ctx: HelpPageContext) -> str:
    ip = html.escape(ctx.proxy_ip)
    port = ctx.proxy_port
    wifi_link = _deeplink_button("Open Wi-Fi settings", "prefs:root=WIFI")
    return f"""
      <section class="tab-panel" data-panel="wifi">
        <p class="lead">Simpler, but only Safari and apps that honour the Wi-Fi proxy
        are captured — many native apps and QUIC traffic are not.</p>
        <div class="proxy">
          <div class="field">
            <span class="label">Server</span>
            <code>{ip}</code>
            <button class="copy" onclick="copyValue('{ip}', this)">Copy</button>
          </div>
          <div class="field">
            <span class="label">Port</span>
            <code>{port}</code>
            <button class="copy" onclick="copyValue('{port}', this)">Copy</button>
          </div>
        </div>
        <ol>
          <li>
            <span class="step-title">Set a manual proxy.</span><br>
            Settings &rarr; Wi-Fi &rarr; tap your network &rarr; Configure Proxy &rarr;
            Manual. Enter the Server and Port above, then Save.<br>
            {wifi_link}
          </li>
        </ol>
      </section>
"""


def render_help_page(ctx: HelpPageContext) -> str:
    has_wireguard = ctx.mode == "wireguard" and bool(ctx.wireguard_conf)
    profiles_link = _deeplink_button(
        "Open VPN & Device Management",
        "prefs:root=General&path=ManagedConfigurationList",
    )
    trust_link = _deeplink_button(
        "Open Certificate Trust Settings",
        "prefs:root=General&path=About/CERT_TRUST_SETTINGS",
    )

    tabs = []
    panels = []
    if has_wireguard:
        tabs.append('<button class="tab active" data-tab="wireguard">WireGuard — every app</button>')
        tabs.append('<button class="tab" data-tab="wifi">Wi-Fi proxy — Safari only</button>')
        panels.append(_wireguard_tab(ctx))
        panels.append(_wifi_tab(ctx))
    else:
        tabs.append('<button class="tab active" data-tab="wifi">Wi-Fi proxy</button>')
        panels.append(_wifi_tab(ctx))

    tabs_html = "".join(tabs)
    panels_html = "".join(panels)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>mitm-tracker device setup</title>
<style>
  body {{ font-family: -apple-system, system-ui, sans-serif; margin: 0; padding: 1.5rem;
         color: #1d1d1f; background: #f5f5f7; line-height: 1.5; }}
  .card {{ max-width: 640px; margin: 0 auto 1rem; background: #fff; border-radius: 16px;
          padding: 1.5rem; box-shadow: 0 1px 4px rgba(0,0,0,.08); }}
  h1 {{ font-size: 1.4rem; margin: 0 0 .25rem; }}
  .step-label {{ text-transform: uppercase; letter-spacing: .04em; font-size: .75rem;
                color: #0071e3; font-weight: 700; margin: 0 0 .25rem; }}
  h2 {{ font-size: 1.2rem; margin: .1rem 0 .75rem; }}
  .lead {{ color: #6e6e73; margin: 0 0 1rem; }}
  .tabs {{ display: flex; gap: .4rem; background: #f0f0f2; border-radius: 12px;
          padding: .3rem; margin-bottom: 1rem; }}
  .tab {{ flex: 1; border: none; background: transparent; border-radius: 9px;
         padding: .55rem .5rem; font-size: .9rem; font-weight: 600; color: #6e6e73;
         cursor: pointer; }}
  .tab.active {{ background: #fff; color: #1d1d1f; box-shadow: 0 1px 3px rgba(0,0,0,.12); }}
  .tab-panel {{ display: none; }}
  .tab-panel.active {{ display: block; }}
  .proxy {{ background: #f0f7ff; border: 1px solid #cfe4ff; border-radius: 12px;
           padding: 1rem; margin-bottom: 1rem; font-size: 1.05rem; }}
  .field {{ display: flex; align-items: center; gap: .6rem; }}
  .field + .field {{ margin-top: .4rem; }}
  .field .label {{ min-width: 4.5rem; color: #6e6e73; }}
  .field code {{ font-size: 1.15rem; font-weight: 600; }}
  .copy {{ margin-left: auto; border: 1px solid #cfe4ff; background: #fff; color: #0071e3;
          border-radius: 8px; padding: .3rem .7rem; font-size: .85rem; cursor: pointer; }}
  .copy:active {{ background: #e8e8ed; }}
  ol {{ padding-left: 1.25rem; margin: .5rem 0 0; }}
  li {{ margin-bottom: .75rem; }}
  .step-title {{ font-weight: 600; }}
  .btn {{ display: inline-block; margin-top: .35rem; padding: .5rem .9rem;
         background: #0071e3; color: #fff; border-radius: 9px; text-decoration: none;
         font-weight: 600; font-size: .9rem; }}
  .link {{ color: #0071e3; }}
  .deeplink {{ display: inline-block; margin: .35rem .5rem .1rem 0; padding: .4rem .7rem;
              background: #e8e8ed; border-radius: 8px; text-decoration: none;
              color: #0071e3; font-size: .9rem; }}
  .deeplink-note {{ color: #a1a1a6; font-size: .8rem; }}
  .qr {{ text-align: center; margin: .75rem 0; }}
  .qr svg {{ width: 300px; height: 300px; max-width: 92%; image-rendering: pixelated;
            background: #fff; padding: 8px; border-radius: 8px; }}
  .download {{ display: block; text-align: center; background: #0071e3; color: #fff;
              text-decoration: none; padding: .8rem 1rem; border-radius: 12px;
              font-weight: 600; font-size: 1.05rem; margin: .5rem 0 .25rem; }}
  .download.secondary {{ background: #e8e8ed; color: #1d1d1f; font-weight: 500;
                        font-size: .9rem; }}
  .critical {{ background: #fff7e6; border: 1px solid #ffe0a3; border-radius: 10px;
              padding: .75rem .9rem; margin-top: 1rem; color: #6e4b00; }}
  .critical .step-title {{ color: #6e4b00; }}
</style>
</head>
<body>
<div class="card">
  <h1>Set up this device</h1>
  <p class="lead">Two steps: connect this device to mitm-tracker, then trust its
  certificate. Pick how to connect:</p>

  <p class="step-label">Step 1 — Connect</p>
  <div class="tabs">{tabs_html}</div>
  {panels_html}
</div>

<div class="card">
  <p class="step-label">Step 2 — Trust the certificate</p>
  <h2>Required for HTTPS decryption</h2>
  <a class="download" href="{MOBILECONFIG_PATH}">Download certificate profile</a>
  <a class="download secondary" href="{PEM_PATH}">Download raw .pem instead</a>
  <ol>
    <li>
      <span class="step-title">Install the profile.</span><br>
      After downloading, open Settings &rarr; General &rarr; VPN &amp; Device
      Management &rarr; tap the <strong>mitm-tracker CA</strong> &rarr; Install
      (passcode, Install twice).<br>
      {profiles_link}
    </li>
    <li class="critical">
      <span class="step-title">⚠️ Enable FULL TRUST — the step everyone misses.</span><br>
      Settings &rarr; General &rarr; About &rarr; <strong>Certificate Trust
      Settings</strong> &rarr; turn ON the toggle for <strong>mitmproxy</strong>.
      Without it, every HTTPS request fails the TLS handshake and apps show
      connection errors — the proxy is working, the device just doesn't trust it yet.<br>
      {trust_link}
    </li>
  </ol>
  <p class="deeplink-note">The “Open …” buttons are best-effort. Apple blocks Settings
  deeplinks from Safari on iOS 17+, so they may do nothing — use the written steps.</p>
</div>
<script>
  document.querySelectorAll(".tab").forEach(function (tab) {{
    tab.addEventListener("click", function () {{
      var name = tab.getAttribute("data-tab");
      document.querySelectorAll(".tab").forEach(function (t) {{
        t.classList.toggle("active", t === tab);
      }});
      document.querySelectorAll(".tab-panel").forEach(function (p) {{
        p.classList.toggle("active", p.getAttribute("data-panel") === name);
      }});
    }});
  }});
  var first = document.querySelector(".tab-panel");
  if (first) first.classList.add("active");

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
