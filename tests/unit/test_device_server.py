from __future__ import annotations

import plistlib
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from mitm_tracker.device_server import DeviceHelpServer, HelpPageContext, render_help_page

_SAMPLE_PEM = """-----BEGIN CERTIFICATE-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtest
-----END CERTIFICATE-----
"""


def _ctx() -> HelpPageContext:
    return HelpPageContext(
        proxy_ip="192.168.0.10",
        proxy_port=8080,
        help_ip="192.168.0.10",
        help_port=8888,
    )


def test_render_help_page_includes_proxy_and_deeplinks():
    page = render_help_page(_ctx())
    assert "192.168.0.10" in page
    assert "8080" in page
    assert "prefs:root=WIFI" in page
    assert "Certificate Trust Settings" in page
    assert "may not work on iOS 17+" in page


def test_render_help_page_has_copy_buttons():
    page = render_help_page(_ctx())
    assert "copyValue('192.168.0.10'" in page
    assert "copyValue('8080'" in page
    assert "function copyValue" in page
    assert "function fallbackCopy" in page


@pytest.fixture
def running_server(tmp_path: Path):
    pem = tmp_path / "ca.pem"
    pem.write_text(_SAMPLE_PEM, encoding="ascii")
    server = DeviceHelpServer(
        host="127.0.0.1",
        port=0,
        ca_pem_path=pem,
        help_context=_ctx(),
    )
    server.start_background()
    try:
        yield server
    finally:
        server.shutdown()


_NO_PROXY_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def _get(server: DeviceHelpServer, path: str):
    url = f"http://127.0.0.1:{server.port}{path}"
    with _NO_PROXY_OPENER.open(url, timeout=5) as resp:
        return resp.status, resp.headers, resp.read()


def test_server_serves_help_page(running_server):
    status, headers, body = _get(running_server, "/")
    assert status == 200
    assert "text/html" in headers["Content-Type"]
    assert b"192.168.0.10" in body


def test_server_serves_mobileconfig(running_server):
    status, headers, body = _get(running_server, "/cert.mobileconfig")
    assert status == 200
    assert headers["Content-Type"] == "application/x-apple-aspen-config"
    assert "attachment" in headers["Content-Disposition"]
    parsed = plistlib.loads(body)
    assert parsed["PayloadType"] == "Configuration"


def test_server_serves_pem(running_server):
    status, headers, body = _get(running_server, "/cert.pem")
    assert status == 200
    assert b"BEGIN CERTIFICATE" in body


def test_server_404_for_unknown(running_server):
    with pytest.raises(urllib.error.HTTPError) as exc:
        _get(running_server, "/nope")
    assert exc.value.code == 404


_SAMPLE_WG_CONF = (
    "[Interface]\nPrivateKey = EqlHpkKEjf51H2nS07vCHHB745sKChzhbDjYUB2MZxk=\n"
    "Address = 10.0.0.1/32\nDNS = 10.0.0.53\n\n[Peer]\n"
    "PublicKey = ivpxOgQJtzt9gekasQ7ZHh6UrVhPadzjoLJfF+91/ws=\n"
    "AllowedIPs = 0.0.0.0/0\nEndpoint = 192.168.0.10:51820\n"
)


def _wg_ctx() -> HelpPageContext:
    return HelpPageContext(
        proxy_ip="192.168.0.10",
        proxy_port=51820,
        help_ip="192.168.0.10",
        help_port=8888,
        mode="wireguard",
        wireguard_conf=_SAMPLE_WG_CONF,
    )


def test_render_wireguard_mode_has_both_tabs_and_qr():
    page = render_help_page(_wg_ctx())
    assert 'data-tab="wireguard"' in page
    assert 'data-tab="wifi"' in page
    assert "<svg" in page  # QR rendered
    assert "apps.apple.com" in page  # App Store link
    assert "FULL TRUST" in page


def test_render_wifi_only_mode_has_no_wireguard_tab():
    page = render_help_page(_ctx())
    assert 'data-tab="wireguard"' not in page
    assert 'data-tab="wifi"' in page
    assert "<svg" not in page


@pytest.fixture
def wireguard_server(tmp_path: Path):
    pem = tmp_path / "ca.pem"
    pem.write_text(_SAMPLE_PEM, encoding="ascii")
    server = DeviceHelpServer(
        host="127.0.0.1",
        port=0,
        ca_pem_path=pem,
        help_context=_wg_ctx(),
    )
    server.start_background()
    try:
        yield server
    finally:
        server.shutdown()


def test_server_serves_wireguard_conf(wireguard_server):
    status, headers, body = _get(wireguard_server, "/mitm-tracker.conf")
    assert status == 200
    assert "attachment" in headers["Content-Disposition"]
    assert b"[Interface]" in body
    assert b"[Peer]" in body


def test_server_wireguard_conf_404_in_wifi_mode(running_server):
    with pytest.raises(urllib.error.HTTPError) as exc:
        _get(running_server, "/mitm-tracker.conf")
    assert exc.value.code == 404
