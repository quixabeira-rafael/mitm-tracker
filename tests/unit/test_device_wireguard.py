from __future__ import annotations

import json
from pathlib import Path

import pytest

from mitm_tracker import device_wireguard as wg
from mitm_tracker.device_wireguard import WireGuardError

# Known mitmproxy keyfile and the server public key it derives to
# (captured from a real `mitmdump --mode wireguard` run).
_SERVER_KEY = "dbguPjorHQtG+lUXvLRxC7HWI63M0x8CyYjeO+E2HDs="
_CLIENT_KEY = "EqlHpkKEjf51H2nS07vCHHB745sKChzhbDjYUB2MZxk="
_EXPECTED_SERVER_PUB = "ivpxOgQJtzt9gekasQ7ZHh6UrVhPadzjoLJfF+91/ws="


def _write_keyfile(tmp_path: Path) -> Path:
    kf = tmp_path / "wireguard.conf"
    kf.write_text(
        json.dumps({"server_key": _SERVER_KEY, "client_key": _CLIENT_KEY}),
        encoding="ascii",
    )
    return kf


def test_ensure_keyfile_creates_valid_keys(tmp_path: Path):
    kf = tmp_path / "runtime" / "wireguard.conf"
    wg.ensure_keyfile(kf)
    assert kf.exists()
    data = json.loads(kf.read_text())
    assert "server_key" in data and "client_key" in data
    # keys are valid base64 X25519 (32 bytes)
    import base64

    assert len(base64.b64decode(data["server_key"])) == 32
    assert len(base64.b64decode(data["client_key"])) == 32


def test_ensure_keyfile_is_idempotent(tmp_path: Path):
    kf = tmp_path / "wireguard.conf"
    wg.ensure_keyfile(kf)
    first = kf.read_text()
    wg.ensure_keyfile(kf)
    assert kf.read_text() == first


def test_client_config_derives_server_public_key(tmp_path: Path):
    kf = _write_keyfile(tmp_path)
    cfg = wg.client_config(kf, endpoint_host="192.168.1.44", endpoint_port=51820)
    assert cfg.server_public_key == _EXPECTED_SERVER_PUB
    assert cfg.client_private_key == _CLIENT_KEY


def test_client_config_conf_format(tmp_path: Path):
    kf = _write_keyfile(tmp_path)
    conf = wg.client_config(kf, endpoint_host="10.1.2.3", endpoint_port=51820).to_conf()
    assert "[Interface]" in conf
    assert f"PrivateKey = {_CLIENT_KEY}" in conf
    assert "Address = 10.0.0.1/32" in conf
    assert "DNS = 10.0.0.53" in conf
    assert "[Peer]" in conf
    assert f"PublicKey = {_EXPECTED_SERVER_PUB}" in conf
    assert "AllowedIPs = 0.0.0.0/0" in conf
    assert "Endpoint = 10.1.2.3:51820" in conf


def test_client_config_rejects_malformed_keyfile(tmp_path: Path):
    kf = tmp_path / "bad.conf"
    kf.write_text(json.dumps({"server_key": ""}), encoding="ascii")
    with pytest.raises(WireGuardError):
        wg.client_config(kf, endpoint_host="x", endpoint_port=1)


def test_qr_svg_renders(tmp_path: Path):
    kf = _write_keyfile(tmp_path)
    conf = wg.client_config(kf, endpoint_host="192.168.1.44", endpoint_port=51820).to_conf()
    svg = wg.qr_svg(conf)
    assert "<svg" in svg
