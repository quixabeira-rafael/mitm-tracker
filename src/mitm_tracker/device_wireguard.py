from __future__ import annotations

import base64
import io
import json
from dataclasses import dataclass
from pathlib import Path

CLIENT_ADDRESS = "10.0.0.1/32"
CLIENT_DNS = "10.0.0.53"
ALLOWED_IPS = "0.0.0.0/0"

WIREGUARD_APP_STORE_URL = "https://apps.apple.com/app/wireguard/id1441195209"


class WireGuardError(RuntimeError):
    pass


@dataclass(frozen=True)
class WireGuardConfig:
    client_private_key: str
    server_public_key: str
    endpoint_host: str
    endpoint_port: int

    def to_conf(self) -> str:
        return (
            "[Interface]\n"
            f"PrivateKey = {self.client_private_key}\n"
            f"Address = {CLIENT_ADDRESS}\n"
            f"DNS = {CLIENT_DNS}\n"
            "\n"
            "[Peer]\n"
            f"PublicKey = {self.server_public_key}\n"
            f"AllowedIPs = {ALLOWED_IPS}\n"
            f"Endpoint = {self.endpoint_host}:{self.endpoint_port}\n"
        )


def ensure_keyfile(path: Path) -> Path:
    path = Path(path)
    if path.exists():
        return path
    path.parent.mkdir(parents=True, exist_ok=True)
    server_key = _generate_private_key()
    client_key = _generate_private_key()
    path.write_text(
        json.dumps({"server_key": server_key, "client_key": client_key}, indent=4),
        encoding="utf-8",
    )
    return path


def client_config(keyfile: Path, *, endpoint_host: str, endpoint_port: int) -> WireGuardConfig:
    data = json.loads(Path(keyfile).read_text(encoding="utf-8"))
    server_key = data.get("server_key")
    client_key = data.get("client_key")
    if not server_key or not client_key:
        raise WireGuardError(f"malformed WireGuard keyfile at {keyfile}")
    return WireGuardConfig(
        client_private_key=client_key,
        server_public_key=_public_key_from_private(server_key),
        endpoint_host=endpoint_host,
        endpoint_port=endpoint_port,
    )


def qr_svg(conf_text: str) -> str:
    import segno

    qr = segno.make(conf_text, error="m")
    buffer = io.BytesIO()
    qr.save(buffer, kind="svg", scale=5, border=2, dark="#1d1d1f", light="#ffffff")
    return buffer.getvalue().decode("utf-8")


def _generate_private_key() -> str:
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives import serialization

    raw = X25519PrivateKey.generate().private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    return base64.b64encode(raw).decode("ascii")


def _public_key_from_private(private_b64: str) -> str:
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives import serialization

    raw = base64.b64decode(private_b64)
    private = X25519PrivateKey.from_private_bytes(raw)
    public = private.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    return base64.b64encode(public).decode("ascii")
