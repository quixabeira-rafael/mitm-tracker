from __future__ import annotations

import base64
import hashlib
import re
from pathlib import Path

PROFILE_DISPLAY_NAME = "mitm-tracker CA"
PROFILE_DESCRIPTION = (
    "Installs the mitmproxy root certificate so this device can be "
    "intercepted by mitm-tracker for HTTPS debugging."
)
PROFILE_IDENTIFIER = "com.mitm-tracker.ca"
PAYLOAD_IDENTIFIER = "com.mitm-tracker.ca.cert"


class DeviceProfileError(RuntimeError):
    pass


def _pem_to_der(pem: str) -> bytes:
    body = re.sub(
        r"-----BEGIN [A-Z ]+-----|-----END [A-Z ]+-----|\s+",
        "",
        pem,
        flags=re.MULTILINE,
    )
    if not body:
        raise DeviceProfileError("empty or malformed PEM")
    return base64.b64decode(body)


def _stable_uuid(seed: str) -> str:
    digest = hashlib.sha1(seed.encode("utf-8")).hexdigest().upper()
    return (
        f"{digest[0:8]}-{digest[8:12]}-{digest[12:16]}-"
        f"{digest[16:20]}-{digest[20:32]}"
    )


def build_mobileconfig(ca_pem_path: Path) -> bytes:
    pem = Path(ca_pem_path).read_text(encoding="ascii", errors="replace")
    der = _pem_to_der(pem)
    cert_b64 = base64.b64encode(der).decode("ascii")
    wrapped = "\n".join(
        cert_b64[i : i + 60] for i in range(0, len(cert_b64), 60)
    )

    payload_uuid = _stable_uuid(f"payload:{cert_b64}")
    profile_uuid = _stable_uuid(f"profile:{cert_b64}")

    document = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" '
        '"http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n'
        '<plist version="1.0">\n'
        "<dict>\n"
        "    <key>PayloadContent</key>\n"
        "    <array>\n"
        "        <dict>\n"
        "            <key>PayloadCertificateFileName</key>\n"
        "            <string>mitmproxy-ca-cert.pem</string>\n"
        "            <key>PayloadContent</key>\n"
        "            <data>\n"
        f"{wrapped}\n"
        "            </data>\n"
        "            <key>PayloadDescription</key>\n"
        "            <string>Adds the mitmproxy root certificate.</string>\n"
        "            <key>PayloadDisplayName</key>\n"
        f"            <string>{PROFILE_DISPLAY_NAME}</string>\n"
        "            <key>PayloadIdentifier</key>\n"
        f"            <string>{PAYLOAD_IDENTIFIER}</string>\n"
        "            <key>PayloadType</key>\n"
        "            <string>com.apple.security.root</string>\n"
        "            <key>PayloadUUID</key>\n"
        f"            <string>{payload_uuid}</string>\n"
        "            <key>PayloadVersion</key>\n"
        "            <integer>1</integer>\n"
        "        </dict>\n"
        "    </array>\n"
        "    <key>PayloadDescription</key>\n"
        f"    <string>{PROFILE_DESCRIPTION}</string>\n"
        "    <key>PayloadDisplayName</key>\n"
        f"    <string>{PROFILE_DISPLAY_NAME}</string>\n"
        "    <key>PayloadIdentifier</key>\n"
        f"    <string>{PROFILE_IDENTIFIER}</string>\n"
        "    <key>PayloadType</key>\n"
        "    <string>Configuration</string>\n"
        "    <key>PayloadUUID</key>\n"
        f"    <string>{profile_uuid}</string>\n"
        "    <key>PayloadVersion</key>\n"
        "    <integer>1</integer>\n"
        "</dict>\n"
        "</plist>\n"
    )
    return document.encode("utf-8")
