from __future__ import annotations

import base64
import plistlib
from pathlib import Path

import pytest

from mitm_tracker import device_profile
from mitm_tracker.device_profile import DeviceProfileError

_SAMPLE_PEM = """-----BEGIN CERTIFICATE-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtest
-----END CERTIFICATE-----
"""


def _write_pem(tmp_path: Path) -> Path:
    pem = tmp_path / "ca.pem"
    pem.write_text(_SAMPLE_PEM, encoding="ascii")
    return pem


def test_build_mobileconfig_is_valid_plist(tmp_path: Path):
    pem = _write_pem(tmp_path)
    data = device_profile.build_mobileconfig(pem)
    parsed = plistlib.loads(data)
    assert parsed["PayloadType"] == "Configuration"
    assert parsed["PayloadIdentifier"] == device_profile.PROFILE_IDENTIFIER
    payload = parsed["PayloadContent"][0]
    assert payload["PayloadType"] == "com.apple.security.root"


def test_build_mobileconfig_embeds_certificate_der(tmp_path: Path):
    pem = _write_pem(tmp_path)
    data = device_profile.build_mobileconfig(pem)
    parsed = plistlib.loads(data)
    embedded = parsed["PayloadContent"][0]["PayloadContent"]
    expected_der = device_profile._pem_to_der(_SAMPLE_PEM)
    assert bytes(embedded) == expected_der


def test_build_mobileconfig_is_deterministic(tmp_path: Path):
    pem = _write_pem(tmp_path)
    first = device_profile.build_mobileconfig(pem)
    second = device_profile.build_mobileconfig(pem)
    assert first == second


def test_build_mobileconfig_rejects_empty_pem(tmp_path: Path):
    pem = tmp_path / "empty.pem"
    pem.write_text("-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n", encoding="ascii")
    with pytest.raises(DeviceProfileError):
        device_profile.build_mobileconfig(pem)
