from __future__ import annotations

import hashlib
import re
import sqlite3
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

from mitm_tracker.simulators import Simulator

DEFAULT_CA_PATH = Path.home() / ".mitmproxy" / "mitmproxy-ca-cert.pem"


class CertManagerError(RuntimeError):
    pass


@dataclass(frozen=True)
class InstallResult:
    udid: str
    name: str
    installed: bool
    skipped_reason: str | None = None
    stdout: str = ""
    stderr: str = ""

    def to_dict(self) -> dict:
        return {
            "udid": self.udid,
            "name": self.name,
            "installed": self.installed,
            "skipped_reason": self.skipped_reason,
        }


def ca_path(custom: Path | None = None) -> Path:
    return Path(custom) if custom else DEFAULT_CA_PATH


def ensure_ca_exists(path: Path | None = None, *, runner=None) -> Path:
    target = ca_path(path)
    if target.exists():
        return target
    runner = runner or _default_runner
    runner(
        [
            "mitmdump",
            "--listen-host",
            "127.0.0.1",
            "--listen-port",
            "0",
            "-q",
            "--no-server",
        ]
    )
    if not target.exists():
        raise CertManagerError(
            f"mitmproxy CA not generated at {target}; please run mitmdump once manually"
        )
    return target


def fingerprint(pem_path: Path, *, algorithm: str = "sha1") -> bytes:
    pem = pem_path.read_text(encoding="ascii", errors="replace")
    der = _pem_to_der(pem)
    return hashlib.new(algorithm, der).digest()


def is_installed(simulator: Simulator, *, ca_pem: Path | None = None) -> bool:
    pem_path = ca_path(ca_pem)
    if not pem_path.exists():
        return False
    for truststore in _trust_store_paths(simulator):
        if not truststore.exists():
            continue
        if _truststore_contains_ca(truststore, pem_path):
            return True
    return False


def _truststore_contains_ca(truststore: Path, pem_path: Path) -> bool:
    try:
        conn = sqlite3.connect(f"file:{truststore}?mode=ro", uri=True)
    except sqlite3.OperationalError:
        return False
    try:
        columns = {
            row[1]
            for row in conn.execute("PRAGMA table_info(tsettings)").fetchall()
        }
        if not columns:
            return False
        column, algorithm = _select_fingerprint_column(columns)
        if column is None:
            return False
        try:
            digest = fingerprint(pem_path, algorithm=algorithm)
        except Exception:
            return False
        try:
            rows = conn.execute(f"SELECT {column} FROM tsettings").fetchall()
        except sqlite3.OperationalError:
            return False
        for (stored,) in rows:
            if _digest_matches(stored, digest):
                return True
        return False
    finally:
        conn.close()


def _select_fingerprint_column(columns: set[str]) -> tuple[str | None, str]:
    if "sha256" in columns:
        return "sha256", "sha256"
    if "sha1" in columns:
        return "sha1", "sha1"
    return None, "sha1"


def _digest_matches(stored, expected: bytes) -> bool:
    if stored is None:
        return False
    if isinstance(stored, str):
        try:
            stored = bytes.fromhex(stored)
        except ValueError:
            stored = stored.encode("latin-1")
    return isinstance(stored, bytes) and stored == expected


def install(simulator: Simulator, *, ca_pem: Path | None = None, runner=None) -> InstallResult:
    pem = ensure_ca_exists(ca_pem, runner=runner)
    if not simulator.is_booted:
        return InstallResult(
            udid=simulator.udid,
            name=simulator.name,
            installed=False,
            skipped_reason="not_booted",
        )
    if is_installed(simulator, ca_pem=pem):
        return InstallResult(
            udid=simulator.udid,
            name=simulator.name,
            installed=True,
            skipped_reason="already_installed",
        )
    runner = runner or _default_runner
    proc = runner(
        ["xcrun", "simctl", "keychain", simulator.udid, "add-root-cert", str(pem)]
    )
    if proc.returncode != 0:
        raise CertManagerError(
            f"simctl add-root-cert failed (exit {proc.returncode}): "
            f"{proc.stderr.strip() or proc.stdout.strip()}"
        )
    return InstallResult(
        udid=simulator.udid,
        name=simulator.name,
        installed=True,
        stdout=proc.stdout,
        stderr=proc.stderr,
    )


def _trust_store_paths(simulator: Simulator) -> list[Path]:
    base = (
        Path.home()
        / "Library"
        / "Developer"
        / "CoreSimulator"
        / "Devices"
        / simulator.udid
        / "data"
    )
    return [
        base / "private" / "var" / "protected" / "trustd" / "private" / "TrustStore.sqlite3",
        base / "Library" / "Keychains" / "TrustStore.sqlite3",
    ]


def _trust_store_path(simulator: Simulator) -> Path:
    return _trust_store_paths(simulator)[-1]


def _pem_to_der(pem: str) -> bytes:
    body = re.sub(
        r"-----BEGIN [A-Z ]+-----|-----END [A-Z ]+-----|\s+",
        "",
        pem,
        flags=re.MULTILINE,
    )
    if not body:
        raise CertManagerError("empty or malformed PEM")
    import base64

    return base64.b64decode(body)


def _default_runner(args: Sequence[str]) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(
            list(args),
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
    except FileNotFoundError as exc:
        raise CertManagerError(f"command not found: {args[0]}") from exc
    except subprocess.TimeoutExpired as exc:
        raise CertManagerError(f"command timed out: {' '.join(args)}") from exc
