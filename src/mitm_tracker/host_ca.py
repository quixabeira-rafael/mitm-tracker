from __future__ import annotations

import json
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable

from mitm_tracker import cert_manager

SYSTEM_KEYCHAIN = "/Library/Keychains/System.keychain"
SECURITY_BIN = "/usr/bin/security"
OPENSSL_BIN = "openssl"
INSTALLED_LOG = Path.home() / ".mitmproxy" / "host_installed_shas.json"
STALE_PEM_TMPDIR = Path.home() / ".mitm-tracker-host-tmp"
MITMPROXY_CN_SUBSTRING = "mitmproxy"

Runner = Callable[[list[str]], subprocess.CompletedProcess]
PrivilegedRunner = Callable[[list[list[str]], str], subprocess.CompletedProcess]


RECOVERY_SNIPPET = (
    "sudo /usr/bin/security find-certificate -Z -a -c \"mitmproxy\" "
    "/Library/Keychains/System.keychain \\\n"
    "  | awk '/SHA-1 hash:/ {print $3}' \\\n"
    "  | while read sha; do\n"
    "      sudo /usr/bin/security find-certificate -Z \"$sha\" -p "
    "/Library/Keychains/System.keychain > /tmp/_m.pem\n"
    "      sudo /usr/bin/security remove-trusted-cert -d /tmp/_m.pem\n"
    "      sudo /usr/bin/security delete-certificate -Z \"$sha\" "
    "/Library/Keychains/System.keychain\n"
    "    done\n"
    "rm -f /tmp/_m.pem"
)


class HostCaError(RuntimeError):
    pass


def _default_runner(args: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(args, capture_output=True, text=True, check=False, timeout=30)


# --- Hash helpers -------------------------------------------------------------


def _sha_to_hex(digest: bytes) -> str:
    return digest.hex().upper()


def _hex_with_colons(hex_no_colons: str) -> str:
    return ":".join(hex_no_colons[i : i + 2] for i in range(0, len(hex_no_colons), 2))


def current_ca_sha1(ca_path: Path) -> tuple[str, str]:
    digest = cert_manager.fingerprint(ca_path, algorithm="sha1")
    no_colons = _sha_to_hex(digest)
    return no_colons, _hex_with_colons(no_colons)


# --- Validation ---------------------------------------------------------------


def validate_pem_is_root_ca(
    ca_path: Path, *, runner: Runner | None = None
) -> tuple[bool, str | None]:
    if not ca_path.exists():
        return False, f"PEM not found at {ca_path}"
    runner = runner or _default_runner
    try:
        proc = runner([OPENSSL_BIN, "x509", "-in", str(ca_path), "-noout", "-text"])
    except FileNotFoundError:
        return False, "openssl not found on PATH"
    if proc.returncode != 0:
        return False, f"openssl could not parse PEM: {proc.stderr.strip() or proc.stdout.strip()}"
    text = proc.stdout
    if MITMPROXY_CN_SUBSTRING not in text.lower():
        return False, "PEM subject does not contain 'mitmproxy'"
    if "CA:TRUE" not in text:
        return False, "PEM is not a CA certificate (basicConstraints CA:TRUE missing)"
    return True, None


# --- Keychain enumeration -----------------------------------------------------


_SHA1_LINE_RE = re.compile(r"^SHA-1 hash:\s*([0-9A-Fa-f]{40})\s*$")


def enumerate_keychain_matches(*, runner: Runner | None = None) -> list[dict]:
    """List every certificate in the System Keychain whose CN contains
    'mitmproxy'. Returns a list of {sha1_hex, sha1_colons}. The only
    enumeration source for any mutating code path."""
    runner = runner or _default_runner
    proc = runner(
        [
            SECURITY_BIN,
            "find-certificate",
            "-Z",
            "-a",
            "-c",
            MITMPROXY_CN_SUBSTRING,
            SYSTEM_KEYCHAIN,
        ]
    )
    if proc.returncode != 0:
        # No matches → security exits non-zero. That's fine; treat as empty list.
        return []
    matches: list[dict] = []
    for line in proc.stdout.splitlines():
        m = _SHA1_LINE_RE.match(line.strip())
        if m:
            hex_no_colons = m.group(1).upper()
            matches.append(
                {
                    "sha1_hex": hex_no_colons,
                    "sha1_colons": _hex_with_colons(hex_no_colons),
                }
            )
    # Dedupe (security may print the same SHA twice in some scenarios).
    seen: set[str] = set()
    unique: list[dict] = []
    for m in matches:
        if m["sha1_hex"] not in seen:
            seen.add(m["sha1_hex"])
            unique.append(m)
    return unique


def is_trusted(ca_path: Path, *, runner: Runner | None = None) -> bool:
    if not ca_path.exists():
        return False
    runner = runner or _default_runner
    proc = runner([SECURITY_BIN, "verify-cert", "-c", str(ca_path), "-p", "ssl"])
    return proc.returncode == 0


# --- Persisted log of SHAs we installed --------------------------------------


def read_installed_log() -> set[str]:
    if not INSTALLED_LOG.exists():
        return set()
    try:
        data = json.loads(INSTALLED_LOG.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return set()
    if not isinstance(data, list):
        return set()
    return {str(s).upper() for s in data if isinstance(s, str)}


def write_installed_log(shas: Iterable[str]) -> None:
    INSTALLED_LOG.parent.mkdir(parents=True, exist_ok=True)
    INSTALLED_LOG.write_text(
        json.dumps(sorted({s.upper() for s in shas}), indent=2) + "\n",
        encoding="utf-8",
    )


# --- PEM extraction for stale CAs --------------------------------------------


_PEM_BLOCK_RE = re.compile(
    r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
    re.DOTALL,
)


def extract_pem_for_sha(
    sha_hex: str, dest: Path, *, runner: Runner | None = None
) -> bool:
    """Dump the PEM of a cert that's already in the System Keychain whose
    SHA-1 matches `sha_hex`. We need the PEM (not just the hash) so we can
    feed it to `remove-trusted-cert -d <pem>` on stale entries whose
    original PEM file is no longer on disk.

    `security find-certificate` does NOT have a filter-by-hash flag (`-Z`
    on find-certificate is *output*, on delete-certificate it's the *filter*
    — different enough that we can't rely on it here). We use `-a -p -c`
    to dump every PEM under the mitmproxy CN, then locally hash each block
    and pick the matching one."""
    import hashlib

    runner = runner or _default_runner
    proc = runner(
        [
            SECURITY_BIN,
            "find-certificate",
            "-a",
            "-p",
            "-c",
            MITMPROXY_CN_SUBSTRING,
            SYSTEM_KEYCHAIN,
        ]
    )
    if proc.returncode != 0:
        return False
    target = sha_hex.upper().replace(":", "")
    for block in _PEM_BLOCK_RE.findall(proc.stdout):
        try:
            der = cert_manager._pem_to_der(block)
        except Exception:
            continue
        if hashlib.sha1(der).hexdigest().upper() == target:
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(block + "\n", encoding="ascii")
            return True
    return False


# --- Command builders --------------------------------------------------------


def build_install_commands(
    ca_path: Path, *, stale_pairs: list[tuple[str, Path]]
) -> list[list[str]]:
    """stale_pairs is [(sha_hex, pem_path), ...] for each mitmproxy CA in the
    keychain whose SHA differs from the current PEM. We remove their trust
    setting + delete them, then add the current CA fresh."""
    cmds: list[list[str]] = []
    for sha, pem in stale_pairs:
        cmds.append([SECURITY_BIN, "remove-trusted-cert", "-d", str(pem)])
        cmds.append(
            [SECURITY_BIN, "delete-certificate", "-Z", sha, SYSTEM_KEYCHAIN]
        )
    cmds.append(
        [
            SECURITY_BIN,
            "add-trusted-cert",
            "-d",
            "-r",
            "trustRoot",
            "-k",
            SYSTEM_KEYCHAIN,
            str(ca_path),
        ]
    )
    return cmds


def build_uninstall_commands(
    pairs: list[tuple[str, Path]],
) -> list[list[str]]:
    cmds: list[list[str]] = []
    for sha, pem in pairs:
        cmds.append([SECURITY_BIN, "remove-trusted-cert", "-d", str(pem)])
        cmds.append(
            [SECURITY_BIN, "delete-certificate", "-Z", sha, SYSTEM_KEYCHAIN]
        )
    return cmds


# --- Result dataclasses -------------------------------------------------------


@dataclass(frozen=True)
class HostCaInstallResult:
    ca_path: Path
    ca_sha1_hex: str
    ca_sha1_colons: str
    system_keychain_path: str
    replaced_existing: bool
    stale_removed: list[str]
    invoked_privileged: bool
    verified_trusted: bool

    def to_dict(self) -> dict:
        return {
            "ca_path": str(self.ca_path),
            "ca_sha1_hex": self.ca_sha1_hex,
            "ca_sha1_colons": self.ca_sha1_colons,
            "system_keychain_path": self.system_keychain_path,
            "replaced_existing": self.replaced_existing,
            "stale_removed": list(self.stale_removed),
            "invoked_privileged": self.invoked_privileged,
            "verified_trusted": self.verified_trusted,
        }


@dataclass(frozen=True)
class HostCaUninstallResult:
    system_keychain_path: str
    removed_shas: list[str]
    skipped_unmanaged_shas: list[str]
    invoked_privileged: bool

    def to_dict(self) -> dict:
        return {
            "system_keychain_path": self.system_keychain_path,
            "removed_shas": list(self.removed_shas),
            "skipped_unmanaged_shas": list(self.skipped_unmanaged_shas),
            "invoked_privileged": self.invoked_privileged,
        }


@dataclass(frozen=True)
class HostCaMatch:
    sha1_hex: str
    sha1_colons: str
    is_current: bool
    is_managed: bool
    is_trusted: bool

    def to_dict(self) -> dict:
        return {
            "sha1_hex": self.sha1_hex,
            "sha1_colons": self.sha1_colons,
            "is_current": self.is_current,
            "is_managed": self.is_managed,
            "is_trusted": self.is_trusted,
        }


@dataclass(frozen=True)
class HostCaStatusResult:
    ca_path: Path | None
    current_sha1_hex: str | None
    current_sha1_colons: str | None
    system_keychain_path: str
    installed_current: bool
    trusted_current: bool
    matching_cn: list[HostCaMatch] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "ca_path": str(self.ca_path) if self.ca_path else None,
            "current_sha1_hex": self.current_sha1_hex,
            "current_sha1_colons": self.current_sha1_colons,
            "system_keychain_path": self.system_keychain_path,
            "installed_current": self.installed_current,
            "trusted_current": self.trusted_current,
            "matching_cn": [m.to_dict() for m in self.matching_cn],
        }


# --- Top-level orchestration --------------------------------------------------


def install(
    *,
    ca_path: Path | None = None,
    runner: Runner | None = None,
    privileged_runner: PrivilegedRunner,
    force: bool = False,
    tmpdir: Path | None = None,
) -> HostCaInstallResult:
    runner = runner or _default_runner
    pem = ca_path or cert_manager.ca_path()
    if not pem.exists():
        raise HostCaError(
            f"mitmproxy CA not found at {pem}; run `mitm-tracker record start` once first "
            "to bootstrap the CA, then retry."
        )
    ok, reason = validate_pem_is_root_ca(pem, runner=runner)
    if not ok:
        raise HostCaError(f"refusing to install: {reason}")

    current_hex, current_colons = current_ca_sha1(pem)
    matches = enumerate_keychain_matches(runner=runner)
    match_shas = {m["sha1_hex"] for m in matches}

    already_present = current_hex in match_shas
    already_trusted = already_present and is_trusted(pem, runner=runner)

    if already_present and already_trusted and not force:
        return HostCaInstallResult(
            ca_path=pem,
            ca_sha1_hex=current_hex,
            ca_sha1_colons=current_colons,
            system_keychain_path=SYSTEM_KEYCHAIN,
            replaced_existing=False,
            stale_removed=[],
            invoked_privileged=False,
            verified_trusted=True,
        )

    work_tmpdir = tmpdir or STALE_PEM_TMPDIR
    work_tmpdir.mkdir(parents=True, exist_ok=True)
    stale_pairs: list[tuple[str, Path]] = []
    try:
        for m in matches:
            if m["sha1_hex"] == current_hex:
                continue
            stale_pem_path = work_tmpdir / f"stale_{m['sha1_hex']}.pem"
            if extract_pem_for_sha(m["sha1_hex"], stale_pem_path, runner=runner):
                stale_pairs.append((m["sha1_hex"], stale_pem_path))

        cmds = build_install_commands(pem, stale_pairs=stale_pairs)
        proc = privileged_runner(
            cmds,
            "mitm-tracker is installing the mitmproxy CA into the macOS System Keychain.",
        )
        if proc.returncode != 0:
            message = (proc.stderr or proc.stdout or "").strip() or f"exit {proc.returncode}"
            raise HostCaError(f"privileged install failed: {message}")

        verified = is_trusted(pem, runner=runner)
        log = read_installed_log()
        log.add(current_hex)
        write_installed_log(log)

        return HostCaInstallResult(
            ca_path=pem,
            ca_sha1_hex=current_hex,
            ca_sha1_colons=current_colons,
            system_keychain_path=SYSTEM_KEYCHAIN,
            replaced_existing=already_present,
            stale_removed=[sha for sha, _ in stale_pairs],
            invoked_privileged=True,
            verified_trusted=verified,
        )
    finally:
        try:
            shutil.rmtree(work_tmpdir, ignore_errors=True)
        except OSError:
            pass


def uninstall(
    *,
    ca_path: Path | None = None,
    runner: Runner | None = None,
    privileged_runner: PrivilegedRunner,
    tmpdir: Path | None = None,
) -> HostCaUninstallResult:
    runner = runner or _default_runner

    log = read_installed_log()
    pem_path = ca_path or cert_manager.ca_path()
    current_hex: str | None = None
    if pem_path.exists():
        current_hex, _ = current_ca_sha1(pem_path)
        log.add(current_hex)

    matches = enumerate_keychain_matches(runner=runner)
    match_shas = [m["sha1_hex"] for m in matches]

    to_remove = [sha for sha in match_shas if sha in log]
    skipped = [sha for sha in match_shas if sha not in log]

    if not to_remove:
        return HostCaUninstallResult(
            system_keychain_path=SYSTEM_KEYCHAIN,
            removed_shas=[],
            skipped_unmanaged_shas=skipped,
            invoked_privileged=False,
        )

    work_tmpdir = tmpdir or STALE_PEM_TMPDIR
    work_tmpdir.mkdir(parents=True, exist_ok=True)
    pairs: list[tuple[str, Path]] = []
    try:
        for sha in to_remove:
            pem_dest = work_tmpdir / f"remove_{sha}.pem"
            if extract_pem_for_sha(sha, pem_dest, runner=runner):
                pairs.append((sha, pem_dest))

        cmds = build_uninstall_commands(pairs)
        if not cmds:
            return HostCaUninstallResult(
                system_keychain_path=SYSTEM_KEYCHAIN,
                removed_shas=[],
                skipped_unmanaged_shas=skipped,
                invoked_privileged=False,
            )

        proc = privileged_runner(
            cmds,
            "mitm-tracker is removing the mitmproxy CA from the macOS System Keychain.",
        )
        if proc.returncode != 0:
            message = (proc.stderr or proc.stdout or "").strip() or f"exit {proc.returncode}"
            raise HostCaError(f"privileged uninstall failed: {message}")

        remaining_log = log - {sha for sha, _ in pairs}
        write_installed_log(remaining_log)

        return HostCaUninstallResult(
            system_keychain_path=SYSTEM_KEYCHAIN,
            removed_shas=[sha for sha, _ in pairs],
            skipped_unmanaged_shas=skipped,
            invoked_privileged=True,
        )
    finally:
        try:
            shutil.rmtree(work_tmpdir, ignore_errors=True)
        except OSError:
            pass


def status(*, ca_path: Path | None = None, runner: Runner | None = None) -> HostCaStatusResult:
    runner = runner or _default_runner
    pem = ca_path or cert_manager.ca_path()
    pem_exists = pem.exists()
    current_hex: str | None = None
    current_colons: str | None = None
    if pem_exists:
        current_hex, current_colons = current_ca_sha1(pem)

    matches = enumerate_keychain_matches(runner=runner)
    log = read_installed_log()

    trust_now = is_trusted(pem, runner=runner) if pem_exists else False

    matching = []
    for m in matches:
        sha = m["sha1_hex"]
        is_current = current_hex is not None and sha == current_hex
        is_managed = sha in log or is_current
        # `is_trusted` per-cert would require trust-settings-export parsing;
        # we approximate using the verify-cert result for the *current* CA only.
        # Other entries are reported with is_trusted=False unless they happen
        # to be the current cert.
        is_cert_trusted = is_current and trust_now
        matching.append(
            HostCaMatch(
                sha1_hex=sha,
                sha1_colons=m["sha1_colons"],
                is_current=is_current,
                is_managed=is_managed,
                is_trusted=is_cert_trusted,
            )
        )

    installed_current = current_hex is not None and any(
        m.is_current for m in matching
    )

    return HostCaStatusResult(
        ca_path=pem if pem_exists else None,
        current_sha1_hex=current_hex,
        current_sha1_colons=current_colons,
        system_keychain_path=SYSTEM_KEYCHAIN,
        installed_current=installed_current,
        trusted_current=trust_now,
        matching_cn=matching,
    )
