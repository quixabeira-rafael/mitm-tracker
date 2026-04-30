from __future__ import annotations

import platform
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

from mitm_tracker import auth_setup, claude_skill, host_ca, tray_launch_agent
from mitm_tracker.config import workspace_for
from mitm_tracker.profile_manager import ProfileError, ProfileManager
from mitm_tracker.session_manager import SessionManager
from mitm_tracker.ssl_list import SslList

STATUS_OK = "ok"
STATUS_WARN = "warn"
STATUS_ERROR = "error"
STATUS_INFO = "info"


@dataclass(frozen=True)
class CheckResult:
    name: str
    status: str
    detail: str
    fix: str | None = None
    group: str = "system"

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "status": self.status,
            "detail": self.detail,
            "fix": self.fix,
            "group": self.group,
        }


# --- Default subprocess wrappers (replaced in tests) -------------------------


def _run(cmd: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=30)


def _get_macos_product_version() -> str | None:
    try:
        proc = _run(["sw_vers", "-productVersion"])
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0:
        return None
    return proc.stdout.strip() or None


def _get_macos_codename(version: str) -> str:
    major = int(version.split(".")[0]) if version else 0
    return {
        15: "Sequoia",
        14: "Sonoma",
        13: "Ventura",
        12: "Monterey",
        11: "Big Sur",
    }.get(major, f"macOS {major}")


# --- Individual checks --------------------------------------------------------


def check_macos_version() -> CheckResult:
    version = _get_macos_product_version()
    if version is None:
        return CheckResult(
            name="macOS",
            status=STATUS_ERROR,
            detail="could not detect macOS version (is this a Mac?)",
            group="system",
        )
    major = int(version.split(".")[0])
    codename = _get_macos_codename(version)
    if major >= 14:
        return CheckResult(
            name="macOS",
            status=STATUS_OK,
            detail=f"{version} ({codename})",
            group="system",
        )
    if major >= 12:
        return CheckResult(
            name="macOS",
            status=STATUS_WARN,
            detail=f"{version} ({codename}) — pre-Sonoma; Touch ID via setup install will not activate",
            fix="upgrade to macOS Sonoma 14.0+ for /etc/pam.d/sudo_local support",
            group="system",
        )
    return CheckResult(
        name="macOS",
        status=STATUS_ERROR,
        detail=f"{version} ({codename}) — too old",
        fix="upgrade to a supported macOS (Big Sur 11+ minimum, Sonoma 14+ for full feature set)",
        group="system",
    )


def check_architecture() -> CheckResult:
    machine = platform.machine()
    label = "Apple Silicon" if machine == "arm64" else "Intel" if machine == "x86_64" else machine
    return CheckResult(
        name="Architecture",
        status=STATUS_OK,
        detail=f"{machine} ({label})",
        group="system",
    )


def check_python_version() -> CheckResult:
    info = sys.version_info
    detail = f"{info.major}.{info.minor}.{info.micro}"
    if info >= (3, 11):
        return CheckResult(name="Python", status=STATUS_OK, detail=detail, group="system")
    return CheckResult(
        name="Python",
        status=STATUS_ERROR,
        detail=f"{detail} — too old",
        fix="reinstall mitm-tracker via pipx with --python python3.11+",
        group="system",
    )


def check_mitmdump() -> CheckResult:
    path = shutil.which("mitmdump")
    if path is None:
        return CheckResult(
            name="mitmdump",
            status=STATUS_ERROR,
            detail="not found on PATH",
            fix="brew install mitmproxy",
            group="tools",
        )
    try:
        proc = _run([path, "--version"])
        version = proc.stdout.splitlines()[0] if proc.stdout else "unknown"
    except (subprocess.TimeoutExpired, IndexError):
        version = "unknown"
    return CheckResult(name="mitmdump", status=STATUS_OK, detail=f"{path} ({version})", group="tools")


def check_xcrun() -> CheckResult:
    path = shutil.which("xcrun")
    if path is None:
        return CheckResult(
            name="xcrun simctl",
            status=STATUS_WARN,
            detail="not found on PATH (iOS Simulator features unavailable)",
            fix="install Xcode CLI tools: xcode-select --install",
            group="tools",
        )
    try:
        proc = _run([path, "--find", "simctl"])
        if proc.returncode != 0:
            return CheckResult(
                name="xcrun simctl",
                status=STATUS_WARN,
                detail="xcrun present but simctl missing",
                fix="install Xcode (full IDE) or accept license: sudo xcodebuild -license accept",
                group="tools",
            )
    except subprocess.TimeoutExpired:
        return CheckResult(name="xcrun simctl", status=STATUS_WARN, detail="xcrun timed out", group="tools")
    return CheckResult(name="xcrun simctl", status=STATUS_OK, detail=path, group="tools")


def check_pam_tid_module() -> CheckResult:
    candidates = [
        Path("/usr/lib/pam/pam_tid.so.2"),
        Path("/usr/lib/pam/pam_tid.so"),
    ]
    for path in candidates:
        if path.exists():
            return CheckResult(
                name="pam_tid.so",
                status=STATUS_OK,
                detail=str(path),
                group="tools",
            )
    return CheckResult(
        name="pam_tid.so",
        status=STATUS_ERROR,
        detail="not found in /usr/lib/pam",
        fix="usually shipped with macOS; reinstall macOS or check Apple support",
        group="tools",
    )


def check_rumps() -> CheckResult:
    try:
        import rumps  # noqa: F401
    except ImportError:
        return CheckResult(
            name="rumps (tray)",
            status=STATUS_WARN,
            detail="not installed (tray indicator unavailable)",
            fix='pipx install -e ".[tray]" --force',
            group="optional",
        )
    version = getattr(rumps, "__version__", "unknown")
    return CheckResult(name="rumps (tray)", status=STATUS_OK, detail=f"{version}", group="optional")


def check_touch_id_setup() -> CheckResult:
    configured = auth_setup.is_touch_id_configured()
    if configured:
        return CheckResult(
            name="Touch ID setup",
            status=STATUS_OK,
            detail="/etc/pam.d/sudo_local has pam_tid.so",
            group="optional",
        )
    return CheckResult(
        name="Touch ID setup",
        status=STATUS_WARN,
        detail="not configured; record start/stop will prompt for password",
        fix="mitm-tracker setup install",
        group="optional",
    )


def check_sudo_cache_setup() -> CheckResult:
    configured = auth_setup.is_sudo_cache_configured()
    if configured:
        return CheckResult(
            name="sudo cache",
            status=STATUS_OK,
            detail="/etc/sudoers.d/mitm-tracker scopes 60min cache to /usr/sbin/networksetup",
            group="optional",
        )
    return CheckResult(
        name="sudo cache",
        status=STATUS_WARN,
        detail="not configured; each record start/stop re-authenticates",
        fix="mitm-tracker setup install",
        group="optional",
    )


def check_claude_skill() -> CheckResult:
    if not claude_skill.claude_code_present():
        return CheckResult(
            name="Claude Code skill",
            status=STATUS_INFO,
            detail="Claude Code not detected (~/.claude missing); skill install is optional",
            group="optional",
        )
    sk = claude_skill.status()
    if sk.is_managed_symlink:
        return CheckResult(
            name="Claude Code skill",
            status=STATUS_OK,
            detail=f"installed (symlink -> {sk.points_to})",
            group="optional",
        )
    if sk.installed:
        return CheckResult(
            name="Claude Code skill",
            status=STATUS_WARN,
            detail=f"a SKILL.md exists at {sk.skill_file} but it is not the managed symlink",
            fix="mitm-tracker skill install --json   (will replace it with our symlink)",
            group="optional",
        )
    return CheckResult(
        name="Claude Code skill",
        status=STATUS_WARN,
        detail="not installed; mitm-tracker skill is unavailable to Claude Code outside this repo",
        fix="mitm-tracker skill install",
        group="optional",
    )


def check_tray_launch_agent() -> CheckResult:
    status = tray_launch_agent.status()
    if status.installed and status.loaded:
        return CheckResult(
            name="tray LaunchAgent",
            status=STATUS_OK,
            detail=f"loaded (PID {status.pid if status.pid is not None else '-'}, workspace: {status.workspace})",
            group="optional",
        )
    if status.installed and not status.loaded:
        return CheckResult(
            name="tray LaunchAgent",
            status=STATUS_WARN,
            detail="plist installed but not loaded",
            fix=f"launchctl load -w {status.plist_path}",
            group="optional",
        )
    return CheckResult(
        name="tray LaunchAgent",
        status=STATUS_WARN,
        detail="not installed; tray will not auto-launch on login",
        fix="mitm-tracker setup install (or mitm-tracker tray install)",
        group="optional",
    )


def check_host_ca() -> CheckResult:
    try:
        st = host_ca.status()
    except Exception as exc:
        return CheckResult(
            name="Host CA",
            status=STATUS_INFO,
            detail=f"could not query System Keychain: {exc}",
            group="optional",
        )
    if st.ca_path is None:
        return CheckResult(
            name="Host CA",
            status=STATUS_INFO,
            detail="mitmproxy CA not generated yet (run `mitm-tracker record start` once)",
            group="optional",
        )
    log = host_ca.read_installed_log()
    stale_in_keychain = [
        m for m in st.matching_cn if not m.is_current and m.sha1_hex in log
    ]
    other_in_keychain = [
        m for m in st.matching_cn if not m.is_current and m.sha1_hex not in log
    ]
    if st.installed_current and st.trusted_current:
        detail = "trusted as root in /Library/Keychains/System.keychain"
        if other_in_keychain:
            detail += f" (note: {len(other_in_keychain)} unmanaged mitmproxy CA(s) also present)"
        if stale_in_keychain:
            return CheckResult(
                name="Host CA",
                status=STATUS_WARN,
                detail=(
                    f"current CA trusted, but {len(stale_in_keychain)} stale "
                    "mitm-tracker-managed CA(s) still in keychain"
                ),
                fix="mitm-tracker cert host install --force   # cleans up stale entries",
                group="optional",
            )
        return CheckResult(name="Host CA", status=STATUS_OK, detail=detail, group="optional")
    if st.installed_current and not st.trusted_current:
        return CheckResult(
            name="Host CA",
            status=STATUS_WARN,
            detail="cert is in the keychain but trust setting is missing or rejected",
            fix="mitm-tracker cert host install --force",
            group="optional",
        )
    if stale_in_keychain:
        return CheckResult(
            name="Host CA",
            status=STATUS_WARN,
            detail=(
                f"current CA NOT installed, but {len(stale_in_keychain)} stale "
                "mitm-tracker-managed CA(s) are still in the keychain"
            ),
            fix="mitm-tracker cert host uninstall   # cleans them up",
            group="optional",
        )
    return CheckResult(
        name="Host CA",
        status=STATUS_INFO,
        detail="not installed; HTTPS originating from the Mac host won't be decrypted",
        group="optional",
    )


def check_active_profile_ssl_list() -> CheckResult:
    ws = workspace_for()
    if not ws.base.exists():
        return CheckResult(
            name="Active profile SSL list",
            status=STATUS_INFO,
            detail="no workspace in cwd",
            group="state",
        )
    pm = ProfileManager(ws)
    try:
        profile = pm.active_name()
        ssl = SslList.load(ws.ssl_path(profile))
    except (ProfileError, OSError) as exc:
        return CheckResult(
            name="Active profile SSL list",
            status=STATUS_WARN,
            detail=f"could not load SSL list: {exc}",
            group="state",
        )
    count = len(ssl.entries)
    if count == 0:
        return CheckResult(
            name="Active profile SSL list",
            status=STATUS_WARN,
            detail=f"profile '{profile}' has 0 hosts; record will run in passthrough mode (no HTTPS capture)",
            fix=f'mitm-tracker ssl add "*.api.example.com" --profile {profile}',
            group="state",
        )
    return CheckResult(
        name="Active profile SSL list",
        status=STATUS_OK,
        detail=f"profile '{profile}' has {count} hosts",
        group="state",
    )


def check_workspace() -> CheckResult:
    ws = workspace_for()
    if ws.base.exists():
        return CheckResult(
            name="Workspace",
            status=STATUS_INFO,
            detail=str(ws.base),
            group="state",
        )
    return CheckResult(
        name="Workspace",
        status=STATUS_INFO,
        detail=f"no workspace at {ws.base} (will be created on first record start)",
        group="state",
    )


def check_record_session() -> CheckResult:
    ws = workspace_for()
    if not ws.base.exists():
        return CheckResult(
            name="Record session",
            status=STATUS_INFO,
            detail="no workspace in cwd",
            group="state",
        )
    sm = SessionManager(ws)
    try:
        if sm.detect_crashed():
            state = sm.read_state()
            return CheckResult(
                name="Record session",
                status=STATUS_WARN,
                detail=f"zombie state: state.json says running (PID {state.get('pid')}) but PID is dead",
                fix="mitm-tracker record stop",
                group="state",
            )
        if sm.is_running():
            state = sm.read_state()
            return CheckResult(
                name="Record session",
                status=STATUS_INFO,
                detail=f"running (PID {state.get('pid')}, port {state.get('port')})",
                group="state",
            )
    except Exception as exc:
        return CheckResult(
            name="Record session",
            status=STATUS_WARN,
            detail=f"could not read state: {exc}",
            group="state",
        )
    return CheckResult(name="Record session", status=STATUS_INFO, detail="not running", group="state")


def check_mitmproxy_ca() -> CheckResult:
    ca_path = Path.home() / ".mitmproxy" / "mitmproxy-ca-cert.pem"
    if not ca_path.exists():
        return CheckResult(
            name="mitmproxy CA",
            status=STATUS_INFO,
            detail="not generated yet (will be created on first mitmdump run)",
            group="state",
        )
    try:
        proc = _run(["openssl", "x509", "-in", str(ca_path), "-noout", "-fingerprint", "-sha256"])
        fingerprint = proc.stdout.strip() if proc.returncode == 0 else "unable to compute"
    except (FileNotFoundError, subprocess.TimeoutExpired):
        fingerprint = "unable to compute"
    return CheckResult(name="mitmproxy CA", status=STATUS_INFO, detail=f"{ca_path} ({fingerprint})", group="state")


def check_booted_simulators() -> CheckResult:
    if shutil.which("xcrun") is None:
        return CheckResult(
            name="iOS Simulators",
            status=STATUS_INFO,
            detail="xcrun missing; cannot enumerate",
            group="state",
        )
    try:
        proc = _run(["xcrun", "simctl", "list", "devices", "booted"])
    except subprocess.TimeoutExpired:
        return CheckResult(name="iOS Simulators", status=STATUS_INFO, detail="simctl timed out", group="state")
    if proc.returncode != 0:
        return CheckResult(
            name="iOS Simulators",
            status=STATUS_INFO,
            detail="simctl failed; no booted simulators detected",
            group="state",
        )
    booted = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line or line.startswith("==") or line.startswith("--"):
            continue
        if "(Booted)" in line:
            booted.append(line)
    if not booted:
        return CheckResult(name="iOS Simulators", status=STATUS_INFO, detail="none booted", group="state")
    return CheckResult(
        name="iOS Simulators",
        status=STATUS_INFO,
        detail=f"{len(booted)} booted: " + "; ".join(booted),
        group="state",
    )


# --- Orchestration ------------------------------------------------------------


def run_all_checks() -> list[CheckResult]:
    return [
        check_macos_version(),
        check_architecture(),
        check_python_version(),
        check_mitmdump(),
        check_xcrun(),
        check_pam_tid_module(),
        check_rumps(),
        check_touch_id_setup(),
        check_sudo_cache_setup(),
        check_tray_launch_agent(),
        check_claude_skill(),
        check_host_ca(),
        check_workspace(),
        check_active_profile_ssl_list(),
        check_record_session(),
        check_mitmproxy_ca(),
        check_booted_simulators(),
    ]


def aggregate_status(results: list[CheckResult]) -> str:
    has_error = any(r.status == STATUS_ERROR for r in results)
    has_warn = any(r.status == STATUS_WARN for r in results)
    if has_error:
        return STATUS_ERROR
    if has_warn:
        return STATUS_WARN
    return STATUS_OK
