from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

PAM_LOCAL_LINE = "auth       sufficient     pam_tid.so"
SUDOERS_FILENAME = "mitm-tracker"
SUDOERS_MANAGED_MARKER = "# managed by mitm-tracker"
SUDOERS_CONTENT = (
    f"{SUDOERS_MANAGED_MARKER} (do not edit; remove via `mitm-tracker setup uninstall`)\n"
    "Defaults!/usr/sbin/networksetup timestamp_timeout=60\n"
)

_PAM_TID_LINE_RE = re.compile(r"^\s*auth\s+\S+\s+pam_tid\.so")


PrivilegedRunner = Callable[[list[list[str]], str], subprocess.CompletedProcess]


class AuthSetupError(RuntimeError):
    pass


@dataclass(frozen=True)
class AuthSetupPaths:
    pam_local: Path
    sudoers_d: Path

    @property
    def sudoers_file(self) -> Path:
        return self.sudoers_d / SUDOERS_FILENAME

    @classmethod
    def for_system(cls) -> AuthSetupPaths:
        return cls(
            pam_local=Path("/etc/pam.d/sudo_local"),
            sudoers_d=Path("/etc/sudoers.d"),
        )

    @classmethod
    def for_test(cls, root: Path) -> AuthSetupPaths:
        return cls(
            pam_local=root / "etc" / "pam.d" / "sudo_local",
            sudoers_d=root / "etc" / "sudoers.d",
        )


@dataclass(frozen=True)
class TmpFiles:
    tmpdir: Path
    sudo_local_new: Path
    sudoers_new: Path


@dataclass(frozen=True)
class TouchIdInstallResult:
    pam_local_path: Path
    line_added: bool
    already_present: bool

    def to_dict(self) -> dict:
        return {
            "pam_local_path": str(self.pam_local_path),
            "line_added": self.line_added,
            "already_present": self.already_present,
        }


@dataclass(frozen=True)
class SudoCacheInstallResult:
    sudoers_path: Path
    written: bool
    already_present: bool
    validated: bool

    def to_dict(self) -> dict:
        return {
            "sudoers_path": str(self.sudoers_path),
            "written": self.written,
            "already_present": self.already_present,
            "validated": self.validated,
        }


@dataclass(frozen=True)
class UninstallResult:
    pam_local_path: Path
    sudoers_path: Path
    pam_local_removed: bool
    pam_local_line_stripped: bool
    sudoers_removed: bool
    sudoers_skipped_unmanaged: bool

    def to_dict(self) -> dict:
        return {
            "pam_local_path": str(self.pam_local_path),
            "sudoers_path": str(self.sudoers_path),
            "pam_local_removed": self.pam_local_removed,
            "pam_local_line_stripped": self.pam_local_line_stripped,
            "sudoers_removed": self.sudoers_removed,
            "sudoers_skipped_unmanaged": self.sudoers_skipped_unmanaged,
        }


@dataclass(frozen=True)
class SetupStatus:
    pam_local_path: Path
    sudoers_path: Path
    touch_id_configured: bool
    sudo_cache_configured: bool

    def to_dict(self) -> dict:
        return {
            "pam_local_path": str(self.pam_local_path),
            "sudoers_path": str(self.sudoers_path),
            "touch_id_configured": self.touch_id_configured,
            "sudo_cache_configured": self.sudo_cache_configured,
        }


def is_touch_id_configured(paths: AuthSetupPaths | None = None) -> bool:
    paths = paths or AuthSetupPaths.for_system()
    if not paths.pam_local.exists():
        return False
    try:
        text = paths.pam_local.read_text(encoding="utf-8")
    except OSError:
        return False
    return _has_active_pam_tid_line(text)


def is_sudo_cache_configured(paths: AuthSetupPaths | None = None) -> bool:
    paths = paths or AuthSetupPaths.for_system()
    sudoers_file = paths.sudoers_file
    if not sudoers_file.exists():
        return False
    try:
        text = sudoers_file.read_text(encoding="utf-8")
    except OSError:
        return False
    return SUDOERS_MANAGED_MARKER in text


def status(paths: AuthSetupPaths | None = None) -> SetupStatus:
    paths = paths or AuthSetupPaths.for_system()
    return SetupStatus(
        pam_local_path=paths.pam_local,
        sudoers_path=paths.sudoers_file,
        touch_id_configured=is_touch_id_configured(paths),
        sudo_cache_configured=is_sudo_cache_configured(paths),
    )


def _has_active_pam_tid_line(text: str) -> bool:
    for raw in text.splitlines():
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if _PAM_TID_LINE_RE.match(raw):
            return True
    return False


def _read_pam_local_or_empty(paths: AuthSetupPaths) -> str:
    if not paths.pam_local.exists():
        return ""
    try:
        return paths.pam_local.read_text(encoding="utf-8")
    except OSError:
        return ""


def _merged_sudo_local_content(existing: str) -> str:
    if _has_active_pam_tid_line(existing):
        return existing
    if existing and not existing.endswith("\n"):
        existing = existing + "\n"
    return PAM_LOCAL_LINE + "\n" + existing


def _strip_pam_tid_lines(existing: str) -> str:
    kept = [line for line in existing.splitlines() if not _PAM_TID_LINE_RE.match(line)]
    if not kept:
        return ""
    result = "\n".join(kept)
    if not result.endswith("\n"):
        result += "\n"
    return result


def prepare_tmp_files(
    paths: AuthSetupPaths,
    *,
    tmpdir: Path,
    install_touch_id: bool,
    install_sudo_cache: bool,
) -> TmpFiles:
    tmpdir.mkdir(parents=True, exist_ok=True)
    sudo_local_new = tmpdir / "sudo_local.new"
    sudoers_new = tmpdir / "sudoers.new"
    if install_touch_id:
        existing = _read_pam_local_or_empty(paths)
        sudo_local_new.write_text(_merged_sudo_local_content(existing), encoding="utf-8")
    if install_sudo_cache:
        sudoers_new.write_text(SUDOERS_CONTENT, encoding="utf-8")
    return TmpFiles(tmpdir=tmpdir, sudo_local_new=sudo_local_new, sudoers_new=sudoers_new)


def build_install_commands(
    paths: AuthSetupPaths,
    tmp: TmpFiles,
    *,
    install_touch_id: bool,
    install_sudo_cache: bool,
) -> list[list[str]]:
    cmds: list[list[str]] = []
    if install_sudo_cache:
        cmds.append(["visudo", "-cf", str(tmp.sudoers_new)])
    if install_touch_id:
        cmds.append(
            [
                "install",
                "-m",
                "0644",
                "-o",
                "root",
                "-g",
                "wheel",
                str(tmp.sudo_local_new),
                str(paths.pam_local),
            ]
        )
    if install_sudo_cache:
        cmds.append(
            [
                "install",
                "-m",
                "0440",
                "-o",
                "root",
                "-g",
                "wheel",
                str(tmp.sudoers_new),
                str(paths.sudoers_file),
            ]
        )
    cmds.append(["rm", "-rf", str(tmp.tmpdir)])
    return cmds


@dataclass(frozen=True)
class InstallResult:
    touch_id: TouchIdInstallResult
    sudo_cache: SudoCacheInstallResult
    invoked_privileged: bool

    def to_dict(self) -> dict:
        return {
            "touch_id": self.touch_id.to_dict(),
            "sudo_cache": self.sudo_cache.to_dict(),
            "invoked_privileged": self.invoked_privileged,
        }


def install(
    *,
    paths: AuthSetupPaths | None = None,
    privileged_runner: PrivilegedRunner,
    tmpdir: Path,
    skip_touch_id: bool = False,
    skip_sudo_cache: bool = False,
) -> InstallResult:
    paths = paths or AuthSetupPaths.for_system()

    touch_id_already = is_touch_id_configured(paths)
    sudo_cache_already = is_sudo_cache_configured(paths)

    do_touch_id = (not skip_touch_id) and not touch_id_already
    do_sudo_cache = (not skip_sudo_cache) and not sudo_cache_already

    if not do_touch_id and not do_sudo_cache:
        return InstallResult(
            touch_id=TouchIdInstallResult(
                pam_local_path=paths.pam_local,
                line_added=False,
                already_present=touch_id_already,
            ),
            sudo_cache=SudoCacheInstallResult(
                sudoers_path=paths.sudoers_file,
                written=False,
                already_present=sudo_cache_already,
                validated=False,
            ),
            invoked_privileged=False,
        )

    tmp = prepare_tmp_files(
        paths, tmpdir=tmpdir, install_touch_id=do_touch_id, install_sudo_cache=do_sudo_cache
    )
    cmds = build_install_commands(
        paths, tmp, install_touch_id=do_touch_id, install_sudo_cache=do_sudo_cache
    )

    proc = privileged_runner(
        cmds, "mitm-tracker needs to enable Touch ID and extend the sudo cache."
    )
    if proc.returncode != 0:
        message = (proc.stderr or proc.stdout or "").strip() or f"exit {proc.returncode}"
        raise AuthSetupError(f"privileged setup failed: {message}")

    return InstallResult(
        touch_id=TouchIdInstallResult(
            pam_local_path=paths.pam_local,
            line_added=do_touch_id,
            already_present=touch_id_already,
        ),
        sudo_cache=SudoCacheInstallResult(
            sudoers_path=paths.sudoers_file,
            written=do_sudo_cache,
            already_present=sudo_cache_already,
            validated=do_sudo_cache,
        ),
        invoked_privileged=True,
    )


def build_uninstall_plan(paths: AuthSetupPaths) -> tuple[list[list[str]], dict]:
    cmds: list[list[str]] = []
    flags = {
        "pam_local_removed": False,
        "pam_local_line_stripped": False,
        "sudoers_removed": False,
        "sudoers_skipped_unmanaged": False,
    }

    if paths.pam_local.exists():
        existing = _read_pam_local_or_empty(paths)
        if _has_active_pam_tid_line(existing):
            stripped = _strip_pam_tid_lines(existing)
            if stripped:
                tmp = paths.pam_local.parent / "sudo_local.uninstall.tmp"
                cmds.append(
                    [
                        "install",
                        "-m",
                        "0644",
                        "-o",
                        "root",
                        "-g",
                        "wheel",
                        str(tmp),
                        str(paths.pam_local),
                    ]
                )
                flags["pam_local_line_stripped"] = True
            else:
                cmds.append(["rm", "-f", str(paths.pam_local)])
                flags["pam_local_removed"] = True

    if paths.sudoers_file.exists():
        try:
            text = paths.sudoers_file.read_text(encoding="utf-8")
        except OSError:
            text = ""
        if SUDOERS_MANAGED_MARKER in text:
            cmds.append(["rm", "-f", str(paths.sudoers_file)])
            flags["sudoers_removed"] = True
        else:
            flags["sudoers_skipped_unmanaged"] = True

    return cmds, flags


def uninstall(
    *,
    paths: AuthSetupPaths | None = None,
    privileged_runner: PrivilegedRunner,
    tmpdir: Path,
) -> UninstallResult:
    paths = paths or AuthSetupPaths.for_system()

    cmds, flags = build_uninstall_plan(paths)

    if flags["pam_local_line_stripped"]:
        existing = _read_pam_local_or_empty(paths)
        stripped = _strip_pam_tid_lines(existing)
        tmpdir.mkdir(parents=True, exist_ok=True)
        tmp_path = tmpdir / "sudo_local.uninstall.tmp"
        tmp_path.write_text(stripped, encoding="utf-8")
        cmds = [_rewrite_install_src(cmd, tmp_path) for cmd in cmds]
        cmds.append(["rm", "-rf", str(tmpdir)])

    if cmds:
        proc = privileged_runner(
            cmds, "mitm-tracker is removing Touch ID and sudo cache configuration."
        )
        if proc.returncode != 0:
            message = (proc.stderr or proc.stdout or "").strip() or f"exit {proc.returncode}"
            raise AuthSetupError(f"privileged uninstall failed: {message}")

    return UninstallResult(
        pam_local_path=paths.pam_local,
        sudoers_path=paths.sudoers_file,
        pam_local_removed=flags["pam_local_removed"],
        pam_local_line_stripped=flags["pam_local_line_stripped"],
        sudoers_removed=flags["sudoers_removed"],
        sudoers_skipped_unmanaged=flags["sudoers_skipped_unmanaged"],
    )


def _rewrite_install_src(cmd: list[str], real_src: Path) -> list[str]:
    if cmd[:1] != ["install"]:
        return cmd
    if len(cmd) < 2:
        return cmd
    rewritten = list(cmd)
    rewritten[-2] = str(real_src)
    return rewritten
