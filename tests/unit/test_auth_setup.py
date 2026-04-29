from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from mitm_tracker import auth_setup
from mitm_tracker.auth_setup import (
    PAM_LOCAL_LINE,
    SUDOERS_CONTENT,
    SUDOERS_MANAGED_MARKER,
    AuthSetupError,
    AuthSetupPaths,
)


def _result(returncode: int = 0, stdout: str = "", stderr: str = "") -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr=stderr)


def _paths(tmp_path: Path) -> AuthSetupPaths:
    paths = AuthSetupPaths.for_test(tmp_path)
    paths.pam_local.parent.mkdir(parents=True, exist_ok=True)
    paths.sudoers_d.mkdir(parents=True, exist_ok=True)
    return paths


def test_is_touch_id_configured_false_when_missing(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    assert auth_setup.is_touch_id_configured(paths) is False


def test_is_touch_id_configured_true_with_active_line(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    paths.pam_local.write_text("auth       sufficient     pam_tid.so\n")
    assert auth_setup.is_touch_id_configured(paths) is True


def test_is_touch_id_configured_false_when_only_commented(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    paths.pam_local.write_text("# auth sufficient pam_tid.so\n")
    assert auth_setup.is_touch_id_configured(paths) is False


def test_is_touch_id_configured_true_when_other_lines_present(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    paths.pam_local.write_text("auth sufficient pam_other.so\nauth sufficient pam_tid.so\n")
    assert auth_setup.is_touch_id_configured(paths) is True


def test_is_sudo_cache_configured_requires_marker(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    paths.sudoers_file.write_text("Defaults timestamp_timeout=60\n")
    assert auth_setup.is_sudo_cache_configured(paths) is False
    paths.sudoers_file.write_text(SUDOERS_CONTENT)
    assert auth_setup.is_sudo_cache_configured(paths) is True


def test_status_reflects_state(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    s = auth_setup.status(paths)
    assert s.touch_id_configured is False
    assert s.sudo_cache_configured is False

    paths.pam_local.write_text(PAM_LOCAL_LINE + "\n")
    paths.sudoers_file.write_text(SUDOERS_CONTENT)
    s = auth_setup.status(paths)
    assert s.touch_id_configured is True
    assert s.sudo_cache_configured is True


def test_prepare_tmp_files_prepends_when_missing(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    tmpdir = tmp_path / "tmp"

    tmp = auth_setup.prepare_tmp_files(
        paths, tmpdir=tmpdir, install_touch_id=True, install_sudo_cache=True
    )

    assert tmp.sudo_local_new.read_text().startswith(PAM_LOCAL_LINE)
    assert SUDOERS_MANAGED_MARKER in tmp.sudoers_new.read_text()


def test_prepare_tmp_files_preserves_existing_lines(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    paths.pam_local.write_text("auth sufficient pam_other.so\n")
    tmpdir = tmp_path / "tmp"

    tmp = auth_setup.prepare_tmp_files(
        paths, tmpdir=tmpdir, install_touch_id=True, install_sudo_cache=False
    )

    text = tmp.sudo_local_new.read_text()
    assert PAM_LOCAL_LINE in text
    assert "pam_other.so" in text


def test_prepare_tmp_files_idempotent(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    paths.pam_local.write_text(PAM_LOCAL_LINE + "\n")
    tmpdir = tmp_path / "tmp"

    tmp = auth_setup.prepare_tmp_files(
        paths, tmpdir=tmpdir, install_touch_id=True, install_sudo_cache=False
    )

    text = tmp.sudo_local_new.read_text()
    assert text.count("pam_tid.so") == 1


def test_install_skips_when_already_configured(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    paths.pam_local.write_text(PAM_LOCAL_LINE + "\n")
    paths.sudoers_file.write_text(SUDOERS_CONTENT)
    runner = MagicMock()

    result = auth_setup.install(
        paths=paths, privileged_runner=runner, tmpdir=tmp_path / "tmp"
    )

    assert result.invoked_privileged is False
    assert result.touch_id.already_present is True
    assert result.sudo_cache.already_present is True
    runner.assert_not_called()


def test_install_invokes_privileged_runner_when_needed(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    runner = MagicMock(return_value=_result(returncode=0))

    result = auth_setup.install(
        paths=paths, privileged_runner=runner, tmpdir=tmp_path / "tmp"
    )

    assert result.invoked_privileged is True
    assert result.touch_id.line_added is True
    assert result.sudo_cache.written is True
    runner.assert_called_once()
    args, _ = runner.call_args
    cmds, _prompt = args
    assert any(cmd[:1] == ["visudo"] for cmd in cmds)
    assert any(cmd[0] == "install" for cmd in cmds)


def test_install_raises_on_privileged_failure(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    runner = MagicMock(return_value=_result(returncode=1, stderr="visudo: parse error"))

    with pytest.raises(AuthSetupError):
        auth_setup.install(paths=paths, privileged_runner=runner, tmpdir=tmp_path / "tmp")


def test_install_skip_flags_only_run_what_remains(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    runner = MagicMock(return_value=_result(returncode=0))

    result = auth_setup.install(
        paths=paths,
        privileged_runner=runner,
        tmpdir=tmp_path / "tmp",
        skip_sudo_cache=True,
    )

    args, _ = runner.call_args
    cmds, _prompt = args
    # should not contain visudo since sudo_cache was skipped
    assert not any(cmd[:1] == ["visudo"] for cmd in cmds)
    assert result.touch_id.line_added is True
    assert result.sudo_cache.written is False


def test_uninstall_skips_unmanaged_sudoers(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    paths.sudoers_file.write_text("Defaults timestamp_timeout=60\n")  # no marker
    runner = MagicMock(return_value=_result(returncode=0))

    result = auth_setup.uninstall(
        paths=paths, privileged_runner=runner, tmpdir=tmp_path / "tmp"
    )

    assert result.sudoers_skipped_unmanaged is True
    assert result.sudoers_removed is False


def test_uninstall_removes_managed_sudoers(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    paths.sudoers_file.write_text(SUDOERS_CONTENT)
    runner = MagicMock(return_value=_result(returncode=0))

    result = auth_setup.uninstall(
        paths=paths, privileged_runner=runner, tmpdir=tmp_path / "tmp"
    )

    assert result.sudoers_removed is True
    assert result.sudoers_skipped_unmanaged is False
    args, _ = runner.call_args
    cmds, _prompt = args
    assert any(cmd[:2] == ["rm", "-f"] and cmd[-1] == str(paths.sudoers_file) for cmd in cmds)


def test_uninstall_strips_pam_tid_line_when_other_lines_remain(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    paths.pam_local.write_text(PAM_LOCAL_LINE + "\nauth sufficient pam_other.so\n")
    runner = MagicMock(return_value=_result(returncode=0))

    result = auth_setup.uninstall(
        paths=paths, privileged_runner=runner, tmpdir=tmp_path / "tmp"
    )

    assert result.pam_local_line_stripped is True
    assert result.pam_local_removed is False


def test_uninstall_removes_pam_local_when_only_our_line(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    paths.pam_local.write_text(PAM_LOCAL_LINE + "\n")
    runner = MagicMock(return_value=_result(returncode=0))

    result = auth_setup.uninstall(
        paths=paths, privileged_runner=runner, tmpdir=tmp_path / "tmp"
    )

    assert result.pam_local_removed is True
    assert result.pam_local_line_stripped is False


def test_uninstall_no_op_when_nothing_installed(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    runner = MagicMock()

    result = auth_setup.uninstall(
        paths=paths, privileged_runner=runner, tmpdir=tmp_path / "tmp"
    )

    runner.assert_not_called()
    assert result.pam_local_removed is False
    assert result.sudoers_removed is False
