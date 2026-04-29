from __future__ import annotations

import subprocess
from typing import Sequence

import pytest

from mitm_tracker.proxy_manager import (
    ProxyAuthorizationError,
    ProxyBackup,
    ProxyManager,
    ProxyManagerError,
    ProxyState,
    _default_privileged_runner,
    _privilege_error_from,
    build_osascript,
    build_shell_script,
)


def _completed(stdout: str = "", stderr: str = "", code: int = 0) -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(
        args=[], returncode=code, stdout=stdout, stderr=stderr
    )


def _scripted_runner(responses: dict[tuple[str, ...], subprocess.CompletedProcess]):
    calls: list[list[str]] = []

    def runner(args: Sequence[str]) -> subprocess.CompletedProcess:
        key = tuple(args)
        calls.append(list(args))
        if key in responses:
            return responses[key]
        return _completed()

    return runner, calls


def _capturing_privileged():
    invocations: list[tuple[list[list[str]], str]] = []

    def runner(commands: list[list[str]], prompt: str) -> subprocess.CompletedProcess:
        invocations.append(([list(c) for c in commands], prompt))
        return _completed()

    return runner, invocations


def test_proxy_state_round_trip() -> None:
    s = ProxyState(enabled=True, server="127.0.0.1", port=8080)
    assert ProxyState.from_dict(s.to_dict()) == s


def test_proxy_backup_round_trip() -> None:
    backup = ProxyBackup(
        service="Wi-Fi",
        web=ProxyState(enabled=True, server="127.0.0.1", port=8080),
        secure=ProxyState(enabled=False, server=None, port=None),
    )
    assert ProxyBackup.from_dict(backup.to_dict()) == backup


def test_list_services_strips_disabled_marker_and_header() -> None:
    runner, _calls = _scripted_runner(
        {
            ("networksetup", "-listallnetworkservices"): _completed(
                stdout=(
                    "An asterisk (*) denotes that a network service is disabled.\n"
                    "Wi-Fi\n"
                    "*USB 10/100/1000 LAN\n"
                    "Ethernet\n"
                )
            )
        }
    )
    pm = ProxyManager(runner=runner)
    assert pm.list_services() == ["Wi-Fi", "Ethernet"]


def test_get_active_service_prefers_wifi() -> None:
    runner, _ = _scripted_runner(
        {
            ("networksetup", "-listallnetworkservices"): _completed(
                stdout="Header\nEthernet\nWi-Fi\n"
            )
        }
    )
    pm = ProxyManager(runner=runner)
    assert pm.get_active_service() == "Wi-Fi"


def test_get_active_service_falls_back_to_first() -> None:
    runner, _ = _scripted_runner(
        {
            ("networksetup", "-listallnetworkservices"): _completed(
                stdout="Header\nThunderbolt Bridge\n"
            )
        }
    )
    pm = ProxyManager(runner=runner)
    assert pm.get_active_service() == "Thunderbolt Bridge"


def test_get_web_proxy_parses_state() -> None:
    runner, _ = _scripted_runner(
        {
            ("networksetup", "-getwebproxy", "Wi-Fi"): _completed(
                stdout="Enabled: Yes\nServer: 127.0.0.1\nPort: 8080\nAuthenticated Proxy Enabled: 0\n"
            )
        }
    )
    pm = ProxyManager(runner=runner)
    state = pm.get_web_proxy("Wi-Fi")
    assert state == ProxyState(enabled=True, server="127.0.0.1", port=8080)


def test_get_web_proxy_handles_disabled_state() -> None:
    runner, _ = _scripted_runner(
        {
            ("networksetup", "-getwebproxy", "Wi-Fi"): _completed(
                stdout="Enabled: No\nServer: \nPort: 0\n"
            )
        }
    )
    pm = ProxyManager(runner=runner)
    state = pm.get_web_proxy("Wi-Fi")
    assert state.enabled is False
    assert state.server is None
    assert state.port == 0


def test_set_proxy_routes_through_privileged_runner_in_one_call() -> None:
    runner, _calls = _scripted_runner({})
    privileged, invocations = _capturing_privileged()
    pm = ProxyManager(runner=runner, privileged_runner=privileged)
    pm.set_proxy("Wi-Fi", "127.0.0.1", 8080)
    assert len(invocations) == 1
    commands, prompt = invocations[0]
    assert commands == [
        ["networksetup", "-setwebproxy", "Wi-Fi", "127.0.0.1", "8080"],
        ["networksetup", "-setsecurewebproxy", "Wi-Fi", "127.0.0.1", "8080"],
        ["networksetup", "-setwebproxystate", "Wi-Fi", "on"],
        ["networksetup", "-setsecurewebproxystate", "Wi-Fi", "on"],
    ]
    assert "macOS web proxy" in prompt


def test_restore_disables_when_backup_was_disabled() -> None:
    runner, _ = _scripted_runner({})
    privileged, invocations = _capturing_privileged()
    pm = ProxyManager(runner=runner, privileged_runner=privileged)
    backup = ProxyBackup(
        service="Wi-Fi",
        web=ProxyState(enabled=False, server=None, port=None),
        secure=ProxyState(enabled=False, server=None, port=None),
    )
    pm.restore(backup)
    assert len(invocations) == 1
    commands, _prompt = invocations[0]
    assert commands == [
        ["networksetup", "-setwebproxystate", "Wi-Fi", "off"],
        ["networksetup", "-setsecurewebproxystate", "Wi-Fi", "off"],
    ]


def test_restore_re_enables_with_original_values() -> None:
    runner, _ = _scripted_runner({})
    privileged, invocations = _capturing_privileged()
    pm = ProxyManager(runner=runner, privileged_runner=privileged)
    backup = ProxyBackup(
        service="Wi-Fi",
        web=ProxyState(enabled=True, server="proxy.example.com", port=3128),
        secure=ProxyState(enabled=True, server="proxy.example.com", port=3128),
    )
    pm.restore(backup)
    assert len(invocations) == 1
    commands, _prompt = invocations[0]
    assert commands == [
        ["networksetup", "-setwebproxy", "Wi-Fi", "proxy.example.com", "3128"],
        ["networksetup", "-setwebproxystate", "Wi-Fi", "on"],
        ["networksetup", "-setsecurewebproxy", "Wi-Fi", "proxy.example.com", "3128"],
        ["networksetup", "-setsecurewebproxystate", "Wi-Fi", "on"],
    ]


def test_set_proxy_raises_authorization_error_on_user_cancel() -> None:
    def cancelled(commands, prompt):
        return _completed(stderr="execution error: User canceled. (-128)", code=1)

    pm = ProxyManager(runner=_scripted_runner({})[0], privileged_runner=cancelled)
    with pytest.raises(ProxyAuthorizationError):
        pm.set_proxy("Wi-Fi", "127.0.0.1", 8080)


def test_set_proxy_propagates_other_failures() -> None:
    def failing(commands, prompt):
        return _completed(stderr="something else broke", code=1)

    pm = ProxyManager(runner=_scripted_runner({})[0], privileged_runner=failing)
    with pytest.raises(ProxyManagerError):
        pm.set_proxy("Wi-Fi", "127.0.0.1", 8080)


def test_build_shell_script_chains_with_and() -> None:
    script = build_shell_script(
        [
            ["networksetup", "-setwebproxy", "Wi-Fi", "127.0.0.1", "8080"],
            ["networksetup", "-setwebproxystate", "Wi-Fi", "on"],
        ]
    )
    assert " && " in script
    assert "Wi-Fi" in script


def test_build_osascript_quotes_arguments_safely() -> None:
    osascript = build_osascript('echo "hi"', "Prompt with \"quotes\"")
    assert osascript.startswith("do shell script ")
    assert "with administrator privileges" in osascript
    assert 'with prompt' in osascript
    assert "\\\"hi\\\"" in osascript
    assert "\\\"quotes\\\"" in osascript


def test_command_failure_raises() -> None:
    def runner(_args: Sequence[str]) -> subprocess.CompletedProcess:
        return _completed(stderr="permission denied", code=1)

    pm = ProxyManager(runner=runner)
    with pytest.raises(ProxyManagerError):
        pm.list_services()


def test_snapshot_combines_web_and_secure() -> None:
    runner, _ = _scripted_runner(
        {
            ("networksetup", "-getwebproxy", "Wi-Fi"): _completed(
                stdout="Enabled: Yes\nServer: 1.1.1.1\nPort: 8080\n"
            ),
            ("networksetup", "-getsecurewebproxy", "Wi-Fi"): _completed(
                stdout="Enabled: Yes\nServer: 1.1.1.1\nPort: 8080\n"
            ),
        }
    )
    pm = ProxyManager(runner=runner)
    snap = pm.snapshot("Wi-Fi")
    assert snap.service == "Wi-Fi"
    assert snap.web.enabled is True
    assert snap.secure.enabled is True


def test_privilege_error_recognizes_osascript_cancel() -> None:
    err = _privilege_error_from(_completed(stderr="User canceled.", code=1))
    assert isinstance(err, ProxyAuthorizationError)


def test_privilege_error_recognizes_touch_id_cancel() -> None:
    err = _privilege_error_from(_completed(stderr="pam_tid: cancelled by user", code=1))
    assert isinstance(err, ProxyAuthorizationError)


def test_privilege_error_recognizes_sudo_password_failure() -> None:
    err = _privilege_error_from(
        _completed(stderr="sudo: 3 incorrect password attempts", code=1)
    )
    assert isinstance(err, ProxyAuthorizationError)


def test_privilege_error_recognizes_sudo_password_required() -> None:
    err = _privilege_error_from(
        _completed(stderr="sudo: a password is required", code=1)
    )
    assert isinstance(err, ProxyAuthorizationError)


def test_default_privileged_runner_uses_sudo_when_touch_id_configured(monkeypatch) -> None:
    captured: dict = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        return _completed(stdout="ok")

    monkeypatch.setattr("mitm_tracker.proxy_manager._can_use_sudo_touch_id", lambda: True)
    monkeypatch.setattr("subprocess.run", fake_run)

    _default_privileged_runner([["networksetup", "-getwebproxy", "Wi-Fi"]], "test")

    assert captured["cmd"][0] == "sudo"
    assert "/bin/bash" in captured["cmd"]
    assert "osascript" not in captured["cmd"]


def test_default_privileged_runner_falls_back_to_osascript(monkeypatch) -> None:
    captured: dict = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        return _completed(stdout="ok")

    monkeypatch.setattr("mitm_tracker.proxy_manager._can_use_sudo_touch_id", lambda: False)
    monkeypatch.setattr("subprocess.run", fake_run)

    _default_privileged_runner([["networksetup", "-getwebproxy", "Wi-Fi"]], "test")

    assert captured["cmd"][0] == "osascript"
