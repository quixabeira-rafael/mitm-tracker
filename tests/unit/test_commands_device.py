from __future__ import annotations

import json
from pathlib import Path

from mitm_tracker import net_info
from mitm_tracker.cli import main
from mitm_tracker.commands import device as device_module
from mitm_tracker.config import workspace_for
from mitm_tracker.output import EXIT_INVALID_STATE, EXIT_OK
from mitm_tracker.session_manager import SessionManager


def test_status_no_session(tmp_repo: Path, capsys):
    rc = main(["device", "status", "--json"])
    assert rc == EXIT_OK
    payload = json.loads(capsys.readouterr().out)
    assert payload["running"] is False
    assert payload["lan_bound"] is False


def test_status_reports_lan_binding(tmp_repo: Path, monkeypatch, capsys):
    ws = workspace_for()
    ws.ensure()
    sm = SessionManager(ws)
    sm.start(
        pid=4242,
        mode="all",
        port=8080,
        session_db=ws.captures_dir / "s.db",
        proxy_service=None,
        listen_host="0.0.0.0",
    )
    sm.set_device_help(help_pid=4243, help_port=8888, lan_ip="192.168.1.7")
    monkeypatch.setattr(SessionManager, "is_running", lambda self: True)

    rc = main(["device", "status", "--json"])
    assert rc == EXIT_OK
    payload = json.loads(capsys.readouterr().out)
    assert payload["running"] is True
    assert payload["lan_bound"] is True
    assert payload["lan_ip"] == "192.168.1.7"
    assert payload["help_url"] == "http://192.168.1.7:8888/"


def test_start_fails_without_lan_ip(tmp_repo: Path, monkeypatch, capsys):
    monkeypatch.setattr(
        device_module.cert_manager,
        "ensure_ca_exists",
        lambda *a, **k: tmp_repo / "ca.pem",
    )
    monkeypatch.setattr(
        net_info,
        "lan_address",
        lambda **kw: net_info.LanAddress(service=None, ip=None, source="none"),
    )

    rc = main(["device", "start", "--json"])
    assert rc == EXIT_INVALID_STATE
    err = capsys.readouterr().err
    assert "no_lan_ip" in err


def test_start_wireguard_generates_keyfile_and_uses_wireguard_mode(
    tmp_repo: Path, monkeypatch, capsys
):
    from mitm_tracker.commands import record as record_module

    ca = tmp_repo / "ca.pem"
    ca.write_text("x", encoding="ascii")
    monkeypatch.setattr(device_module.cert_manager, "ensure_ca_exists", lambda *a, **k: ca)
    monkeypatch.setattr(
        net_info,
        "lan_address",
        lambda **kw: net_info.LanAddress(service="Wi-Fi", ip="192.168.1.44", source="networksetup"),
    )

    captured = {}

    def fake_launch(**kwargs):
        captured.update(kwargs)
        return record_module.ProxyLaunchResult(
            pid=4242,
            mode="all",
            port=kwargs["port"],
            listen_host=kwargs["listen_host"],
            profile="default",
            session_db=workspace_for().captures_dir / "s.db",
            ssl_count=3,
            proxy_service=None,
            no_cache=True,
            proxy_mode=kwargs["proxy_mode"],
        )

    monkeypatch.setattr(record_module, "launch_proxy", fake_launch)
    monkeypatch.setattr(device_module, "_spawn_help_server", lambda **kw: 4243)

    rc = main(["device", "start", "--transport", "wireguard", "--json"])
    assert rc == EXIT_OK
    payload = json.loads(capsys.readouterr().out)
    assert payload["transport"] == "wireguard"
    assert captured["proxy_mode"] == "wireguard"
    assert captured["wireguard_keyfile"] is not None
    # keyfile was generated in the workspace runtime dir
    assert workspace_for().wireguard_keyfile.exists()


def test_start_forwards_the_session_delay(tmp_repo: Path, monkeypatch, capsys):
    from mitm_tracker.commands import record as record_module
    from mitm_tracker.delay import DelayProfile

    ca = tmp_repo / "ca.pem"
    ca.write_text("x", encoding="ascii")
    monkeypatch.setattr(device_module.cert_manager, "ensure_ca_exists", lambda *a, **k: ca)
    monkeypatch.setattr(
        net_info,
        "lan_address",
        lambda **kw: net_info.LanAddress(service="Wi-Fi", ip="192.168.1.44", source="networksetup"),
    )

    captured = {}

    def fake_launch(**kwargs):
        captured.update(kwargs)
        return record_module.ProxyLaunchResult(
            pid=4242,
            mode="all",
            port=kwargs["port"],
            listen_host=kwargs["listen_host"],
            profile="default",
            session_db=workspace_for().captures_dir / "s.db",
            ssl_count=3,
            proxy_service=None,
            no_cache=True,
            proxy_mode=kwargs["proxy_mode"],
            delay=kwargs["delay"],
        )

    monkeypatch.setattr(record_module, "launch_proxy", fake_launch)
    monkeypatch.setattr(device_module, "_spawn_help_server", lambda **kw: 4243)

    rc = main(
        ["device", "start", "--delay", "1s", "--delay-jitter", "250ms", "--json"]
    )
    assert rc == EXIT_OK
    payload = json.loads(capsys.readouterr().out)
    assert captured["delay"] == DelayProfile(base_ms=1000, jitter_ms=250)
    assert payload["delay_ms"] == 1000
    assert payload["delay_jitter_ms"] == 250


def test_start_rejects_invalid_delay(tmp_repo: Path, monkeypatch, capsys):
    from mitm_tracker.commands import record as record_module

    ca = tmp_repo / "ca.pem"
    ca.write_text("x", encoding="ascii")
    monkeypatch.setattr(device_module.cert_manager, "ensure_ca_exists", lambda *a, **k: ca)
    monkeypatch.setattr(
        net_info,
        "lan_address",
        lambda **kw: net_info.LanAddress(service="Wi-Fi", ip="192.168.1.44", source="networksetup"),
    )

    def fake_launch(**kwargs):
        raise AssertionError("launch_proxy should not run with an invalid delay")

    monkeypatch.setattr(record_module, "launch_proxy", fake_launch)

    rc = main(["device", "start", "--delay", "soon", "--json"])
    assert rc == EXIT_INVALID_STATE
    assert json.loads(capsys.readouterr().err)["error"] == "invalid_delay"


def test_status_reports_wireguard_transport(tmp_repo: Path, monkeypatch, capsys):
    ws = workspace_for()
    ws.ensure()
    sm = SessionManager(ws)
    sm.start(
        pid=1234,
        mode="all",
        port=51820,
        session_db=ws.captures_dir / "s.db",
        proxy_service=None,
        listen_host="0.0.0.0",
        proxy_mode="wireguard",
    )
    sm.set_device_help(help_pid=1235, help_port=8888, lan_ip="192.168.1.44")
    monkeypatch.setattr(SessionManager, "is_running", lambda self: True)

    rc = main(["device", "status", "--json"])
    assert rc == EXIT_OK
    payload = json.loads(capsys.readouterr().out)
    assert payload["transport"] == "wireguard"
    assert payload["help_url"] == "http://192.168.1.44:8888/"


def test_status_reports_wifi_proxy_transport(tmp_repo: Path, monkeypatch, capsys):
    ws = workspace_for()
    ws.ensure()
    sm = SessionManager(ws)
    sm.start(
        pid=1234,
        mode="all",
        port=8080,
        session_db=ws.captures_dir / "s.db",
        proxy_service=None,
        listen_host="0.0.0.0",
        proxy_mode="regular",
    )
    monkeypatch.setattr(SessionManager, "is_running", lambda self: True)

    rc = main(["device", "status", "--json"])
    assert rc == EXIT_OK
    payload = json.loads(capsys.readouterr().out)
    assert payload["transport"] == "wifi-proxy"
