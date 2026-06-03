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
