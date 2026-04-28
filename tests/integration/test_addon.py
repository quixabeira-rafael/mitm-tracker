from __future__ import annotations

import json
from pathlib import Path

import pytest
from mitmproxy.test import taddons, tflow

from mitm_tracker.addon import TrackerAddon, build_request_payload, build_response_payload
from mitm_tracker.store import FlowStore


pytestmark = pytest.mark.integration


def _bootstrap_addon(db_path: Path) -> tuple[TrackerAddon, taddons.context]:
    addon = TrackerAddon()
    ctx = taddons.context(addon)
    ctx.configure(
        addon,
        tracker_db_path=str(db_path),
        tracker_mode="all",
    )
    return addon, ctx


def test_request_hook_writes_row(db_path: Path) -> None:
    addon, ctx = _bootstrap_addon(db_path)
    with ctx:
        flow = tflow.tflow(resp=False)
        addon.request(flow)

    reader = FlowStore(db_path, read_only=True)
    rows = reader.query_recent()
    assert len(rows) == 1
    assert rows[0]["seq"] == 1
    assert rows[0]["flow_uuid"] == flow.id
    assert rows[0]["method"] == flow.request.method
    assert rows[0]["host"] == flow.request.pretty_host
    assert rows[0]["response_status_code"] is None
    reader.close()


def test_request_then_response_updates_same_row(db_path: Path) -> None:
    addon, ctx = _bootstrap_addon(db_path)
    with ctx:
        flow = tflow.tflow(resp=True)
        addon.request(flow)
        addon.response(flow)

    reader = FlowStore(db_path, read_only=True)
    rows = reader.query_recent()
    assert len(rows) == 1
    row = rows[0]
    assert row["response_status_code"] == flow.response.status_code
    assert row["response_reason"] == flow.response.reason
    assert row["duration_total_ms"] is not None
    reader.close()


def test_error_hook_records_message(db_path: Path) -> None:
    addon, ctx = _bootstrap_addon(db_path)
    with ctx:
        flow = tflow.tflow(err=True)
        addon.request(flow)
        addon.error(flow)

    reader = FlowStore(db_path, read_only=True)
    rows = reader.query_recent()
    assert len(rows) == 1
    assert rows[0]["error_msg"]
    reader.close()


def test_seq_is_monotonic_for_multiple_flows(db_path: Path) -> None:
    addon, ctx = _bootstrap_addon(db_path)
    with ctx:
        flows = [tflow.tflow(resp=True) for _ in range(5)]
        for flow in flows:
            addon.request(flow)
        for flow in flows:
            addon.response(flow)

    reader = FlowStore(db_path, read_only=True)
    rows = reader.query_recent(limit=10)
    seqs = [r["seq"] for r in rows]
    assert seqs == [1, 2, 3, 4, 5]
    reader.close()


def test_response_without_request_is_ignored(db_path: Path) -> None:
    addon, ctx = _bootstrap_addon(db_path)
    with ctx:
        flow = tflow.tflow(resp=True)
        addon.response(flow)

    reader = FlowStore(db_path, read_only=True)
    assert reader.count() == 0
    reader.close()


def test_done_finalizes_session(db_path: Path) -> None:
    addon, ctx = _bootstrap_addon(db_path)
    with ctx:
        flow = tflow.tflow(resp=True)
        addon.request(flow)
        addon.response(flow)
        addon.done()

    reader = FlowStore(db_path, read_only=True)
    info = reader.session_info()
    assert info is not None
    assert info["ended_at"] is not None
    reader.close()


def test_listed_mode_drops_everything_for_now(db_path: Path) -> None:
    addon = TrackerAddon()
    ctx = taddons.context(addon)
    ctx.configure(
        addon,
        tracker_db_path=str(db_path),
        tracker_mode="listed",
    )
    with ctx:
        flow = tflow.tflow(resp=True)
        addon.request(flow)
        addon.response(flow)

    reader = FlowStore(db_path, read_only=True)
    assert reader.count() == 0
    reader.close()


def test_body_truncation_flags_oversize(db_path: Path) -> None:
    addon = TrackerAddon()
    ctx = taddons.context(addon)
    ctx.configure(
        addon,
        tracker_db_path=str(db_path),
        tracker_mode="all",
        tracker_body_limit=8,
    )
    with ctx:
        flow = tflow.tflow(resp=True)
        flow.request.set_content(b"X" * 64)
        addon.request(flow)
        flow.response.set_content(b"Y" * 64)
        addon.response(flow)

    reader = FlowStore(db_path, read_only=True)
    rows = reader.query_recent()
    assert len(rows) == 1
    row = rows[0]
    assert row["request_body_truncated"] == 1
    assert row["request_body_size"] == 64
    assert row["response_body_truncated"] == 1
    assert row["response_body_size"] == 64
    reader.close()


def test_build_request_payload_serializes_headers() -> None:
    flow = tflow.tflow(resp=False)
    flow.request.headers["X-Custom"] = "value"
    payload = build_request_payload(flow, seq=1)
    decoded = json.loads(payload["request_headers"])
    assert ["X-Custom", "value"] in decoded


def test_build_response_payload_returns_empty_when_no_response() -> None:
    flow = tflow.tflow(resp=False)
    assert build_response_payload(flow) == {}


def test_maplocal_rule_short_circuits_request(db_path: Path, tmp_path: Path) -> None:
    from mitm_tracker.maplocal import MapLocalStore

    profile_dir = tmp_path / "profile"
    store = MapLocalStore(profile_dir=profile_dir)
    rule = store.add(
        url_pattern="http://address:22/path",
        status=418,
        headers=[("Content-Type", "application/json"), ("X-Mock", "yes")],
        body=b'{"mocked":true}',
        description="teapot mock",
    )

    addon = TrackerAddon()
    ctx = taddons.context(addon)
    ctx.configure(
        addon,
        tracker_db_path=str(db_path),
        tracker_mode="all",
        tracker_maplocal_dir=str(profile_dir),
    )
    with ctx:
        flow = tflow.tflow(resp=False)
        addon.request(flow)

    assert flow.response is not None
    assert flow.response.status_code == 418
    assert flow.response.content == b'{"mocked":true}'
    assert flow.response.headers["Content-Type"] == "application/json"
    assert flow.response.headers["X-Mock"] == "yes"

    reader = FlowStore(db_path, read_only=True)
    rows = reader.query_recent()
    assert len(rows) == 1
    row = rows[0]
    assert row["mocked"] == 1
    assert row["mock_rule_id"] == rule.id
    assert row["mock_rule_description"] == "teapot mock"
    assert row["response_status_code"] == 418
    reader.close()


def test_maplocal_disabled_rule_does_not_match(db_path: Path, tmp_path: Path) -> None:
    from mitm_tracker.maplocal import MapLocalStore

    profile_dir = tmp_path / "profile"
    store = MapLocalStore(profile_dir=profile_dir)
    rule = store.add(
        url_pattern="http://address:22/path",
        status=200,
        body=b"unused",
    )
    store.set_enabled(rule.id, False)

    addon = TrackerAddon()
    ctx = taddons.context(addon)
    ctx.configure(
        addon,
        tracker_db_path=str(db_path),
        tracker_mode="all",
        tracker_maplocal_dir=str(profile_dir),
    )
    with ctx:
        flow = tflow.tflow(resp=False)
        addon.request(flow)

    reader = FlowStore(db_path, read_only=True)
    rows = reader.query_recent()
    assert len(rows) == 1
    assert rows[0]["mocked"] == 0
    assert rows[0]["mock_rule_id"] is None
    reader.close()


def test_maplocal_hot_reload_picks_up_new_rule(db_path: Path, tmp_path: Path) -> None:
    from mitm_tracker.maplocal import MapLocalStore

    profile_dir = tmp_path / "profile"
    store = MapLocalStore(profile_dir=profile_dir)

    addon = TrackerAddon()
    ctx = taddons.context(addon)
    ctx.configure(
        addon,
        tracker_db_path=str(db_path),
        tracker_mode="all",
        tracker_maplocal_dir=str(profile_dir),
    )
    with ctx:
        first = tflow.tflow(resp=False)
        addon.request(first)
        assert first.response is None  # no rule yet, request not mocked

        store.add(
            url_pattern="http://address:22/path",
            status=418,
            headers=[("Content-Type", "text/plain")],
            body=b"hot-reloaded",
        )

        second = tflow.tflow(resp=False)
        addon.request(second)
        assert second.response is not None
        assert second.response.status_code == 418
        assert second.response.content == b"hot-reloaded"


def test_maplocal_hot_reload_picks_up_body_change(db_path: Path, tmp_path: Path) -> None:
    import time as _time
    from mitm_tracker.maplocal import MapLocalStore

    profile_dir = tmp_path / "profile"
    store = MapLocalStore(profile_dir=profile_dir)
    rule = store.add(
        url_pattern="http://address:22/path",
        status=200,
        headers=[("Content-Type", "text/plain")],
        body=b"original",
    )

    addon = TrackerAddon()
    ctx = taddons.context(addon)
    ctx.configure(
        addon,
        tracker_db_path=str(db_path),
        tracker_mode="all",
        tracker_maplocal_dir=str(profile_dir),
    )
    with ctx:
        first = tflow.tflow(resp=False)
        addon.request(first)
        assert first.response.content == b"original"

        # Force mtime increment so signature changes
        _time.sleep(1.1)
        store.write_body(rule.id, b"updated")

        second = tflow.tflow(resp=False)
        addon.request(second)
        assert second.response.content == b"updated"


def test_maplocal_hot_reload_drops_disabled_rule(db_path: Path, tmp_path: Path) -> None:
    import time as _time
    from mitm_tracker.maplocal import MapLocalStore

    profile_dir = tmp_path / "profile"
    store = MapLocalStore(profile_dir=profile_dir)
    rule = store.add(
        url_pattern="http://address:22/path",
        status=200,
        body=b"mocked",
    )

    addon = TrackerAddon()
    ctx = taddons.context(addon)
    ctx.configure(
        addon,
        tracker_db_path=str(db_path),
        tracker_mode="all",
        tracker_maplocal_dir=str(profile_dir),
    )
    with ctx:
        first = tflow.tflow(resp=False)
        addon.request(first)
        assert first.response is not None  # initially mocked

        _time.sleep(1.1)
        store.set_enabled(rule.id, False)

        second = tflow.tflow(resp=False)
        addon.request(second)
        assert second.response is None  # rule disabled, request passes through


def test_maplocal_no_match_passes_request_through(db_path: Path, tmp_path: Path) -> None:
    from mitm_tracker.maplocal import MapLocalStore

    profile_dir = tmp_path / "profile"
    store = MapLocalStore(profile_dir=profile_dir)
    store.add(
        url_pattern="http://other.example.com/x",
        body=b"not used",
    )

    addon = TrackerAddon()
    ctx = taddons.context(addon)
    ctx.configure(
        addon,
        tracker_db_path=str(db_path),
        tracker_mode="all",
        tracker_maplocal_dir=str(profile_dir),
    )
    with ctx:
        flow = tflow.tflow(resp=False)
        addon.request(flow)

    assert flow.response is None
    reader = FlowStore(db_path, read_only=True)
    rows = reader.query_recent()
    assert rows[0]["mocked"] == 0
    reader.close()
