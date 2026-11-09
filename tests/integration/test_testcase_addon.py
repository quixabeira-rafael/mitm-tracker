from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from mitmproxy.test import taddons, tflow

from mitm_tracker import testplan
from mitm_tracker.addon import TrackerAddon
from mitm_tracker.maplocal import MapLocalStore
from mitm_tracker.testcase_addon import HEADER_ACTION, HEADER_TEST, TestCaseAddon
from mitm_tracker.testplan import ActiveTest, PlanStore


pytestmark = pytest.mark.integration


class Harness:
    def __init__(self, tmp_path: Path, db_path: Path) -> None:
        self.profile_dir = tmp_path / "profile"
        self.active_path = tmp_path / "runtime" / "active_test.json"
        self.plans = PlanStore(self.profile_dir)
        self.plans.create_plan("plan")
        self.case_addon = TestCaseAddon()
        self.tracker = TrackerAddon()
        self.ctx = taddons.context(self.case_addon, self.tracker)
        self.ctx.configure(self.case_addon, tracker_active_test_path=str(self.active_path))
        self.ctx.configure(
            self.tracker,
            tracker_db_path=str(db_path),
            tracker_mode="all",
            tracker_maplocal_dir=str(self.profile_dir),
        )

    def apply(self, case: str, source: str) -> Path:
        path = self.plans.case_path("plan", case)
        path.write_text(source, encoding="utf-8")
        testplan.write_active(
            self.active_path,
            ActiveTest(
                profile="default",
                plan="plan",
                case=case,
                script_path=str(path),
                state_path=str(self.plans.state_path("plan")),
                applied_at=testplan.now_iso(),
            ),
        )
        return path

    async def run(self, flow, *, upstream: bool = True):
        await self.case_addon.request(flow)
        self.tracker.request(flow)
        if flow.error is not None:
            return flow
        if flow.response is None and upstream:
            flow.response = tflow.tresp()
        await self.case_addon.response(flow)
        self.tracker.response(flow)
        return flow


@pytest.fixture
def harness(tmp_path: Path, db_path: Path) -> Harness:
    return Harness(tmp_path, db_path)


async def test_no_active_case_leaves_flow_untouched(harness: Harness) -> None:
    with harness.ctx:
        flow = await harness.run(tflow.tflow(resp=False))
    assert HEADER_TEST not in flow.response.headers


async def test_respond_short_circuits_and_on_response_runs(harness: Harness) -> None:
    harness.apply(
        "local",
        "def on_request(request):\n"
        "    request.respond(503, json={'error': 'down'})\n"
        "def on_response(request, response):\n"
        "    response.headers['X-Seen'] = 'yes'\n",
    )
    with harness.ctx:
        flow = await harness.run(tflow.tflow(resp=False), upstream=False)
    assert flow.response.status_code == 503
    assert json.loads(flow.response.content) == {"error": "down"}
    assert flow.response.headers["X-Seen"] == "yes"
    assert flow.response.headers[HEADER_TEST] == "plan/local"
    assert flow.response.headers[HEADER_ACTION] == "responded"


async def test_request_modification_is_reported(harness: Harness) -> None:
    harness.apply(
        "rewrite",
        "def on_request(request):\n"
        "    request.headers['X-Test'] = '1'\n",
    )
    with harness.ctx:
        flow = await harness.run(tflow.tflow(resp=False))
    assert flow.request.headers["X-Test"] == "1"
    assert flow.response.headers[HEADER_ACTION] == "modified"


async def test_untouched_flow_is_passthrough(harness: Harness) -> None:
    harness.apply("noop", "def on_response(request, response):\n    pass\n")
    with harness.ctx:
        flow = await harness.run(tflow.tflow(resp=False))
    assert flow.response.headers[HEADER_ACTION] == "passthrough"


async def test_claims_bypass_maplocal(harness: Harness) -> None:
    MapLocalStore(profile_dir=harness.profile_dir).add(
        url_pattern="http://address:22/path", status=418, body=b"mock"
    )
    with harness.ctx:
        mocked = await harness.run(tflow.tflow(resp=False), upstream=False)
    assert mocked.response.status_code == 418

    harness.apply(
        "claims",
        'CLAIMS = ["http://address:22/path"]\n'
        "def on_response(request, response):\n    pass\n",
    )
    with harness.ctx:
        flow = await harness.run(tflow.tflow(resp=False))
    assert flow.response.status_code == 200
    assert flow.response.headers[HEADER_ACTION] == "claimed"


async def test_maplocal_still_serves_unclaimed_requests(harness: Harness) -> None:
    MapLocalStore(profile_dir=harness.profile_dir).add(
        url_pattern="http://address:22/path", status=418, body=b"mock"
    )
    harness.apply(
        "patch",
        "def on_response(request, response):\n"
        "    response.headers['X-Patched'] = '1'\n",
    )
    with harness.ctx:
        flow = await harness.run(tflow.tflow(resp=False), upstream=False)
    assert flow.response.status_code == 418
    assert flow.response.headers["X-Patched"] == "1"


async def test_claim_call_bypasses_maplocal(harness: Harness) -> None:
    MapLocalStore(profile_dir=harness.profile_dir).add(
        url_pattern="http://address:22/path", status=418, body=b"mock"
    )
    harness.apply("claim", "def on_request(request):\n    request.claim()\n")
    with harness.ctx:
        flow = await harness.run(tflow.tflow(resp=False))
    assert flow.response.status_code == 200


async def test_abort_kills_flow(harness: Harness) -> None:
    harness.apply("abort", "def on_request(request):\n    request.abort()\n")
    with harness.ctx:
        flow = await harness.run(tflow.tflow(resp=False))
    assert flow.error is not None
    assert flow.response is None


async def test_hook_error_reverts_changes_and_is_recorded(harness: Harness) -> None:
    harness.apply(
        "broken",
        "def on_request(request):\n"
        "    request.headers['X-Partial'] = '1'\n"
        "    raise RuntimeError('boom')\n"
        "def on_response(request, response):\n"
        "    response.status = 418\n"
        "    raise ValueError('bad')\n",
    )
    with harness.ctx:
        flow = await harness.run(tflow.tflow(resp=False))
    assert "X-Partial" not in flow.request.headers
    assert flow.response.status_code == 200
    error = testplan.read_error(harness.active_path)
    assert error["hook"] == "on_response"
    assert "bad" in error["error"]


async def test_store_is_injected_and_persists(harness: Harness) -> None:
    harness.apply(
        "first_fails",
        "def on_request(request):\n"
        "    if store.incr('calls') == 1:\n"
        "        request.respond(500)\n",
    )
    with harness.ctx:
        first = await harness.run(tflow.tflow(resp=False), upstream=False)
        second = await harness.run(tflow.tflow(resp=False))
    assert first.response.status_code == 500
    assert second.response.status_code == 200
    state = json.loads(harness.plans.state_path("plan").read_text(encoding="utf-8"))
    assert state == {"calls": 2}


async def test_script_edit_and_clear_are_hot_reloaded(harness: Harness) -> None:
    path = harness.apply("edit", "def on_request(request):\n    request.respond(201)\n")
    with harness.ctx:
        flow = await harness.run(tflow.tflow(resp=False), upstream=False)
        assert flow.response.status_code == 201

        path.write_text("def on_request(request):\n    request.respond(202)\n", encoding="utf-8")
        stat = path.stat()
        os.utime(path, ns=(stat.st_atime_ns, stat.st_mtime_ns + 1_000_000))
        flow = await harness.run(tflow.tflow(resp=False), upstream=False)
        assert flow.response.status_code == 202

        testplan.clear_active(harness.active_path)
        flow = await harness.run(tflow.tflow(resp=False))
        assert flow.response.status_code == 200
        assert HEADER_TEST not in flow.response.headers


async def test_load_failure_disables_case_and_records_error(harness: Harness) -> None:
    path = harness.apply("bad", "def on_request(request):\n    pass\nraise RuntimeError('import time')\n")
    with harness.ctx:
        flow = await harness.run(tflow.tflow(resp=False))
        assert HEADER_TEST not in flow.response.headers
        assert testplan.read_error(harness.active_path)["hook"] == "load"

        path.write_text("def on_request(request):\n    request.respond(204)\n", encoding="utf-8")
        flow = await harness.run(tflow.tflow(resp=False), upstream=False)
        assert flow.response.status_code == 204


async def test_delays_hold_the_flow(harness: Harness, monkeypatch: pytest.MonkeyPatch) -> None:
    slept: list[float] = []

    async def fake_sleep(seconds: float) -> None:
        slept.append(seconds)

    monkeypatch.setattr("mitm_tracker.testcase_addon.asyncio.sleep", fake_sleep)
    harness.apply(
        "delays",
        "def on_request(request):\n    request.delay = 300\n"
        "def on_response(request, response):\n    response.delay = 1500\n",
    )
    with harness.ctx:
        await harness.run(tflow.tflow(resp=False))
    assert slept == [0.3, 1.5]
