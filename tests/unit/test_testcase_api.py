from __future__ import annotations

import json
import multiprocessing
import threading
from pathlib import Path

import pytest
from mitmproxy.test import tflow

from mitm_tracker.testcase_api import FlowControl, Request, Response, StateStore


def _incr_many(path: str, count: int) -> None:
    store = StateStore(Path(path))
    for _ in range(count):
        store.incr("hits")


def test_store_basic_operations(tmp_path: Path) -> None:
    store = StateStore(tmp_path / "state.json")
    assert store.get("missing", "fallback") == "fallback"
    store.set("user", {"id": 1})
    assert store.get("user") == {"id": 1}
    assert store.incr("n") == 1
    assert store.incr("n", 5) == 6
    assert store.delete("user") is True
    assert store.delete("user") is False
    assert store.all() == {"n": 6}
    store.clear()
    assert store.all() == {}


def test_store_file_is_readable_json(tmp_path: Path) -> None:
    path = tmp_path / "state.json"
    store = StateStore(path)
    store.set("b", 2)
    store.set("a", 1)
    text = path.read_text(encoding="utf-8")
    assert text == '{\n  "a": 1,\n  "b": 2\n}\n'


def test_store_sees_external_edits(tmp_path: Path) -> None:
    path = tmp_path / "state.json"
    store = StateStore(path)
    store.set("a", 1)
    path.write_text(json.dumps({"a": 99}), encoding="utf-8")
    assert store.get("a") == 99


def test_store_rejects_non_serializable_and_non_int_incr(tmp_path: Path) -> None:
    store = StateStore(tmp_path / "state.json")
    with pytest.raises(TypeError):
        store.set("obj", object())
    store.set("s", "text")
    with pytest.raises(TypeError):
        store.incr("s")
    assert store.all() == {"s": "text"}


def test_store_incr_is_thread_safe(tmp_path: Path) -> None:
    store = StateStore(tmp_path / "state.json")
    threads = [threading.Thread(target=lambda: [store.incr("hits") for _ in range(50)]) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert store.get("hits") == 400


def test_store_incr_is_process_safe(tmp_path: Path) -> None:
    path = tmp_path / "state.json"
    ctx = multiprocessing.get_context("spawn")
    procs = [ctx.Process(target=_incr_many, args=(str(path), 40)) for _ in range(4)]
    for p in procs:
        p.start()
    for p in procs:
        p.join(30)
    assert all(p.exitcode == 0 for p in procs)
    assert StateStore(path).get("hits") == 160


def test_request_wrapper_reads_and_mutates() -> None:
    flow = tflow.tflow(resp=False)
    flow.request.path = "/path?a=1"
    request = Request(flow, FlowControl())

    assert request.method == "GET"
    assert request.path == "/path"
    assert request.query["a"] == "1"
    assert request.url == "http://address:22/path?a=1"

    request.method = "post"
    request.path = "/other"
    request.query["b"] = "2"
    request.headers["X-Test"] = "1"
    request.json = {"k": "v"}

    assert flow.request.method == "POST"
    assert flow.request.path == "/other?a=1&b=2"
    assert flow.request.headers["X-Test"] == "1"
    assert flow.request.headers["Content-Type"] == "application/json"
    assert json.loads(flow.request.content) == {"k": "v"}


def test_request_matches_uses_maplocal_patterns() -> None:
    flow = tflow.tflow(resp=False)
    request = Request(flow, FlowControl())
    assert request.matches("http://address:22/path")
    assert request.matches("http://address:22/**")
    assert not request.matches("http://address:22/other")


def test_request_respond_builds_local_response_and_claims() -> None:
    flow = tflow.tflow(resp=False)
    control = FlowControl()
    Request(flow, control).respond(503, json={"e": 1}, headers={"Retry-After": "5"}, delay=250)

    assert flow.response.status_code == 503
    assert flow.response.reason == "Service Unavailable"
    assert flow.response.headers["Content-Type"] == "application/json"
    assert flow.response.headers["Retry-After"] == "5"
    assert json.loads(flow.response.content) == {"e": 1}
    assert control.responded and control.claimed
    assert control.response_delay_ms == 250


def test_request_abort_and_claim_set_control_flags() -> None:
    control = FlowControl()
    request = Request(tflow.tflow(resp=False), control)
    request.claim()
    assert control.claimed and not control.aborted
    request.abort()
    assert control.aborted
    request.delay = 300
    assert control.request_delay_ms == 300


def test_response_wrapper_status_sets_reason_and_body_helpers() -> None:
    flow = tflow.tflow(resp=True)
    flow.response.set_content(b'{"a": 1}')
    response = Response(flow, FlowControl())

    assert response.json == {"a": 1}
    response.status = 201
    assert flow.response.reason == "Created"
    response.json = {"a": 2}
    assert json.loads(flow.response.content) == {"a": 2}
    response.text = "plain"
    assert flow.response.content == b"plain"
    response.delay = 1500
    assert response.delay == 1500
