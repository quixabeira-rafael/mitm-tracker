from __future__ import annotations

import asyncio
import logging
import threading
import traceback
from pathlib import Path
from types import ModuleType

from mitmproxy import ctx
from mitmproxy.http import HTTPFlow

from mitm_tracker import testplan
from mitm_tracker.testcase_api import FlowControl, Request, Response, StateStore
from mitm_tracker.url_matcher import CompiledPattern, compile_pattern
from mitm_tracker.url_matcher import matches as url_matches

log = logging.getLogger("mitm_tracker.testcase")

METADATA_KEY = "mitm_tracker.test"
HEADER_TEST = "X-Mitm-Test"
HEADER_ACTION = "X-Mitm-Test-Action"

ACTION_ABORTED = "aborted"
ACTION_RESPONDED = "responded"
ACTION_MODIFIED = "modified"
ACTION_CLAIMED = "claimed"
ACTION_PASSTHROUGH = "passthrough"


def is_claimed(flow: HTTPFlow) -> bool:
    entry = flow.metadata.get(METADATA_KEY)
    return bool(entry and entry["control"].claimed)


class _LoadedCase:
    def __init__(
        self,
        active: testplan.ActiveTest,
        module: ModuleType | None,
        claims: list[CompiledPattern],
        script_signature: tuple | None,
    ) -> None:
        self.active = active
        self.module = module
        self.claims = claims
        self.script_signature = script_signature

    def hook(self, name: str):
        fn = getattr(self.module, name, None)
        return fn if callable(fn) else None


class TestCaseAddon:
    __test__ = False

    def __init__(self) -> None:
        self._active_path: Path | None = None
        self._active_signature: tuple | None = None
        self._case: _LoadedCase | None = None
        self._lock = threading.Lock()

    def load(self, loader) -> None:
        loader.add_option(
            name="tracker_active_test_path",
            typespec=str,
            default="",
            help="Path to the runtime file naming the active test case.",
        )

    def configure(self, updates) -> None:
        if "tracker_active_test_path" in updates:
            value = ctx.options.tracker_active_test_path
            self._active_path = Path(value) if value else None
            self._active_signature = None
            self._case = None

    async def request(self, flow: HTTPFlow) -> None:
        case = self._current_case()
        if case is None:
            return
        control = FlowControl()
        url = flow.request.pretty_url
        if any(url_matches(pattern, url) for pattern in case.claims):
            control.claimed = True
        entry = {"label": case.active.label, "control": control, "modified": False}
        flow.metadata[METADATA_KEY] = entry

        hook = case.hook("on_request")
        if hook is not None:
            before = flow.request.get_state()
            claimed_before = control.claimed
            try:
                hook(Request(flow, control))
            except Exception:
                flow.request.set_state(before)
                flow.response = None
                control.claimed = claimed_before
                control.responded = False
                control.aborted = False
                control.request_delay_ms = 0
                control.response_delay_ms = 0
                self._report_error(case, "on_request", flow)
            else:
                entry["modified"] = flow.request.get_state() != before

        if control.aborted:
            if flow.killable:
                flow.kill()
            return
        if control.request_delay_ms:
            await asyncio.sleep(control.request_delay_ms / 1000.0)

    async def response(self, flow: HTTPFlow) -> None:
        entry = flow.metadata.get(METADATA_KEY)
        if entry is None or flow.response is None:
            return
        control: FlowControl = entry["control"]
        case = self._case
        hook = case.hook("on_response") if case and case.active.label == entry["label"] else None
        if hook is not None:
            before = flow.response.get_state()
            delay_before = control.response_delay_ms
            try:
                hook(Request(flow, control), Response(flow, control))
            except Exception:
                flow.response.set_state(before)
                control.response_delay_ms = delay_before
                self._report_error(case, "on_response", flow)
            else:
                if flow.response.get_state() != before:
                    entry["modified"] = True

        flow.response.headers[HEADER_TEST] = entry["label"]
        flow.response.headers[HEADER_ACTION] = _action(control, entry["modified"])
        if control.response_delay_ms:
            await asyncio.sleep(control.response_delay_ms / 1000.0)

    def _current_case(self) -> _LoadedCase | None:
        if self._active_path is None:
            return None
        with self._lock:
            signature = _file_signature(self._active_path)
            if signature != self._active_signature:
                self._active_signature = signature
                self._case = None
                active = testplan.read_active(self._active_path) if signature else None
                if active is not None:
                    self._case = self._load_case(active)
                    log.info("Test case active: %s", active.label)
                else:
                    log.info("No active test case")
            elif self._case is not None:
                script_signature = _file_signature(Path(self._case.active.script_path))
                if script_signature != self._case.script_signature:
                    self._case = self._load_case(self._case.active)
                    log.info("Test case reloaded: %s", self._case.active.label)
            if self._case is None or self._case.module is None:
                return None
            return self._case

    def _load_case(self, active: testplan.ActiveTest) -> _LoadedCase:
        script = Path(active.script_path)
        signature = _file_signature(script)
        try:
            source = script.read_text(encoding="utf-8")
            module = ModuleType(f"mitm_tracker_case_{active.plan}_{active.case}")
            module.__file__ = str(script)
            module.store = StateStore(Path(active.state_path))
            exec(compile(source, str(script), "exec"), module.__dict__)
            claims = [compile_pattern(p) for p in getattr(module, testplan.CLAIMS_NAME, None) or []]
        except Exception as exc:
            log.error("Failed to load test case %s: %s", active.label, exc)
            self._write_error(active, "load", None, exc)
            return _LoadedCase(active, None, [], signature)
        return _LoadedCase(active, module, claims, signature)

    def _report_error(self, case: _LoadedCase, hook: str, flow: HTTPFlow) -> None:
        log.error(
            "Test case %s %s failed for %s:\n%s",
            case.active.label,
            hook,
            flow.request.pretty_url,
            traceback.format_exc(),
        )
        self._write_error(case.active, hook, flow.request.pretty_url, None)

    def _write_error(
        self,
        active: testplan.ActiveTest,
        hook: str,
        url: str | None,
        exc: BaseException | None,
    ) -> None:
        if self._active_path is None:
            return
        try:
            testplan.record_error(
                self._active_path,
                {
                    "plan": active.plan,
                    "case": active.case,
                    "hook": hook,
                    "url": url,
                    "error": str(exc) if exc is not None else traceback.format_exc().strip().splitlines()[-1],
                    "traceback": traceback.format_exc(),
                },
            )
        except OSError:
            log.exception("Failed to record test case error")


def _action(control: FlowControl, modified: bool) -> str:
    if control.aborted:
        return ACTION_ABORTED
    if control.responded:
        return ACTION_RESPONDED
    if modified:
        return ACTION_MODIFIED
    if control.claimed:
        return ACTION_CLAIMED
    return ACTION_PASSTHROUGH


def _file_signature(path: Path) -> tuple | None:
    try:
        stat = path.stat()
    except OSError:
        return None
    return (stat.st_mtime_ns, stat.st_size)
