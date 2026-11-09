from __future__ import annotations

import argparse
import json
from typing import Any

from mitm_tracker import testplan
from mitm_tracker.config import workspace_for
from mitm_tracker.output import (
    EXIT_INVALID_STATE,
    EXIT_OK,
    emit_error,
    emit_json,
    emit_text,
    render_table,
)
from mitm_tracker.profile_manager import ProfileManager
from mitm_tracker.session_manager import SessionManager
from mitm_tracker.testcase_api import StateStore
from mitm_tracker.testcase_reference import REFERENCE, render_text


TEST_DESCRIPTION = """\
Script scenarios against live traffic. A test plan groups test cases under a
title and description; each test case is a Python script with optional
on_request(request) / on_response(request, response) hooks. Only one case is
active at a time, and only while a proxy session is running.
"""

TEST_EPILOG = """\
workflow:
  mitm-tracker test new --test checkout --title "Checkout"
  mitm-tracker test new-case --test checkout --test-case cart_returns_400
  # edit .mitm-tracker/profiles/<profile>/tests/checkout/cart_returns_400.py
  mitm-tracker record start
  mitm-tracker test apply --test checkout --test-case cart_returns_400
  mitm-tracker test status          # active case + last script error
  mitm-tracker test clear

script example:
  CLAIMS = ["https://api.example.com/cart/**"]   # claimed URLs skip Map Local

  def on_request(request):                        # before Map Local and the server
      if request.path == "/cart" and store.incr("calls") == 1:
          request.respond(503, json={"error": "unavailable"})

  def on_response(request, response):            # every response
      if request.path == "/orders":
          response.delay = 1500

Full script API (request, response, store, pipeline, rules):
  mitm-tracker test api            # or --json
"""


def register(subparsers: argparse._SubParsersAction) -> None:
    parser = subparsers.add_parser(
        "test",
        help="Script test plans (groups of Python test cases) against live traffic.",
        description=TEST_DESCRIPTION,
        epilog=TEST_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="test_command", metavar="ACTION")
    sub.required = True

    list_p = _add(sub, "list", "List test plans in the profile.")
    _common(list_p)
    list_p.set_defaults(func=cmd_list)

    show_p = _add(
        sub,
        "show",
        "Show a test plan and its cases.",
        "Show a plan's title, description and every case with its description,\n"
        "hooks and CLAIMS. Invalid cases are listed with the validation error.",
    )
    _plan_arg(show_p)
    _common(show_p)
    show_p.set_defaults(func=cmd_show)

    new_p = _add(
        sub,
        "new",
        "Create a test plan.",
        "Create tests/<plan>/plan.json in the profile.",
        "example:\n  mitm-tracker test new --test checkout --title \"Checkout\" "
        "--description \"Cart and payment flows\"",
    )
    _plan_arg(new_p)
    new_p.add_argument("--title", help="Plan title (default: the plan name).")
    new_p.add_argument("--description", help="What the plan covers.")
    _common(new_p)
    new_p.set_defaults(func=cmd_new)

    case_p = _add(
        sub,
        "new-case",
        "Create a test case script from a template.",
        "Create tests/<plan>/<case>.py with empty on_request/on_response hooks;\n"
        "--description becomes the module docstring.",
        "example:\n  mitm-tracker test new-case --test checkout --test-case cart_returns_400 "
        "--description \"Cart returns 400\"\n\nscript API: mitm-tracker test api",
    )
    _plan_arg(case_p)
    _case_arg(case_p)
    case_p.add_argument("--description", help="Case description (module docstring).")
    _common(case_p)
    case_p.set_defaults(func=cmd_new_case)

    apply_p = _add(
        sub,
        "apply",
        "Activate a test case on the running proxy session.",
        "Validate the case (exists, compiles, defines a hook, CLAIMS are valid\n"
        "URL patterns) and make it the active case. Takes effect on the next\n"
        "request; replaces any previously active case. Fails with not_running\n"
        "when no proxy session is up.",
        "example:\n  mitm-tracker test apply --test checkout --test-case cart_returns_400",
    )
    _plan_arg(apply_p)
    _case_arg(apply_p)
    _common(apply_p)
    apply_p.set_defaults(func=cmd_apply)

    clear_p = _add(sub, "clear", "Deactivate the active test case.")
    clear_p.add_argument("--json", action="store_true", dest="json_mode")
    clear_p.set_defaults(func=cmd_clear)

    status_p = _add(
        sub,
        "status",
        "Show the active test case and its last error.",
        "Report whether the proxy runs, which plan/case is active, and the last\n"
        "exception raised by the case script (hook, URL, error).",
    )
    status_p.add_argument("--json", action="store_true", dest="json_mode")
    status_p.set_defaults(func=cmd_status)

    api_p = _add(
        sub,
        "api",
        "Print the test case script API reference.",
        "Print hooks, module globals, the request/response/store API, the\n"
        "per-request pipeline, tracking headers and rules.",
    )
    api_p.add_argument("--json", action="store_true", dest="json_mode")
    api_p.set_defaults(func=cmd_api)

    state_p = _add(
        sub,
        "state",
        "Inspect or reset a test plan's key/value store.",
        "The store (tests/<plan>/state.json) is shared by every case of a plan and\n"
        "survives apply and proxy restarts.",
    )
    state_sub = state_p.add_subparsers(dest="state_command", metavar="ACTION")
    state_sub.required = True

    state_show_p = state_sub.add_parser("show", help="Print the store contents.")
    _plan_arg(state_show_p)
    _common(state_show_p)
    state_show_p.set_defaults(func=cmd_state_show)

    state_clear_p = state_sub.add_parser("clear", help="Erase every key in the store.")
    _plan_arg(state_clear_p)
    _common(state_clear_p)
    state_clear_p.set_defaults(func=cmd_state_clear)


def _add(
    sub: argparse._SubParsersAction,
    name: str,
    help_text: str,
    description: str | None = None,
    epilog: str | None = None,
) -> argparse.ArgumentParser:
    return sub.add_parser(
        name,
        help=help_text,
        description=description or help_text,
        epilog=epilog,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )


def _plan_arg(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--test", required=True, metavar="PLAN", help="Test plan name.")


def _case_arg(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--test-case", required=True, dest="test_case", metavar="CASE", help="Test case name."
    )


def _common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--profile", help="Profile (default: active).")
    parser.add_argument("--json", action="store_true", dest="json_mode", help="Emit JSON.")


def _resolve(args: argparse.Namespace):
    workspace = workspace_for()
    workspace.ensure()
    pm = ProfileManager(workspace)
    profile = getattr(args, "profile", None) or pm.active_name()
    if not pm.exists(profile):
        return None, emit_error(
            "profile_not_found",
            f"profile {profile!r} does not exist",
            json_mode=args.json_mode,
            exit_code=EXIT_INVALID_STATE,
        )
    store = testplan.PlanStore(workspace.profile_dir(profile))
    return (workspace, profile, store), EXIT_OK


def _plan_error(args: argparse.Namespace, exc: testplan.TestPlanError) -> int:
    return emit_error(
        "invalid_test", str(exc), json_mode=args.json_mode, exit_code=EXIT_INVALID_STATE
    )


def cmd_list(args: argparse.Namespace) -> int:
    resolved, rc = _resolve(args)
    if resolved is None:
        return rc
    _workspace, profile, store = resolved
    try:
        plans = store.list_plans()
    except testplan.TestPlanError as exc:
        return _plan_error(args, exc)

    if args.json_mode:
        emit_json(
            {"profile": profile, "count": len(plans), "plans": [p.to_dict() for p in plans]}
        )
        return EXIT_OK
    if not plans:
        emit_text(f"[{profile}] (no test plans)")
        return EXIT_OK
    rows = [
        {"name": p.name, "cases": len(p.cases), "title": p.title}
        for p in plans
    ]
    emit_text(f"[{profile}]")
    emit_text(render_table(rows, columns=[("name", "TEST"), ("cases", "CASES"), ("title", "TITLE")]))
    return EXIT_OK


def cmd_show(args: argparse.Namespace) -> int:
    resolved, rc = _resolve(args)
    if resolved is None:
        return rc
    _workspace, profile, store = resolved
    try:
        plan = store.load_plan(args.test)
        cases: list[dict[str, Any]] = []
        for name in plan.cases:
            try:
                cases.append(store.inspect_case(plan.name, name).to_dict())
            except testplan.TestPlanError as exc:
                cases.append({"name": name, "path": str(store.case_path(plan.name, name)), "error": str(exc)})
    except testplan.TestPlanError as exc:
        return _plan_error(args, exc)

    payload = {"profile": profile, **plan.to_dict(), "cases": cases}
    if args.json_mode:
        emit_json(payload)
        return EXIT_OK
    lines = [
        f"[{profile}] {plan.name}",
        f"  title:       {plan.title or ''}",
        f"  description: {plan.description or ''}",
        f"  path:        {plan.path}",
        "  cases:",
    ]
    if not cases:
        lines.append("    (none)")
    for case in cases:
        if "error" in case:
            lines.append(f"    - {case['name']}: INVALID ({case['error']})")
            continue
        lines.append(f"    - {case['name']}: {case['description'] or ''}")
        lines.append(f"        hooks: {', '.join(case['hooks'])}")
        if case["claims"]:
            lines.append(f"        claims: {', '.join(case['claims'])}")
    emit_text("\n".join(lines))
    return EXIT_OK


def cmd_new(args: argparse.Namespace) -> int:
    resolved, rc = _resolve(args)
    if resolved is None:
        return rc
    _workspace, profile, store = resolved
    try:
        plan = store.create_plan(args.test, title=args.title, description=args.description)
    except testplan.TestPlanError as exc:
        return _plan_error(args, exc)
    payload = {"profile": profile, "created": True, **plan.to_dict()}
    if args.json_mode:
        emit_json(payload)
    else:
        emit_text(f"[{profile}] created test plan {plan.name} at {plan.path}")
    return EXIT_OK


def cmd_new_case(args: argparse.Namespace) -> int:
    resolved, rc = _resolve(args)
    if resolved is None:
        return rc
    _workspace, profile, store = resolved
    try:
        case = store.create_case(args.test, args.test_case, description=args.description)
    except testplan.TestPlanError as exc:
        return _plan_error(args, exc)
    payload = {"profile": profile, "test": args.test, "created": True, **case.to_dict()}
    if args.json_mode:
        emit_json(payload)
    else:
        emit_text(f"[{profile}] created test case {args.test}/{case.name} at {case.path}")
    return EXIT_OK


def cmd_apply(args: argparse.Namespace) -> int:
    resolved, rc = _resolve(args)
    if resolved is None:
        return rc
    workspace, profile, store = resolved
    if not SessionManager(workspace).is_running():
        return emit_error(
            "not_running",
            "no running proxy session; start one with `mitm-tracker record start` first",
            json_mode=args.json_mode,
            exit_code=EXIT_INVALID_STATE,
        )
    try:
        store.load_plan(args.test)
        case = store.inspect_case(args.test, args.test_case)
    except testplan.TestPlanError as exc:
        return _plan_error(args, exc)

    active = testplan.ActiveTest(
        profile=profile,
        plan=args.test,
        case=case.name,
        script_path=str(case.path),
        state_path=str(store.state_path(args.test)),
        applied_at=testplan.now_iso(),
    )
    testplan.clear_active(workspace.active_test_path)
    testplan.write_active(workspace.active_test_path, active)

    payload = {"applied": True, **active.to_dict(), "description": case.description, "hooks": case.hooks, "claims": case.claims}
    if args.json_mode:
        emit_json(payload)
    else:
        emit_text(f"[{profile}] active test case: {active.label}")
        if case.description:
            emit_text(f"  {case.description}")
    return EXIT_OK


def cmd_clear(args: argparse.Namespace) -> int:
    workspace = workspace_for()
    cleared = testplan.clear_active(workspace.active_test_path)
    if args.json_mode:
        emit_json({"cleared": cleared})
    else:
        emit_text("test case deactivated" if cleared else "no active test case")
    return EXIT_OK


def cmd_status(args: argparse.Namespace) -> int:
    workspace = workspace_for()
    running = SessionManager(workspace).is_running()
    active = testplan.read_active(workspace.active_test_path) if running else None
    last_error = testplan.read_error(workspace.active_test_path) if active else None
    payload = {
        "running": running,
        "active": active.to_dict() if active else None,
        "last_error": last_error,
    }
    if args.json_mode:
        emit_json(payload)
        return EXIT_OK
    if not running:
        emit_text("proxy not running (no test case active)")
        return EXIT_OK
    if active is None:
        emit_text("no active test case")
        return EXIT_OK
    lines = [
        f"active: {active.label} (profile {active.profile})",
        f"applied_at: {active.applied_at}",
        f"script: {active.script_path}",
    ]
    if last_error:
        lines.append(
            f"last_error: [{last_error.get('at')}] {last_error.get('hook')} "
            f"{last_error.get('url') or ''}: {last_error.get('error')}"
        )
    emit_text("\n".join(lines))
    return EXIT_OK


def cmd_api(args: argparse.Namespace) -> int:
    if args.json_mode:
        emit_json(REFERENCE)
    else:
        emit_text(render_text())
    return EXIT_OK


def cmd_state_show(args: argparse.Namespace) -> int:
    resolved, rc = _resolve(args)
    if resolved is None:
        return rc
    _workspace, profile, store = resolved
    try:
        store.load_plan(args.test)
        data = StateStore(store.state_path(args.test)).all()
    except testplan.TestPlanError as exc:
        return _plan_error(args, exc)
    except ValueError as exc:
        return emit_error(
            "invalid_state", str(exc), json_mode=args.json_mode, exit_code=EXIT_INVALID_STATE
        )
    if args.json_mode:
        emit_json({"profile": profile, "test": args.test, "state": data})
    else:
        emit_text(json.dumps(data, indent=2, sort_keys=True, ensure_ascii=False))
    return EXIT_OK


def cmd_state_clear(args: argparse.Namespace) -> int:
    resolved, rc = _resolve(args)
    if resolved is None:
        return rc
    _workspace, profile, store = resolved
    try:
        store.load_plan(args.test)
    except testplan.TestPlanError as exc:
        return _plan_error(args, exc)
    StateStore(store.state_path(args.test)).clear()
    if args.json_mode:
        emit_json({"profile": profile, "test": args.test, "cleared": True})
    else:
        emit_text(f"[{profile}] state cleared for test plan {args.test}")
    return EXIT_OK
