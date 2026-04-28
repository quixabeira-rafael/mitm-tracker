from __future__ import annotations

import argparse

from mitm_tracker import cert_manager, simulators
from mitm_tracker.cert_manager import CertManagerError, InstallResult
from mitm_tracker.output import (
    EXIT_INVALID_STATE,
    EXIT_OK,
    EXIT_SYSTEM,
    emit_error,
    emit_json,
    emit_text,
    render_table,
)
from mitm_tracker.simulators import Simulator, SimulatorError


def register(subparsers: argparse._SubParsersAction) -> None:
    cert_parser = subparsers.add_parser(
        "cert", help="Manage the mitmproxy CA in iOS simulators."
    )
    cert_sub = cert_parser.add_subparsers(dest="cert_command", metavar="ACTION")
    cert_sub.required = True

    sim_p = cert_sub.add_parser(
        "simulators", help="List iOS simulators known to xcrun simctl."
    )
    sim_p.add_argument("--booted-only", action="store_true")
    sim_p.add_argument("--json", action="store_true", dest="json_mode")
    sim_p.set_defaults(func=cmd_simulators)

    status_p = cert_sub.add_parser(
        "status", help="Show whether the CA is installed on each booted simulator."
    )
    status_p.add_argument("--json", action="store_true", dest="json_mode")
    status_p.set_defaults(func=cmd_status)

    install_p = cert_sub.add_parser(
        "install", help="Install the mitmproxy CA in booted simulators."
    )
    install_p.add_argument("--udid", help="Install only on this UDID.")
    install_p.add_argument("--name", help="Install only on simulators with this name.")
    install_p.add_argument(
        "--all-booted",
        action="store_true",
        help="Install on every booted simulator without prompting.",
    )
    install_p.add_argument("--json", action="store_true", dest="json_mode")
    install_p.set_defaults(func=cmd_install)


def cmd_simulators(args: argparse.Namespace) -> int:
    try:
        sims = simulators.list_simulators()
    except SimulatorError as exc:
        return emit_error(
            "simctl_failed", str(exc), json_mode=args.json_mode, exit_code=EXIT_SYSTEM
        )
    if args.booted_only:
        sims = [s for s in sims if s.is_booted]

    if args.json_mode:
        emit_json({"count": len(sims), "simulators": [s.to_dict() for s in sims]})
        return EXIT_OK

    if not sims:
        emit_text("(no simulators found)")
        return EXIT_OK

    rows = [{**s.to_dict(), "booted": "yes" if s.is_booted else "no"} for s in sims]
    table = render_table(
        rows,
        columns=[
            ("state", "STATE"),
            ("name", "NAME"),
            ("runtime", "RUNTIME"),
            ("udid", "UDID"),
        ],
    )
    emit_text(table)
    return EXIT_OK


def cmd_status(args: argparse.Namespace) -> int:
    try:
        booted = simulators.list_booted()
    except SimulatorError as exc:
        return emit_error(
            "simctl_failed", str(exc), json_mode=args.json_mode, exit_code=EXIT_SYSTEM
        )
    rows = []
    for sim in booted:
        try:
            installed = cert_manager.is_installed(sim)
        except Exception:
            installed = False
        rows.append({**sim.to_dict(), "cert_installed": installed})

    if args.json_mode:
        emit_json({"count": len(rows), "simulators": rows})
        return EXIT_OK

    if not rows:
        emit_text("(no booted simulators)")
        return EXIT_OK

    table_rows = [
        {**r, "cert": "installed" if r["cert_installed"] else "missing"} for r in rows
    ]
    table = render_table(
        table_rows,
        columns=[
            ("name", "NAME"),
            ("runtime", "RUNTIME"),
            ("cert", "CERT"),
            ("udid", "UDID"),
        ],
    )
    emit_text(table)
    return EXIT_OK


def cmd_install(args: argparse.Namespace) -> int:
    try:
        targets = _resolve_install_targets(args)
    except CertManagerError as exc:
        return emit_error(
            "invalid_state",
            str(exc),
            json_mode=args.json_mode,
            exit_code=EXIT_INVALID_STATE,
        )
    except SimulatorError as exc:
        return emit_error(
            "simctl_failed", str(exc), json_mode=args.json_mode, exit_code=EXIT_SYSTEM
        )

    if not targets:
        return emit_error(
            "no_simulators",
            "no booted simulators matched; boot a simulator and try again",
            json_mode=args.json_mode,
            exit_code=EXIT_INVALID_STATE,
        )

    results: list[InstallResult] = []
    errors: list[dict] = []
    for sim in targets:
        try:
            results.append(cert_manager.install(sim))
        except CertManagerError as exc:
            errors.append({"udid": sim.udid, "name": sim.name, "error": str(exc)})

    payload = {
        "installed": [r.to_dict() for r in results],
        "errors": errors,
    }

    if args.json_mode:
        emit_json(payload)
    else:
        for r in results:
            status = (
                "already_installed"
                if r.skipped_reason == "already_installed"
                else ("installed" if r.installed else r.skipped_reason or "skipped")
            )
            emit_text(f"{r.name} ({r.udid}): {status}")
        for err in errors:
            emit_text(f"{err['name']} ({err['udid']}): error: {err['error']}")

    return EXIT_OK if not errors else EXIT_SYSTEM


def _resolve_install_targets(args: argparse.Namespace) -> list[Simulator]:
    booted = simulators.list_booted()
    if args.udid:
        match = [s for s in booted if s.udid.lower() == args.udid.lower()]
        if not match:
            raise CertManagerError(f"no booted simulator with udid {args.udid}")
        return match
    if args.name:
        match = [s for s in booted if s.name.lower() == args.name.lower()]
        if not match:
            raise CertManagerError(f"no booted simulator with name {args.name!r}")
        return match
    if args.all_booted:
        return booted
    if len(booted) == 1:
        return booted
    if len(booted) > 1:
        raise CertManagerError(
            f"{len(booted)} simulators booted; pass --all-booted, --udid, or --name"
        )
    return []
