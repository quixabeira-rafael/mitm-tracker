from __future__ import annotations

import argparse
import sys

from mitm_tracker import cert_manager, host_ca, simulators
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

    host_p = cert_sub.add_parser(
        "host",
        help="Manage the mitmproxy CA in the macOS System Keychain (host-wide TLS).",
    )
    host_sub = host_p.add_subparsers(dest="cert_host_command", metavar="ACTION")
    host_sub.required = True

    host_install_p = host_sub.add_parser(
        "install",
        help="Trust the mitmproxy CA system-wide on this Mac (DANGEROUS).",
    )
    host_install_p.add_argument(
        "--yes",
        action="store_true",
        help="Skip the interactive confirmation banner.",
    )
    host_install_p.add_argument(
        "--force",
        action="store_true",
        help="Re-run add-trusted-cert even when the cert is already trusted.",
    )
    host_install_p.add_argument("--json", action="store_true", dest="json_mode")
    host_install_p.set_defaults(func=cmd_host_install)

    host_uninstall_p = host_sub.add_parser(
        "uninstall",
        help="Remove the mitm-tracker-managed mitmproxy CA(s) from the System Keychain.",
    )
    host_uninstall_p.add_argument("--json", action="store_true", dest="json_mode")
    host_uninstall_p.set_defaults(func=cmd_host_uninstall)

    host_status_p = host_sub.add_parser(
        "status",
        help="Show whether the mitmproxy CA is installed and trusted in the System Keychain.",
    )
    host_status_p.add_argument("--json", action="store_true", dest="json_mode")
    host_status_p.set_defaults(func=cmd_host_status)


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


# --- cert host -----------------------------------------------------------------


_HOST_INSTALL_BANNER = (
    "\n"
    "================================================================\n"
    " WARNING: macOS System Keychain trust install\n"
    "================================================================\n"
    " You are about to install:\n"
    "     {ca_path}\n"
    "     SHA1: {sha}\n"
    " as a TRUSTED ROOT CERTIFICATE in /Library/Keychains/System.keychain.\n"
    "\n"
    " Your Mac will trust this CA for ALL TLS connections, system-wide:\n"
    "   - Safari / Chrome / any browser\n"
    "   - App Store and OS updates\n"
    "   - Every native app and system process\n"
    "\n"
    " The matching private key lives at:\n"
    "     ~/.mitmproxy/mitmproxy-ca.pem\n"
    " Anyone with read access to it can intercept your TLS traffic.\n"
    "\n"
    " Reverse with:\n"
    "     mitm-tracker cert host uninstall\n"
    "================================================================\n"
)


def _privileged_runner():
    # Lazy import to avoid a circular dependency at module load
    # (commands.setup imports auth_setup which is unrelated, but
    # keeping the import local is safe).
    from mitm_tracker.commands.setup import _sudo_privileged_runner

    return _sudo_privileged_runner


def cmd_host_install(args: argparse.Namespace) -> int:
    try:
        ca_path = cert_manager.ca_path()
    except CertManagerError as exc:
        return emit_error(
            "ca_path_error",
            str(exc),
            json_mode=args.json_mode,
            exit_code=EXIT_SYSTEM,
        )
    if not ca_path.exists():
        return emit_error(
            "ca_missing",
            f"mitmproxy CA not found at {ca_path}; run `mitm-tracker record start` "
            "once first to bootstrap it, then retry.",
            json_mode=args.json_mode,
            exit_code=EXIT_INVALID_STATE,
        )

    ok, reason = host_ca.validate_pem_is_root_ca(ca_path)
    if not ok:
        return emit_error(
            "ca_invalid",
            f"refusing to install: {reason}",
            json_mode=args.json_mode,
            exit_code=EXIT_INVALID_STATE,
        )

    sha_no_colons, sha_colons = host_ca.current_ca_sha1(ca_path)

    if not args.json_mode and not args.yes:
        sys.stderr.write(
            _HOST_INSTALL_BANNER.format(ca_path=ca_path, sha=sha_colons)
        )
        sys.stderr.flush()
        try:
            response = input("Continue? [y/N] ").strip().lower()
        except EOFError:
            response = ""
        if response not in ("y", "yes"):
            return emit_error(
                "user_aborted",
                "install cancelled by user",
                json_mode=args.json_mode,
                exit_code=EXIT_INVALID_STATE,
            )

    try:
        result = host_ca.install(
            ca_path=ca_path,
            privileged_runner=_privileged_runner(),
            force=args.force,
        )
    except host_ca.HostCaError as exc:
        return emit_error(
            "host_ca_failed",
            str(exc),
            json_mode=args.json_mode,
            exit_code=EXIT_SYSTEM,
        )

    if args.json_mode:
        emit_json(result.to_dict())
    else:
        verb = "replaced" if result.replaced_existing else (
            "skipped (already trusted)" if not result.invoked_privileged else "installed"
        )
        emit_text(
            f"host CA {verb}: {result.ca_path}\n"
            f"  sha1:               {result.ca_sha1_colons}\n"
            f"  system_keychain:    {result.system_keychain_path}\n"
            f"  stale_removed:      {len(result.stale_removed)}\n"
            f"  invoked_privileged: {result.invoked_privileged}\n"
            f"  verified_trusted:   {result.verified_trusted}"
        )

    if not result.verified_trusted:
        return emit_error(
            "verify_failed",
            "the cert is in the keychain but `security verify-cert` did not confirm trust. "
            "Try `mitm-tracker cert host install --force`. If that fails, run the recovery "
            f"snippet:\n{host_ca.RECOVERY_SNIPPET}",
            json_mode=args.json_mode,
            exit_code=EXIT_SYSTEM,
        )
    return EXIT_OK


def cmd_host_uninstall(args: argparse.Namespace) -> int:
    try:
        result = host_ca.uninstall(privileged_runner=_privileged_runner())
    except host_ca.HostCaError as exc:
        return emit_error(
            "host_ca_failed",
            str(exc),
            json_mode=args.json_mode,
            exit_code=EXIT_SYSTEM,
        )

    if args.json_mode:
        emit_json(result.to_dict())
    else:
        emit_text(
            f"host CA uninstall:\n"
            f"  removed_shas:           {len(result.removed_shas)}\n"
            f"  skipped_unmanaged_shas: {len(result.skipped_unmanaged_shas)}\n"
            f"  invoked_privileged:     {result.invoked_privileged}"
        )
        if result.skipped_unmanaged_shas:
            emit_text(
                "\nThe following mitmproxy CA(s) in the System Keychain were "
                "NOT installed by mitm-tracker and were left in place:",
                stream=sys.stderr,
            )
            for sha in result.skipped_unmanaged_shas:
                emit_text(f"  - {sha}", stream=sys.stderr)
            emit_text(
                "\nIf you want to remove them too, run the recovery snippet:\n"
                + host_ca.RECOVERY_SNIPPET,
                stream=sys.stderr,
            )
    return EXIT_OK


def cmd_host_status(args: argparse.Namespace) -> int:
    result = host_ca.status()
    if args.json_mode:
        emit_json(result.to_dict())
    else:
        emit_text(
            f"ca_path:            {result.ca_path or '-'}\n"
            f"current_sha1:       {result.current_sha1_colons or '-'}\n"
            f"system_keychain:    {result.system_keychain_path}\n"
            f"installed_current:  {result.installed_current}\n"
            f"trusted_current:    {result.trusted_current}\n"
            f"matching_cn_count:  {len(result.matching_cn)}"
        )
        for m in result.matching_cn:
            emit_text(
                f"  - {m.sha1_colons}  current={m.is_current} "
                f"managed={m.is_managed} trusted={m.is_trusted}"
            )
    return EXIT_OK
