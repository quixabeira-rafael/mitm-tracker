from __future__ import annotations

import argparse
import errno
import sys

from mitm_tracker import __version__
from mitm_tracker.commands import cert as cert_commands
from mitm_tracker.commands import maplocal as maplocal_commands
from mitm_tracker.commands import profile as profile_commands
from mitm_tracker.commands import query as query_commands
from mitm_tracker.commands import record as record_commands
from mitm_tracker.commands import release as release_commands
from mitm_tracker.commands import ssl as ssl_commands
from mitm_tracker.commands import tray as tray_commands
from mitm_tracker.output import EXIT_SYSTEM, EXIT_USAGE, emit_error


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mitm-tracker",
        description="Charles-like HTTP(S) proxy with SQLite capture.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command", metavar="COMMAND")

    profile_commands.register(subparsers)
    ssl_commands.register(subparsers)
    maplocal_commands.register(subparsers)
    cert_commands.register(subparsers)
    record_commands.register(subparsers)
    query_commands.register(subparsers)
    release_commands.register(subparsers)
    tray_commands.register(subparsers)

    return parser


def _json_mode(args: argparse.Namespace) -> bool:
    return bool(getattr(args, "json_mode", False))


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    func = getattr(args, "func", None)
    if func is None:
        parser.print_help(sys.stderr)
        return EXIT_USAGE

    try:
        return int(func(args))
    except PermissionError as exc:
        return emit_error(
            "permission_denied",
            _format_os_error("permission denied", exc),
            json_mode=_json_mode(args),
            exit_code=EXIT_SYSTEM,
        )
    except FileNotFoundError as exc:
        return emit_error(
            "path_not_found",
            _format_os_error("path not found", exc),
            json_mode=_json_mode(args),
            exit_code=EXIT_SYSTEM,
        )
    except IsADirectoryError as exc:
        return emit_error(
            "filesystem_error",
            _format_os_error("expected a file but found a directory", exc),
            json_mode=_json_mode(args),
            exit_code=EXIT_SYSTEM,
        )
    except OSError as exc:
        code = getattr(exc, "errno", None)
        if code in {errno.ENOSPC, errno.EDQUOT}:
            return emit_error(
                "no_space",
                _format_os_error("no space left on device", exc),
                json_mode=_json_mode(args),
                exit_code=EXIT_SYSTEM,
            )
        return emit_error(
            "filesystem_error",
            _format_os_error("filesystem error", exc),
            json_mode=_json_mode(args),
            exit_code=EXIT_SYSTEM,
        )


def _format_os_error(prefix: str, exc: OSError) -> str:
    parts = [prefix]
    detail = str(exc) or exc.__class__.__name__
    parts.append(detail)
    return ": ".join(parts)
