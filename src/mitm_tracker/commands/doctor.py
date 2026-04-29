from __future__ import annotations

import argparse

from mitm_tracker import doctor
from mitm_tracker.output import (
    EXIT_INVALID_STATE,
    EXIT_OK,
    EXIT_SYSTEM,
    emit_json,
    emit_text,
)

_GROUP_LABELS = {
    "system": "System",
    "tools": "Required tools",
    "optional": "Optional features (setup install)",
    "state": "Runtime state",
}

_GROUP_ORDER = ["system", "tools", "optional", "state"]

_STATUS_GLYPH = {
    doctor.STATUS_OK: "✅",
    doctor.STATUS_WARN: "⚠️ ",
    doctor.STATUS_ERROR: "❌",
    doctor.STATUS_INFO: "ℹ️ ",
}


def register(subparsers: argparse._SubParsersAction) -> None:
    parser = subparsers.add_parser(
        "doctor",
        help="Diagnose the local environment and report missing or broken pieces.",
    )
    parser.add_argument("--json", action="store_true", dest="json_mode")
    parser.set_defaults(func=cmd_doctor)


def cmd_doctor(args: argparse.Namespace) -> int:
    results = doctor.run_all_checks()
    aggregated = doctor.aggregate_status(results)

    if args.json_mode:
        emit_json(
            {
                "status": aggregated,
                "checks": [r.to_dict() for r in results],
            }
        )
    else:
        _render_text(results, aggregated)

    if aggregated == doctor.STATUS_ERROR:
        return EXIT_SYSTEM
    if aggregated == doctor.STATUS_WARN:
        return EXIT_INVALID_STATE
    return EXIT_OK


def _render_text(results: list[doctor.CheckResult], aggregated: str) -> None:
    grouped: dict[str, list[doctor.CheckResult]] = {g: [] for g in _GROUP_ORDER}
    for result in results:
        grouped.setdefault(result.group, []).append(result)

    lines: list[str] = ["mitm-tracker doctor", ""]
    name_width = max(
        (len(r.name) for r in results),
        default=20,
    )

    for group in _GROUP_ORDER:
        items = grouped.get(group) or []
        if not items:
            continue
        label = _GROUP_LABELS.get(group, group)
        lines.append(f"{label}:")
        for result in items:
            glyph = _STATUS_GLYPH.get(result.status, "?")
            lines.append(f"  {glyph} {result.name.ljust(name_width)}  {result.detail}")
            if result.fix:
                lines.append(f"     {' ' * name_width}  fix: {result.fix}")
        lines.append("")

    counts = {s: sum(1 for r in results if r.status == s) for s in (
        doctor.STATUS_OK,
        doctor.STATUS_WARN,
        doctor.STATUS_ERROR,
        doctor.STATUS_INFO,
    )}
    lines.append(
        f"Summary: {counts[doctor.STATUS_OK]} OK, "
        f"{counts[doctor.STATUS_WARN]} warn, "
        f"{counts[doctor.STATUS_ERROR]} error, "
        f"{counts[doctor.STATUS_INFO]} info "
        f"-> overall: {aggregated}"
    )
    emit_text("\n".join(lines))
