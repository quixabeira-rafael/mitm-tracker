from __future__ import annotations

import json
import sys
from typing import Any, IO, Iterable

EXIT_OK = 0
EXIT_USAGE = 1
EXIT_INVALID_STATE = 2
EXIT_SYSTEM = 3


def emit_json(payload: Any, stream: IO[str] | None = None) -> None:
    target = stream if stream is not None else sys.stdout
    json.dump(payload, target, ensure_ascii=False, default=_default, indent=None)
    target.write("\n")
    target.flush()


def emit_text(text: str, stream: IO[str] | None = None) -> None:
    target = stream if stream is not None else sys.stdout
    target.write(text)
    if not text.endswith("\n"):
        target.write("\n")
    target.flush()


def render_table(
    rows: Iterable[dict[str, Any]],
    columns: list[tuple[str, str]],
) -> str:
    rows_list = list(rows)
    if not rows_list:
        return ""
    widths = {key: len(label) for key, label in columns}
    for row in rows_list:
        for key, _ in columns:
            value = _stringify(row.get(key))
            widths[key] = max(widths[key], len(value))

    header = "  ".join(label.ljust(widths[key]) for key, label in columns)
    separator = "  ".join("-" * widths[key] for key, _ in columns)
    body_lines = []
    for row in rows_list:
        body_lines.append(
            "  ".join(_stringify(row.get(key)).ljust(widths[key]) for key, _ in columns)
        )
    return "\n".join([header, separator, *body_lines])


def emit_error(error: str, message: str, *, json_mode: bool, exit_code: int) -> int:
    if json_mode:
        emit_json({"error": error, "message": message}, stream=sys.stderr)
    else:
        emit_text(f"error: {message}", stream=sys.stderr)
    return exit_code


def _stringify(value: Any) -> str:
    if value is None:
        return "-"
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def _default(value: Any) -> Any:
    if isinstance(value, (set, frozenset)):
        return sorted(value)
    if hasattr(value, "isoformat"):
        return value.isoformat()
    raise TypeError(f"object of type {type(value).__name__} is not JSON serializable")
