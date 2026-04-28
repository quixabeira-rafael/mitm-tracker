from __future__ import annotations

import json
import re
import subprocess
from dataclasses import dataclass
from typing import Sequence


class SimulatorError(RuntimeError):
    pass


@dataclass(frozen=True)
class Simulator:
    udid: str
    name: str
    runtime: str
    state: str

    @property
    def is_booted(self) -> bool:
        return self.state == "Booted"

    def to_dict(self) -> dict:
        return {
            "udid": self.udid,
            "name": self.name,
            "runtime": self.runtime,
            "state": self.state,
        }


def list_simulators(*, runner=None) -> list[Simulator]:
    runner = runner or _default_runner
    raw = _run_simctl_list(runner)
    return _parse_simctl_list(raw)


def list_booted(*, runner=None) -> list[Simulator]:
    return [s for s in list_simulators(runner=runner) if s.is_booted]


def find_by_udid(udid: str, *, runner=None) -> Simulator | None:
    udid = udid.lower()
    for sim in list_simulators(runner=runner):
        if sim.udid.lower() == udid:
            return sim
    return None


def find_by_name(name: str, *, runner=None, only_booted: bool = False) -> list[Simulator]:
    name_lower = name.lower()
    matches = [
        sim
        for sim in list_simulators(runner=runner)
        if sim.name.lower() == name_lower
    ]
    if only_booted:
        matches = [s for s in matches if s.is_booted]
    return matches


def _default_runner(args: Sequence[str]) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(
            list(args),
            capture_output=True,
            text=True,
            check=False,
        )
    except FileNotFoundError as exc:
        raise SimulatorError(
            f"command not found: {args[0]} (Xcode command line tools required)"
        ) from exc


def _run_simctl_list(runner) -> dict:
    proc = runner(["xcrun", "simctl", "list", "devices", "--json"])
    if proc.returncode != 0:
        raise SimulatorError(
            f"xcrun simctl failed (exit {proc.returncode}): {proc.stderr.strip() or proc.stdout.strip()}"
        )
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise SimulatorError(f"invalid JSON from simctl: {exc}") from exc


def _parse_simctl_list(payload: dict) -> list[Simulator]:
    devices = payload.get("devices") or {}
    out: list[Simulator] = []
    for runtime_id, items in devices.items():
        runtime = _normalize_runtime(runtime_id)
        for item in items or []:
            udid = item.get("udid")
            name = item.get("name")
            state = item.get("state", "Unknown")
            if not udid or not name:
                continue
            if item.get("isAvailable") is False:
                continue
            out.append(
                Simulator(
                    udid=str(udid),
                    name=str(name),
                    runtime=runtime,
                    state=str(state),
                )
            )
    return out


def _normalize_runtime(runtime_id: str) -> str:
    match = re.match(
        r"com\.apple\.CoreSimulator\.SimRuntime\.(.+)", runtime_id or ""
    )
    if match:
        return match.group(1).replace("-", " ").replace("_", " ").strip() or runtime_id
    return runtime_id
