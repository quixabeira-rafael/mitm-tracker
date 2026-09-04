from __future__ import annotations

import random
import re
from dataclasses import dataclass

MAX_DELAY_MS = 120_000

_DURATION_RE = re.compile(r"^\s*(\d+(?:\.\d+)?)\s*(ms|s)?\s*$", re.IGNORECASE)


class DelayError(ValueError):
    pass


def parse_duration_ms(value: str | int | float) -> int:
    """Parse a human duration into whole milliseconds.

    Accepts bare numbers (milliseconds), '800ms', '1.5s', '2s'.
    """
    if isinstance(value, bool):
        raise DelayError(f"invalid duration {value!r}")
    if isinstance(value, (int, float)):
        amount, unit = float(value), "ms"
    else:
        match = _DURATION_RE.match(value)
        if not match:
            raise DelayError(
                f"invalid duration {value!r}; use '800', '800ms' or '1.5s'"
            )
        amount = float(match.group(1))
        unit = (match.group(2) or "ms").lower()

    ms = amount * 1000.0 if unit == "s" else amount
    if ms < 0:
        raise DelayError(f"duration cannot be negative: {value!r}")
    if ms > MAX_DELAY_MS:
        raise DelayError(
            f"duration {value!r} exceeds the {MAX_DELAY_MS}ms cap"
        )
    return int(round(ms))


@dataclass(frozen=True)
class DelayProfile:
    """Session-wide artificial latency applied to every response."""

    base_ms: int = 0
    jitter_ms: int = 0

    @classmethod
    def parse(
        cls, base: str | int | None, jitter: str | int | None = None
    ) -> "DelayProfile":
        base_ms = parse_duration_ms(base) if base is not None else 0
        jitter_ms = parse_duration_ms(jitter) if jitter is not None else 0
        if jitter_ms and not base_ms:
            raise DelayError("--delay-jitter requires --delay")
        return cls(base_ms=base_ms, jitter_ms=jitter_ms)

    @property
    def active(self) -> bool:
        return self.base_ms > 0

    @property
    def min_ms(self) -> int:
        return max(0, self.base_ms - self.jitter_ms)

    @property
    def max_ms(self) -> int:
        return min(MAX_DELAY_MS, self.base_ms + self.jitter_ms)

    def next_delay_ms(self, rng: random.Random | None = None) -> int:
        """Draw the delay for a single response, in milliseconds."""
        if not self.active:
            return 0
        if self.jitter_ms <= 0:
            return self.base_ms
        source = rng or random
        return source.randint(self.min_ms, self.max_ms)

    def describe(self) -> str:
        if not self.active:
            return "off"
        if self.jitter_ms <= 0:
            return f"{self.base_ms}ms"
        return f"{self.base_ms}ms +/-{self.jitter_ms}ms ({self.min_ms}-{self.max_ms}ms)"

    def to_dict(self) -> dict:
        return {"delay_ms": self.base_ms, "delay_jitter_ms": self.jitter_ms}
