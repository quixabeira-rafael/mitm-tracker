from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

SCHEMA_VERSION = 1


@dataclass
class SslEntry:
    pattern: str
    added_at: str

    def to_dict(self) -> dict:
        return {"pattern": self.pattern, "added_at": self.added_at}


@dataclass
class SslList:
    path: Path
    entries: list[SslEntry] = field(default_factory=list)

    @classmethod
    def load(cls, path: Path) -> "SslList":
        if not path.exists():
            return cls(path=path, entries=[])
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise SslListError(f"invalid JSON in {path}: {exc}") from exc
        if not isinstance(data, dict):
            raise SslListError(f"invalid SSL list shape in {path}: expected object")
        domains = data.get("domains") or []
        if not isinstance(domains, list):
            raise SslListError(f"invalid 'domains' field in {path}: expected list")
        entries = []
        for raw in domains:
            if not isinstance(raw, dict):
                raise SslListError(f"invalid entry in {path}: {raw!r}")
            pattern = raw.get("pattern")
            if not isinstance(pattern, str) or not pattern:
                raise SslListError(f"invalid pattern in {path}: {raw!r}")
            entries.append(
                SslEntry(pattern=pattern, added_at=str(raw.get("added_at", _now())))
            )
        return cls(path=path, entries=entries)

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "version": SCHEMA_VERSION,
            "domains": [e.to_dict() for e in self.entries],
        }
        self.path.write_text(
            json.dumps(payload, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )

    def patterns(self) -> list[str]:
        return [e.pattern for e in self.entries]

    def add(self, pattern: str) -> bool:
        pattern = _normalize(pattern)
        if not pattern:
            raise SslListError("empty pattern")
        if pattern in self.patterns():
            return False
        self.entries.append(SslEntry(pattern=pattern, added_at=_now()))
        return True

    def remove(self, pattern: str) -> bool:
        pattern = _normalize(pattern)
        before = len(self.entries)
        self.entries = [e for e in self.entries if e.pattern != pattern]
        return len(self.entries) != before

    def matches(self, host: str) -> str | None:
        host = (host or "").lower()
        for entry in self.entries:
            if _matches(entry.pattern, host):
                return entry.pattern
        return None

    def to_allow_hosts_regex(self) -> str | None:
        if not self.entries:
            return None
        alternatives = [_pattern_to_regex(e.pattern) for e in self.entries]
        body = "|".join(alternatives)
        return f"^(?:{body})(?::\\d+)?$"


class SslListError(RuntimeError):
    pass


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _normalize(pattern: str) -> str:
    return (pattern or "").strip().lower()


def _matches(pattern: str, host: str) -> bool:
    pattern = pattern.lower()
    if pattern == host:
        return True
    if pattern.startswith("*."):
        suffix = pattern[2:]
        if host == suffix:
            return True
        return host.endswith("." + suffix)
    return False


def _pattern_to_regex(pattern: str) -> str:
    pattern = pattern.lower()
    if pattern.startswith("*."):
        suffix = re.escape(pattern[2:])
        return rf"(?:[^.]+\.)*{suffix}"
    return re.escape(pattern)
