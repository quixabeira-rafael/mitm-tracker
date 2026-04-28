from __future__ import annotations

import json
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from mitm_tracker.url_matcher import (
    ALL_QUERY_MODES,
    QUERY_MODE_IGNORE,
    UrlMatcherError,
    compile_pattern,
)

SCHEMA_VERSION = 1
BODIES_DIRNAME = "maplocal-bodies"
HEADERS_SUFFIX = ".headers.json"
BODY_SUFFIX = ".body"


class MapLocalError(RuntimeError):
    pass


@dataclass
class MapLocalSource:
    from_flow: int | None = None
    session_db: str | None = None
    captured_at: str | None = None

    def to_dict(self) -> dict:
        return {
            "from_flow": self.from_flow,
            "session_db": self.session_db,
            "captured_at": self.captured_at,
        }

    @classmethod
    def from_dict(cls, data: dict | None) -> "MapLocalSource":
        if not data:
            return cls()
        return cls(
            from_flow=data.get("from_flow"),
            session_db=data.get("session_db"),
            captured_at=data.get("captured_at"),
        )


@dataclass
class MapLocalRule:
    id: str
    enabled: bool
    url_pattern: str
    query_mode: str
    status: int
    headers_file: str
    body_file: str
    created_at: str
    description: str | None = None
    source: MapLocalSource = field(default_factory=MapLocalSource)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "enabled": self.enabled,
            "url_pattern": self.url_pattern,
            "query_mode": self.query_mode,
            "response": {
                "status": self.status,
                "headers_file": self.headers_file,
                "body_file": self.body_file,
            },
            "source": self.source.to_dict(),
            "metadata": {
                "created_at": self.created_at,
                "description": self.description,
            },
        }

    @classmethod
    def from_dict(cls, data: dict) -> "MapLocalRule":
        response = data.get("response") or {}
        metadata = data.get("metadata") or {}
        return cls(
            id=str(data["id"]),
            enabled=bool(data.get("enabled", True)),
            url_pattern=str(data["url_pattern"]),
            query_mode=str(data.get("query_mode", QUERY_MODE_IGNORE)),
            status=int(response.get("status", 200)),
            headers_file=str(response.get("headers_file", "")),
            body_file=str(response.get("body_file", "")),
            created_at=str(metadata.get("created_at") or _now()),
            description=metadata.get("description"),
            source=MapLocalSource.from_dict(data.get("source")),
        )


class MapLocalStore:
    def __init__(self, profile_dir: Path) -> None:
        self._profile_dir = profile_dir
        self._json_path = profile_dir / "maplocal.json"
        self._bodies_dir = profile_dir / BODIES_DIRNAME

    @property
    def profile_dir(self) -> Path:
        return self._profile_dir

    @property
    def json_path(self) -> Path:
        return self._json_path

    @property
    def bodies_dir(self) -> Path:
        return self._bodies_dir

    def body_path(self, rule_id: str) -> Path:
        return self._bodies_dir / f"{rule_id}{BODY_SUFFIX}"

    def headers_path(self, rule_id: str) -> Path:
        return self._bodies_dir / f"{rule_id}{HEADERS_SUFFIX}"

    def ensure(self) -> None:
        self._profile_dir.mkdir(parents=True, exist_ok=True)
        self._bodies_dir.mkdir(parents=True, exist_ok=True)

    def load(self) -> list[MapLocalRule]:
        if not self._json_path.exists():
            return []
        try:
            data = json.loads(self._json_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise MapLocalError(f"invalid JSON in {self._json_path}: {exc}") from exc
        if not isinstance(data, dict):
            raise MapLocalError(f"invalid maplocal.json shape (expected object)")
        rules_raw = data.get("rules") or []
        if not isinstance(rules_raw, list):
            raise MapLocalError("'rules' must be a list")
        return [MapLocalRule.from_dict(r) for r in rules_raw]

    def save(self, rules: list[MapLocalRule]) -> None:
        self.ensure()
        payload = {
            "version": SCHEMA_VERSION,
            "rules": [r.to_dict() for r in rules],
        }
        self._json_path.write_text(
            json.dumps(payload, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )

    def add(
        self,
        *,
        url_pattern: str,
        query_mode: str = QUERY_MODE_IGNORE,
        status: int = 200,
        headers: list[tuple[str, str]] | None = None,
        body: bytes = b"",
        description: str | None = None,
        source: MapLocalSource | None = None,
    ) -> MapLocalRule:
        if query_mode not in ALL_QUERY_MODES:
            raise MapLocalError(
                f"invalid query_mode {query_mode!r}; choose from {ALL_QUERY_MODES}"
            )
        try:
            compile_pattern(url_pattern, query_mode)
        except UrlMatcherError as exc:
            raise MapLocalError(str(exc)) from exc

        rule_id = _new_id()
        self.ensure()
        rule = MapLocalRule(
            id=rule_id,
            enabled=True,
            url_pattern=url_pattern,
            query_mode=query_mode,
            status=int(status),
            headers_file=f"{rule_id}{HEADERS_SUFFIX}",
            body_file=f"{rule_id}{BODY_SUFFIX}",
            created_at=_now(),
            description=description,
            source=source or MapLocalSource(),
        )
        self._write_headers(rule_id, headers or [])
        self._write_body(rule_id, body)
        rules = self.load()
        rules.append(rule)
        self.save(rules)
        return rule

    def remove(self, rule_id: str, *, keep_files: bool = False) -> bool:
        rules = self.load()
        before = len(rules)
        rules = [r for r in rules if r.id != rule_id]
        if len(rules) == before:
            return False
        self.save(rules)
        if not keep_files:
            self.body_path(rule_id).unlink(missing_ok=True)
            self.headers_path(rule_id).unlink(missing_ok=True)
        return True

    def find(self, rule_id: str) -> MapLocalRule | None:
        for rule in self.load():
            if rule.id == rule_id:
                return rule
        return None

    def update(self, rule: MapLocalRule) -> None:
        rules = self.load()
        for i, existing in enumerate(rules):
            if existing.id == rule.id:
                rules[i] = rule
                self.save(rules)
                return
        raise MapLocalError(f"rule {rule.id!r} not found")

    def set_enabled(self, rule_id: str, enabled: bool) -> bool:
        rule = self.find(rule_id)
        if rule is None:
            return False
        rule.enabled = enabled
        self.update(rule)
        return True

    def read_body(self, rule_id: str) -> bytes:
        path = self.body_path(rule_id)
        if not path.exists():
            return b""
        return path.read_bytes()

    def read_headers(self, rule_id: str) -> list[tuple[str, str]]:
        path = self.headers_path(rule_id)
        if not path.exists():
            return []
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return []
        if not isinstance(data, list):
            return []
        return [(str(k), str(v)) for pair in data for k, v in [pair]]

    def write_body(self, rule_id: str, body: bytes) -> None:
        self._write_body(rule_id, body)

    def write_headers(
        self, rule_id: str, headers: list[tuple[str, str]]
    ) -> None:
        self._write_headers(rule_id, headers)

    def _write_body(self, rule_id: str, body: bytes) -> None:
        self.ensure()
        self.body_path(rule_id).write_bytes(body)

    def _write_headers(
        self, rule_id: str, headers: list[tuple[str, str]]
    ) -> None:
        self.ensure()
        normalized = [[str(k), str(v)] for k, v in headers]
        self.headers_path(rule_id).write_text(
            json.dumps(normalized, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _new_id() -> str:
    return secrets.token_hex(4)
