from __future__ import annotations

from dataclasses import dataclass

from mitm_tracker.config import (
    DEFAULT_PROFILE_NAME,
    Workspace,
    is_valid_profile_name,
)
from mitm_tracker.session_manager import SessionManager


class ProfileError(RuntimeError):
    pass


@dataclass(frozen=True)
class Profile:
    name: str
    is_active: bool
    ssl_count: int

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "is_active": self.is_active,
            "ssl_count": self.ssl_count,
        }


class ProfileManager:
    def __init__(self, workspace: Workspace) -> None:
        self._workspace = workspace
        self._sessions = SessionManager(workspace)

    def ensure_default(self) -> None:
        self._workspace.ensure()

    def list(self) -> list[str]:
        if not self._workspace.profiles_dir.exists():
            return [DEFAULT_PROFILE_NAME]
        names = sorted(
            entry.name
            for entry in self._workspace.profiles_dir.iterdir()
            if entry.is_dir() and is_valid_profile_name(entry.name)
        )
        others = [n for n in names if n != DEFAULT_PROFILE_NAME]
        return [DEFAULT_PROFILE_NAME, *others]

    def exists(self, name: str) -> bool:
        if not is_valid_profile_name(name):
            return False
        return self._workspace.profile_dir(name).is_dir()

    def create(self, name: str) -> bool:
        if not is_valid_profile_name(name):
            raise ProfileError(
                f"invalid profile name {name!r}: use letters, digits, '-' or '_'"
            )
        path = self._workspace.profile_dir(name)
        if path.exists():
            return False
        path.mkdir(parents=True, exist_ok=False)
        return True

    def delete(self, name: str) -> bool:
        if name == DEFAULT_PROFILE_NAME:
            raise ProfileError("the 'default' profile cannot be deleted")
        if not is_valid_profile_name(name):
            raise ProfileError(f"invalid profile name {name!r}")
        path = self._workspace.profile_dir(name)
        if not path.exists():
            return False
        if self.active_name() == name:
            self.set_active(DEFAULT_PROFILE_NAME)
        for child in sorted(path.rglob("*"), reverse=True):
            if child.is_file() or child.is_symlink():
                child.unlink()
            elif child.is_dir():
                child.rmdir()
        path.rmdir()
        return True

    def active_name(self) -> str:
        state = self._sessions.read_state()
        name = state.get("active_profile") or DEFAULT_PROFILE_NAME
        if not is_valid_profile_name(name):
            return DEFAULT_PROFILE_NAME
        return name

    def set_active(self, name: str) -> None:
        if not is_valid_profile_name(name):
            raise ProfileError(f"invalid profile name {name!r}")
        if not self.exists(name):
            raise ProfileError(f"profile {name!r} does not exist")
        state = self._sessions.read_state()
        state["active_profile"] = name
        self._sessions.write_state(state)

    def describe(self, name: str | None = None) -> Profile:
        target = name or self.active_name()
        if not self.exists(target):
            raise ProfileError(f"profile {target!r} does not exist")
        ssl_path = self._workspace.ssl_path(target)
        ssl_count = 0
        if ssl_path.exists():
            ssl_count = self._count_ssl_entries(ssl_path)
        return Profile(
            name=target,
            is_active=(self.active_name() == target),
            ssl_count=ssl_count,
        )

    def describe_all(self) -> list[Profile]:
        active = self.active_name()
        result: list[Profile] = []
        for name in self.list():
            ssl_path = self._workspace.ssl_path(name)
            ssl_count = (
                self._count_ssl_entries(ssl_path) if ssl_path.exists() else 0
            )
            result.append(
                Profile(
                    name=name,
                    is_active=(name == active),
                    ssl_count=ssl_count,
                )
            )
        return result

    @staticmethod
    def _count_ssl_entries(ssl_path) -> int:
        import json

        try:
            data = json.loads(ssl_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return 0
        domains = data.get("domains") if isinstance(data, dict) else None
        if not isinstance(domains, list):
            return 0
        return len(domains)
