from __future__ import annotations

import ast
import json
import os
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from mitm_tracker.config import is_valid_profile_name
from mitm_tracker.url_matcher import compile_pattern

TESTS_DIRNAME = "tests"
PLAN_FILENAME = "plan.json"
STATE_FILENAME = "state.json"
CASE_SUFFIX = ".py"
TEST_ERROR_FILENAME = "test_error.json"
HOOK_NAMES = ("on_request", "on_response")
CLAIMS_NAME = "CLAIMS"

CASE_TEMPLATE = '''"""{description}"""

CLAIMS = []


def on_request(request):
    pass


def on_response(request, response):
    pass
'''


class TestPlanError(RuntimeError):
    __test__ = False


@dataclass
class CaseInfo:
    name: str
    path: Path
    description: str | None
    hooks: list[str]
    claims: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "path": str(self.path),
            "description": self.description,
            "hooks": list(self.hooks),
            "claims": list(self.claims),
        }


@dataclass
class PlanInfo:
    name: str
    path: Path
    title: str | None
    description: str | None
    cases: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "path": str(self.path),
            "title": self.title,
            "description": self.description,
            "cases": list(self.cases),
        }


@dataclass
class ActiveTest:
    profile: str
    plan: str
    case: str
    script_path: str
    state_path: str
    applied_at: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "profile": self.profile,
            "plan": self.plan,
            "case": self.case,
            "script_path": self.script_path,
            "state_path": self.state_path,
            "applied_at": self.applied_at,
        }

    @property
    def label(self) -> str:
        return f"{self.plan}/{self.case}"

    @classmethod
    def from_dict(cls, data: dict) -> "ActiveTest":
        return cls(
            profile=str(data["profile"]),
            plan=str(data["plan"]),
            case=str(data["case"]),
            script_path=str(data["script_path"]),
            state_path=str(data["state_path"]),
            applied_at=str(data.get("applied_at") or ""),
        )


class PlanStore:
    def __init__(self, profile_dir: Path) -> None:
        self._profile_dir = profile_dir
        self._tests_dir = profile_dir / TESTS_DIRNAME

    @property
    def tests_dir(self) -> Path:
        return self._tests_dir

    def plan_dir(self, plan: str) -> Path:
        return self._tests_dir / plan

    def plan_path(self, plan: str) -> Path:
        return self.plan_dir(plan) / PLAN_FILENAME

    def state_path(self, plan: str) -> Path:
        return self.plan_dir(plan) / STATE_FILENAME

    def case_path(self, plan: str, case: str) -> Path:
        return self.plan_dir(plan) / f"{case}{CASE_SUFFIX}"

    def exists(self, plan: str) -> bool:
        return is_valid_profile_name(plan) and self.plan_path(plan).is_file()

    def list_plans(self) -> list[PlanInfo]:
        if not self._tests_dir.is_dir():
            return []
        plans: list[PlanInfo] = []
        for entry in sorted(self._tests_dir.iterdir()):
            if entry.is_dir() and self.exists(entry.name):
                plans.append(self.load_plan(entry.name))
        return plans

    def load_plan(self, plan: str) -> PlanInfo:
        _require_name(plan, "test plan")
        path = self.plan_path(plan)
        if not path.is_file():
            raise TestPlanError(f"test plan {plan!r} not found")
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise TestPlanError(f"invalid JSON in {path}: {exc}") from exc
        if not isinstance(data, dict):
            raise TestPlanError(f"invalid {PLAN_FILENAME} shape in {path} (expected object)")
        return PlanInfo(
            name=plan,
            path=self.plan_dir(plan),
            title=data.get("title"),
            description=data.get("description"),
            cases=self.list_cases(plan),
        )

    def list_cases(self, plan: str) -> list[str]:
        directory = self.plan_dir(plan)
        if not directory.is_dir():
            return []
        return sorted(
            entry.stem
            for entry in directory.glob(f"*{CASE_SUFFIX}")
            if entry.is_file() and is_valid_profile_name(entry.stem)
        )

    def create_plan(
        self, plan: str, *, title: str | None = None, description: str | None = None
    ) -> PlanInfo:
        _require_name(plan, "test plan")
        if self.plan_path(plan).exists():
            raise TestPlanError(f"test plan {plan!r} already exists")
        self.plan_dir(plan).mkdir(parents=True, exist_ok=True)
        payload = {"title": title or plan, "description": description or ""}
        _atomic_write_text(
            self.plan_path(plan),
            json.dumps(payload, indent=2, ensure_ascii=False) + "\n",
        )
        return self.load_plan(plan)

    def create_case(
        self, plan: str, case: str, *, description: str | None = None
    ) -> CaseInfo:
        self.load_plan(plan)
        _require_name(case, "test case")
        path = self.case_path(plan, case)
        if path.exists():
            raise TestPlanError(f"test case {case!r} already exists in plan {plan!r}")
        text = (description or case).replace('"""', "'''")
        _atomic_write_text(path, CASE_TEMPLATE.format(description=text))
        return self.inspect_case(plan, case)

    def inspect_case(self, plan: str, case: str) -> CaseInfo:
        _require_name(plan, "test plan")
        _require_name(case, "test case")
        path = self.case_path(plan, case)
        if not path.is_file():
            raise TestPlanError(f"test case {case!r} not found in plan {plan!r}")
        return inspect_case_source(case, path)


def inspect_case_source(case: str, path: Path) -> CaseInfo:
    source = path.read_text(encoding="utf-8")
    try:
        tree = ast.parse(source, filename=str(path))
        compile(tree, str(path), "exec")
    except SyntaxError as exc:
        raise TestPlanError(
            f"test case {case!r} does not compile: {exc.msg} (line {exc.lineno})"
        ) from exc

    hooks = [
        node.name
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name in HOOK_NAMES
    ]
    if not hooks:
        raise TestPlanError(
            f"test case {case!r} must define on_request(request) and/or "
            "on_response(request, response)"
        )
    async_hooks = [
        node.name
        for node in tree.body
        if isinstance(node, ast.AsyncFunctionDef) and node.name in HOOK_NAMES
    ]
    if async_hooks:
        raise TestPlanError(
            f"test case {case!r}: {', '.join(async_hooks)} must be a plain def, not async def"
        )

    claims = _extract_claims(case, tree)
    for pattern in claims:
        try:
            compile_pattern(pattern)
        except ValueError as exc:
            raise TestPlanError(f"test case {case!r}: invalid CLAIMS entry: {exc}") from exc

    return CaseInfo(
        name=case,
        path=path,
        description=ast.get_docstring(tree),
        hooks=hooks,
        claims=claims,
    )


def _extract_claims(case: str, tree: ast.Module) -> list[str]:
    claims: list[str] = []
    for node in tree.body:
        if isinstance(node, ast.Assign):
            targets = node.targets
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            targets = [node.target]
        else:
            continue
        if not any(isinstance(t, ast.Name) and t.id == CLAIMS_NAME for t in targets):
            continue
        try:
            value = ast.literal_eval(node.value)
        except ValueError as exc:
            raise TestPlanError(
                f"test case {case!r}: CLAIMS must be a literal list of URL patterns"
            ) from exc
        if not isinstance(value, (list, tuple)) or not all(isinstance(v, str) for v in value):
            raise TestPlanError(
                f"test case {case!r}: CLAIMS must be a list of URL pattern strings"
            )
        claims = list(value)
    return claims


def read_active(path: Path) -> ActiveTest | None:
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return ActiveTest.from_dict(data)
    except (json.JSONDecodeError, KeyError, TypeError, OSError):
        return None


def write_active(path: Path, active: ActiveTest) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    _atomic_write_text(path, json.dumps(active.to_dict(), indent=2) + "\n")


def clear_active(path: Path) -> bool:
    existed = path.exists()
    path.unlink(missing_ok=True)
    error_path(path).unlink(missing_ok=True)
    return existed


def error_path(active_path: Path) -> Path:
    return active_path.with_name(TEST_ERROR_FILENAME)


def record_error(active_path: Path, payload: dict[str, Any]) -> None:
    data = {"at": now_iso(), **payload}
    _atomic_write_text(error_path(active_path), json.dumps(data, indent=2) + "\n")


def read_error(active_path: Path) -> dict[str, Any] | None:
    path = error_path(active_path)
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None
    return data if isinstance(data, dict) else None


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _require_name(name: str, kind: str) -> None:
    if not is_valid_profile_name(name):
        raise TestPlanError(
            f"invalid {kind} name {name!r}: use letters, digits, '_' and '-' (max 64 chars)"
        )


def _atomic_write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fp:
            fp.write(text)
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise
