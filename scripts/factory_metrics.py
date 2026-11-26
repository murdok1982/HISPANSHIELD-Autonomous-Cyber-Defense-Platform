#!/usr/bin/env python3
"""Recompute HISPANSHIELD engineering metrics from the repository.

Every number published in the documentation must be reproducible by running
this script. It never edits documentation on its own: it writes
``.factory/EVIDENCE/METRICS.json`` and ``.factory/EVIDENCE/METRICS.md`` so a
reviewer can diff the claims against the code.

Usage:
    python3 scripts/factory_metrics.py [--json]
"""

from __future__ import annotations

import argparse
import ast
import json
import re
import subprocess
import sys
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend"
FRONTEND = ROOT / "frontend"
EVIDENCE = ROOT / ".factory" / "EVIDENCE"


@dataclass
class Metrics:
    generated_at: str
    git_head: str
    git_dirty: bool
    backend_tests_collected: int
    backend_test_files: int
    backend_test_functions: int
    edge_tests: int
    frontend_page_components: int
    frontend_content_screens: int
    frontend_nav_screens: int
    backend_modules: int
    backend_routers: int
    http_endpoints: int
    http_paths: int
    orm_tables: int
    migrations: int
    connector_adapters: int
    action_catalog_entries: int
    a4_actions: int
    task_total: int
    task_verified: int
    task_deferred: int
    task_pending: int
    ac_total: int
    ac_checked: int
    docs_present: int
    evidence_files: int


def _git(*args: str) -> str:
    try:
        return subprocess.run(
            ["git", *args], cwd=ROOT, check=True, capture_output=True, text=True
        ).stdout.strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        return ""


def _count_pytest_tests(directory: Path, *, extra_env: dict[str, str] | None = None) -> int:
    """Collect tests without connecting to PostgreSQL (collection does not touch the DB)."""
    env = {
        "HS_ENV": "test",
        "HS_SECRET_KEY": "metrics-secret-key-0123456789-abcdefghijklmnopqrstuvwxyz",
        "HS_ENCRYPTION_KEY": "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=",
        "PATH": str(Path.home() / ".local" / "bin") + ":/usr/bin:/bin",
    }
    if extra_env:
        env.update(extra_env)
    try:
        result = subprocess.run(
            [sys.executable, "-m", "pytest", "--collect-only", "-q", "-o", "addopts="],
            cwd=directory,
            check=False,
            capture_output=True,
            text=True,
            env=env,
            timeout=180,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return 0
    match = re.search(r"(\d+) tests? collected", result.stdout)
    return int(match.group(1)) if match else 0


def _count_endpoints() -> tuple[int, int]:
    endpoints = 0
    routers = 0
    for path in (BACKEND / "app").rglob("router.py"):
        routers += 1
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for decorator in node.decorator_list:
                target = decorator.func if isinstance(decorator, ast.Call) else decorator
                if isinstance(target, ast.Attribute) and target.attr in {
                    "get",
                    "post",
                    "put",
                    "patch",
                    "delete",
                }:
                    endpoints += 1
    return endpoints, routers


def _count_openapi_operations() -> tuple[int, int]:
    """Count operations from the real OpenAPI schema (authoritative contract)."""
    code = (
        "import json;"
        "from app.main import create_app;"
        "schema=create_app().openapi();"
        "paths=schema['paths'];"
        "verbs={'get','post','put','patch','delete'};"
        "ops=sum(1 for methods in paths.values() for method in methods if method in verbs);"
        "print(json.dumps({'paths':len(paths),'ops':ops}))"
    )
    env = {
        "HS_ENV": "test",
        "HS_SECRET_KEY": "metrics-secret-key-0123456789-abcdefghijklmnopqrstuvwxyz",
        "HS_ENCRYPTION_KEY": "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=",
        "PATH": "/usr/bin:/bin",
    }
    try:
        result = subprocess.run(
            [sys.executable, "-c", code],
            cwd=BACKEND,
            check=False,
            capture_output=True,
            text=True,
            env=env,
            timeout=120,
        )
        payload = json.loads(result.stdout.strip().splitlines()[-1])
        return int(payload["ops"]), int(payload["paths"])
    except (subprocess.TimeoutExpired, ValueError, KeyError, IndexError):
        return 0, 0


def _count_tables() -> int:
    pattern = re.compile(r'__tablename__\s*=\s*"([a-z0-9_]+)"')
    tables: set[str] = set()
    for path in (BACKEND / "app" / "models").glob("*.py"):
        tables.update(pattern.findall(path.read_text(encoding="utf-8")))
    return len(tables)


def _count_frontend() -> tuple[int, int, int]:
    pages = [path for path in (FRONTEND / "src" / "pages").glob("*.tsx") if not path.name.startswith("__")]
    content = [path for path in pages if path.stem not in {"Login", "NotFound"}]
    nav = (FRONTEND / "src" / "components" / "layout" / "navigation.ts").read_text(encoding="utf-8")
    nav_screens = len(re.findall(r'path:\s*"', nav))
    return len(pages), len(content), nav_screens


def _count_adapters() -> int:
    init = (BACKEND / "app" / "services" / "connectors" / "adapters" / "__init__.py").read_text(encoding="utf-8")
    match = re.search(r"ADAPTER_MODULES\s*=\s*\((.*?)\)", init, re.S)
    if not match:
        return len(list((BACKEND / "app" / "services" / "connectors" / "adapters").glob("*.py"))) - 2
    return len(re.findall(r'"[a-z0-9_]+"', match.group(1)))


def _count_actions() -> tuple[int, int]:
    text = (BACKEND / "app" / "services" / "actions.py").read_text(encoding="utf-8")
    entries = len(re.findall(r'^    "[a-z.]+": ActionDefinition\(', text, re.M))
    a4 = len(re.findall(r'min_level="A4"', text))
    return entries, a4


def _tasks() -> tuple[int, int, int, int]:
    text = (ROOT / ".factory" / "TASKS.md").read_text(encoding="utf-8")
    pending = len(re.findall(r"^- \[ \]", text, re.M))
    in_progress = len(re.findall(r"^- \[~\]", text, re.M))
    verified = len(re.findall(r"^- \[x\]", text, re.M))
    deferred = len(re.findall(r"^- \[!\]", text, re.M))
    return pending + in_progress + verified + deferred, verified, deferred, pending + in_progress


def _acs() -> tuple[int, int]:
    text = (ROOT / ".factory" / "SPEC.md").read_text(encoding="utf-8")
    acs = set(re.findall(r"AC-[0-9]{2,3}", text))
    checked = len(re.findall(r"- \[x\] \*\*AC-[0-9]{2,3}\*\*", text))
    return len(acs), checked


def collect() -> Metrics:
    backend_tests = _count_pytest_tests(BACKEND)
    edge_tests = _count_pytest_tests(ROOT / "edge")
    endpoint_count, router_count = _count_endpoints()
    openapi_ops, openapi_paths = _count_openapi_operations()
    pages, content, nav = _count_frontend()
    entries, a4 = _count_actions()
    total, verified, deferred, pending = _tasks()
    ac_total, ac_checked = _acs()
    migrations = len(list((BACKEND / "migrations" / "versions").glob("*.py")))
    modules = len(
        [
            path
            for path in (BACKEND / "app" / "modules").iterdir()
            if path.is_dir() and not path.name.startswith("__")
        ]
    )
    test_files = list((BACKEND / "tests").rglob("test_*.py"))
    test_functions = 0
    for path in test_files:
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except SyntaxError:
            continue
        test_functions += sum(
            1
            for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith("test_")
        )
    evidence_files = 0
    if EVIDENCE.exists():
        evidence_files = len([path for path in EVIDENCE.rglob("*") if path.is_file()])
    return Metrics(
        generated_at=datetime.now(UTC).isoformat(),
        git_head=_git("rev-parse", "--short", "HEAD") or "unknown",
        git_dirty=bool(_git("status", "--porcelain")),
        backend_tests_collected=backend_tests,
        backend_test_files=len(test_files),
        backend_test_functions=test_functions,
        edge_tests=edge_tests,
        frontend_page_components=pages,
        frontend_content_screens=content,
        frontend_nav_screens=nav,
        backend_modules=modules,
        backend_routers=router_count,
        http_endpoints=openapi_ops or endpoint_count,
        http_paths=openapi_paths,
        orm_tables=_count_tables(),
        migrations=migrations,
        connector_adapters=_count_adapters(),
        action_catalog_entries=entries,
        a4_actions=a4,
        task_total=total,
        task_verified=verified,
        task_deferred=deferred,
        task_pending=pending,
        ac_total=ac_total,
        ac_checked=ac_checked,
        docs_present=len(list((ROOT / "docs").glob("*.md"))),
        evidence_files=evidence_files,
    )


def render_markdown(metrics: Metrics) -> str:
    data = asdict(metrics)
    rows = "\n".join(f"| `{key}` | {value} |" for key, value in data.items())
    return f"""# Recomputed engineering metrics

Generated by `python3 scripts/factory_metrics.py`. Do not hand-edit: re-run the
script and commit the diff.

| Metric | Value |
| :--- | --- |
{rows}
"""


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="print JSON instead of a summary")
    args = parser.parse_args()
    metrics = collect()
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    (EVIDENCE / "METRICS.json").write_text(json.dumps(asdict(metrics), indent=2) + "\n", encoding="utf-8")
    (EVIDENCE / "METRICS.md").write_text(render_markdown(metrics), encoding="utf-8")
    if args.json:
        print(json.dumps(asdict(metrics), indent=2))
    else:
        print(
            "tasks {task_verified}/{task_total} verified, {task_deferred} deferred; "
            "tests backend={backend_tests_collected} edge={edge_tests}; "
            "screens nav={frontend_nav_screens} content={frontend_content_screens}; "
            "endpoints={http_endpoints}; adapters={connector_adapters}; "
            "ACs checked {ac_checked}/{ac_total}".format(**asdict(metrics))
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
