"""Run selected project integration tests and require exact, current evidence."""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

from scripts.ci.plan import digest, expected_plan
from scripts.security.aggregate_coverage import _xml, validate_junit
from scripts.security.common import read_json, sha256_file, write_json


def passed_junit(path: Path, profile: str | None = None) -> int:
    validate_junit(path)
    cases = list(_xml(path).iter("testcase"))
    if any(case.find("skipped") is not None for case in cases):
        raise ValueError("Selected integration capability tests may not be skipped")
    passed = cases
    expected = {"test_real_asgi_lifecycle_and_http"}
    if profile == "postgres":
        expected.update(
            {
                "test_real_migration_round_trip_and_transaction_rollback",
                "test_real_database_readiness_failure_and_lifespan_cleanup",
            }
        )
    if profile is not None and (
        {case.get("name") for case in passed} != expected or len(passed) != len(expected)
    ):
        raise ValueError("Integration suite did not execute the required capability tests")
    return len(passed)


def run(root: Path, plan_path: Path, reports: Path, target_id: str) -> int:
    root, reports = root.resolve(), reports.resolve()
    plan = expected_plan(root, plan_path)
    if target_id not in plan["selected"]:
        raise ValueError("Requested target is not required by independently recomputed plan")
    target = next(target for target in plan["targets"] if target["id"] == target_id)
    profile = target["integration_profile"]
    project = root / target["path"]
    directory = reports / target_id
    directory.mkdir(parents=True, exist_ok=True)
    junit = directory / "junit.xml"
    status = directory / "status.json"
    if junit.exists() or status.exists():
        raise ValueError(
            "Refusing to reuse stale integration evidence; use a fresh output directory"
        )
    # app.main also creates a module-level application. Explicit Settings in tests
    # cannot protect that import from a developer's cwd/.env; use an empty cwd.
    with tempfile.TemporaryDirectory(prefix="fcb65-integration-") as directory:
        result = subprocess.run(
            [
                str(project / ".venv/bin/python"),
                "-I",
                "-B",
                "-m",
                "pytest",
                "-c",
                str(root / ".ci/security-tools/pyproject.toml"),
                str(root / "scripts/tests/integration/test_service_runtime.py"),
                f"--junitxml={junit}",
                *(["-k", "test_real_asgi_lifecycle_and_http"] if profile == "asgi" else []),
            ],
            cwd=directory,
            env={
                **{key: value for key, value in os.environ.items() if not key.startswith("APP_")},
                "PYTHONDONTWRITEBYTECODE": "1",
                "FCB_INTEGRATION_PROJECT": str(project),
                "FCB_INTEGRATION_PROFILE": profile,
            },
            timeout=600,
            check=False,
        )
    passed = 0
    if result.returncode == 0:
        passed = passed_junit(junit, profile)
    write_json(
        status,
        {
            "schema_version": 1,
            "commit": plan["commit"],
            "plan_sha256": digest(plan),
            "target": target_id,
            "exit_code": result.returncode,
            "passed_tests": passed,
            "junit_sha256": sha256_file(junit) if junit.is_file() else None,
            "scope": "integration-only; not included in unit coverage",
        },
    )
    return result.returncode


def verify(root: Path, plan_path: Path, reports: Path) -> None:
    plan = expected_plan(root.resolve(), plan_path)
    expected = set(plan["selected"])
    found = {path.parent.name for path in reports.glob("*/status.json")}
    if found != expected:
        raise ValueError("Missing or unexpected integration target evidence")
    for target in sorted(expected):
        status = read_json(reports / target / "status.json")
        profile = next(t["integration_profile"] for t in plan["targets"] if t["id"] == target)
        if status != {
            "schema_version": 1,
            "commit": plan["commit"],
            "plan_sha256": digest(plan),
            "target": target,
            "exit_code": 0,
            "passed_tests": passed_junit(reports / target / "junit.xml", profile),
            "junit_sha256": sha256_file(reports / target / "junit.xml"),
            "scope": "integration-only; not included in unit coverage",
        }:
            raise ValueError(f"Invalid, failed or stale integration status: {target}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["run", "verify"])
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--plan", type=Path, default=Path("reports/ci-plan.json"))
    parser.add_argument("--reports", type=Path, default=Path("reports/integration"))
    parser.add_argument("--target")
    args = parser.parse_args(argv)
    try:
        if args.action == "verify":
            verify(args.root, args.plan, args.reports)
            print("All selected integration evidence matches the recomputed execution plan")
            return 0
        if not args.target:
            raise ValueError("run requires --target")
        return run(args.root, args.plan, args.reports, args.target)
    except (OSError, ValueError, ET.ParseError, subprocess.SubprocessError) as error:
        print(f"Integration check failed: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
