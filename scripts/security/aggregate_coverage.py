"""Sum covered/valid counters; never average percentages from different projects."""

from __future__ import annotations

import argparse
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

from .common import contained_path, git_commit, read_json, sha256_file, write_json
from .discover_targets import discover


def _xml(path: Path) -> ET.Element:
    if path.stat().st_size > 20 * 1024 * 1024:
        raise ValueError("XML report exceeds the size limit")
    data = path.read_text(encoding="utf-8-sig")
    if "<!DOCTYPE" in data.upper() or "<!ENTITY" in data.upper():
        raise ValueError("DTD and entity declarations are forbidden in reports")
    return ET.fromstring(data)


def _integer(element: ET.Element, key: str) -> int:
    value = element.get(key)
    if value is None or not re.fullmatch(r"[0-9]+", value):
        raise ValueError(f"Missing or invalid nonnegative integer: {key}")
    return int(value)


def coverage_counts(path: Path) -> dict[str, int]:
    root = _xml(path)
    if root.tag != "coverage":
        raise ValueError("Expected a Cobertura coverage element")
    result = {
        key: _integer(root, key)
        for key in (
            "lines-covered",
            "lines-valid",
            "branches-covered",
            "branches-valid",
        )
    }
    for kind in ("lines", "branches"):
        if result[f"{kind}-covered"] > result[f"{kind}-valid"]:
            raise ValueError("Covered count exceeds valid count")
    if result["lines-valid"] <= 0:
        raise ValueError("Coverage report contains no executable lines")
    return result


def validate_junit(path: Path) -> None:
    root = _xml(path)
    if root.tag not in {"testsuite", "testsuites"}:
        raise ValueError("Expected a JUnit testsuite/testsuites element")
    suites = [element for element in root.iter("testsuite") if not element.findall("testsuite")]
    if not suites:
        raise ValueError("JUnit report contains no suites")
    totals = {key: 0 for key in ("tests", "failures", "errors", "skipped")}
    for suite in suites:
        for key in totals:
            totals[key] += _integer(suite, key)
    if totals["errors"] or totals["failures"]:
        raise ValueError("JUnit report contains failing tests")
    if totals["tests"] <= totals["skipped"]:
        raise ValueError("JUnit report contains no executed tests")
    cases = list(root.iter("testcase"))
    if len(cases) != totals["tests"]:
        raise ValueError("JUnit test counters do not match actual test cases")
    if any(case.find("failure") is not None or case.find("error") is not None for case in cases):
        raise ValueError("JUnit report contains a failing test case")
    if sum(case.find("skipped") is not None for case in cases) != totals["skipped"]:
        raise ValueError("JUnit skipped counters do not match actual cases")


def _verified_test_files(
    target: str,
    commit: str,
    reports: Path,
) -> tuple[Path, Path]:
    envelope = read_json(contained_path(reports, f"{target}/tests.json"))
    expected = {
        "schema_version": 1,
        "commit": commit,
        "target": target,
        "check": "tests",
        "status": "ok",
        "branch_coverage": True,
    }
    if not isinstance(envelope, dict) or any(envelope.get(k) != v for k, v in expected.items()):
        raise ValueError("Test evidence has incorrect provenance, status or branch measurement")
    artifacts = envelope.get("artifacts")
    if not isinstance(artifacts, list) or any(not isinstance(a, dict) for a in artifacts):
        raise ValueError("Test artifact inventory is missing or malformed")
    index = {a.get("path"): a.get("sha256") for a in artifacts}
    if len(index) != len(artifacts):
        raise ValueError("Duplicate test artifact paths")
    paths = []
    for name in ("coverage.xml", "junit.xml"):
        relative = f"{target}/{name}"
        path = contained_path(reports, relative)
        if not path.is_file() or index.get(relative) != sha256_file(path):
            raise ValueError(f"Missing or changed test artifact: {relative}")
        paths.append(path)
    return paths[0], paths[1]


def _rates(counts: dict[str, int]) -> dict[str, Any]:
    covered = counts["lines-covered"] + counts["branches-covered"]
    valid = counts["lines-valid"] + counts["branches-valid"]
    return {
        **counts,
        "covered": covered,
        "valid": valid,
        "line_percent": 100 * counts["lines-covered"] / counts["lines-valid"],
        "branch_percent": (
            100 * counts["branches-covered"] / counts["branches-valid"]
            if counts["branches-valid"]
            else None
        ),
        "combined_percent": 100 * covered / valid,
    }


def aggregate(manifest: dict[str, Any], reports: Path, minimum: int = 90) -> dict[str, Any]:
    if type(minimum) is not int or not 0 <= minimum <= 100:
        raise ValueError("Coverage threshold must be an integer from 0 to 100")
    if not isinstance(manifest, dict) or manifest.get("schema_version") != 1:
        raise ValueError("Invalid manifest schema")
    commit = manifest.get("commit")
    if not isinstance(commit, str) or not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("Invalid manifest commit")
    targets = manifest.get("targets")
    if not isinstance(targets, list) or not targets:
        raise ValueError("Missing expected target inventory")
    seen: set[str] = set()
    expected = []
    for target in targets:
        if not isinstance(target, dict) or not isinstance(target.get("id"), str):
            raise ValueError("Invalid target entry")
        target_id = target["id"]
        if not re.fullmatch(r"[a-z][a-z0-9]*(?:-[a-z0-9]+)*", target_id) or target_id in seen:
            raise ValueError("Invalid or duplicate target ID")
        seen.add(target_id)
        if type(target.get("coverage")) is not bool:
            raise ValueError("Each target must explicitly declare its coverage scope")
        if target["coverage"]:
            if "tests" not in target.get("checks", []):
                raise ValueError("Coverage target does not require tests")
            expected.append(target_id)
    if not expected:
        raise ValueError("No coverage targets declared")
    results = []
    errors = []
    totals = dict.fromkeys(
        ("lines-covered", "lines-valid", "branches-covered", "branches-valid"), 0
    )
    for target_id in expected:
        try:
            coverage, junit = _verified_test_files(target_id, commit, reports)
            validate_junit(junit)
            counts = coverage_counts(coverage)
            rates = _rates(counts)
            # Integer arithmetic: 89.999 must not become an accepted 90.00.
            passed = 100 * rates["covered"] >= minimum * rates["valid"]
            results.append({"target": target_id, **rates, "passed": passed})
            if not passed:
                errors.append(f"{target_id}: coverage below {minimum}%")
            for key, value in counts.items():
                totals[key] += value
        except OSError, ValueError, TypeError, ET.ParseError:
            errors.append(f"{target_id}: missing, invalid or unsuccessful test evidence")
    total = _rates(totals) if totals["lines-valid"] else None
    if total and 100 * total["covered"] < minimum * total["valid"]:
        errors.append(f"Aggregate coverage below {minimum}%")
    return {
        "schema_version": 1,
        "commit": commit,
        "minimum_percent": minimum,
        "passed": not errors,
        "errors": errors,
        "targets": results,
        "complete": len(results) == len(expected),
        "total": total,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--manifest", type=Path, default=Path("reports/manifest.json"))
    parser.add_argument("--reports", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    try:
        manifest = read_json(args.manifest)
        if manifest.get("commit") != git_commit(args.root):
            raise ValueError("Manifest does not belong to the current checkout")
        expected = discover(args.root)
        if manifest.get("targets") != expected["targets"] or manifest.get("inputs") != expected.get(
            "inputs"
        ):
            raise ValueError("Manifest does not match the full current target inventory")
        policy = read_json(args.root / "security/policy.json")
        reports = args.reports or args.manifest.parent
        summary = aggregate(manifest, reports, policy["coverage"]["minimum_percent"])
        write_json(args.output or reports / "coverage-summary.json", summary)
        for error in summary["errors"]:
            print(error, file=sys.stderr)
        if summary["total"]:
            print(f"Combined coverage: {summary['total']['combined_percent']:.2f}%")
        return 0 if summary["passed"] else 1
    except OSError, ValueError, KeyError, TypeError:
        print("Cannot aggregate coverage: invalid or missing inputs", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
