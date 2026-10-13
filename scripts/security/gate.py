"""Fail-closed validation of security policy, exceptions and scan evidence."""

from __future__ import annotations

import argparse
import hashlib
import re
import subprocess
import xml.etree.ElementTree as ET
from datetime import UTC, date, datetime, time
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import urlparse

from .common import read_json
from .discover_targets import discover

CHECKS = frozenset({"dependencies", "licenses", "image", "iac", "secrets", "compose", "tests"})
SEVERITIES = frozenset({"UNKNOWN", "INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"})
HEX40 = re.compile(r"[0-9a-f]{40}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
IDENTIFIER = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_.-]*\Z")


def _text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _utc(now: datetime | date | None) -> datetime:
    if now is None:
        return datetime.now(UTC)
    if isinstance(now, datetime):
        return now.replace(tzinfo=UTC) if now.tzinfo is None else now.astimezone(UTC)
    return datetime.combine(now, time.min, tzinfo=UTC)


def _day(value: Any) -> date:
    if not isinstance(value, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", value):
        raise ValueError("Date must use YYYY-MM-DD")
    return date.fromisoformat(value)


def validate_policy(policy: Any) -> list[str]:
    """Return errors instead of accepting an incomplete policy as permissive."""
    if (
        not isinstance(policy, dict)
        or type(policy.get("schema_version")) is not int
        or policy["schema_version"] != 1
    ):
        return ["Policy must be an object with schema_version 1"]
    errors: list[str] = []
    checks = policy.get("checks")
    if (
        not isinstance(checks, list)
        or any(not isinstance(v, str) for v in checks)
        or set(checks) != CHECKS
        or len(checks) != len(CHECKS)
    ):
        errors.append("Policy must declare every supported check exactly once")
    severities = policy.get("blocking_severities")
    if (
        not isinstance(severities, list)
        or any(v not in SEVERITIES for v in severities if isinstance(v, str))
        or any(not isinstance(v, str) for v in severities)
    ):
        errors.append("Policy blocking_severities must be a list of known severities")
    elif not {"HIGH", "CRITICAL"}.issubset(severities) or len(set(severities)) != len(severities):
        errors.append("Policy must block at least HIGH and CRITICAL without duplicate severities")
    coverage = policy.get("coverage")
    minimum = coverage.get("minimum_percent") if isinstance(coverage, dict) else None
    if type(minimum) is not int or not 90 <= minimum <= 100:
        errors.append("Coverage minimum_percent must be an integer between 90 and 100")
    licenses = policy.get("licenses")
    if not isinstance(licenses, dict):
        errors.append("Policy licenses must be an object")
    else:
        approved = licenses.get("approved_expressions")
        valid_approved = (
            isinstance(approved, list) and bool(approved) and all(_text(v) for v in approved)
        )
        if not valid_approved or (valid_approved and len(approved) != len(set(approved))):
            errors.append("License approved_expressions must be a nonempty unique string list")
        elif any(
            v.strip().upper() in {"UNKNOWN", "UNDEFINED", "NOASSERTION", "NONE", "N/A", "*"}
            for v in approved
        ):
            errors.append("Unknown or wildcard license expressions cannot be approved")
        aliases = licenses.get("aliases")
        if not isinstance(aliases, dict) or any(
            not _text(k) or not _text(v) for k, v in aliases.items()
        ):
            errors.append("License aliases must map nonempty strings to approved expressions")
        elif valid_approved:
            for alias, target in aliases.items():
                if target not in approved or alias.upper() in {
                    "UNKNOWN",
                    "UNDEFINED",
                    "NOASSERTION",
                    "NONE",
                    "N/A",
                    "*",
                }:
                    errors.append(
                        "License alias must have an explicit identity and approved destination"
                    )
    options = policy.get("exceptions")
    maximum = options.get("max_days") if isinstance(options, dict) else None
    if type(maximum) is not int or not 1 <= maximum <= 30:
        errors.append("Exception max_days must be an integer between 1 and 30")
    return errors


def validate_exceptions(
    exceptions: Any, policy: dict[str, Any], now: datetime | date | None = None
) -> list[str]:
    """Validate scope and expiry, including entries unused by current scans."""
    policy_errors = validate_policy(policy)
    if policy_errors:
        return policy_errors
    if (
        not isinstance(exceptions, dict)
        or type(exceptions.get("schema_version")) is not int
        or exceptions["schema_version"] != 1
        or not isinstance(exceptions.get("exceptions"), list)
    ):
        return ["Exceptions must contain schema_version 1 and an exceptions list"]
    errors: list[str] = []
    seen_ids: set[str] = set()
    current = _utc(now)
    for index, entry in enumerate(exceptions["exceptions"]):
        prefix = f"Exception entry {index + 1}"
        if not isinstance(entry, dict):
            errors.append(f"{prefix}: expected an object")
            continue
        required = (
            "id",
            "check",
            "target",
            "finding_id",
            "owner",
            "reason",
            "tracking_issue",
            "created_at",
            "expires_at",
            "compensating_control",
        )
        if any(not _text(entry.get(field)) for field in required):
            errors.append(f"{prefix}: required metadata is missing")
            continue
        if entry["id"] in seen_ids:
            errors.append(f"{prefix}: duplicate exception identifier")
        seen_ids.add(entry["id"])
        if not IDENTIFIER.fullmatch(entry["id"]) or not IDENTIFIER.fullmatch(entry["target"]):
            errors.append(f"{prefix}: identifier and target must be exact names")
        check = entry["check"]
        if check not in CHECKS or check in {"secrets", "tests"}:
            errors.append(f"{prefix}: exceptions are forbidden for this check")
        if check in {"dependencies", "licenses", "image"}:
            if not _text(entry.get("package")) or not _text(entry.get("version")):
                errors.append(f"{prefix}: exact package and version are required")
        if check in {"iac", "compose"} and not _text(entry.get("path")):
            errors.append(f"{prefix}: exact source path is required")
        for field in ("finding_id", "package", "version", "path"):
            if field in entry and (
                not _text(entry[field]) or any(c in entry[field] for c in ("*", "?", "["))
            ):
                # Compose locations use [index] literally; never interpret glob syntax.
                if (
                    field != "path"
                    or not _text(entry[field])
                    or "*" in entry[field]
                    or "?" in entry[field]
                ):
                    errors.append(f"{prefix}: exception selectors must be exact values")
        try:
            created, expires = _day(entry["created_at"]), _day(entry["expires_at"])
            if created > current.date():
                errors.append(f"{prefix}: creation date cannot be in the future")
            if not 0 < (expires - created).days <= policy["exceptions"]["max_days"]:
                errors.append(f"{prefix}: expiry must be after creation and within max_days")
            if current >= datetime.combine(expires, time.min, tzinfo=UTC):
                errors.append(f"{prefix}: exception expired at midnight UTC")
        except ValueError:
            errors.append(f"{prefix}: dates must be valid YYYY-MM-DD values")
        review = entry.get("severity_review")
        if review is not None:
            if (
                not isinstance(review, dict)
                or not isinstance(review.get("severity"), str)
                or review["severity"] not in {"LOW", "MEDIUM", "HIGH"}
                or review.get("finding_id") != entry["finding_id"]
                or not _text(review.get("reviewed_by"))
            ):
                errors.append(
                    f"{prefix}: severity review needs a matching advisory, "
                    "reviewer and noncritical severity"
                )
            else:
                try:
                    reference = urlparse(
                        review.get("source", "") if isinstance(review.get("source"), str) else ""
                    )
                except ValueError:
                    errors.append(f"{prefix}: severity advisory source is malformed")
                    continue
                if (
                    reference.scheme != "https"
                    or not reference.hostname
                    or reference.username
                    or reference.password
                    or not reference.path.strip("/")
                ):
                    errors.append(f"{prefix}: severity review needs an HTTPS advisory source")
                try:
                    reviewed_at = _day(review.get("reviewed_at"))
                    if reviewed_at > current.date():
                        errors.append(f"{prefix}: severity review cannot be in the future")
                except ValueError:
                    errors.append(f"{prefix}: severity review date is invalid")
    return errors


def _report_errors(report: Any) -> list[str]:
    if not isinstance(report, dict):
        return ["Report must be an object"]
    errors: list[str] = []
    if type(report.get("schema_version")) is not int or report["schema_version"] != 1:
        errors.append("Report schema_version must be 1")
    if not isinstance(report.get("commit"), str) or not HEX40.fullmatch(report["commit"]):
        errors.append("Report must identify the full checked-out commit")
    if not isinstance(report.get("target"), str) or not IDENTIFIER.fullmatch(report["target"]):
        errors.append("Report target is missing or invalid")
    check = report.get("check")
    if not isinstance(check, str) or check not in CHECKS:
        errors.append("Report check is missing or unknown")
        check = ""
    tool = report.get("tool")
    if not isinstance(tool, dict) or not _text(tool.get("name")) or not _text(tool.get("version")):
        errors.append("Report tool identity and version are required")
    if report.get("status") not in ("ok", "error"):
        errors.append("Report status must be ok or error")
    operational = report.get("errors")
    if not isinstance(operational, list) or any(not _text(v) for v in operational):
        errors.append("Report errors must be a string list")
    elif report.get("status") == "ok" and operational:
        errors.append("Successful report cannot contain scanner errors")
    elif report.get("status") == "error" and not operational:
        errors.append("Failed report must identify an operational error")
    findings = report.get("findings")
    if not isinstance(findings, list):
        errors.append("Report findings must be a list")
    else:
        if check == "licenses" and report.get("status") == "ok" and not findings:
            errors.append("License inventory cannot be empty")
        for index, finding in enumerate(findings):
            if (
                not isinstance(finding, dict)
                or not _text(finding.get("id"))
                or not isinstance(finding.get("severity"), str)
                or finding["severity"] not in SEVERITIES
            ):
                errors.append(f"Finding {index + 1}: identifier and known severity are required")
                continue
            if check in {"dependencies", "licenses", "image"} and (
                not _text(finding.get("package")) or not _text(finding.get("version"))
            ):
                errors.append(f"Finding {index + 1}: package and version are required")
            if check in {"secrets", "iac", "compose"} and not _text(finding.get("path")):
                errors.append(f"Finding {index + 1}: source path is required")
            if check == "licenses" and not isinstance(finding.get("license"), str):
                errors.append(f"Finding {index + 1}: raw license expression is required")
    artifacts = report.get("artifacts")
    if not isinstance(artifacts, list):
        errors.append("Report artifacts must be a list")
    else:
        if report.get("status") == "ok" and not artifacts:
            errors.append("Successful report must retain raw evidence")
        seen: set[str] = set()
        for artifact in artifacts:
            if (
                not isinstance(artifact, dict)
                or not _text(artifact.get("path"))
                or not isinstance(artifact.get("sha256"), str)
                or not HEX64.fullmatch(artifact["sha256"])
            ):
                errors.append("Artifact path and SHA-256 are required")
                continue
            if artifact["path"] in seen:
                errors.append("Report contains a duplicate artifact path")
            seen.add(artifact["path"])
    return errors


def _exception_matches(
    entry: dict[str, Any], report: dict[str, Any], finding: dict[str, Any]
) -> bool:
    if (
        entry["check"] != report["check"]
        or entry["target"] != report["target"]
        or entry["finding_id"] != finding["id"]
    ):
        return False
    if report["check"] in {"secrets", "tests"} or finding["severity"] == "CRITICAL":
        return False
    for field in ("package", "version", "path"):
        if field in entry and entry[field] != finding.get(field):
            return False
    if finding["severity"] == "UNKNOWN" and report["check"] in {
        "dependencies",
        "image",
        "iac",
        "compose",
    }:
        # A pip-audit finding has no uniform severity. A reviewer must provide
        # explicit advisory evidence before it can bypass the critical policy.
        review = entry.get("severity_review")
        return (
            isinstance(review, dict)
            and review.get("finding_id") == finding["id"]
            and review.get("severity") in {"LOW", "MEDIUM", "HIGH"}
        )
    return True


def evaluate_report(
    report: Any,
    policy: dict[str, Any],
    exceptions: dict[str, Any],
    now: datetime | date | None = None,
) -> list[str]:
    """Validate one normalized report and return blocking errors (empty = pass)."""
    configuration = validate_policy(policy) or validate_exceptions(exceptions, policy, now)
    if configuration:
        return configuration
    schema_errors = _report_errors(report)
    if schema_errors:
        return schema_errors
    label = f"{report['target']}/{report['check']}"
    if report["status"] == "error":
        return [f"{label}: scanner failed; report values are withheld"]
    errors: list[str] = []
    for index, finding in enumerate(report["findings"]):
        check = report["check"]
        if check == "licenses":
            raw_license = finding["license"].strip()
            aliases = policy["licenses"]["aliases"]
            scoped_key = f"{finding['package']}=={finding['version']}::{raw_license}"
            expression = aliases.get(
                scoped_key,
                aliases.get(raw_license, raw_license),
            )
            blocked = expression not in policy["licenses"]["approved_expressions"]
        elif check in {"secrets", "dependencies", "tests"}:
            blocked = True
        else:
            blocked = (
                finding["severity"] in policy["blocking_severities"]
                or finding["severity"] == "UNKNOWN"
            )
        if blocked and not any(
            _exception_matches(entry, report, finding) for entry in exceptions["exceptions"]
        ):
            errors.append(f"{label}: finding {index + 1} violates policy")
    return errors


def _load_json(path: Path) -> Any:
    """Bound report size; shared reader rejects duplicate keys and NaN."""
    if path.stat().st_size > 32 * 1024 * 1024:
        raise ValueError("JSON report exceeds the supported size")
    return read_json(path)


def _evidence_path(reports: Path, relative: str) -> Path:
    """Accept only ordinary files below the report directory, without symlinks."""
    part = PurePosixPath(relative)
    if part.is_absolute() or ".." in part.parts or "\\" in relative or not part.parts:
        raise ValueError("Artifact path must stay inside the reports directory")
    candidate = reports
    for segment in part.parts:
        candidate = candidate / segment
        if candidate.is_symlink():
            raise ValueError("Artifact symlinks are forbidden")
    if not candidate.is_file() or not candidate.resolve().is_relative_to(reports.resolve()):
        raise ValueError("Artifact is missing or outside reports")
    return candidate


def _junit_errors(path: Path) -> list[str]:
    try:
        if path.stat().st_size > 32 * 1024 * 1024:
            raise ValueError("JUnit is too large")
        content = path.read_bytes()
        if b"<!DOCTYPE" in content.upper() or b"<!ENTITY" in content.upper():
            raise ValueError("DTD is forbidden")
        root = ET.fromstring(content)
        if root.tag not in {"testsuite", "testsuites"}:
            raise ValueError("Not a JUnit document")
        cases = list(root.iter("testcase"))
        if not cases or all(case.find("skipped") is not None for case in cases):
            raise ValueError("JUnit contains no executed test cases")
        for suite in root.iter("testsuite"):
            for attribute in ("errors", "failures"):
                if int(suite.get(attribute, "0")) != 0:
                    raise ValueError("JUnit reports failed tests")
        if any(
            case.find("failure") is not None or case.find("error") is not None for case in cases
        ):
            raise ValueError("JUnit contains failed test cases")
    except OSError, ValueError, ET.ParseError:
        return ["JUnit evidence is invalid, empty, skipped-only or reports failed tests"]
    return []


def evaluate_manifest(
    root: Path,
    manifest_path: Path,
    reports: Path,
    policy: dict[str, Any],
    exceptions: dict[str, Any],
    now: datetime | date | None = None,
) -> list[str]:
    """Verify expected normalized reports, checked-out revision and raw evidence."""
    errors = validate_policy(policy) or validate_exceptions(exceptions, policy, now)
    if errors:
        return errors
    try:
        manifest = _load_json(manifest_path)
    except OSError, UnicodeError, ValueError:
        return ["Expected scan manifest is missing or invalid"]
    if (
        not isinstance(manifest, dict)
        or type(manifest.get("schema_version")) is not int
        or manifest["schema_version"] != 1
        or not isinstance(manifest.get("commit"), str)
        or not HEX40.fullmatch(manifest["commit"])
    ):
        return ["Manifest schema or checked-out commit is invalid"]
    try:
        checked_out = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
            timeout=15,
        ).stdout.strip()
    except OSError, subprocess.SubprocessError:
        return ["Cannot verify the checked-out Git revision"]
    if manifest["commit"] != checked_out:
        return ["Manifest does not describe the checked-out Git revision"]
    try:
        current_manifest = discover(root)
    except OSError, ValueError, subprocess.SubprocessError:
        return ["Cannot independently discover the current scan inventory"]
    if manifest.get("inputs") != current_manifest.get("inputs"):
        return ["Manifest policy, exceptions or tool lock hashes are stale"]
    if any(
        not _text(manifest.get(field)) or manifest.get(field) != current_manifest.get(field)
        for field in ("run_id", "run_attempt")
    ):
        return ["Manifest does not belong to the current workflow run and attempt"]
    expected_context = {field: manifest[field] for field in ("run_id", "run_attempt", "inputs")}
    targets = manifest.get("targets")
    if not isinstance(targets, list) or not targets:
        return ["Manifest targets must be a nonempty list"]
    expected: set[tuple[str, str]] = set()
    target_ids: set[str] = set()
    for target in targets:
        if (
            not isinstance(target, dict)
            or not isinstance(target.get("id"), str)
            or not IDENTIFIER.fullmatch(target["id"])
        ):
            return ["Manifest target identifier is invalid"]
        if target["id"] in target_ids:
            return ["Manifest contains duplicate targets"]
        target_ids.add(target["id"])
        checks = target.get("checks")
        if (
            not isinstance(checks, list)
            or not checks
            or any(not isinstance(c, str) or c not in CHECKS for c in checks)
            or len(set(checks)) != len(checks)
        ):
            return ["Manifest target checks are missing, unknown or duplicated"]
        expected.update((target["id"], check) for check in checks)
    # Ignore creation timestamps but compare the complete structural inventory,
    # including each current lockfile hash and required checks. An attacker must
    # not make a missing service pass by deleting it from the manifest as well.
    actual_by_id = {target["id"]: target for target in targets}
    expected_by_id = {target["id"]: target for target in current_manifest["targets"]}
    if actual_by_id != expected_by_id:
        return ["Manifest inventory differs from independently discovered projects"]

    for target, check in sorted(expected):
        label = f"{target}/{check}"
        try:
            report_path = _evidence_path(reports, f"{label}.json")
            report = _load_json(report_path)
        except OSError, UnicodeError, ValueError:
            errors.append(f"{label}: expected report is missing or invalid")
            continue
        report_errors = _report_errors(report)
        if report_errors:
            errors.extend(f"{label}: {error}" for error in report_errors)
            continue
        if (
            report["commit"] != manifest["commit"]
            or report["target"] != target
            or report["check"] != check
            or report.get("run_context") != expected_context
        ):
            errors.append(f"{label}: report provenance does not match its manifest location")
            continue
        errors.extend(evaluate_report(report, policy, exceptions, now))
        test_artifacts: dict[str, Path] = {}
        for artifact in report["artifacts"]:
            try:
                artifact_path = _evidence_path(reports, artifact["path"])
                if artifact_path == report_path:
                    raise ValueError("A normalized report is not its own raw evidence")
                with artifact_path.open("rb") as stream:
                    digest = hashlib.file_digest(stream, "sha256").hexdigest()
                if digest != artifact["sha256"]:
                    raise ValueError("Artifact digest differs")
                if check == "tests" and artifact_path.name in {"junit.xml", "coverage.xml"}:
                    if artifact_path.name in test_artifacts:
                        raise ValueError("Duplicate test evidence filename")
                    test_artifacts[artifact_path.name] = artifact_path
            except OSError, ValueError:
                errors.append(f"{label}: artifact is missing, unsafe or has a different digest")
        if check == "tests":
            if set(test_artifacts) != {"junit.xml", "coverage.xml"}:
                errors.append(f"{label}: JUnit and coverage XML evidence are both required")
            else:
                errors.extend(
                    f"{label}: {error}" for error in _junit_errors(test_artifacts["junit.xml"])
                )

    # Reject a second normalized report for the same target/check or an unknown
    # report. Raw scanner JSON without our normalized identity is only evidence.
    seen: set[tuple[str, str]] = set()
    for candidate in reports.rglob("*.json"):
        if candidate == manifest_path or candidate.is_symlink():
            continue
        try:
            data = _load_json(candidate)
        except OSError, UnicodeError, ValueError:
            continue  # Required report/evidence parsing is checked above.
        if not isinstance(data, dict) or not {
            "schema_version",
            "target",
            "check",
            "commit",
        }.issubset(data):
            continue
        identity = (data.get("target"), data.get("check"))
        if not all(isinstance(v, str) for v in identity) or identity not in expected:
            errors.append("Found a normalized report for an unexpected target/check")
        elif identity in seen:
            errors.append("Found duplicate normalized reports for a target/check")
        seen.add(identity) if all(isinstance(v, str) for v in identity) else None
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("validate-policy", "evaluate"):
        command = commands.add_parser(name)
        command.add_argument("--root", type=Path, default=Path("."))
        if name == "evaluate":
            command.add_argument("--manifest", type=Path, required=True)
            command.add_argument("--reports", type=Path, required=True)
    args = parser.parse_args()
    root = args.root.resolve()
    try:
        policy = _load_json(root / "security/policy.json")
        exceptions = _load_json(root / "security/exceptions.json")
    except OSError, UnicodeError, ValueError:
        print("Security configuration is missing or invalid; input values are withheld")
        return 2
    errors = validate_policy(policy) or validate_exceptions(exceptions, policy)
    if errors:
        print("\n".join(errors))
        return 2
    if args.command == "evaluate":
        manifest = args.manifest if args.manifest.is_absolute() else root / args.manifest
        reports = args.reports if args.reports.is_absolute() else root / args.reports
        errors = evaluate_manifest(root, manifest.resolve(), reports.resolve(), policy, exceptions)
    if errors:
        print("\n".join(errors))
        return 1
    print(
        "Security policy validation passed"
        if args.command == "validate-policy"
        else "Security evidence and policy gates passed"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
