"""Policy decisions and complete-evidence checks, without scanners or network."""

from __future__ import annotations

import copy
import hashlib
import json
from datetime import UTC, date, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts.security import gate, scan_compose

ROOT = Path(__file__).resolve().parents[3]
NOW = date(2026, 10, 7)
COMMIT = "a" * 40


@pytest.fixture
def policy():
    return json.loads((ROOT / "security/policy.json").read_text())


@pytest.fixture
def exceptions():
    return {"schema_version": 1, "exceptions": []}


def report(check="dependencies", findings=None):
    return {
        "schema_version": 1,
        "commit": COMMIT,
        "target": "content-service",
        "check": check,
        "tool": {"name": "fixture-scanner", "version": "1"},
        "status": "ok",
        "findings": [] if findings is None else findings,
        "errors": [],
        "run_context": {
            "run_id": "unit",
            "run_attempt": "1",
            "inputs": {"security/policy.json": "hash"},
        },
        "artifacts": [{"path": f"content-service/raw-{check}.json", "sha256": "b" * 64}],
    }


def finding(severity="HIGH", **changes):
    return {
        "id": "ADVISORY-1",
        "severity": severity,
        "package": "example",
        "version": "1.0",
        **changes,
    }


def exception(check="dependencies", **changes):
    return {
        "id": "SEC-001",
        "check": check,
        "target": "content-service",
        "finding_id": "ADVISORY-1",
        "package": "example",
        "version": "1.0",
        "owner": "backend-team",
        "reason": "A documented mitigation is deployed",
        "tracking_issue": "FCB-62",
        "compensating_control": "Feature disabled until update",
        "created_at": "2026-10-01",
        "expires_at": "2026-10-14",
        **changes,
    }


def severity_review(**changes):
    return {
        "severity": "HIGH",
        "finding_id": "ADVISORY-1",
        "source": "https://osv.dev/vulnerability/ADVISORY-1",
        "reviewed_by": "backend-team",
        "reviewed_at": "2026-10-06",
        **changes,
    }


def test_default_policy_and_empty_exceptions_are_valid(policy, exceptions):
    assert gate.validate_policy(policy) == []
    assert gate.validate_exceptions(exceptions, policy, NOW) == []
    assert gate.evaluate_report(report(), policy, exceptions, NOW) == []


@pytest.mark.parametrize("value", [None, [], {}, {"schema_version": True}, {"schema_version": 2}])
def test_incomplete_policy_fails(value):
    assert gate.validate_policy(value)


@pytest.mark.parametrize(
    "key,value",
    [
        ("checks", []),
        ("checks", ["dependencies"]),
        ("checks", [None]),
        ("blocking_severities", []),
        ("blocking_severities", ["CRITICAL"]),
        ("blocking_severities", ["HIGH", "CRITICAL", "surprise"]),
        ("blocking_severities", [None]),
        ("blocking_severities", None),
        ("blocking_severities", ["HIGH", "CRITICAL", "HIGH"]),
        ("coverage", {"minimum_percent": True}),
        ("coverage", {"minimum_percent": 89}),
        ("coverage", None),
        ("licenses", None),
        ("exceptions", {"max_days": 31}),
        ("exceptions", {"max_days": False}),
        ("exceptions", None),
    ],
)
def test_policy_invalid_fields_fail(policy, key, value):
    policy[key] = value
    assert gate.validate_policy(policy)


@pytest.mark.parametrize(
    "licenses",
    [
        {"approved_expressions": [], "aliases": {}},
        {"approved_expressions": ["MIT", "MIT"], "aliases": {}},
        {"approved_expressions": ["UNKNOWN"], "aliases": {}},
        {"approved_expressions": ["MIT"], "aliases": []},
        {"approved_expressions": ["MIT"], "aliases": {"MIT License": "GPL-3.0"}},
        {"approved_expressions": ["MIT"], "aliases": {"UNKNOWN": "MIT"}},
        {"approved_expressions": ["MIT"], "aliases": {"": "MIT"}},
    ],
)
def test_invalid_license_policy_fails(policy, licenses):
    policy["licenses"] = licenses
    assert gate.validate_policy(policy)


@pytest.mark.parametrize(
    "document",
    [
        None,
        [],
        {},
        {"schema_version": True, "exceptions": []},
        {"schema_version": 1, "exceptions": None},
    ],
)
def test_invalid_exception_document_fails(policy, document):
    assert gate.validate_exceptions(document, policy, NOW)


@pytest.mark.parametrize(
    "change",
    [
        {"owner": ""},
        {"id": "*"},
        {"target": "*"},
        {"check": "secrets"},
        {"check": "tests"},
        {"check": "unknown"},
        {"version": "*"},
        {"package": ""},
        {"package": None},
        {"finding_id": "CVE-*"},
        {"check": "iac", "path": "*"},
        {"check": "compose", "path": ""},
        {"created_at": "2026-10-10"},
        {"created_at": "2026-01-01"},
        {"expires_at": "2026-10-07"},
        {"expires_at": "2026-10-01"},
        {"expires_at": "2026-99-99"},
        {"expires_at": "20261014"},
        {"expires_at": "2026-10-14T00:00:00Z"},
        {"severity_review": {}},
        {"severity_review": {"severity": []}},
        {"severity_review": severity_review(severity="CRITICAL")},
        {"severity_review": severity_review(finding_id="OTHER")},
        {"severity_review": severity_review(source="http://osv.dev/ADVISORY-1")},
        {"severity_review": severity_review(source="https://user:password@osv.dev/id")},
        {"severity_review": severity_review(source="https://[malformed/")},
        {"severity_review": severity_review(reviewed_at="2026-10-09")},
        {"severity_review": severity_review(reviewed_at="bad-date")},
    ],
)
def test_invalid_or_expired_exception_fails(policy, change):
    document = {"schema_version": 1, "exceptions": [exception(**change)]}
    assert gate.validate_exceptions(document, policy, NOW)


def test_duplicate_and_nonobject_exceptions_fail(policy):
    assert gate.validate_exceptions({"schema_version": 1, "exceptions": [1]}, policy, NOW)
    assert gate.validate_exceptions(
        {"schema_version": 1, "exceptions": [exception(), exception()]}, policy, NOW
    )
    assert gate.validate_exceptions({}, {}, NOW)


def test_expiry_uses_utc_and_is_checked_even_without_matching_findings(policy):
    document = {"schema_version": 1, "exceptions": [exception(expires_at="2026-10-08")]}
    assert (
        gate.evaluate_report(report(), policy, document, datetime(2026, 10, 7, 23, 59, tzinfo=UTC))
        == []
    )
    assert gate.evaluate_report(report(), policy, document, datetime(2026, 10, 8))
    assert isinstance(gate._utc(None), datetime)


def test_exact_exception_scope_and_unknown_severity_review(policy):
    data = report(findings=[finding()])
    document = {"schema_version": 1, "exceptions": [exception()]}
    assert gate.evaluate_report(data, policy, document, NOW) == []
    for change in (
        {"target": "other"},
        {"check": "image"},
        {"finding_id": "other"},
        {"package": "other"},
        {"version": "2.0"},
    ):
        wrong = {"schema_version": 1, "exceptions": [exception(**change)]}
        assert gate.evaluate_report(data, policy, wrong, NOW)
    data["findings"][0]["severity"] = "UNKNOWN"
    assert gate.evaluate_report(data, policy, document, NOW)
    document["exceptions"][0]["severity_review"] = severity_review()
    assert gate.evaluate_report(data, policy, document, NOW) == []
    data["findings"][0]["severity"] = "CRITICAL"
    assert gate.evaluate_report(data, policy, document, NOW)


def test_exact_iac_path_exception(policy):
    entry = exception(check="iac", path="deploy/workload.yaml")
    del entry["package"], entry["version"]
    document = {"schema_version": 1, "exceptions": [entry]}
    data = report("iac", [finding(path="deploy/workload.yaml")])
    assert gate.evaluate_report(data, policy, document, NOW) == []
    data["findings"][0]["path"] = "deploy/other.yaml"
    assert gate.evaluate_report(data, policy, document, NOW)


@pytest.mark.parametrize(
    "severity,blocked",
    [
        ("INFO", False),
        ("LOW", False),
        ("MEDIUM", False),
        ("HIGH", True),
        ("CRITICAL", True),
        ("UNKNOWN", True),
    ],
)
def test_severity_policy_for_image(policy, exceptions, severity, blocked):
    assert (
        bool(gate.evaluate_report(report("image", [finding(severity)]), policy, exceptions, NOW))
        is blocked
    )


@pytest.mark.parametrize(
    "license_name,allowed",
    [
        ("MIT", True),
        ("MIT License", True),
        ("MIT AND GPL-3.0-only", False),
        ("UNKNOWN", False),
        ("", False),
        ("MIT OR GPL-3.0-only", False),
    ],
)
def test_license_expressions_are_exact_not_substrings(policy, exceptions, license_name, allowed):
    data = report("licenses", [finding("INFO", license=license_name)])
    assert (gate.evaluate_report(data, policy, exceptions, NOW) == []) is allowed


def test_critical_fixture_is_rejected(policy, exceptions):
    fixture = ROOT / "scripts/tests/fixtures/security/critical-image.json"
    assert gate.evaluate_report(json.loads(fixture.read_text()), policy, exceptions, NOW)


@pytest.mark.parametrize(
    "key,value",
    [
        ("schema_version", True),
        ("schema_version", 2),
        ("commit", "short"),
        ("target", "../outside"),
        ("check", "other"),
        ("tool", {}),
        ("status", "success"),
        ("errors", "text"),
        ("errors", [""]),
        ("errors", ["possibly sensitive scanner message"]),
        ("findings", None),
        ("findings", [{}]),
        ("findings", [finding(severity="bad")]),
        ("findings", [finding(package="")]),
        ("artifacts", None),
        ("artifacts", []),
        ("artifacts", [{}]),
    ],
)
def test_malformed_report_fails_closed(policy, exceptions, key, value):
    data = report()
    data[key] = value
    assert gate.evaluate_report(data, policy, exceptions, NOW)


def test_edge_report_shapes_and_safe_errors(policy, exceptions):
    assert gate.evaluate_report(None, policy, exceptions, NOW)
    assert gate.evaluate_report(report("licenses"), policy, exceptions, NOW)
    assert gate.evaluate_report(report("licenses", [finding()]), policy, exceptions, NOW)
    assert gate.evaluate_report(report("secrets", [finding()]), policy, exceptions, NOW)
    assert gate.evaluate_report(
        report("secrets", [finding(path="source.py")]), policy, exceptions, NOW
    )
    data = report()
    data["artifacts"] *= 2
    assert gate.evaluate_report(data, policy, exceptions, NOW)
    data = report()
    data["status"] = "error"
    assert gate.evaluate_report(data, policy, exceptions, NOW)
    data["errors"] = ["password=do-not-print"]
    errors = gate.evaluate_report(data, policy, exceptions, NOW)
    assert errors and "do-not-print" not in repr(errors)


def test_wrong_type_check_does_not_crash_schema_validation(policy, exceptions):
    data = report(findings=[finding()])
    data["check"] = []
    assert gate.evaluate_report(data, policy, exceptions, NOW)


def _write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value))


@pytest.fixture
def evidence(tmp_path, monkeypatch):
    reports = tmp_path / "reports"
    raw = reports / "content-service/raw-dependencies.json"
    _write(raw, {"dependencies": []})
    data = report()
    data["artifacts"][0]["sha256"] = hashlib.sha256(raw.read_bytes()).hexdigest()
    _write(reports / "content-service/dependencies.json", data)
    manifest = {
        "schema_version": 1,
        "commit": COMMIT,
        "run_id": "unit",
        "run_attempt": "1",
        "inputs": {"security/policy.json": "hash"},
        "targets": [{"id": "content-service", "checks": ["dependencies"]}],
    }
    path = reports / "manifest.json"
    _write(path, manifest)
    monkeypatch.setattr(gate, "discover", lambda root: copy.deepcopy(manifest))
    monkeypatch.setattr(
        gate.subprocess, "run", lambda *a, **k: SimpleNamespace(stdout=COMMIT + "\n")
    )
    return tmp_path, reports, path, manifest, data


def test_complete_evidence_and_digests(policy, exceptions, evidence):
    root, reports, path, _, _ = evidence
    assert gate.evaluate_manifest(root, path, reports, policy, exceptions, NOW) == []
    (reports / "content-service/raw-dependencies.json").write_text("tampered")
    assert gate.evaluate_manifest(root, path, reports, policy, exceptions, NOW)


def test_complete_test_evidence_requires_both_xml_reports(policy, exceptions, evidence):
    root, reports, path, manifest, _ = evidence
    manifest["targets"][0]["checks"] = ["tests"]
    _write(path, manifest)
    (reports / "content-service/dependencies.json").unlink()
    data = report("tests")
    data["artifacts"] = []
    for name, content in (
        ("junit.xml", '<testsuite tests="1"><testcase name="works"/></testsuite>'),
        ("coverage.xml", '<coverage lines-covered="10" lines-valid="10"/>'),
    ):
        destination = reports / "content-service" / name
        destination.write_text(content)
        data["artifacts"].append(
            {
                "path": f"content-service/{name}",
                "sha256": hashlib.sha256(destination.read_bytes()).hexdigest(),
            }
        )
    normalized = reports / "content-service/tests.json"
    _write(normalized, data)
    assert gate.evaluate_manifest(root, path, reports, policy, exceptions, NOW) == []
    data["artifacts"].pop()
    _write(normalized, data)
    assert gate.evaluate_manifest(root, path, reports, policy, exceptions, NOW)


def test_manifest_operational_failures_are_safe(policy, exceptions, evidence, monkeypatch):
    root, reports, path, _, _ = evidence
    assert gate.evaluate_manifest(root, path, reports, {}, exceptions, NOW)

    def fail(*args, **kwargs):
        raise ValueError("sensitive source data")

    monkeypatch.setattr(gate, "discover", fail)
    errors = gate.evaluate_manifest(root, path, reports, policy, exceptions, NOW)
    assert errors and "sensitive" not in repr(errors)

    def no_git(*args, **kwargs):
        raise OSError("sensitive git output")

    monkeypatch.setattr(gate.subprocess, "run", no_git)
    errors = gate.evaluate_manifest(root, path, reports, policy, exceptions, NOW)
    assert errors and "sensitive" not in repr(errors)
    path.unlink()
    assert gate.evaluate_manifest(root, path, reports, policy, exceptions, NOW)


@pytest.mark.parametrize(
    "change",
    [
        {"commit": "b" * 40},
        {"commit": "bad"},
        {"schema_version": True},
        {"inputs": {}},
        {"targets": []},
        {"targets": [{}]},
        {"targets": [{"id": "content-service", "checks": ["unknown"]}]},
        {"targets": [{"id": "content-service", "checks": []}]},
        {"targets": [{"id": "content-service", "checks": ["dependencies", "dependencies"]}]},
        {"targets": [{"id": "content-service", "checks": ["dependencies"]}] * 2},
        {"targets": [{"id": "unlisted-service", "checks": ["dependencies"]}]},
    ],
)
def test_manifest_inventory_is_independently_verified(policy, exceptions, evidence, change):
    root, reports, path, manifest, _ = evidence
    _write(path, {**manifest, **change})
    assert gate.evaluate_manifest(root, path, reports, policy, exceptions, NOW)


@pytest.mark.parametrize(
    "change",
    [{"commit": "b" * 40}, {"check": "image"}, {"target": "other-service"}, {"schema_version": 5}],
)
def test_report_provenance_must_match_manifest(policy, exceptions, evidence, change):
    root, reports, path, _, data = evidence
    _write(reports / "content-service/dependencies.json", {**data, **change})
    assert gate.evaluate_manifest(root, path, reports, policy, exceptions, NOW)


@pytest.mark.parametrize(
    "change",
    [
        {"run_id": "old-run"},
        {"run_attempt": "2"},
        {"inputs": {}},
    ],
)
def test_same_commit_report_from_another_run_or_policy_is_rejected(
    policy,
    exceptions,
    evidence,
    change,
):
    root, reports, path, _, data = evidence
    data["run_context"].update(change)
    _write(reports / "content-service/dependencies.json", data)
    assert gate.evaluate_manifest(root, path, reports, policy, exceptions, NOW)


def test_missing_corrupt_and_duplicate_reports(policy, exceptions, evidence):
    root, reports, path, _, data = evidence
    original = reports / "content-service/dependencies.json"
    original.unlink()
    assert gate.evaluate_manifest(root, path, reports, policy, exceptions, NOW)
    original.write_text("{")
    assert gate.evaluate_manifest(root, path, reports, policy, exceptions, NOW)
    _write(original, data)
    _write(reports / "other-copy.json", data)
    assert gate.evaluate_manifest(root, path, reports, policy, exceptions, NOW)


@pytest.mark.parametrize(
    "artifact_path",
    [
        "../outside",
        "/tmp/outside",
        "content-service\\outside",
        "content-service/missing.json",
        "content-service/dependencies.json",
    ],
)
def test_artifact_paths_cannot_escape_or_reference_themselves(
    policy, exceptions, evidence, artifact_path
):
    root, reports, path, _, data = evidence
    data["artifacts"][0]["path"] = artifact_path
    _write(reports / "content-service/dependencies.json", data)
    assert gate.evaluate_manifest(root, path, reports, policy, exceptions, NOW)


def test_artifact_symlink_is_rejected(policy, exceptions, evidence):
    root, reports, path, _, _ = evidence
    raw = reports / "content-service/raw-dependencies.json"
    other = reports / "raw.json"
    raw.rename(other)
    raw.symlink_to(other)
    assert gate.evaluate_manifest(root, path, reports, policy, exceptions, NOW)


@pytest.mark.parametrize(
    "xml",
    [
        "<testsuites/>",
        "not-xml",
        "<root/>",
        "<testsuite><testcase><skipped/></testcase></testsuite>",
        '<testsuite failures="1"><testcase/></testsuite>',
        '<testsuite errors="1"><testcase/></testsuite>',
        "<testsuite><testcase><failure/></testcase></testsuite>",
        "<!DOCTYPE x><testsuite><testcase/></testsuite>",
    ],
)
def test_junit_evidence_must_show_executed_passing_tests(tmp_path, xml):
    path = tmp_path / "junit.xml"
    path.write_text(xml)
    assert gate._junit_errors(path)


def test_valid_junit_and_missing_junit(tmp_path):
    path = tmp_path / "junit.xml"
    assert gate._junit_errors(path)
    path.write_text(
        '<testsuites><testsuite failures="0" errors="0">'
        '<testcase name="check"/></testsuite></testsuites>'
    )
    assert gate._junit_errors(path) == []


def test_cli_policy_and_evaluate(policy, exceptions, evidence, monkeypatch, capsys):
    root, reports, path, _, _ = evidence
    _write(root / "security/policy.json", policy)
    _write(root / "security/exceptions.json", exceptions)
    monkeypatch.setattr("sys.argv", ["gate", "validate-policy", "--root", str(root)])
    assert gate.main() == 0
    monkeypatch.setattr(
        "sys.argv",
        [
            "gate",
            "evaluate",
            "--root",
            str(root),
            "--manifest",
            "reports/manifest.json",
            "--reports",
            "reports",
        ],
    )
    assert gate.main() == 0
    (reports / "content-service/dependencies.json").unlink()
    assert gate.main() == 1
    _write(root / "security/policy.json", {})
    assert gate.main() == 2
    (root / "security/policy.json").unlink()
    assert gate.main() == 2
    assert "passed" in capsys.readouterr().out


def test_valid_compose_reveals_no_environment_values():
    document = {
        "services": {
            "api": {
                "environment": {"DATABASE_PASSWORD": "do-not-leak"},
                "ports": [{"published": "8000", "target": 8000, "host_ip": "127.0.0.1"}],
                "volumes": [{"type": "volume", "source": "data", "target": "/data"}],
                "security_opt": ["no-new-privileges:true"],
            }
        }
    }
    assert scan_compose.scan_compose(document, "compose.yaml") == []


@pytest.mark.parametrize(
    "settings,rule",
    [
        ({"privileged": True}, "001"),
        ({"network_mode": "host"}, "002"),
        ({"pid": "host"}, "003"),
        ({"ipc": "host"}, "004"),
        ({"volumes": [{"type": "bind", "source": "/run/docker.sock", "target": "/socket"}]}, "005"),
        ({"volumes": [{"type": "bind", "source": "/etc/secrets", "target": "/config"}]}, "006"),
        ({"volumes": [{"type": "bind", "source": "/", "target": "/host"}]}, "006"),
        ({"cap_add": ["CAP_SYS_ADMIN"]}, "007"),
        ({"security_opt": ["seccomp=unconfined"]}, "008"),
        ({"devices": ["/dev/device:/dev/device"]}, "009"),
        ({"ports": [{"published": "8000", "target": 8000}]}, "010"),
        ({"ports": [{"published": "8000", "target": 8000, "host_ip": "::"}]}, "010"),
    ],
)
def test_compose_negative_rules_have_safe_locations(settings, rule):
    settings["environment"] = {"DATABASE_PASSWORD": "do-not-leak"}
    findings = scan_compose.scan_compose({"services": {"api": settings}}, "compose.yaml")
    assert findings[0]["id"] == "FCB-COMPOSE-" + rule
    assert findings[0]["path"].startswith("compose.yaml#services.api.")
    assert "do-not-leak" not in json.dumps(findings)


@pytest.mark.parametrize(
    "settings",
    [
        {"privileged": "false"},
        {"network_mode": []},
        {"volumes": "bad"},
        {"volumes": ["source:target"]},
        {"volumes": [{"type": "bind"}]},
        {"cap_add": "ALL"},
        {"cap_add": [None]},
        {"security_opt": 1},
        {"devices": "device"},
        {"ports": "8000:8000"},
        {"ports": ["8000:8000"]},
        {"ports": [{"published": "8000", "host_ip": 1}]},
        {"ports": [{"published": "8000", "host_ip": "bad-address"}]},
    ],
)
def test_malformed_rendered_compose_fails(settings):
    with pytest.raises(scan_compose.ComposeInputError):
        scan_compose.scan_compose({"services": {"api": settings}}, "compose.yaml")


@pytest.mark.parametrize(
    "document", [[], {}, {"services": {}}, {"services": {"api": 1}}, {"services": {1: {}}}]
)
def test_missing_or_invalid_compose_services_fail(document):
    with pytest.raises(scan_compose.ComposeInputError):
        scan_compose.scan_compose(document, "compose.yaml")


def test_compose_safe_mount_ipv6_and_target_only_ports():
    document = {
        "services": {
            "api": {
                "volumes": [{"type": "bind", "source": "/workspace/code", "target": "/app"}],
                "ports": [{"target": 8000}, {"published": "8001", "host_ip": "[::1]"}],
            }
        }
    }
    assert scan_compose.scan_compose(document, "compose.yaml") == []
    with pytest.raises(scan_compose.ComposeInputError):
        scan_compose.scan_compose(document, "")


def test_compose_cli(tmp_path, monkeypatch, capsys):
    document = tmp_path / "compose.json"
    _write(document, {"services": {"api": {}}})
    monkeypatch.setattr("sys.argv", ["compose", str(document), "--source", "compose.yaml"])
    assert scan_compose.main() == 0
    _write(document, {"services": {"api": {"privileged": True}}})
    assert scan_compose.main() == 1
    document.write_text("invalid secret-input")
    assert scan_compose.main() == 2
    assert "secret-input" not in capsys.readouterr().out


@pytest.mark.parametrize(
    ("package", "version", "raw_license", "allowed"),
    [
        ("Jinja2", "3.1.6", "BSD License", True),
        ("Jinja2", "3.1.7", "BSD License", False),
        ("another-package", "3.1.6", "BSD License", False),
        ("Jinja2", "3.1.6", "UNKNOWN", False),
    ],
)
def test_license_alias_is_scoped_to_package_version_and_declaration(
    policy,
    exceptions,
    package,
    version,
    raw_license,
    allowed,
):
    policy["licenses"]["aliases"]["Jinja2==3.1.6::BSD License"] = "BSD-3-Clause"

    data = report(
        "licenses",
        [
            finding(
                "UNKNOWN",
                package=package,
                version=version,
                license=raw_license,
            )
        ],
    )

    errors = gate.evaluate_report(data, policy, exceptions, NOW)
    assert (errors == []) is allowed
