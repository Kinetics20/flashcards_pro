"""Mock external processes to exercise scanner orchestration and report safety."""

from __future__ import annotations

import copy
import json
import subprocess
from pathlib import Path

import pytest

from scripts.security import discover_targets, run_scans

COMMIT = "a" * 40
IMAGE_ID = "sha256:" + "b" * 64
KIT = Path(__file__).resolve().parents[3]


def write(path, document):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document))


def completed(command, stdout="", code=0):
    return subprocess.CompletedProcess(command, code, stdout, "")


def option(command, name):
    return command[command.index(name) + 1]


def vulnerability_document():
    return {
        "SchemaVersion": 2,
        "ArtifactName": "fixture-image",
        "ArtifactType": "container_image",
        "Metadata": {
            "ImageID": IMAGE_ID,
            "ImageConfig": {"config": {"Env": ["PASSWORD=never-publish-this"]}},
        },
        "Results": [
            {
                "Target": "python-package-metadata",
                "Class": "lang-pkgs",
                "Type": "python-pkg",
                "Packages": [{"Name": "example", "Version": "1.0"}],
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "FIXTURE-ADVISORY",
                        "Severity": "HIGH",
                        "PkgName": "example",
                        "InstalledVersion": "1.0",
                    }
                ],
            }
        ],
    }


def sbom_document():
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "components": [
            {"type": "library", "name": "example", "version": "1.0", "purl": "pkg:pypi/example@1.0"}
        ],
    }


@pytest.fixture
def context(tmp_path, monkeypatch):
    root = tmp_path / "repo"
    root.mkdir()
    project = root / "services/content-service"
    project.mkdir(parents=True)
    (project / "uv.lock").write_text("version = 1\n")
    write(
        root / "security/tools.lock.json",
        {
            "schema_version": 1,
            "python_tools": {"pip-audit": "2.10.1", "pip-licenses": "5.5.5"},
            "tools": {"gitleaks": {"version": "8.30.1"}, "trivy": {"version": "0.75.0"}},
        },
    )
    write(root / "security/policy.json", json.loads((KIT / "security/policy.json").read_text()))
    write(root / "security/exceptions.json", {"schema_version": 1, "exceptions": []})
    (root / "security/gitleaks.toml").write_text((KIT / "security/gitleaks.toml").read_text())
    target = {
        "id": "content-service",
        "kind": "service",
        "path": "services/content-service",
        "project_name": "content-service",
        "checks": ["dependencies", "licenses", "tests", "image"],
    }
    manifest = {"schema_version": 1, "commit": COMMIT, "targets": [target]}
    output = root / "reports"
    runner = run_scans.Runner(root, output, manifest)
    monkeypatch.setattr(runner, "tool", lambda name: (f"/verified/{name}", "1"))
    calls = []
    state = {
        "audit": {
            "dependencies": [
                {"name": "example", "version": "1.0", "vulns": [{"id": "FIXTURE-ADVISORY"}]}
            ]
        },
        "audit_code": 1,
        "licenses": [
            {"Name": "content_service", "Version": "0.1.0", "License": "UNKNOWN"},
            {"Name": "example", "Version": "1.0", "License": "MIT"},
        ],
        "installed": [
            {"name": "content-service", "version": "0.1.0"},
            {"name": "example", "version": "1.0"},
        ],
        "sbom": sbom_document(),
        "image": vulnerability_document(),
        "shallow": "false",
        "image_id": IMAGE_ID,
        "secrets": [],
        "tracked": ["compose.yaml", "Dockerfile"],
        "compose": {"services": {"api": {}}},
    }
    (root / "compose.yaml").write_text("services:\n  api:\n    image: fixture\n")
    (root / "Dockerfile").write_text("FROM scratch\n")

    def fake_run(command, cwd, **kwargs):
        calls.append((command, Path(cwd), kwargs))
        executable = Path(command[0]).name
        if executable == "pip-audit":
            if state.get("audit_failure"):
                raise run_scans.ScanError("fixture audit failed safely")
            if not state.get("audit_no_write"):
                write(Path(option(command, "--output")), state["audit"])
            return completed(command, code=state["audit_code"])
        if executable == "pip-licenses":
            return completed(command, json.dumps(state["licenses"]))
        if command[:3] == ["uv", "pip", "list"]:
            return completed(command, json.dumps(state["installed"]))
        if executable == "git":
            if "--is-shallow-repository" in command:
                return completed(command, state["shallow"] + "\n")
            if "ls-files" in command:
                return completed(command, "\0".join(state["tracked"]) + "\0")
        if executable == "gitleaks":
            write(Path(option(command, "--report-path")), state["secrets"])
            return completed(command, code=7 if state["secrets"] else 0)
        if command[:3] == ["docker", "image", "inspect"]:
            return completed(command, state["image_id"] + "\n")
        if command[:2] == ["docker", "compose"]:
            return completed(command, json.dumps(state["compose"]))
        if command[:2] == ["uv", "export"]:
            Path(option(command, "--output-file")).write_text("example==1.0\n")
        if "tox" in command or "pytest" in command:
            if state.get("tests_failure"):
                raise run_scans.ScanError("fixture tests failed safely")
            for argument in command:
                if argument.startswith("--junitxml="):
                    Path(argument.split("=", 1)[1]).write_text("<testsuite><testcase/></testsuite>")
                if argument.startswith("--cov-report=xml:"):
                    Path(argument.split("xml:", 1)[1]).write_text("<coverage/>")
        return completed(command)

    def fake_trivy(arguments, cwd, **kwargs):
        calls.append((["trivy", *arguments], Path(cwd), kwargs))
        if state.get("trivy_no_write"):
            return
        if "cyclonedx" in arguments:
            document = state["sbom"]
        elif "--scanners" in arguments and option(arguments, "--scanners") == "license":
            document = {
                "SchemaVersion": 2,
                "Results": [
                    {
                        "Target": "os-packages",
                        "Class": "os-pkgs",
                        "Type": "debian",
                        "Licenses": [{"PkgName": "base-utils", "Name": "GPL-3.0-only"}],
                    }
                ],
            }
        elif arguments[0] == "config":
            document = {
                "SchemaVersion": 2,
                "ArtifactName": "fixture-snapshot",
                "ArtifactType": "filesystem",
                "Results": [
                    {
                        "Target": "Dockerfile",
                        "Class": "config",
                        "Type": "dockerfile",
                        "MisconfSummary": {"Successes": 1, "Failures": 1, "Exceptions": 0},
                        "Misconfigurations": [
                            {
                                "AVDID": "AVD-DOCKER-FIXTURE",
                                "ID": "DS-FIXTURE",
                                "Severity": "HIGH",
                                "Message": "never-publish-this",
                                "CauseMetadata": {"Code": {"Lines": ["secret"]}},
                            }
                        ],
                    }
                ],
            }
        else:
            document = state["image"]
        write(Path(option(arguments, "--output")), document)

    monkeypatch.setattr(run_scans, "run", fake_run)
    monkeypatch.setattr(runner, "trivy", fake_trivy)
    monkeypatch.setattr(discover_targets, "discover", lambda supplied: copy.deepcopy(manifest))
    return runner, target, calls, state, manifest


def test_python_scans_runtime_and_tools_without_first_party_license(context):
    runner, target, calls, _, _ = context
    runner.python(target)
    dependency, licenses = runner.reports
    assert dependency["status"] == licenses["status"] == "ok"
    assert dependency["findings"][0]["severity"] == "UNKNOWN"
    assert dependency["findings"][0]["id"] == "FIXTURE-ADVISORY"
    assert [row["package"] for row in licenses["findings"]] == ["example"]
    assert len(dependency["artifacts"]) == 2
    commands = [command for command, _, _ in calls]
    assert (
        sum(command[:4] == ["uv", "sync", "--all-groups", "--frozen"] for command in commands) == 2
    )
    export = next(command for command in commands if command[:2] == ["uv", "export"])
    assert "--no-emit-project" in export
    audit = next(command for command in commands if Path(command[0]).name == "pip-audit")
    assert "--require-hashes" in audit and "--strict" in audit
    license_command = next(
        command for command in commands if Path(command[0]).name == "pip-licenses"
    )
    assert option(license_command, "--python") == str(
        runner.root / target["path"] / ".venv/bin/python"
    )


@pytest.mark.parametrize(
    "change",
    [
        {"audit_failure": True},
        {"audit": {"dependencies": [{"name": "example", "skip_reason": "not audited"}]}},
        {"audit_code": 0},
        {"sbom": {}},
    ],
)
def test_dependency_failure_still_records_separate_license_scan(context, change):
    runner, target, _, state, _ = context
    state.update(change)
    runner.python(target)
    assert runner.reports[0]["status"] == "error"
    assert runner.reports[1]["status"] == "ok"


@pytest.mark.parametrize("inventory", [[], {}, [{"Name": "broken"}]])
def test_bad_license_inventory_becomes_operational_failure(context, inventory):
    runner, target, _, state, _ = context
    state["licenses"] = inventory
    runner.python(target)
    assert runner.reports[1]["status"] == "error"


def repository_target():
    return {
        "id": "repository",
        "kind": "repository",
        "path": ".",
        "checks": ["secrets", "iac", "compose"],
    }


def test_repository_scans_sanitize_iac_and_compose_output(context):
    runner, _, _, state, _ = context
    state["compose"]["services"]["api"]["environment"] = {"PASSWORD": "never-publish-this"}
    runner.repository(repository_target())
    assert [entry["status"] for entry in runner.reports] == ["ok", "ok", "ok"]
    assert runner.reports[1]["findings"][0]["id"] == "AVD-DOCKER-FIXTURE"
    for name in ("iac.raw.json", "compose.raw.json"):
        assert "never-publish-this" not in (runner.output / "repository" / name).read_text()


def test_shallow_history_is_not_a_successful_secret_scan(context):
    runner, _, _, state, _ = context
    state["shallow"] = "true"
    runner.repository(repository_target())
    assert runner.reports[0]["status"] == "error"
    assert runner.reports[1]["status"] == runner.reports[2]["status"] == "ok"


def test_secret_findings_keep_fingerprint_and_are_critical(context):
    runner, _, _, state, _ = context
    state["secrets"] = [
        {
            "Fingerprint": "fixture-fingerprint",
            "File": "example.py",
            "RuleID": "github-pat",
            "StartLine": 1,
        }
    ]
    runner.repository(repository_target())
    assert runner.reports[0]["findings"] == [
        {"id": "fixture-fingerprint", "severity": "CRITICAL", "path": "example.py"}
    ]


def test_compose_inventory_cannot_be_silently_empty(context):
    runner, _, _, state, _ = context
    state["tracked"] = ["Dockerfile"]
    runner.repository(repository_target())
    assert runner.reports[2]["status"] == "error"


def test_tracked_snapshot_rejects_symlinks_and_empty_repository(context, tmp_path):
    runner, _, _, state, _ = context
    link = runner.root / "alias"
    link.symlink_to(runner.root / "Dockerfile")
    state["tracked"] = ["alias"]
    with pytest.raises(run_scans.ScanError):
        runner.tracked_snapshot(tmp_path / "snapshot")
    state["tracked"] = []
    with pytest.raises(run_scans.ScanError):
        runner.tracked_snapshot(tmp_path / "snapshot")


@pytest.mark.parametrize("reference", [None, "local-existing:fixture"])
def test_image_scans_exact_immutable_image_and_preserves_sbom(context, reference):
    runner, target, calls, _, _ = context
    runner.image(target, reference)
    assert runner.reports[0]["status"] == "ok"
    assert len(runner.reports[0]["artifacts"]) == 4
    commands = [command for command, _, _ in calls]
    assert any(command[:2] == ["docker", "build"] for command in commands) is (reference is None)
    scans = [command for command in commands if command[:2] == ["trivy", "image"]]
    assert len(scans) == 3 and all(IMAGE_ID in command for command in scans)
    identity = json.loads((runner.output / "content-service/image.identity.json").read_text())
    assert identity["image_id"] == IMAGE_ID and identity["commit"] == COMMIT
    assert (
        "never-publish-this" not in (runner.output / "content-service/image.raw.json").read_text()
    )
    assert all("license" not in entry for entry in runner.reports[0]["findings"])


def test_previous_dependency_output_cannot_be_used_as_new_evidence(context):
    runner, target, _, state, _ = context
    raw = runner.directory(target) / "dependencies.raw.json"
    write(raw, state["audit"])
    state["audit_no_write"] = True
    runner.python(target)
    assert runner.reports[0]["status"] == "error"


def test_license_inventory_must_match_installed_environment(context):
    runner, target, _, state, _ = context
    state["installed"].append({"name": "missing-from-license-report", "version": "1"})
    runner.python(target)
    assert runner.reports[1]["status"] == "error"


def test_invalid_image_identity_fails_before_scanning(context):
    runner, target, _, state, _ = context
    state["image_id"] = "mutable-tag"
    runner.image(target, "fixture")
    assert runner.reports[0]["status"] == "error"


def test_image_sbom_must_have_components(context):
    runner, target, _, state, _ = context
    state["sbom"] = {}
    runner.image(target, "fixture")
    assert runner.reports[0]["status"] == "error"


@pytest.mark.parametrize("kind", ["service", "tooling"])
def test_project_tests_produce_both_evidence_files(context, kind):
    runner, target, calls, _, _ = context
    if kind == "tooling":
        target = {
            **target,
            "id": "repo-security-tools",
            "kind": "tooling",
            "path": ".ci/security-tools",
        }
        (runner.root / target["path"]).mkdir(parents=True)
    runner.tests(target)
    entry = runner.reports[0]
    assert entry["status"] == "ok"
    assert entry["branch_coverage"] is True
    assert {Path(artifact["path"]).name for artifact in entry["artifacts"]} == {
        "junit.xml",
        "coverage.xml",
    }
    commands = [command for command, _, _ in calls]
    assert any("tox" in command for command in commands) is (kind == "service")


def test_failed_tests_have_failed_normalized_report(context):
    runner, target, _, state, _ = context
    state["tests_failure"] = True
    runner.tests(target)
    assert runner.reports[0]["status"] == "error"


@pytest.mark.parametrize("exit_code,missing", [(1, False), (0, True)])
def test_record_tests_rejects_failure_or_missing_report(context, tmp_path, exit_code, missing):
    runner, target, _, _, _ = context
    coverage, junit = tmp_path / "coverage.xml", tmp_path / "junit.xml"
    if not missing:
        coverage.write_text("<coverage/>")
        junit.write_text("<testsuite/>")
    runner.record_tests(target, coverage, junit, exit_code)
    assert runner.reports[0]["status"] == "error"


def test_record_tests_copies_only_evidence_files(context, tmp_path):
    runner, target, _, _, _ = context
    coverage, junit = tmp_path / "coverage.xml", tmp_path / "junit.xml"
    coverage.write_text("<coverage/>")
    junit.write_text("<testsuite/>")
    runner.record_tests(target, coverage, junit, 0)
    assert runner.reports[0]["status"] == "ok"
    assert (runner.output / "content-service/coverage.xml").read_text() == "<coverage/>"


def test_main_selects_target_and_returns_policy_failure(context, monkeypatch):
    runner, _, _, _, _ = context

    def fake_python(current, target):
        raw = current.directory(target) / "dependencies.raw.json"
        write(raw, {"dependencies": []})
        current.report(
            target,
            "dependencies",
            ("fixture", "1"),
            lambda: (
                [{"id": "ADVISORY", "severity": "UNKNOWN", "package": "example", "version": "1"}],
                [raw],
            ),
        )

    monkeypatch.setattr(run_scans.Runner, "python", fake_python)
    assert (
        run_scans.main(
            ["--root", str(runner.root), "--phase", "python", "--target", "content-service"]
        )
        == 1
    )
    assert run_scans.main(["--root", str(runner.root), "--target", "missing"]) == 2
    assert run_scans.main(["--root", str(runner.root), "--phase", "repository"]) == 2


def test_main_image_phase_and_all_dispatch(context, monkeypatch):
    runner, _, _, _, _ = context
    phases = []

    def fake_phase(name):
        def perform(current, target, *args):
            phases.append(name)
            raw = current.directory(target) / "result.raw.json"
            write(raw, {})
            current.report(target, "image", ("fixture", "1"), lambda: ([], [raw]))

        return perform

    for phase in ("python", "tests", "image", "repository"):
        monkeypatch.setattr(run_scans.Runner, phase, fake_phase(phase))
    assert (
        run_scans.main(["--root", str(runner.root), "--phase", "image", "--image", "fixed-image"])
        == 0
    )
    assert phases == ["image"]
    phases.clear()
    assert run_scans.main(["--root", str(runner.root), "--all"]) == 0
    assert phases == ["python", "tests", "image"]


def test_main_record_tests_and_self_test_modes(context, monkeypatch, tmp_path):
    runner, _, _, _, _ = context
    assert run_scans.main(["--root", str(runner.root), "--record-tests"]) == 2
    coverage, junit = tmp_path / "coverage.xml", tmp_path / "junit.xml"
    coverage.write_text("<coverage/>")
    junit.write_text("<testsuite/>")
    assert (
        run_scans.main(
            [
                "--root",
                str(runner.root),
                "--record-tests",
                "--target",
                "content-service",
                "--coverage",
                str(coverage),
                "--junit",
                str(junit),
            ]
        )
        == 0
    )
    monkeypatch.setattr(run_scans, "self_test_scanners", lambda *args, **kwargs: True)
    assert run_scans.main(["--root", str(runner.root), "--self-test-scanners"]) == 0
    monkeypatch.setattr(run_scans, "self_test_scanners", lambda *args, **kwargs: False)
    assert run_scans.main(["--root", str(runner.root), "--self-test-scanners"]) == 1
