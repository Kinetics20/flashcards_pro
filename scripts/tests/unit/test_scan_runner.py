"""Offline tests for trust boundaries, scanner adapters and evidence hygiene."""

from __future__ import annotations

import hashlib
import io
import json
import shutil
import subprocess
import tarfile
from pathlib import Path
from unittest.mock import Mock

import pytest

from scripts.security import run_scans as scan


@pytest.fixture
def runner(tmp_path):
    return scan.Runner(tmp_path, tmp_path / "reports", {"commit": "a" * 40, "targets": []})


@pytest.fixture
def target():
    return {"id": "content-service", "path": "services/content-service", "kind": "service"}


def tool_fixture(tmp_path, monkeypatch, payload=b"verified executable", member="gitleaks"):
    monkeypatch.setattr(scan, "platform_key", lambda: "linux-amd64")
    directory = tmp_path / ".cache/security-tools/gitleaks/1.0/linux-amd64"
    directory.mkdir(parents=True)
    archive = directory / "archive.tar.gz"
    with tarfile.open(archive, "w:gz") as bundle:
        info = tarfile.TarInfo(member)
        info.size = len(payload)
        bundle.addfile(info, io.BytesIO(payload))
    lock = {
        "tools": {
            "gitleaks": {
                "version": "1.0",
                "platforms": {
                    "linux-amd64": {
                        "url": "https://github.com/gitleaks/gitleaks/test.tar.gz",
                        "sha256": scan.sha256_file(archive),
                    }
                },
            }
        }
    }
    scan.write_json(tmp_path / "security/tools.lock.json", lock)
    return archive, directory / "gitleaks", lock


@pytest.mark.parametrize(
    ("system", "machine", "expected"),
    [
        ("Linux", "x86_64", "linux-amd64"),
        ("Darwin", "arm64", "darwin-arm64"),
        ("Linux", "aarch64", "linux-arm64"),
        ("Plan9", "other", "plan9-other"),
    ],
)
def test_platform_mapping(monkeypatch, system, machine, expected):
    monkeypatch.setattr(scan.platform, "system", lambda: system)
    monkeypatch.setattr(scan.platform, "machine", lambda: machine)
    assert scan.platform_key() == expected


def test_run_captures_output_and_removes_scanner_overrides(tmp_path, monkeypatch):
    monkeypatch.setenv("TRIVY_IGNORE_UNFIXED", "true")
    monkeypatch.setenv("GITLEAKS_CONFIG", "bad")
    fake = Mock(return_value=subprocess.CompletedProcess(["tool"], 0, "private", "private"))
    monkeypatch.setattr(scan.subprocess, "run", fake)
    assert scan.run(["tool"], tmp_path).stdout == "private"
    options = fake.call_args.kwargs
    assert "TRIVY_IGNORE_UNFIXED" not in options["env"]
    assert "GITLEAKS_CONFIG" not in options["env"]
    assert options["capture_output"] is True
    assert options["check"] is False


@pytest.mark.parametrize(
    "failure", [FileNotFoundError("PRIVATE"), subprocess.TimeoutExpired(["PRIVATE"], 1)]
)
def test_run_operational_errors_are_safe(tmp_path, monkeypatch, failure):
    monkeypatch.setattr(scan.subprocess, "run", Mock(side_effect=failure))
    with pytest.raises(scan.ScanError) as error:
        scan.run(["tool", "PRIVATE"], tmp_path)
    assert "PRIVATE" not in str(error.value)


def test_run_nonzero_and_custom_expected_exit(tmp_path, monkeypatch):
    monkeypatch.setattr(
        scan.subprocess,
        "run",
        Mock(return_value=subprocess.CompletedProcess([], 7, "PRIVATE", "PRIVATE")),
    )
    assert scan.run(["tool"], tmp_path, allowed=(7,)).returncode == 7
    with pytest.raises(scan.ScanError, match="unexpected exit code 7"):
        scan.run(["tool"], tmp_path)


def test_tool_extracts_only_verified_binary_and_rechecks_cache(tmp_path, monkeypatch):
    archive, binary, _ = tool_fixture(tmp_path, monkeypatch)
    assert scan.verified_tool(tmp_path, "gitleaks", install=False) == (str(binary), "1.0")
    assert binary.read_bytes() == b"verified executable"
    assert binary.stat().st_mode & 0o100
    assert scan.verified_tool(tmp_path, "gitleaks", install=False)[0] == str(binary)
    binary.write_bytes(b"tampered")
    with pytest.raises(scan.ScanError, match="executable checksum mismatch"):
        scan.verified_tool(tmp_path, "gitleaks", install=True)
    binary.unlink()
    archive.write_bytes(b"tampered")
    with pytest.raises(scan.ScanError, match="archive checksum mismatch"):
        scan.verified_tool(tmp_path, "gitleaks", install=True)


@pytest.mark.parametrize(
    "field,value,error",
    [("sha256", "bad", "invalid locked"), ("platform", "other", "unsupported platform")],
)
def test_tool_bad_lock(tmp_path, monkeypatch, field, value, error):
    _, _, lock = tool_fixture(tmp_path, monkeypatch)
    if field == "platform":
        monkeypatch.setattr(scan, "platform_key", lambda: value)
    else:
        lock["tools"]["gitleaks"]["platforms"]["linux-amd64"][field] = value
        scan.write_json(tmp_path / "security/tools.lock.json", lock)
    with pytest.raises(scan.ScanError, match=error):
        scan.verified_tool(tmp_path, "gitleaks", install=True)


@pytest.mark.parametrize("member", ["../gitleaks", "elsewhere/gitleaks", "wrong"])
def test_archive_never_extracts_traversal_members(tmp_path, monkeypatch, member):
    tool_fixture(tmp_path, monkeypatch, member=member)
    with pytest.raises(scan.ScanError, match="missing or duplicated"):
        scan.verified_tool(tmp_path, "gitleaks", install=False)


def test_tool_missing_download_success_and_hash_failure(tmp_path, monkeypatch):
    archive, binary, lock = tool_fixture(tmp_path, monkeypatch)
    payload = archive.read_bytes()
    archive.unlink()
    with pytest.raises(scan.ScanError, match="--install-tools"):
        scan.verified_tool(tmp_path, "gitleaks", install=False)

    def download(command, cwd, **kwargs):
        Path(command[command.index("--output") + 1]).write_bytes(payload)
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(scan, "run", download)
    scan.verified_tool(tmp_path, "gitleaks", install=True)
    assert binary.is_file()
    archive.unlink()
    lock["tools"]["gitleaks"]["platforms"]["linux-amd64"]["sha256"] = "0" * 64
    scan.write_json(tmp_path / "security/tools.lock.json", lock)
    with pytest.raises(scan.ScanError, match="downloaded archive checksum mismatch"):
        scan.verified_tool(tmp_path, "gitleaks", install=True)
    assert not (archive.parent / "download.part").exists()


def test_tool_rejects_insecure_origin_and_invalid_tar(tmp_path, monkeypatch):
    archive, _, lock = tool_fixture(tmp_path, monkeypatch)
    archive.unlink()
    asset = lock["tools"]["gitleaks"]["platforms"]["linux-amd64"]
    asset["url"] = "http://untrusted.invalid/tool"
    scan.write_json(tmp_path / "security/tools.lock.json", lock)
    with pytest.raises(scan.ScanError, match="download origin"):
        scan.verified_tool(tmp_path, "gitleaks", install=True)
    archive.write_bytes(b"not a tar")
    asset["sha256"] = scan.sha256_file(archive)
    scan.write_json(tmp_path / "security/tools.lock.json", lock)
    with pytest.raises(scan.ScanError, match="invalid archive"):
        scan.verified_tool(tmp_path, "gitleaks", install=True)


def test_tool_download_os_error_is_safe(tmp_path, monkeypatch):
    archive, _, _ = tool_fixture(tmp_path, monkeypatch)
    archive.unlink()
    monkeypatch.setattr(scan, "run", Mock(side_effect=OSError("secret")))
    with pytest.raises(scan.ScanError, match="download failed"):
        scan.verified_tool(tmp_path, "gitleaks", install=True)


@pytest.mark.parametrize(
    "document", [{}, {"Results": None}, {"Results": []}, {"Results": [{}]}, {"Results": [None]}, []]
)
def test_trivy_cannot_treat_unanalysed_report_as_clean(document):
    with pytest.raises(scan.ScanError):
        scan.trivy_findings(document, "Vulnerabilities")


def test_trivy_normalization_and_clean_results():
    document = {
        "Results": [
            {
                "Target": "uv.lock",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-1",
                        "PkgName": "x",
                        "InstalledVersion": "1",
                        "Severity": "HIGH",
                    }
                ],
                "Misconfigurations": [
                    {"ID": "D-1", "Severity": "LOW"},
                    {"ID": "D-2", "AVDID": "AVD-2"},
                ],
            }
        ]
    }
    assert scan.trivy_findings(document, "Vulnerabilities")[0]["package"] == "x"
    assert scan.trivy_findings(document, "Misconfigurations")[1]["id"] == "AVD-2"
    assert scan.trivy_findings({"Results": [{"Target": "uv.lock"}]}, "Vulnerabilities") == []


@pytest.mark.parametrize("items", [{}, "", [None], ["CVE-1"]])
def test_trivy_rejects_malformed_findings_collection(items):
    with pytest.raises(scan.ScanError, match="invalid findings collection"):
        scan.trivy_findings(
            {"Results": [{"Target": "uv.lock", "Vulnerabilities": items}]}, "Vulnerabilities"
        )


def test_sanitization_removes_secrets_but_keeps_inventory():
    document = {
        "Metadata": {"Env": ["PRIVATE"]},
        "Results": [
            {
                "Target": "image",
                "CauseMetadata": {"Code": "PRIVATE"},
                "Vulnerabilities": [{"VulnerabilityID": "CVE-1"}],
            }
        ],
        "components": [{"name": "package", "properties": [{"name": "env", "value": "PRIVATE"}]}],
    }
    cleaned = scan.sanitize_evidence(document)
    assert "PRIVATE" not in json.dumps(cleaned)
    assert cleaned["components"][0]["name"] == "package"
    assert cleaned["Results"][0]["Vulnerabilities"]


@pytest.mark.parametrize(
    "config", ["[extend]\nuseDefault=true\n", 'title="Test"\n[extend]\nuseDefault=true\n']
)
def test_default_gitleaks_config(tmp_path, config):
    path = tmp_path / "security/gitleaks.toml"
    path.parent.mkdir()
    path.write_text(config)
    assert scan.gitleaks_config(tmp_path) == path


@pytest.mark.parametrize(
    "config",
    [
        "[extend]\nuseDefault=false\n",
        '[extend]\nuseDefault=true\ndisabledRules=["test"]\n',
        '[extend]\nuseDefault=true\n[allowlist]\npaths=[".*"]\n',
    ],
)
def test_gitleaks_disallow_bypass_config(tmp_path, config):
    path = tmp_path / "security/gitleaks.toml"
    path.parent.mkdir()
    path.write_text(config)
    with pytest.raises(scan.ScanError):
        scan.gitleaks_config(tmp_path)


def test_report_preserves_provenance_artifact_hash_and_metadata(runner, target):
    raw = runner.directory(target) / "raw.json"
    scan.write_json(raw, {"hello": "world"})
    scan.write_json(raw.with_name(raw.name + ".tool.json"), {"Version": "1"})
    runner.report(target, "tests", ("test", "1"), lambda: ([], [raw]))
    report = scan.read_json(runner.directory(target) / "tests.json")
    assert report["commit"] == "a" * 40
    assert report["status"] == "ok"
    assert report["branch_coverage"] is True
    assert len(report["artifacts"]) == 2
    assert report["artifacts"][0]["sha256"] == hashlib.sha256(raw.read_bytes()).hexdigest()


@pytest.mark.parametrize(
    "failure",
    [
        scan.ScanError("safe failure"),
        KeyError("PRIVATE"),
        ValueError("PRIVATE"),
        OSError("PRIVATE"),
    ],
)
def test_report_operational_failure_redacted(runner, target, failure):
    runner.report(target, "iac", ("test", "1"), Mock(side_effect=failure))
    assert runner.reports[0]["status"] == "error"
    assert "PRIVATE" not in json.dumps(runner.reports)


def test_report_rejects_outside_and_missing_evidence(runner, target, tmp_path):
    outside = tmp_path / "outside.json"
    outside.write_text("{}")
    runner.report(target, "iac", ("test", "1"), lambda: ([], [outside]))
    assert runner.reports[-1]["status"] == "error"
    runner.report(target, "iac", ("test", "1"), lambda: ([], [runner.output / "missing"]))
    assert runner.reports[-1]["status"] == "error"


def test_unsafe_target_paths_rejected(runner):
    with pytest.raises(scan.ScanError):
        runner.directory({"id": "../unsafe"})
    with pytest.raises(scan.ScanError):
        runner.project({"path": ".."})


def test_trivy_stale_output_removed_and_unsanitized_evidence_never_published(runner, monkeypatch):
    artifact = runner.output / "scan.json"
    artifact.write_text("old")
    monkeypatch.setattr(runner, "tool", lambda name: ("trivy", "1"))
    monkeypatch.setattr(
        scan, "run", Mock(return_value=subprocess.CompletedProcess([], 0, "{}", ""))
    )
    with pytest.raises(scan.ScanError, match="output not produced"):
        runner.trivy(["image", "--output", str(artifact), "image"], runner.root)
    assert not artifact.exists()

    def successful(command, cwd, **kwargs):
        if "--output" in command:
            destination = Path(command[command.index("--output") + 1])
            assert not destination.is_relative_to(runner.output)
            scan.write_json(destination, {"Metadata": {"Env": ["PRIVATE"]}, "Results": []})
        return subprocess.CompletedProcess(
            command, 0, '{"Version":"1","VulnerabilityDB":{"UpdatedAt":"2026-10-07"}}', ""
        )

    monkeypatch.setattr(scan, "run", successful)
    runner.trivy(["image", "--output", str(artifact), "image"], runner.root)
    assert "PRIVATE" not in artifact.read_text()
    assert scan.read_json(artifact.with_name(artifact.name + ".tool.json"))["VulnerabilityDB"]


def test_trivy_invalid_output_not_uploaded(runner, monkeypatch):
    artifact = runner.output / "scan.json"
    monkeypatch.setattr(runner, "tool", lambda name: ("trivy", "1"))

    def invalid(command, cwd, **kwargs):
        Path(command[command.index("--output") + 1]).write_text("PRIVATE malformed JSON")
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(scan, "run", invalid)
    with pytest.raises(ValueError):
        runner.trivy(["image", "--output", str(artifact), "image"], runner.root)
    assert not artifact.exists()


@pytest.mark.parametrize(
    "scenario", ["ok", "no-secret", "no-critical", "bad-policy", "bad-clean", "tool-error"]
)
def test_selftest_requires_real_findings_and_clean_control(tmp_path, monkeypatch, scenario):
    source = Path(__file__).resolve().parents[3]
    shutil.copytree(source / "security", tmp_path / "security")
    monkeypatch.setattr(scan, "git_commit", lambda root: "b" * 40)
    monkeypatch.setattr(scan.Runner, "tool", lambda self, name: (name, "1"))

    def scanner(command, cwd, **kwargs):
        if scenario == "tool-error":
            raise scan.ScanError("tool execution failed")
        report = Path(command[command.index("--report-path") + 1])
        clean = Path(command[-1]).read_text().startswith("This file")
        detected = not clean and scenario != "no-secret"
        if scenario == "bad-clean" and clean:
            detected = True
        scan.write_json(report, [{"RuleID": "github-pat"}] if detected else [])
        return subprocess.CompletedProcess(command, 7 if detected else 0, "", "")

    def trivy(self, arguments, cwd, **kwargs):
        report = Path(arguments[arguments.index("--output") + 1])
        scan.write_json(
            report,
            {
                "Results": [
                    {
                        "Target": "requirements.txt",
                        "Vulnerabilities": [
                            {
                                "VulnerabilityID": "CVE-2020-14343",
                                "Severity": "HIGH" if scenario == "no-critical" else "CRITICAL",
                                "PkgName": "PyYAML",
                                "InstalledVersion": "5.3.1",
                            }
                        ],
                    }
                ]
            },
        )

    monkeypatch.setattr(scan, "run", scanner)
    monkeypatch.setattr(scan.Runner, "trivy", trivy)
    if scenario == "bad-policy":
        scan.write_json(tmp_path / "security/policy.json", {})
    output = tmp_path / "reports"
    assert scan.self_test_scanners(tmp_path, output) == (scenario == "ok")
    summary = scan.read_json(output / "scanner-self-test.json")
    assert summary["status"] == ("ok" if scenario == "ok" else "error")
    if scenario == "ok":
        assert summary["commit"] == "b" * 40
