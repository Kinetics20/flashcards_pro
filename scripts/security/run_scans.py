"""Run pinned scanners and produce commit-bound reports; no scanner output is echoed.

Run after `uv sync --project .ci/security-tools --all-groups --frozen`. The tooling
environment supplies pip-audit and pip-licenses; each target has its own locked
environment. Binary tools are extracted only from checksum-verified archives.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import tarfile
import tempfile
import tomllib
from pathlib import Path
from typing import Any

from .common import git_commit, read_json, sha256_file, write_json


class ScanError(RuntimeError):
    """A scanner failed operationally; its output is deliberately not disclosed."""


def run(
    command: list[str],
    cwd: Path,
    *,
    allowed: tuple[int, ...] = (0,),
    timeout: int = 900,
) -> subprocess.CompletedProcess[str]:
    """Capture process output; never put arbitrary output or arguments in errors."""
    env = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith(("TRIVY_", "GITLEAKS_"))
    }
    env["NO_COLOR"] = "1"
    try:
        result = subprocess.run(
            command,
            cwd=cwd,
            env=env,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ScanError(
            f"{Path(command[0]).name}: execution failed ({type(error).__name__})"
        ) from None
    if result.returncode not in allowed:
        raise ScanError(f"{Path(command[0]).name}: unexpected exit code {result.returncode}")
    return result


def platform_key() -> str:
    machine = {"x86_64": "amd64", "aarch64": "arm64"}.get(platform.machine(), platform.machine())
    return f"{platform.system().lower()}-{machine}"


def gitleaks_config(root: Path) -> Path:
    path = root / "security/gitleaks.toml"
    document = tomllib.loads(path.read_text(encoding="utf-8"))
    if set(document) - {"title", "extend"} or document.get("extend") != {"useDefault": True}:
        raise ScanError("Gitleaks config must enable defaults without allowlists or disabled rules")
    return path


def sanitize_evidence(value: Any) -> Any:
    """Omit environment, build history, source snippets and free-form IaC messages."""
    if isinstance(value, dict):
        omitted = {
            "Metadata",
            "ImageConfig",
            "Env",
            "History",
            "CauseMetadata",
            "Message",
            "properties",
        }
        return {key: sanitize_evidence(item) for key, item in value.items() if key not in omitted}
    if isinstance(value, list):
        return [sanitize_evidence(item) for item in value]
    return value


def verified_tool(root: Path, name: str, *, install: bool) -> tuple[str, str]:
    """Verify an archive on every use; validate the extracted executable too."""
    lock = read_json(root / "security/tools.lock.json")["tools"][name]
    asset = lock["platforms"].get(platform_key())
    if asset is None:
        raise ScanError(f"{name}: unsupported platform {platform_key()}")
    if not re.fullmatch(r"[a-f0-9]{64}", asset["sha256"]):
        raise ScanError(f"{name}: invalid locked SHA256")
    directory = root / ".cache/security-tools" / name / lock["version"] / platform_key()
    archive = directory / "archive.tar.gz"
    binary = directory / name
    if not archive.is_file():
        if not install:
            raise ScanError(f"{name}: missing verified tool; rerun with --install-tools")
        if not asset["url"].startswith("https://github.com/"):
            raise ScanError(f"{name}: invalid download origin")
        directory.mkdir(parents=True, exist_ok=True)
        pending = directory / "download.part"
        try:
            run(
                [
                    "curl",
                    "--fail",
                    "--silent",
                    "--show-error",
                    "--location",
                    "--proto",
                    "=https",
                    "--proto-redir",
                    "=https",
                    "--connect-timeout",
                    "30",
                    "--max-time",
                    "180",
                    "--output",
                    str(pending),
                    asset["url"],
                ],
                root,
                timeout=190,
            )
            if sha256_file(pending) != asset["sha256"]:
                raise ScanError(f"{name}: downloaded archive checksum mismatch")
            pending.replace(archive)
        except OSError:
            raise ScanError(f"{name}: download failed") from None
        finally:
            pending.unlink(missing_ok=True)
    if sha256_file(archive) != asset["sha256"]:
        raise ScanError(f"{name}: cached archive checksum mismatch")
    try:
        with tarfile.open(archive, "r:gz") as bundle:
            members = [
                member for member in bundle.getmembers() if member.name == name and member.isfile()
            ]
            if len(members) != 1:
                raise ScanError(f"{name}: executable missing or duplicated in archive")
            stream = bundle.extractfile(members[0])
            if stream is None:
                raise ScanError(f"{name}: cannot read executable")
            payload = stream.read()
    except tarfile.TarError:
        raise ScanError(f"{name}: invalid archive") from None
    expected = hashlib.sha256(payload).hexdigest()
    if not binary.is_file():
        binary.write_bytes(payload)
        binary.chmod(0o755)
    if binary.is_symlink() or sha256_file(binary) != expected:
        raise ScanError(f"{name}: cached executable checksum mismatch")
    return str(binary), lock["version"]


def trivy_findings(document: dict[str, Any], category: str) -> list[dict[str, Any]]:
    if (
        not isinstance(document, dict)
        or not isinstance(document.get("Results"), list)
        or not document["Results"]
    ):
        raise ScanError("Trivy: no analyzed results")
    findings: list[dict[str, Any]] = []
    for result in document["Results"]:
        if (
            not isinstance(result, dict)
            or not isinstance(result.get("Target"), str)
            or not result["Target"]
        ):
            raise ScanError("Trivy: invalid result target")
        target = str(result.get("Target", "unknown"))
        items = result.get(category)
        if items is None:
            items = []
        if not isinstance(items, list) or any(not isinstance(item, dict) for item in items):
            raise ScanError("Trivy: invalid findings collection")
        for item in items:
            if category == "Vulnerabilities":
                findings.append(
                    {
                        "id": item["VulnerabilityID"],
                        "severity": item.get("Severity", "UNKNOWN"),
                        "package": item.get("PkgName", "unknown"),
                        "version": item.get("InstalledVersion", "unknown"),
                        "path": target,
                    }
                )
            elif category == "Misconfigurations":
                findings.append(
                    {
                        "id": item.get("AVDID") or item["ID"],
                        "severity": item.get("Severity", "UNKNOWN"),
                        "path": target,
                    }
                )
    return findings


class Runner:
    def __init__(
        self,
        root: Path,
        output: Path,
        manifest: dict[str, Any],
        *,
        install: bool = False,
    ):
        self.root = root.resolve()
        self.output = output.resolve()
        self.commit = manifest["commit"]
        self.run_context = {key: manifest.get(key) for key in ("run_id", "run_attempt", "inputs")}
        self.targets = manifest["targets"]
        self.install = install
        self.reports: list[dict[str, Any]] = []
        self.output.mkdir(parents=True, exist_ok=True)

    def directory(self, target: dict[str, Any]) -> Path:
        identifier = target["id"]
        if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]*", identifier):
            raise ScanError("unsafe target identifier")
        directory = self.output / identifier
        directory.mkdir(parents=True, exist_ok=True)
        return directory

    def project(self, target: dict[str, Any]) -> Path:
        path = (self.root / target["path"]).resolve()
        if not path.is_relative_to(self.root):
            raise ScanError("target escapes repository")
        return path

    def tool(self, name: str) -> tuple[str, str]:
        return verified_tool(self.root, name, install=self.install)

    def report(
        self, target: dict[str, Any], check: str, tool: tuple[str, str], action: Any
    ) -> None:
        report = {
            "schema_version": 1,
            "commit": self.commit,
            "target": target["id"],
            "check": check,
            "tool": {"name": tool[0], "version": tool[1]},
            "status": "ok",
            "findings": [],
            "errors": [],
            "artifacts": [],
            "run_context": self.run_context,
        }
        if check == "tests":
            report["branch_coverage"] = True
        try:
            findings, paths = action()
            report["findings"] = findings
            for path in paths:
                resolved = path.resolve()
                if (
                    not resolved.is_relative_to(self.output)
                    or not path.is_file()
                    or path.is_symlink()
                ):
                    raise ScanError("missing or unsafe report artifact")
                report["artifacts"].append(
                    {
                        "path": resolved.relative_to(self.output).as_posix(),
                        "sha256": sha256_file(path),
                    }
                )
                metadata = path.with_name(path.name + ".tool.json")
                if metadata.is_file():
                    report["artifacts"].append(
                        {
                            "path": metadata.relative_to(self.output).as_posix(),
                            "sha256": sha256_file(metadata),
                        }
                    )
        except (ScanError, OSError, ValueError, KeyError, TypeError) as error:
            report["status"] = "error"
            report["errors"] = [
                str(error)
                if isinstance(error, ScanError)
                else f"{check}: invalid or missing output ({type(error).__name__})"
            ]
        write_json(self.directory(target) / f"{check}.json", report)
        self.reports.append(report)

    def binary_version(self, name: str) -> str:
        return read_json(self.root / "security/tools.lock.json")["tools"][name]["version"]

    def trivy(self, arguments: list[str], cwd: Path, *, timeout: int = 900) -> None:
        executable, _ = self.tool("trivy")
        artifact = Path(arguments[arguments.index("--output") + 1])
        artifact.unlink(missing_ok=True)
        artifact.with_name(artifact.name + ".tool.json").unlink(missing_ok=True)
        with tempfile.TemporaryDirectory(prefix="fcb-security-config-") as temporary:
            empty = Path(temporary) / "empty"
            empty.write_text("", encoding="utf-8")
            temporary_report = Path(temporary) / "report.json"
            temporary_arguments = list(arguments)
            temporary_arguments[temporary_arguments.index("--output") + 1] = str(temporary_report)
            run(
                [
                    executable,
                    *temporary_arguments,
                    "--config",
                    str(empty),
                    "--ignorefile",
                    str(empty),
                    "--timeout",
                    "10m",
                    "--exit-code",
                    "0",
                ],
                cwd,
                timeout=timeout,
            )
            if not temporary_report.is_file():
                raise ScanError("Trivy: output not produced")
            write_json(artifact, sanitize_evidence(read_json(temporary_report)))
        metadata = json.loads(run([executable, "--version", "--format", "json"], cwd).stdout)
        write_json(artifact.with_name(artifact.name + ".tool.json"), metadata)

    def python(self, target: dict[str, Any]) -> None:
        project = self.project(target)
        directory = self.directory(target)
        tools_lock = read_json(self.root / "security/tools.lock.json")["python_tools"]

        def dependencies() -> tuple[list[dict[str, Any]], list[Path]]:
            run(["uv", "sync", "--all-groups", "--frozen"], project)
            raw = directory / "dependencies.raw.json"
            raw.unlink(missing_ok=True)
            sbom = directory / "dependencies.cdx.json"
            with tempfile.TemporaryDirectory(prefix="fcb-audit-") as temporary:
                requirements = Path(temporary) / "requirements.txt"
                run(
                    [
                        "uv",
                        "export",
                        "--frozen",
                        "--all-groups",
                        "--no-emit-project",
                        "--format",
                        "requirements-txt",
                        "--output-file",
                        str(requirements),
                    ],
                    project,
                )
                result = run(
                    [
                        str(self.root / ".ci/security-tools/.venv/bin/pip-audit"),
                        "--strict",
                        "--require-hashes",
                        "--format",
                        "json",
                        "--output",
                        str(raw),
                        "-r",
                        str(requirements),
                    ],
                    project,
                    allowed=(0, 1),
                )
            document = read_json(raw)
            findings = []
            for package in document["dependencies"]:
                if package.get("skip_reason"):
                    raise ScanError("pip-audit: an exported dependency was skipped")
                for issue in package.get("vulns", []):
                    findings.append(
                        {
                            "id": issue["id"],
                            "severity": "UNKNOWN",
                            "package": package["name"],
                            "version": package["version"],
                            "path": target["path"] + "/uv.lock",
                        }
                    )
            if (result.returncode == 1) != bool(findings):
                raise ScanError("pip-audit: exit code does not match findings")
            self.trivy(
                [
                    "fs",
                    "--scanners",
                    "vuln",
                    "--include-dev-deps",
                    "--format",
                    "cyclonedx",
                    "--output",
                    str(sbom),
                    str(project / "uv.lock"),
                ],
                project,
            )
            if not read_json(sbom).get("components"):
                raise ScanError("Trivy: dependency SBOM has no components")
            return findings, [raw, sbom]

        def licenses() -> tuple[list[dict[str, Any]], list[Path]]:
            run(["uv", "sync", "--all-groups", "--frozen"], project)
            raw = directory / "licenses.raw.json"
            raw.unlink(missing_ok=True)
            result = run(
                [
                    str(self.root / ".ci/security-tools/.venv/bin/pip-licenses"),
                    "--python",
                    str(project / ".venv/bin/python"),
                    "--format",
                    "json",
                    "--with-system",
                ],
                project,
            )
            rows = json.loads(result.stdout)
            if not isinstance(rows, list) or not rows:
                raise ScanError("pip-licenses: empty or invalid inventory")
            write_json(raw, rows)
            installed = json.loads(
                run(
                    [
                        "uv",
                        "pip",
                        "list",
                        "--python",
                        str(project / ".venv/bin/python"),
                        "--format",
                        "json",
                    ],
                    project,
                ).stdout
            )

            def canonical(value: str) -> str:
                return re.sub(r"[-_.]+", "-", value).lower()

            actual = {(canonical(row["Name"]), row["Version"]) for row in rows}
            expected = {(canonical(row["name"]), row["version"]) for row in installed}
            if actual != expected:
                raise ScanError("pip-licenses: inventory does not match installed locked packages")
            own_name = re.sub(r"[-_.]+", "-", target.get("project_name", "")).lower()
            findings = [
                {
                    "id": "license:" + row["Name"],
                    "severity": "UNKNOWN",
                    "package": row["Name"],
                    "version": row["Version"],
                    "license": row.get("License") or "UNKNOWN",
                }
                for row in rows
                if re.sub(r"[-_.]+", "-", row["Name"]).lower() != own_name
            ]
            return findings, [raw]

        if "dependencies" in target["checks"]:
            self.report(
                target,
                "dependencies",
                ("pip-audit", tools_lock["pip-audit"]),
                dependencies,
            )
        if "licenses" in target["checks"]:
            self.report(
                target,
                "licenses",
                ("pip-licenses", tools_lock["pip-licenses"]),
                licenses,
            )

    def tracked_snapshot(self, destination: Path) -> list[str]:
        result = run(["git", "ls-files", "-z"], self.root)
        files = [name for name in result.stdout.split("\0") if name]
        if not files:
            raise ScanError("repository has no tracked files")
        for name in files:
            source = self.root / name
            if source.is_symlink() or not source.resolve().is_relative_to(self.root):
                raise ScanError("tracked symlink or path escape is unsupported")
            if source.is_file():
                destination_file = destination / name
                destination_file.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, destination_file)
        return files

    def repository(self, target: dict[str, Any]) -> None:
        directory = self.directory(target)

        def secrets() -> tuple[list[dict[str, Any]], list[Path]]:
            executable, _ = self.tool("gitleaks")
            shallow = run(["git", "rev-parse", "--is-shallow-repository"], self.root)
            if shallow.stdout.strip() != "false":
                raise ScanError("gitleaks: complete history required; checkout fetch-depth: 0")
            raw = directory / "secrets.raw.json"
            raw.unlink(missing_ok=True)
            with tempfile.TemporaryDirectory(prefix="fcb-gitleaks-") as temporary:
                config = gitleaks_config(self.root)
                ignore = Path(temporary) / "ignore"
                ignore.write_text("", encoding="utf-8")
                result = run(
                    [
                        executable,
                        "git",
                        "--log-opts=--all",
                        "--redact=100",
                        "--ignore-gitleaks-allow",
                        "--gitleaks-ignore-path",
                        str(ignore),
                        "--config",
                        str(config),
                        "--no-banner",
                        "--report-format",
                        "json",
                        "--report-path",
                        str(raw),
                        "--exit-code",
                        "7",
                        str(self.root),
                    ],
                    self.root,
                    allowed=(0, 7),
                )
            rows = read_json(raw)
            findings = [
                {
                    "id": row.get("Fingerprint")
                    or f"{row['RuleID']}:{row['File']}:{row['StartLine']}",
                    "severity": "CRITICAL",
                    "path": row["File"],
                }
                for row in rows
            ]
            if (result.returncode == 7) != bool(findings):
                raise ScanError("gitleaks: exit code does not match findings")
            return findings, [raw]

        def iac() -> tuple[list[dict[str, Any]], list[Path]]:
            raw = directory / "iac.raw.json"
            with tempfile.TemporaryDirectory(prefix="fcb-iac-") as temporary:
                snapshot = Path(temporary)
                inventory = self.tracked_snapshot(snapshot)
                self.trivy(
                    ["config", "--format", "json", "--output", str(raw), str(snapshot)],
                    snapshot,
                )
                document = read_json(raw)
                findings = trivy_findings(document, "Misconfigurations")
                for finding in findings:
                    finding["path"] = str(finding["path"]).removeprefix(str(snapshot) + "/")
                # Code snippets and scanner prose can expose literal config secrets.
                write_json(
                    raw,
                    {
                        "schema_version": 1,
                        "scanner": "trivy-config",
                        "files": inventory,
                        "findings": findings,
                    },
                )
            return findings, [raw]

        def compose() -> tuple[list[dict[str, Any]], list[Path]]:
            try:
                from .scan_compose import scan_compose
            except ImportError:
                from scan_compose import scan_compose
            raw = directory / "compose.raw.json"
            records = []
            findings = []
            names = run(["git", "ls-files", "-z"], self.root).stdout.split("\0")
            sources = [
                name
                for name in names
                if Path(name).name
                in {
                    "compose.yaml",
                    "compose.yml",
                    "docker-compose.yaml",
                    "docker-compose.yml",
                }
            ]
            if not sources:
                raise ScanError("no tracked Compose configuration found")
            for source in sources:
                result = run(
                    [
                        "docker",
                        "compose",
                        "-f",
                        str(self.root / source),
                        "config",
                        "--format",
                        "json",
                    ],
                    self.root,
                )
                document = json.loads(result.stdout)
                detected = scan_compose(document, source)
                findings.extend(detected)
                records.append(
                    {
                        "source": source,
                        "scanner": "compose-policy",
                        "findings": detected,
                    }
                )
            write_json(raw, records)
            return findings, [raw]

        actions = {
            "secrets": (("gitleaks", self.binary_version("gitleaks")), secrets),
            "iac": (("trivy", self.binary_version("trivy")), iac),
            "compose": (("compose-policy", "1"), compose),
        }
        for check, (tool, action) in actions.items():
            if check in target["checks"]:
                self.report(target, check, tool, action)

    def image(self, target: dict[str, Any], reference: str | None) -> None:
        directory = self.directory(target)

        def scan() -> tuple[list[dict[str, Any]], list[Path]]:
            image_ref = reference or f"flashcards-{target['id']}:{self.commit}"
            if reference is None:
                run(
                    ["docker", "build", "--tag", image_ref, str(self.project(target))],
                    self.root,
                    timeout=1800,
                )
            image_id = run(
                ["docker", "image", "inspect", "--format", "{{.Id}}", image_ref],
                self.root,
            ).stdout.strip()
            if not re.fullmatch(r"sha256:[a-f0-9]{64}", image_id):
                raise ScanError("docker: invalid immutable image ID")
            raw = directory / "image.raw.json"
            sbom = directory / "image.cdx.json"
            license_raw = directory / "image.licenses.raw.json"
            self.trivy(
                [
                    "image",
                    "--image-src",
                    "docker",
                    "--scanners",
                    "vuln",
                    "--format",
                    "json",
                    "--output",
                    str(raw),
                    image_id,
                ],
                self.root,
            )
            self.trivy(
                [
                    "image",
                    "--image-src",
                    "docker",
                    "--format",
                    "cyclonedx",
                    "--output",
                    str(sbom),
                    image_id,
                ],
                self.root,
            )
            self.trivy(
                [
                    "image",
                    "--image-src",
                    "docker",
                    "--scanners",
                    "license",
                    "--format",
                    "json",
                    "--output",
                    str(license_raw),
                    image_id,
                ],
                self.root,
            )
            document = read_json(raw)
            document.pop("Metadata", None)
            document["ArtifactID"] = image_id
            write_json(raw, document)
            license_document = read_json(license_raw)
            license_document.pop("Metadata", None)
            write_json(license_raw, license_document)
            if (
                not isinstance(license_document.get("Results"), list)
                or not license_document["Results"]
            ):
                raise ScanError("Trivy: image license inventory has no analyzed results")
            license_findings = []
            for result in license_document["Results"]:
                for license_row in result.get("Licenses") or []:
                    license_findings.append(
                        {
                            "id": "license:" + license_row.get("PkgName", "unknown"),
                            "severity": "UNKNOWN",
                            "package": license_row.get("PkgName", "unknown"),
                            "version": license_row.get("PkgVersion")
                            or license_row.get("InstalledVersion")
                            or "unknown",
                            "license": license_row.get("Name") or "UNKNOWN",
                        }
                    )
            if not license_findings:
                raise ScanError("Trivy: image license inventory is empty")
            if not read_json(sbom).get("components"):
                raise ScanError("Trivy: image SBOM has no components")
            identity = directory / "image.identity.json"
            write_json(
                identity,
                {"commit": self.commit, "target": target["id"], "image_id": image_id},
            )
            return trivy_findings(document, "Vulnerabilities"), [
                raw,
                sbom,
                license_raw,
                identity,
            ]

        self.report(target, "image", ("trivy", self.binary_version("trivy")), scan)

    def record_tests(
        self, target: dict[str, Any], coverage: Path, junit: Path, exit_code: int
    ) -> None:
        def action() -> tuple[list[dict[str, Any]], list[Path]]:
            if exit_code != 0:
                raise ScanError(f"test runner: exit code {exit_code}")
            paths = []
            for source, name in ((coverage, "coverage.xml"), (junit, "junit.xml")):
                if not source.is_file():
                    raise ScanError(f"test runner: missing {name}")
                destination = self.directory(target) / name
                if source.resolve() != destination.resolve():
                    shutil.copyfile(source, destination)
                paths.append(destination)
            return [], paths

        self.report(target, "tests", ("repository-test-runner", "1"), action)

    def tests(self, target: dict[str, Any]) -> None:
        directory = self.directory(target)
        coverage, junit = directory / "coverage.xml", directory / "junit.xml"
        coverage.unlink(missing_ok=True)
        junit.unlink(missing_ok=True)
        project = self.project(target)
        try:
            run(["uv", "sync", "--all-groups", "--frozen"], project)
            options = [
                f"--junitxml={junit}",
                f"--cov-report=xml:{coverage}",
                "--cov-branch",
            ]
            if target["kind"] == "tooling":
                command = [
                    str(project / ".venv/bin/python"),
                    "-m",
                    "pytest",
                    "-c",
                    str(project / "pyproject.toml"),
                    "scripts/tests/unit",
                    "--cov=scripts/security",
                    *options,
                ]
                project = self.root
            else:
                command = [
                    "uv",
                    "run",
                    "--frozen",
                    "tox",
                    "run-parallel",
                    "--",
                    *options,
                ]
            run(command, project, timeout=1800)
        except ScanError as error:
            self.report(
                target,
                "tests",
                ("repository-test-runner", "1"),
                lambda failure=error: (_ for _ in ()).throw(failure),
            )
            return
        self.record_tests(target, coverage, junit, 0)


def self_test_scanners(root: Path, output: Path, *, install: bool = False) -> bool:
    """Real scanner negative controls: never install or execute vulnerable packages."""
    try:
        from .gate import evaluate_report, validate_exceptions, validate_policy

        commit = git_commit(root)
        policy = read_json(root / "security/policy.json")
        exceptions = read_json(root / "security/exceptions.json")
        if validate_policy(policy) or validate_exceptions(exceptions, policy):
            raise ScanError("negative control: invalid policy configuration")
        runner = Runner(root, output, {"commit": commit, "targets": []}, install=install)
        target = {"id": "scanner-self-test", "kind": "repository", "path": "."}
        directory = runner.directory(target)
        with tempfile.TemporaryDirectory(prefix="fcb-scanner-fixtures-") as temporary:
            fixture = Path(temporary)
            secret = fixture / "credentials.txt"
            secret.write_text(
                "token="
                + "ghp_"
                + hashlib.sha256(b"FCB-62 synthetic negative control").hexdigest()[:36]
                + "\n",
                encoding="utf-8",
            )
            raw = directory / "secrets.raw.json"
            raw.unlink(missing_ok=True)
            binary, _ = runner.tool("gitleaks")
            result = run(
                [
                    binary,
                    "dir",
                    "--redact=100",
                    "--config",
                    str(gitleaks_config(root)),
                    "--ignore-gitleaks-allow",
                    "--no-banner",
                    "--report-format",
                    "json",
                    "--report-path",
                    str(raw),
                    "--exit-code",
                    "7",
                    str(secret),
                ],
                fixture,
                allowed=(0, 7),
            )
            detections = read_json(raw)
            if result.returncode != 7 or not any(
                row["RuleID"] == "github-pat" for row in detections
            ):
                raise ScanError("negative control: fake GitHub token not detected")
            requirements = fixture / "requirements.txt"
            requirements.write_text("PyYAML==5.3.1\n", encoding="utf-8")
            vulnerabilities = directory / "vulnerabilities.raw.json"
            runner.trivy(
                [
                    "fs",
                    "--scanners",
                    "vuln",
                    "--format",
                    "json",
                    "--output",
                    str(vulnerabilities),
                    str(requirements),
                ],
                fixture,
            )
            issues = trivy_findings(read_json(vulnerabilities), "Vulnerabilities")
            if not any(
                issue["id"] == "CVE-2020-14343" and issue["severity"] == "CRITICAL"
                for issue in issues
            ):
                raise ScanError(
                    "negative control: expected critical PyYAML vulnerability not detected"
                )
            secret_findings = [
                {"id": row["RuleID"], "severity": "CRITICAL", "path": "credentials.txt"}
                for row in detections
            ]
            runner.report(
                target,
                "secrets",
                ("gitleaks", runner.binary_version("gitleaks")),
                lambda: (secret_findings, [raw]),
            )
            runner.report(
                target,
                "image",
                ("trivy", runner.binary_version("trivy")),
                lambda: (issues, [vulnerabilities]),
            )
            if any(
                report["status"] != "ok" or not evaluate_report(report, policy, exceptions)
                for report in runner.reports
            ):
                raise ScanError("negative control: policy did not reject real scanner findings")
            secret.write_text("This file contains no credentials.\n", encoding="utf-8")
            clean_raw = directory / "clean.raw.json"
            run(
                [
                    binary,
                    "dir",
                    "--config",
                    str(gitleaks_config(root)),
                    "--redact=100",
                    "--report-format",
                    "json",
                    "--report-path",
                    str(clean_raw),
                    str(secret),
                ],
                fixture,
            )
            if read_json(clean_raw):
                raise ScanError("positive control: clean file was rejected")
        write_json(
            output / "scanner-self-test.json",
            {
                "schema_version": 1,
                "commit": commit,
                "status": "ok",
                "controls": [
                    "fake-secret-rejected",
                    "critical-vulnerability-rejected",
                    "clean-file-accepted",
                ],
                "tools": read_json(root / "security/tools.lock.json")["tools"],
            },
        )
        return True
    except (ScanError, OSError, ValueError, KeyError) as error:
        write_json(
            output / "scanner-self-test.json",
            {
                "schema_version": 1,
                "status": "error",
                "errors": [str(error) if isinstance(error, ScanError) else type(error).__name__],
            },
        )
        return False


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--output", type=Path, default=Path("reports"))
    parser.add_argument(
        "--phase",
        choices=["repository", "python", "image", "tests", "all"],
        default="all",
    )
    parser.add_argument("--all", action="store_true")
    parser.add_argument("--target")
    parser.add_argument("--image")
    parser.add_argument("--install-tools", action="store_true")
    parser.add_argument("--self-test-scanners", action="store_true")
    parser.add_argument("--record-tests", action="store_true")
    parser.add_argument("--coverage", type=Path)
    parser.add_argument("--junit", type=Path)
    parser.add_argument("--test-exit-code", type=int, default=0)
    args = parser.parse_args(argv)
    root = args.root.resolve()
    output = args.output.resolve() if args.output.is_absolute() else root / args.output
    if args.self_test_scanners:
        return 0 if self_test_scanners(root, output, install=args.install_tools) else 1
    try:
        try:
            from .discover_targets import discover
            from .gate import evaluate_report
        except ImportError:
            from discover_targets import discover
            from gate import evaluate_report
        manifest = discover(root)
        targets = [
            item for item in manifest["targets"] if args.target is None or item["id"] == args.target
        ]
        if not targets:
            raise ScanError("requested target not found")
        runner = Runner(root, output, manifest, install=args.install_tools)
        phase = "all" if args.all else args.phase
        if args.record_tests:
            if len(targets) != 1 or args.coverage is None or args.junit is None:
                raise ScanError("--record-tests requires one --target, --coverage and --junit")
            runner.record_tests(targets[0], args.coverage, args.junit, args.test_exit_code)
        else:
            for target in targets:
                if phase in {"all", "repository"} and target["kind"] == "repository":
                    runner.repository(target)
                if phase in {"all", "python"} and "dependencies" in target["checks"]:
                    runner.python(target)
                if phase in {"all", "tests"} and "tests" in target["checks"]:
                    runner.tests(target)
                if phase in {"all", "image"} and "image" in target["checks"]:
                    runner.image(target, args.image)
        if not runner.reports:
            raise ScanError("phase did not execute any required checks")
        policy = read_json(root / "security/policy.json")
        exceptions = read_json(root / "security/exceptions.json")
        failures = [
            error
            for report in runner.reports
            for error in evaluate_report(report, policy, exceptions)
        ]
        for report in runner.reports:
            print(
                f"{report['target']}/{report['check']}: {report['status']}; "
                f"{len(report['findings'])} finding(s)"
            )
        for failure in failures:
            print(failure)
        return 1 if failures else 0
    except (ScanError, OSError, ValueError, KeyError, ImportError) as error:
        print(
            str(error)
            if isinstance(error, ScanError)
            else f"scan runner configuration failure ({type(error).__name__})"
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
