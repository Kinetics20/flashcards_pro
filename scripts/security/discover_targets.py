"""Build the expected inventory BEFORE running scanners or collecting reports."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import tomllib
from pathlib import Path
from typing import Any

from .common import contained_path, git_commit, sha256_file, utc_now, write_json

ID_PATTERN = re.compile(r"[a-z][a-z0-9]*(?:-[a-z0-9]+)*")


def _project(root: Path, relative: str, target_id: str, kind: str) -> dict[str, Any]:
    folder = contained_path(root, relative)
    required = ["pyproject.toml", "uv.lock"]
    if kind in {"service", "template"}:
        required.extend(["Dockerfile", "pytest.toml", "tox.toml"])
    if kind == "service":
        required.append("OWNERS.yaml")
    for name in required:
        file = contained_path(root, f"{relative}/{name}")
        if not file.is_file() or not file.stat().st_size:
            raise ValueError(f"Missing required input: {relative}/{name}")
    config = tomllib.loads((folder / "pyproject.toml").read_text(encoding="utf-8"))
    project_name = config.get("project", {}).get("name")
    if not isinstance(project_name, str) or not project_name.strip():
        raise ValueError(f"Missing project.name in {relative}")
    checks = ["dependencies", "licenses", "tests"]
    if kind in {"service", "template"}:
        checks.append("image")
    return {
        "id": target_id,
        "kind": kind,
        "path": relative,
        "project_name": project_name,
        "checks": checks,
        "coverage": True,
        "coverage_source": "scripts/security" if kind == "tooling" else "app",
        "lockfile_sha256": sha256_file(folder / "uv.lock"),
    }


def _folders(root: Path, directory: str) -> list[Path]:
    parent = root / directory
    if not parent.is_dir():
        raise ValueError(f"Missing directory: {directory}")
    folders = sorted(p for p in parent.iterdir() if p.is_dir() and not p.name.startswith("."))
    if not folders:
        raise ValueError(f"No projects found in {directory}")
    for folder in folders:
        if not ID_PATTERN.fullmatch(folder.name):
            raise ValueError(f"Invalid project directory name in {directory}")
    return folders


def discover(root: Path) -> dict[str, Any]:
    root = Path(root).resolve()
    targets = [
        _project(root, f"services/{p.name}", p.name, "service") for p in _folders(root, "services")
    ]
    for p in _folders(root, "templates"):
        target_id = "template-fastapi" if p.name == "fastapi-microservice" else f"template-{p.name}"
        targets.append(_project(root, f"templates/{p.name}", target_id, "template"))
    targets.append(_project(root, ".ci/security-tools", "repo-security-tools", "tooling"))
    targets.append(
        {
            "id": "repository",
            "kind": "repository",
            "path": ".",
            "checks": ["secrets", "iac", "compose"],
            "coverage": False,
        }
    )
    ids = [target["id"] for target in targets]
    if len(ids) != len(set(ids)):
        raise ValueError("Duplicate target IDs")
    inputs = {}
    for relative in (
        "security/policy.json",
        "security/exceptions.json",
        "security/tools.lock.json",
        "security/gitleaks.toml",
    ):
        inputs[relative] = sha256_file(contained_path(root, relative))
    return {
        "schema_version": 1,
        "commit": git_commit(root),
        "created_at": utc_now(),
        "run_id": os.getenv("GITHUB_RUN_ID", "local"),
        "run_attempt": os.getenv("GITHUB_RUN_ATTEMPT", "1"),
        "inputs": inputs,
        "targets": targets,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--output", type=Path, default=Path("reports/manifest.json"))
    parser.add_argument("--github-output", type=Path)
    args = parser.parse_args(argv)
    try:
        manifest = discover(args.root)
        write_json(args.output, manifest)
        if args.github_output:
            groups = {
                "services": [t["id"] for t in manifest["targets"] if t["kind"] == "service"],
                "targets": [t["id"] for t in manifest["targets"] if t["coverage"]],
                "images": [t["id"] for t in manifest["targets"] if "image" in t["checks"]],
            }
            with args.github_output.open("a", encoding="utf-8") as handle:
                for key, value in groups.items():
                    handle.write(f"{key}={json.dumps(value)}\n")
        print(f"Discovered {len(manifest['targets'])} targets")
        return 0
    except (OSError, ValueError) as exc:
        print(f"Discovery failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
