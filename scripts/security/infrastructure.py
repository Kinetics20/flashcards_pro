"""Scan every local-stack image by the immutable ID exercised by integration tests.

This is an additional image-only gate. It does not replace or narrow the FCB-62
service/template manifest, Python inventory, or line-and-branch coverage gate.
"""

from __future__ import annotations

import argparse
import hashlib
import re
from pathlib import Path
from typing import Any

from .common import git_commit, read_json, sha256_file, write_json
from .compose_inventory import INVENTORY, TOKEN, documents
from .gate import evaluate_report, validate_exceptions, validate_policy
from .run_scans import Runner, ScanError, run

IMAGE_ID = re.compile(r"sha256:[a-f0-9]{64}")
PINNED = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9._:/-]*:[a-zA-Z0-9._-]+@sha256:[a-f0-9]{64}")


def identities(path: Path, commit: str) -> dict[str, Any]:
    document = read_json(path)
    if (
        not isinstance(document, dict)
        or set(document) != {"schema_version", "commit", "local_image_tag", "images"}
        or type(document["schema_version"]) is not int
        or document["schema_version"] != 1
        or document["commit"] != commit
        or not isinstance(document["local_image_tag"], str)
        or len(document["local_image_tag"]) > 63
        or not TOKEN.fullmatch(document["local_image_tag"])
        or not isinstance(document["images"], list)
        or not document["images"]
    ):
        raise ScanError("Integration image identity manifest is invalid or stale")
    seen = set()
    for row in document["images"]:
        if (
            not isinstance(row, dict)
            or set(row) != {"reference", "image_id"}
            or not isinstance(row["reference"], str)
            or not row["reference"]
            or row["reference"] in seen
            or not isinstance(row["image_id"], str)
            or not IMAGE_ID.fullmatch(row["image_id"])
        ):
            raise ScanError("Integration image identity entry is invalid or duplicated")
        seen.add(row["reference"])
    return document


def expected_images(root: Path, image_tag: str) -> tuple[dict[str, list[str]], dict[str, str]]:
    """Discover every profile, deduplicating shared images but not omitted services."""
    images: dict[str, list[str]] = {}
    inputs = {INVENTORY: sha256_file(root / INVENTORY)}
    for target, document in documents(root, image_tag):
        inputs[target["path"]] = sha256_file(root / target["path"])
        if target["kind"] == "template":
            # Every template image remains mandatory in the existing FCB-62 gate.
            continue
        for service, specification in sorted(document["services"].items()):
            reference = specification.get("image")
            if not isinstance(reference, str):
                raise ScanError("Every infrastructure service must declare an image")
            if "build" in specification:
                if not re.fullmatch(
                    r"flashcards-local-[a-z0-9-]+:" + re.escape(image_tag), reference
                ):
                    raise ScanError("Built infrastructure image must use the isolated tested tag")
                build = specification["build"]
                if not isinstance(build, dict) or not isinstance(build.get("context"), str):
                    raise ScanError("Infrastructure build must have a local context")
                context = Path(build["context"]).resolve()
                dockerfile = (context / build.get("dockerfile", "Dockerfile")).resolve()
                if not context.is_relative_to(root) or not dockerfile.is_relative_to(context):
                    raise ScanError("Infrastructure build inputs escape the repository")
                inputs[dockerfile.relative_to(root).as_posix()] = sha256_file(dockerfile)
            elif not PINNED.fullmatch(reference):
                raise ScanError("Pulled infrastructure images require both tag and digest")
            images.setdefault(reference, []).append(f"{target['path']}#services.{service}")
    if not images:
        raise ScanError("Infrastructure image inventory is empty")
    return images, inputs


def scan(root: Path, identity_path: Path, output: Path, *, install: bool = False) -> list[str]:
    root = root.resolve()
    commit = git_commit(root)
    identity = identities(identity_path, commit)
    expected, inputs = expected_images(root, identity["local_image_tag"])
    actual = {row["reference"]: row["image_id"] for row in identity["images"]}
    if set(expected) != set(actual):
        raise ScanError("Integration images do not cover the exact all-profile inventory")
    policy = read_json(root / "security/policy.json")
    exceptions = read_json(root / "security/exceptions.json")
    if validate_policy(policy) or validate_exceptions(exceptions, policy):
        raise ScanError("Infrastructure scan policy or exceptions are invalid")
    for relative in (
        "security/policy.json",
        "security/exceptions.json",
        "security/tools.lock.json",
    ):
        inputs[relative] = sha256_file(root / relative)
    targets = [
        {
            "id": "infra-" + hashlib.sha256(reference.encode()).hexdigest()[:16],
            "kind": "infrastructure",
            "path": ".",
            "checks": ["image"],
            "coverage": False,
            "reference": reference,
            "image_id": actual[reference],
            "services": expected[reference],
        }
        for reference in sorted(expected)
    ]
    manifest = {
        "schema_version": 1,
        "commit": commit,
        "inputs": inputs,
        "integration_identities_sha256": sha256_file(identity_path),
        "targets": targets,
    }
    write_json(output / "inventory.json", manifest)
    runner = Runner(root, output, manifest, install=install)
    for target in targets:
        current = run(
            ["docker", "image", "inspect", "--format", "{{.Id}}", target["reference"]], root
        ).stdout.strip()
        if current != target["image_id"]:
            raise ScanError("An image reference changed after integration testing")
        runner.image(target, target["image_id"])
    if len(runner.reports) != len(targets):
        raise ScanError("Infrastructure image reports are incomplete")
    failures = [
        failure
        for report in runner.reports
        for failure in evaluate_report(report, policy, exceptions)
    ]
    expected_paths = {output / target["id"] / "image.json" for target in targets}
    if set(output.glob("*/image.json")) != expected_paths:
        raise ScanError("Unexpected infrastructure reports; use a fresh report directory")
    for report in runner.reports:
        for artifact in report["artifacts"]:
            path = (output / artifact["path"]).resolve()
            if not path.is_relative_to(output.resolve()) or sha256_file(path) != artifact["sha256"]:
                raise ScanError("Infrastructure evidence digest mismatch")
    write_json(
        output / "result.json",
        {
            "schema_version": 1,
            "commit": commit,
            "status": "error" if failures else "ok",
            "image_count": len(targets),
            "errors": failures,
            "inventory_sha256": sha256_file(output / "inventory.json"),
        },
    )
    return failures


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--identities", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=Path("reports/infrastructure"))
    parser.add_argument("--install-tools", action="store_true")
    args = parser.parse_args(argv)
    try:
        errors = scan(args.root, args.identities, args.output, install=args.install_tools)
        print(f"Infrastructure policy: {len(errors)} blocking finding(s)")
        return 1 if errors else 0
    except (ScanError, OSError, ValueError, KeyError, TypeError) as error:
        message = (
            str(error) if isinstance(error, ScanError) else "Infrastructure evidence is invalid"
        )
        write_json(
            args.output / "result.json",
            {"schema_version": 1, "status": "error", "errors": [message]},
        )
        print(message)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
