"""Select extra integration checks; never narrow the full security/coverage baseline."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

from scripts.contracts.validate import load_registry, validate_registry_metadata
from scripts.security.common import read_json, write_json
from scripts.security.discover_targets import discover

SHA = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})")


def git(root: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(root), *args], check=True, capture_output=True, timeout=30
    )
    output = result.stdout.decode("utf-8", errors="strict")
    # A newline can be part of a filename, including the first NUL-delimited item.
    return output if "-z" in args else output.removesuffix("\n")


def revision(root: Path, value: str) -> str:
    if not isinstance(value, str) or not SHA.fullmatch(value) or set(value) == {"0"}:
        raise ValueError("Expected a non-zero full Git commit SHA")
    return git(root, "rev-parse", "--verify", f"{value}^{{commit}}")


def event_range(event: str, payload: dict[str, Any]) -> tuple[str, str]:
    if event == "pull_request":
        request = payload["pull_request"]
        return request["base"]["sha"], request["head"]["sha"]
    if event == "push":
        return payload["before"], payload["after"]
    raise ValueError("This event requires a full run")


def changed_paths(root: Path, event: str, payload: dict[str, Any]) -> tuple[list[str], str, str]:
    before, after = event_range(event, payload)
    before, after = revision(root, before), revision(root, after)
    # The tested checkout is the PR merge commit or the push head, not arbitrary event data.
    git(root, "merge-base", "--is-ancestor", after, "HEAD")
    if event == "push" and after != git(root, "rev-parse", "HEAD"):
        raise ValueError("Push head does not match tested checkout")
    base = git(root, "merge-base", before, after) if event == "pull_request" else before
    # Disable rename collapsing: both the removed and added path affect dependency impact.
    raw = git(root, "diff", "--name-only", "-z", "--no-renames", base, after, "--")
    return sorted(set(filter(None, raw.split("\0")))), base, after


def select_targets(
    targets: list[dict[str, Any]], registry: dict[str, Any], paths: list[str]
) -> tuple[list[str], str]:
    ids = {target["id"] for target in targets}
    edges: dict[str, set[str]] = {}
    for entry in registry["contracts"]:
        edges.setdefault(entry["producer"], set()).update(entry["consumers"])
    selected: set[str] = set()
    for path in paths:
        documentation = path.startswith(("docs/", "adr/")) and Path(path).suffix.lower() in {
            ".md",
            ".txt",
            ".png",
            ".jpg",
            ".jpeg",
            ".svg",
            ".webp",
        }
        if documentation or path in {"README.md", "CONTRIBUTING.md"}:
            continue
        matched = next((t for t in targets if path.startswith(t["path"] + "/")), None)
        if matched is not None and matched["kind"] == "service":
            selected.add(matched["id"])
            continue
        contract = next(
            (entry for entry in registry["contracts"] if path == entry["schema_path"]), None
        )
        if contract is not None:
            selected.add(contract["producer"])
            selected.update(contract["consumers"])
            continue
        # Includes template changes, removed projects, shared refs, the registry itself,
        # generators, workflows and any new path we cannot prove to be documentation.
        return sorted(ids), "full: shared, removed, or unclassified path"
    pending = list(selected)
    while pending:
        for consumer in edges.get(pending.pop(), set()) - selected:
            selected.add(consumer)
            pending.append(consumer)
    if not selected <= ids:
        raise ValueError("Contract dependency points outside runnable project inventory")
    return sorted(selected), "changed projects and transitive contract consumers"


def build_plan(root: Path, event: str, payload: dict[str, Any]) -> dict[str, Any]:
    root = root.resolve()
    inventory = discover(root)
    targets = [
        {
            **{key: target[key] for key in ("id", "kind", "path", "lockfile_sha256")},
            "integration_profile": "postgres"
            if target["id"] == "template-fastapi"
            or (root / target["path"] / "alembic.ini").is_file()
            or (root / target["path"] / "src/app/platform/database.py").is_file()
            else "asgi",
        }
        for target in inventory["targets"]
        if target["kind"] in {"service", "template"}
    ]
    registry = load_registry(root)
    errors = validate_registry_metadata(root, registry)
    if errors:
        raise ValueError("Invalid contract dependency inventory: " + "; ".join(errors))
    base = head = None
    paths: list[str] = []
    try:
        paths, base, head = changed_paths(root, event, payload)
    except KeyError, TypeError, ValueError, subprocess.SubprocessError, UnicodeError:
        selected = sorted(target["id"] for target in targets)
        reason = "full: event requires full run or comparison history is unavailable"
    else:
        selected, reason = select_targets(targets, registry, paths)
    return {
        "schema_version": 1,
        "commit": inventory["commit"],
        "event": event,
        "comparison_base": base,
        "comparison_head": head,
        "changed_paths": paths,
        "reason": reason,
        "targets": targets,
        "registry_sha256": hashlib.sha256(
            (root / "contracts/registry.json").read_bytes()
        ).hexdigest(),
        "selected": selected,
        "baseline": "full-security-unit-coverage-and-image-checks",
    }


def digest(plan: dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(plan, sort_keys=True).encode()).hexdigest()


def context(event: str | None = None, event_path: Path | None = None) -> tuple[str, dict]:
    name = event or os.environ.get("GITHUB_EVENT_NAME", "workflow_dispatch")
    source = event_path or os.environ.get("GITHUB_EVENT_PATH")
    payload = read_json(Path(source)) if source else {}
    if not isinstance(payload, dict):
        raise ValueError("Event payload must be an object")
    return name, payload


def expected_plan(root: Path, path: Path) -> dict[str, Any]:
    """Downloaded evidence is never authority for which checks are required."""
    event, payload = context()
    expected = build_plan(root, event, payload)
    if read_json(path) != expected:
        raise ValueError("Execution plan does not match current Git/event/inventory inputs")
    return expected


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--output", type=Path, default=Path("reports/ci-plan.json"))
    parser.add_argument("--github-output", type=Path)
    parser.add_argument("--event")
    parser.add_argument("--event-path", type=Path)
    args = parser.parse_args(argv)
    try:
        event, payload = context(args.event, args.event_path)
        plan = build_plan(args.root, event, payload)
        write_json(args.output, plan)
        if args.github_output:
            with args.github_output.open("a", encoding="utf-8") as output:
                output.write(f"targets={json.dumps(plan['selected'])}\n")
                output.write(f"has_targets={str(bool(plan['selected'])).lower()}\n")
        print(json.dumps({"selected": plan["selected"], "reason": plan["reason"]}))
        return 0
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(f"CI planning failed: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
