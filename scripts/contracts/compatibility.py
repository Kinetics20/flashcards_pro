"""Fail-closed OpenAPI/event comparison against an exact Git baseline commit."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import tempfile
from pathlib import Path
from urllib.parse import unquote, urlsplit

from scripts.contracts.build import inside, json_bytes
from scripts.contracts.support import load_support
from scripts.contracts.validate import _documents, load_registry, validate_registry
from scripts.security.common import _invalid_constant, _unique_pairs, read_json
from scripts.security.run_scans import ScanError, run, verified_tool

ANNOTATIONS = {"title", "description", "examples", "$comment", "$schema"}
SCHEMA_MAPS = {"properties", "patternProperties", "$defs", "definitions", "dependentSchemas"}
SCHEMA_ARRAYS = {"allOf", "anyOf", "oneOf", "prefixItems"}
SCHEMA_VALUES = {
    "items",
    "contains",
    "additionalProperties",
    "unevaluatedProperties",
    "propertyNames",
    "not",
    "if",
    "then",
    "else",
    "unevaluatedItems",
    "contentSchema",
}


def git(root: Path, *arguments: str) -> bytes:
    result = subprocess.run(
        ["git", "-C", str(root), *arguments], capture_output=True, timeout=30, check=False
    )
    if result.returncode:
        raise ValueError("Cannot read the exact Git contract baseline")
    return result.stdout


def baseline_tree(root: Path, commit: str, destination: Path) -> None:
    """Read selected regular Git blobs, never checkout or execute baseline code."""
    if not re.fullmatch(r"[a-f0-9]{40}", commit):
        raise ValueError("Baseline must be an exact 40-character commit SHA")
    resolved = git(root, "rev-parse", "--verify", commit + "^{commit}").decode().strip()
    if resolved != commit:
        raise ValueError("Baseline does not identify an exact commit")
    records = git(root, "ls-tree", "-r", "-z", commit, "--", "contracts", "services")
    total = 0
    for record in records.split(b"\0"):
        if not record:
            continue
        metadata, raw_path = record.split(b"\t", 1)
        mode, kind, oid = metadata.decode().split()
        relative = raw_path.decode("utf-8")
        path = Path(relative)
        selected = (relative.startswith("contracts/") and path.suffix == ".json") or (
            len(path.parts) == 3
            and path.parts[0] == "services"
            and path.name in {"OWNERS.yaml", "pyproject.toml"}
        )
        if not selected or "generated" in path.parts:
            continue
        if kind != "blob" or mode not in {"100644", "100755"}:
            raise ValueError("Baseline inputs must be regular files, not symlinks")
        content = git(root, "cat-file", "blob", oid)
        total += len(content)
        if len(content) > 8_000_000 or total > 64_000_000:
            raise ValueError("Baseline contract inventory exceeds the safety limit")
        output = inside(destination, relative)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_bytes(content)


def expanded(root: Path, entry: dict) -> dict:
    """Resolve the validated local graph; unsupported recursive changes fail closed."""
    source = (root / entry["schema_path"]).resolve()
    documents = _documents(root, source, read_json(source))

    def resolve(value, path, stack):
        if not isinstance(value, dict):
            return value
        output = {}
        for key, item in value.items():
            if key in ANNOTATIONS or key == "$ref":
                continue
            if key in SCHEMA_MAPS and isinstance(item, dict):
                # These keys are user property/definition names, not schema annotations.
                output[key] = {name: resolve(child, path, stack) for name, child in item.items()}
            elif key in SCHEMA_ARRAYS and isinstance(item, list):
                output[key] = [resolve(child, path, stack) for child in item]
            elif key in SCHEMA_VALUES:
                output[key] = resolve(item, path, stack)
            else:
                # const/enum/default and unknown keywords contain data, not nested schemas.
                output[key] = item
        if "$ref" not in value:
            return output
        reference = urlsplit(value["$ref"])
        target = (path.parent / unquote(reference.path)).resolve() if reference.path else path
        identity = (target, reference.fragment)
        if identity in stack:
            raise ValueError(
                "Recursive event schemas need an explicit compatibility implementation"
            )
        node = documents[target]
        if reference.fragment:
            for part in unquote(reference.fragment)[1:].split("/"):
                key = part.replace("~1", "/").replace("~0", "~")
                node = node[int(key)] if isinstance(node, list) else node[key]
        referred = resolve(node, target, {*stack, identity})
        return {"allOf": [referred, output]} if output else referred

    return resolve(documents[source], source, {(source, "")})


def same_json(left, right) -> bool:
    """JSON booleans are not numbers; Python's True == 1 must not hide a change."""
    if type(left) is not type(right):
        return False
    if isinstance(left, dict):
        return left.keys() == right.keys() and all(same_json(left[key], right[key]) for key in left)
    if isinstance(left, list):
        return len(left) == len(right) and all(
            same_json(before, after) for before, after in zip(left, right, strict=True)
        )
    return left == right


def event_changes(old, new, path: str = "$") -> list[str]:
    """Only annotation changes and unconditionally optional object additions pass.

    This is deliberately not a general JSON Schema language-inclusion prover.
    Any other changed constraint or unsupported construction is blocking.
    """
    if same_json(old, new):
        return []
    if not isinstance(old, dict) or not isinstance(new, dict):
        return [f"{path}: changed constraint is breaking or unsupported"]
    errors = []
    if old.keys() != new.keys():
        return [f"{path}: changed schema keywords are not proven compatible"]
    for key in old:
        left, right = old[key], new[key]
        if same_json(left, right):
            continue
        location = f"{path}/{key}"
        if key == "properties" and isinstance(left, dict) and isinstance(right, dict):
            if left.keys() - right.keys():
                errors.append(f"{location}: a known property was removed")
            added = right.keys() - left.keys()
            conditional = {
                "if",
                "then",
                "else",
                "dependentRequired",
                "dependentSchemas",
                "patternProperties",
                "unevaluatedProperties",
                "anyOf",
                "oneOf",
                "not",
            }
            if added and (conditional & old.keys() or added & set(new.get("required", []))):
                errors.append(f"{location}: additions are conditional or required")
            if added and isinstance(old.get("additionalProperties"), dict):
                errors.append(f"{location}: additions can violate the old reader's map schema")
            for name in sorted(left.keys() & right.keys()):
                errors.extend(event_changes(left[name], right[name], location + "/" + name))
        elif (
            key == "allOf"
            and isinstance(left, list)
            and isinstance(right, list)
            and len(left) == len(right)
        ):
            for index, (before, after) in enumerate(zip(left, right, strict=True)):
                errors.extend(event_changes(before, after, f"{location}/{index}"))
        elif key == "items" and isinstance(left, dict) and isinstance(right, dict):
            errors.extend(event_changes(left, right, location))
        else:
            errors.append(f"{location}: changed constraint is breaking or unsupported")
    return errors


def oasdiff_findings(stdout: str) -> list[dict]:
    """Keep diagnostic coordinates, never arbitrary descriptions or source contents."""
    findings = json.loads(stdout, object_pairs_hook=_unique_pairs, parse_constant=_invalid_constant)
    if not isinstance(findings, list):
        raise ValueError("oasdiff did not return its expected JSON finding list")
    safe = []
    for finding in findings:
        if (
            not isinstance(finding, dict)
            or not isinstance(finding.get("id"), str)
            or not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", finding["id"])
            or type(finding.get("level")) is not int
            or finding["level"] not in {1, 2, 3}
        ):
            raise ValueError("oasdiff returned a malformed finding")
        item = {"id": finding["id"], "level": finding["level"]}
        for field in ("operation", "operationId", "path", "section", "fingerprint"):
            if field not in finding:
                continue
            value = finding[field]
            if not isinstance(value, str) or len(value) > 2048:
                raise ValueError("oasdiff returned invalid diagnostic coordinates")
            item[field] = value
        safe.append(item)
    return safe


def compare(root: Path, baseline: Path, *, install_tools: bool = False) -> dict:
    for label, tree in (("baseline", baseline), ("candidate", root)):
        errors = validate_registry(tree)
        if errors:
            raise ValueError(f"Invalid {label} registry: " + "; ".join(errors))
    current = {entry["id"]: entry for entry in load_registry(root)["contracts"]}
    previous = {entry["id"]: entry for entry in load_registry(baseline)["contracts"]}
    support = {item["contract_id"]: item for item in load_support(root)["bindings"]}
    # The sole bootstrap is FCB-67, which has a registry but no support sidecar yet.
    old_support = (
        {item["contract_id"]: item for item in load_support(baseline)["bindings"]}
        if (baseline / "contracts/support.json").is_file()
        else {}
    )
    errors, comparisons = [], []
    binary = None
    for identifier, old in previous.items():
        if identifier not in current:
            errors.append(f"{identifier}: a previously supported contract was removed")
            continue
        new = current[identifier]
        if any(old[field] != new[field] for field in ("kind", "version", "producer")):
            errors.append(f"{identifier}: keep the old binding; register a new version separately")
            continue
        if identifier in old_support and support[identifier] != old_support[identifier]:
            errors.append(f"{identifier}: a supported binding was changed")
        findings = []
        if new["kind"] == "event":
            changes = event_changes(expanded(baseline, old), expanded(root, new))
        else:
            if binary is None:
                binary, _ = verified_tool(root, "oasdiff", install=install_tools)
            # The current code-first API uses only internal references. Refuse others;
            # don't silently let oasdiff fetch files or URLs from candidate inputs.
            for tree, entry in ((baseline, old), (root, new)):
                path = (tree / entry["schema_path"]).resolve()
                if len(_documents(tree, path, read_json(path))) != 1:
                    raise ValueError("OpenAPI external references need a reviewed offline bundler")
            result = run(
                [
                    binary,
                    "breaking",
                    "--format",
                    "json",
                    "--fail-on",
                    "WARN",
                    "--allow-external-refs=false",
                    str(baseline / old["schema_path"]),
                    str(root / new["schema_path"]),
                ],
                root,
                allowed=(0, 1),
                timeout=60,
            )
            findings = oasdiff_findings(result.stdout)
            blocking = result.returncode or any(finding["level"] >= 2 for finding in findings)
            changes = ["OpenAPI breaking changes detected"] if blocking else []
        errors.extend(f"{identifier}: {message}" for message in changes)
        comparisons.append(
            {
                "contract_id": identifier,
                "compatible": not changes,
                "findings": findings,
            }
        )
    for identifier in sorted(current.keys() - previous.keys()):
        binding = support[identifier]
        siblings = [
            item
            for item in support.values()
            if item["family"] == binding["family"] and item["contract_id"] in previous
        ]
        if siblings and int(binding["version"].split(".")[0]) <= max(
            int(item["version"].split(".")[0]) for item in siblings
        ):
            errors.append(f"{identifier}: a parallel replacement needs a new major version")
    return {
        "schema_version": 1,
        "comparisons": comparisons,
        "errors": errors,
        "required_bindings": sorted(support),
        "status": "error" if errors else "ok",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--base", required=True)
    parser.add_argument("--install-tools", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    try:
        with tempfile.TemporaryDirectory(prefix="contract-baseline-") as temporary:
            baseline = Path(temporary)
            baseline_tree(args.root.resolve(), args.base, baseline)
            result = compare(args.root.resolve(), baseline, install_tools=args.install_tools)
            result["base_commit"] = args.base
    except (OSError, ValueError, KeyError, subprocess.TimeoutExpired, ScanError) as error:
        result = {"schema_version": 1, "status": "error", "errors": [str(error)]}
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_bytes(json_bytes(result))
    print(json.dumps(result, sort_keys=True))
    return int(result["status"] != "ok")


if __name__ == "__main__":
    raise SystemExit(main())
