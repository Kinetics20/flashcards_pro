"""Validate the contract registry and local schemas without network retrieval."""

from __future__ import annotations

import argparse
import re
from datetime import date
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import unquote, urlsplit

import yaml
from jsonschema import Draft202012Validator, FormatChecker
from openapi_spec_validator import OpenAPIV31SpecValidator
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT202012

from scripts.security.common import read_json

SEMVER = (
    r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    r"(?:-(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)"
    r"(?:\.(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
)
DIALECT = "https://json-schema.org/draft/2020-12/schema"
ID = r"^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$"
ENTRY_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": [
        "id",
        "kind",
        "version",
        "owner",
        "producer",
        "consumers",
        "scope",
        "schema_path",
        "lifecycle",
        "deprecation",
    ],
    "properties": {
        "id": {"type": "string", "pattern": ID},
        "kind": {"enum": ["openapi", "event"]},
        "version": {"type": "string", "pattern": "^" + SEMVER + "$"},
        "owner": {"type": "string", "minLength": 1},
        "producer": {"type": "string", "pattern": ID},
        "consumers": {
            "type": "array",
            "uniqueItems": True,
            "items": {"type": "string", "pattern": ID},
        },
        "scope": {"enum": ["public", "internal", "reference"]},
        "schema_path": {"type": "string", "minLength": 1},
        "lifecycle": {"enum": ["active", "deprecated"]},
        "deprecation": {
            "oneOf": [
                {"type": "null"},
                {
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["deprecated_since", "sunset_at", "replacement"],
                    "properties": {
                        "deprecated_since": {"type": "string", "format": "date"},
                        "sunset_at": {"type": "string", "format": "date"},
                        "replacement": {
                            "oneOf": [{"type": "null"}, {"type": "string", "pattern": ID}],
                        },
                    },
                },
            ],
        },
    },
}
REGISTRY_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["schema_version", "contracts"],
    "properties": {
        "schema_version": {"const": 1, "type": "integer"},
        "contracts": {"type": "array", "minItems": 1, "items": ENTRY_SCHEMA},
    },
}


def _contract_path(root: Path, value: str) -> Path:
    """Registry paths have no traversal; references have separate containment checks."""
    part = PurePosixPath(value)
    if (
        not value
        or "\\" in value
        or "\x00" in value
        or part.is_absolute()
        or ".." in part.parts
        or not part.parts
        or part.parts[0] != "contracts"
        or part.suffix != ".json"
    ):
        raise ValueError("Expected a contracts-relative JSON path without traversal")
    base = (root / "contracts").resolve()
    if not base.is_relative_to(root.resolve()):
        raise ValueError("Contracts directory escapes the repository")
    path = (root / part).resolve()
    if not path.is_relative_to(base):
        raise ValueError("Contract path escapes contracts directory")
    return path


def load_registry(root: Path) -> dict[str, Any]:
    """Read strict JSON; malformed metadata is reported by validate_registry_metadata."""
    document = read_json(_contract_path(Path(root), "contracts/registry.json"))
    if not isinstance(document, dict):
        raise ValueError("Registry must be an object")
    return document


def _owners(root: Path) -> dict[str, str]:
    owners = {}
    for folder in sorted((root / "services").iterdir()):
        if not folder.is_dir() or not (folder / "pyproject.toml").is_file():
            continue
        path = folder / "OWNERS.yaml"
        if not path.resolve().is_relative_to(root.resolve()):
            raise ValueError("OWNERS path escapes repository")
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
        if not isinstance(document, dict) or document.get("schemaVersion") != "1":
            raise ValueError("Invalid OWNERS schemaVersion")
        service = document.get("service")
        if (
            not isinstance(service, dict)
            or service.get("id") != folder.name
            or not isinstance(service.get("owner"), str)
            or not service["owner"].strip()
        ):
            raise ValueError("Invalid OWNERS service id or owner")
        owners[folder.name] = service["owner"]
    return owners


def validate_registry_metadata(root: Path, registry: dict[str, Any]) -> list[str]:
    """Validate registry structure and ownership before a code-first export exists."""
    errors = [
        "Registry metadata: " + error.json_path + " violates registry schema"
        for error in Draft202012Validator(
            REGISTRY_SCHEMA,
            format_checker=FormatChecker(),
        ).iter_errors(registry)
    ]
    if errors:
        return errors
    try:
        owners = _owners(root)
    except (OSError, ValueError, yaml.YAMLError) as error:
        return [f"Cannot read service ownership: {type(error).__name__}"]
    entries = registry["contracts"]
    ids = [entry["id"] for entry in entries]
    paths = [entry["schema_path"] for entry in entries]
    if len(set(ids)) != len(ids):
        errors.append("Duplicate contract id")
    if len(set(paths)) != len(paths):
        errors.append("Duplicate contract schema_path")
    for entry in entries:
        label = entry["id"]
        if not re.fullmatch(SEMVER, entry["version"]):
            errors.append(f"{label}: version must be strict SemVer")
        if not re.fullmatch(ID, label):
            errors.append("Contract id must be lowercase kebab-case")
        try:
            path = _contract_path(root, entry["schema_path"])
            prefix = "openapi" if entry["kind"] == "openapi" else "events"
            if not path.is_relative_to((root / "contracts" / prefix).resolve()):
                raise ValueError("Schema path does not match contract kind")
            if entry["version"] not in PurePosixPath(entry["schema_path"]).parts:
                raise ValueError("Schema path must include its exact version directory")
        except ValueError as error:
            errors.append(f"{label}: {error}")
        for service in [entry["producer"], *entry["consumers"]]:
            if service not in owners:
                errors.append(f"{label}: unknown service {service}")
        if entry["producer"] in owners and entry["owner"] != owners[entry["producer"]]:
            errors.append(f"{label}: owner must match producer OWNERS.yaml")
        deprecation = entry["deprecation"]
        if entry["lifecycle"] == "active" and deprecation is not None:
            errors.append(f"{label}: active contract must have null deprecation")
        if entry["lifecycle"] == "deprecated":
            if deprecation is None:
                errors.append(f"{label}: deprecated contract needs deprecation metadata")
                continue
            if date.fromisoformat(deprecation["sunset_at"]) <= date.fromisoformat(
                deprecation["deprecated_since"],
            ):
                errors.append(f"{label}: sunset_at must be after deprecated_since")
            replacement = deprecation["replacement"]
            if replacement is not None and (replacement not in ids or replacement == label):
                errors.append(f"{label}: replacement must reference another registered contract")
    return errors


def _pointer(document: Any, fragment: str) -> None:
    if not fragment:
        return
    if not fragment.startswith("/") or re.search(r"~(?![01])", fragment):
        raise ValueError("Only valid JSON Pointer fragments are supported")
    current = document
    for encoded in fragment[1:].split("/"):
        part = encoded.replace("~1", "/").replace("~0", "~")
        if isinstance(current, dict) and part in current:
            current = current[part]
        elif isinstance(current, list) and re.fullmatch(r"0|[1-9][0-9]*", part):
            try:
                current = current[int(part)]
            except IndexError as error:
                raise ValueError("Reference points to a missing list item") from error
        else:
            raise ValueError("Reference points to a missing JSON value")


def _nodes(document: Any):
    if isinstance(document, dict):
        yield document
        for value in document.values():
            yield from _nodes(value)
    elif isinstance(document, list):
        for value in document:
            yield from _nodes(value)


def _documents(root: Path, path: Path, document: dict[str, Any]) -> dict[Path, dict[str, Any]]:
    """Preflight every local reference before any schema validator is invoked."""
    documents = {path: document}
    pending = [path]
    base = (root / "contracts").resolve()
    while pending:
        current = pending.pop()
        for node in _nodes(documents[current]):
            if any(key in node for key in ("$id", "$dynamicRef", "$recursiveRef")):
                raise ValueError("$id rebasing, $dynamicRef and $recursiveRef are not supported")
            if "$ref" not in node:
                continue
            reference = node["$ref"]
            if not isinstance(reference, str):
                raise ValueError("$ref must be a string")
            uri = urlsplit(reference)
            decoded = unquote(uri.path)
            if (
                uri.scheme
                or uri.netloc
                or uri.query
                or decoded.startswith("/")
                or "\\" in decoded
                or "\x00" in decoded
            ):
                raise ValueError("Only relative local references are allowed")
            target = (current.parent / decoded).resolve() if decoded else current
            if not target.is_relative_to(base) or target.suffix != ".json":
                raise ValueError("Reference escapes contracts or is not JSON")
            if target not in documents:
                loaded = read_json(target)
                if not isinstance(loaded, dict):
                    raise ValueError("Referenced schema must be an object")
                documents[target] = loaded
                pending.append(target)
            _pointer(documents[target], unquote(uri.fragment))
    return documents


def _validate_json_schema(path: Path, documents: dict[Path, dict[str, Any]]) -> list[str]:
    schema = documents[path]
    if schema.get("$schema") != DIALECT:
        return ["JSON Schema must explicitly use draft 2020-12"]
    Draft202012Validator.check_schema(schema)
    registry = Registry().with_resources(
        (source.as_uri(), Resource.from_contents(value, default_specification=DRAFT202012))
        for source, value in documents.items()
    )
    validator = Draft202012Validator(
        {"$ref": path.as_uri()},
        registry=registry,
        format_checker=FormatChecker(),
    )
    examples = schema.get("examples", [])
    if not isinstance(examples, list):
        return ["Schema examples must be a list"]
    return [
        f"Example {index} violates schema at {error.json_path}"
        for index, example in enumerate(examples)
        for error in validator.iter_errors(example)
    ]


def validate_contract_document(entry: dict, document: dict, root: Path) -> list[str]:
    """Validate an export in memory; the exported root file need not exist yet."""
    try:
        path = _contract_path(root, entry["schema_path"])
        if not isinstance(document, dict):
            raise ValueError("Contract document must be an object")
        documents = _documents(root, path, document)
        if entry["kind"] == "openapi":
            if document.get("openapi") not in {"3.1.0", "3.1.1", "3.1.2"}:
                raise ValueError("Only OpenAPI 3.1 contracts are supported")
            if document.get("info", {}).get("version") != entry["version"]:
                raise ValueError("OpenAPI info.version must equal registry version")
            return [
                f"{entry['id']}: OpenAPI validation error at {error.json_path}"
                for error in OpenAPIV31SpecValidator(document, base_uri=path.as_uri()).iter_errors()
            ]
        if entry["scope"] == "reference" and document.get("x-reference-only") is not True:
            raise ValueError("Reference event must declare x-reference-only: true")
        properties = document.get("properties", {})
        if (
            document.get("type") != "object"
            or not {"version", "source"}.issubset(document.get("required", []))
            or properties.get("version", {}).get("const") != entry["version"]
            or properties.get("source", {}).get("const") != entry["producer"]
        ):
            raise ValueError("Event must require version/source constants matching registry")
        return [f"{entry['id']}: {error}" for error in _validate_json_schema(path, documents)]
    except Exception as error:
        # Validation libraries raise several reference/schema-specific exception families.
        # Never include entire documents or examples in diagnostics.
        return [f"{entry.get('id', 'contract')}: invalid schema ({type(error).__name__})"]


def validate_registry(root: Path) -> list[str]:
    """Validate metadata, all declared/shared schemas, references, examples and orphans."""
    root = Path(root).resolve()
    try:
        registry = load_registry(root)
    except OSError, ValueError:
        return ["Cannot read registry as strict JSON"]
    errors = validate_registry_metadata(root, registry)
    if errors:
        return errors
    reachable = set()
    for entry in registry["contracts"]:
        try:
            path = _contract_path(root, entry["schema_path"])
            document = read_json(path)
            errors.extend(validate_contract_document(entry, document, root))
            reachable.update(_documents(root, path, document))
        except OSError, ValueError:
            errors.append(f"{entry['id']}: cannot load contract or its references")
    # Common schemas form an intentional reusable library, not standalone registry entries.
    for path in sorted((root / "contracts" / "common").rglob("*.json")):
        try:
            path = _contract_path(root, path.relative_to(root).as_posix())
            documents = _documents(root, path, read_json(path))
            errors.extend(_validate_json_schema(path, documents))
            reachable.update(documents)
        except Exception as error:
            errors.append(f"Invalid shared schema: {path.name} ({type(error).__name__})")
    for folder in ("openapi", "events"):
        for path in sorted((root / "contracts" / folder).rglob("*.json")):
            if path.resolve() not in reachable:
                errors.append(f"Unregistered/orphan schema: {path.relative_to(root).as_posix()}")
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    args = parser.parse_args(argv)
    errors = validate_registry(args.root)
    for error in errors:
        print(error)
    if not errors:
        print("Contract registry and schemas are valid.")
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
