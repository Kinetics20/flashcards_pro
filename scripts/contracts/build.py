"""Export real API schemas, generate Python types and render offline reference pages."""

from __future__ import annotations

import argparse
import ast
import hashlib
import html
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlsplit

from scripts.contracts.validate import (
    load_registry,
    validate_contract_document,
    validate_registry,
    validate_registry_metadata,
)
from scripts.security.common import read_json

CODEGEN_VERSION = "0.83.0"
METHODS = frozenset({"get", "post", "put", "patch", "delete", "head", "options", "trace"})
EXPORT_SCRIPT = """
import contextlib
import json
import sys

sys.path.insert(0, sys.argv[1])
with contextlib.redirect_stdout(sys.stderr):
    from app.core.config import Settings
    from app.main import create_app
    application = create_app(Settings(
        _env_file=None, environment="test", docs_enabled=True, version=sys.argv[2]
    ))
    document = application.openapi()
print(json.dumps(document, sort_keys=True, allow_nan=False))
"""


class BuildError(ValueError):
    """A deterministic build cannot safely produce its complete output set."""


def json_bytes(document: Any) -> bytes:
    return (
        json.dumps(document, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False) + "\n"
    ).encode()


def clean_environment(directory: Path) -> dict[str, str]:
    """Do not inherit APP settings, dotenv locations, Python hooks or credentials."""
    return {
        "PATH": os.defpath,
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PYTHONDONTWRITEBYTECODE": "1",
    }


def run_command(command: list[str], directory: Path) -> str:
    """Bound execution time and never echo potentially sensitive subprocess output."""
    try:
        result = subprocess.run(
            command,
            cwd=directory,
            env=clean_environment(directory),
            capture_output=True,
            text=True,
            check=False,
            timeout=120,
        )
    except OSError, subprocess.TimeoutExpired:
        raise BuildError(
            "Contract subprocess could not complete; check the locked environments"
        ) from None
    if result.returncode:
        raise BuildError("Contract subprocess failed; check the locked environments and schemas")
    return result.stdout


def inside(root: Path, relative: str) -> Path:
    """Reject symlink paths and traversal before reading or replacing generated files."""
    path = Path(relative)
    if path.is_absolute() or ".." in path.parts or not path.parts:
        raise BuildError("Contract output path must remain inside the repository")
    current = root
    for part in path.parts:
        current /= part
        if current.is_symlink():
            raise BuildError("Contract paths must not contain symlinks")
    if not current.resolve().is_relative_to(root.resolve()):
        raise BuildError("Contract output path escapes the repository")
    return current


def export_openapi(root: Path, entry: dict[str, Any], directory: Path) -> dict[str, Any]:
    """Import the producer in its own environment without entering its lifespan."""
    producer = entry["producer"]
    if not re.fullmatch(r"[a-z][a-z0-9-]*", producer):
        raise BuildError("OpenAPI producer must name a service folder")
    service = inside(root, f"services/{producer}")
    python = service / ".venv/bin/python"
    if not python.is_file() or not (service / "src/app/main.py").is_file():
        raise BuildError(f"{producer}: sync the service environment before exporting OpenAPI")
    exported = run_command(
        [str(python), "-I", "-B", "-c", EXPORT_SCRIPT, str(service / "src"), entry["version"]],
        directory,
    )
    try:
        document = json.loads(exported)
    except ValueError, TypeError:
        raise BuildError(f"{producer}: OpenAPI export did not produce JSON") from None
    if not isinstance(document, dict) or not isinstance(document.get("info"), dict):
        raise BuildError(f"{producer}: OpenAPI export must contain an info object")
    # The real app receives the registry version through explicit export-only settings.
    document["info"]["x-contract"] = {
        key: entry[key]
        for key in ("id", "owner", "producer", "consumers", "scope", "lifecycle", "deprecation")
    }
    return document


def copy_schema_inputs(root: Path, directory: Path) -> None:
    """Preserve relative references without giving the generator remote inputs."""
    for source in sorted((root / "contracts").rglob("*.json")):
        relative = source.relative_to(root)
        if "generated" in relative.parts:
            continue
        source = inside(root, relative.as_posix())
        destination = inside(directory, relative.as_posix())
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(source.read_bytes())


def stage_codegen_schema(
    root: Path, entry: dict[str, Any], document: dict[str, Any], directory: Path
) -> Path:
    """Put referenced schemas beside the input so the generator can stay offline."""
    pending = {entry["schema_path"]: document}
    completed: set[str] = set()

    def filename(relative: str) -> str:
        return "schema-" + hashlib.sha256(relative.encode()).hexdigest() + ".json"

    def rewrite(value: Any, relative: str) -> Any:
        if isinstance(value, list):
            return [rewrite(item, relative) for item in value]
        if not isinstance(value, dict):
            return value
        result = {key: rewrite(item, relative) for key, item in value.items()}
        if "$ref" in result:
            reference = urlsplit(result["$ref"])
            if reference.scheme or reference.netloc or reference.query:
                raise BuildError("Code generation only supports local schema references")
            if reference.path:
                target = (root / relative).parent / unquote(reference.path)
                resolved = target.resolve()
                if not resolved.is_relative_to((root / "contracts").resolve()):
                    raise BuildError("Code generation reference escapes contracts")
                target_relative = resolved.relative_to(root).as_posix()
                if target_relative not in completed and target_relative not in pending:
                    pending[target_relative] = read_json(inside(root, target_relative))
                result["$ref"] = filename(target_relative)
                if reference.fragment:
                    result["$ref"] += "#" + reference.fragment
        return result

    while pending:
        relative = sorted(pending)[0]
        current = pending.pop(relative)
        completed.add(relative)
        (directory / filename(relative)).write_bytes(json_bytes(rewrite(current, relative)))
    return directory / filename(entry["schema_path"])


def validate_staged_registry(root: Path, documents: dict[str, dict], directory: Path) -> None:
    """Validate the complete new inventory, including common and orphan schemas."""
    copy_schema_inputs(root, directory)
    for source in sorted((root / "services").glob("*/pyproject.toml")):
        for path in (source, source.parent / "OWNERS.yaml"):
            relative = path.relative_to(root).as_posix()
            destination = inside(directory, relative)
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(inside(root, relative).read_bytes())
    for relative, document in documents.items():
        destination = inside(directory, relative)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(json_bytes(document))
    errors = validate_registry(directory)
    if errors:
        raise BuildError("Staged registry validation failed: " + "; ".join(errors))


def generate_models(
    root: Path, entry: dict[str, Any], document: dict[str, Any], directory: Path, profile: str
) -> bytes:
    """Generate strict producer types or additive-field-tolerant consumer types."""
    if profile not in {"server", "client"}:
        raise BuildError("Unknown generation profile")
    directory.mkdir(parents=True, exist_ok=True)
    source = stage_codegen_schema(root, entry, document, directory)
    output = directory / "models.py"
    command = [
        sys.executable,
        "-I",
        "-B",
        "-m",
        "datamodel_code_generator",
        "--input",
        str(source.relative_to(directory)),
        "--input-file-type",
        "openapi" if entry["kind"] == "openapi" else "jsonschema",
        "--output",
        "models.py",
        "--output-model-type",
        "pydantic_v2.BaseModel",
        "--target-python-version",
        "3.14",
        "--disable-timestamp",
        "--use-title-as-name",
        "--ignore-pyproject",
        "--no-allow-remote-refs",
        "--formatters",
        "builtin",
        "--extra-fields",
        "forbid" if profile == "server" else "ignore",
    ]
    run_command(command, directory)
    if not output.is_file():
        raise BuildError("Code generator did not produce Python types")
    generated = output.read_text(encoding="utf-8")
    try:
        ast.parse(generated)
    except SyntaxError:
        raise BuildError("Code generator produced invalid Python") from None
    header = (
        f"# Contract: {entry['id']} {entry['version']}; profile: {profile}.\n"
        f"# Generated with datamodel-code-generator {CODEGEN_VERSION}; do not edit.\n"
        "# Transport DTOs only: not an HTTP client, server implementation or event publisher.\n"
    )
    return (header + generated.rstrip() + "\n").encode()


def page(title: str, body: str) -> bytes:
    return (
        '<!doctype html>\n<html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        '<meta http-equiv="Content-Security-Policy" '
        "content=\"default-src 'none'; style-src 'unsafe-inline'\">"
        f"<title>{html.escape(title)}</title><style>"
        "body{max-width:1100px;margin:3rem auto;padding:0 1rem;font:16px system-ui;"
        "line-height:1.6;color:#172b4d;background:#f6f8fb}"
        "h1,h2{line-height:1.2}table{border-collapse:collapse;width:100%;background:white}"
        "td,th{padding:.6rem;text-align:left;border:1px solid #ccd5e1}"
        "pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#11243a;color:#eef5ff;"
        "padding:1rem;border-radius:.5rem}a{color:#075fb5}"
        "</style></head><body>"
        f"<h1>{html.escape(title)}</h1>{body}</body></html>\n"
    ).encode()


def render_contract(entry: dict[str, Any], document: dict[str, Any]) -> bytes:
    rows = "".join(
        f"<tr><th>{html.escape(key)}</th>"
        f"<td>{html.escape(json.dumps(entry[key], ensure_ascii=False))}</td></tr>"
        for key in (
            "version",
            "kind",
            "owner",
            "producer",
            "consumers",
            "scope",
            "lifecycle",
            "deprecation",
            "schema_path",
        )
    )
    body = '<p><a href="index.html">Contract catalog</a></p><table>' + rows + "</table>"
    body += (
        "<p>Python outputs are transport DTOs, not a generated API implementation or client.</p>"
    )
    if entry["scope"] == "reference":
        body += (
            "<p><strong>Reference-only example. "
            "No production publisher or domain flow exists.</strong></p>"
        )
    if entry["kind"] == "openapi":
        body += "<h2>Operations</h2><table><tr><th>Method</th><th>Path</th><th>Summary</th></tr>"
        for path, path_item in sorted(document.get("paths", {}).items()):
            for method, operation in sorted(path_item.items()):
                if method in METHODS:
                    summary = operation.get("summary", operation.get("operationId", ""))
                    body += (
                        f"<tr><td>{method.upper()}</td><td>{html.escape(path)}</td>"
                        f"<td>{html.escape(summary)}</td></tr>"
                    )
        body += "</table>"
    body += "<h2>Complete schema and examples</h2><pre>"
    body += html.escape(json_bytes(document).decode()) + "</pre>"
    return page(entry["id"], body)


def render_index(entries: list[dict[str, Any]]) -> bytes:
    rows = "".join(
        f'<tr><td><a href="{html.escape(entry["id"], quote=True)}.html">'
        f"{html.escape(entry['id'])}</a></td><td>{html.escape(entry['version'])}</td>"
        f"<td>{html.escape(entry['owner'])}</td><td>{html.escape(entry['lifecycle'])}</td>"
        f"<td>{html.escape(entry['scope'])}</td></tr>"
        for entry in entries
    )
    return page(
        "Flashcards contract catalog",
        "<p>Offline documentation. OpenAPI is exported from the actual producer; "
        "reference events are not claimed as implemented features.</p>"
        "<table><tr><th>Contract</th><th>Version</th><th>Owner</th><th>Lifecycle</th>"
        f"<th>Scope</th></tr>{rows}</table>",
    )


def build_outputs(root: Path, directory: Path) -> dict[str, bytes]:
    registry = load_registry(root)
    errors = validate_registry_metadata(root, registry)
    if errors:
        raise BuildError("Registry validation failed: " + "; ".join(errors))
    entries = sorted(registry["contracts"], key=lambda entry: entry["id"])
    names = [entry["id"].replace("-", "_") for entry in entries]
    if len(names) != len(set(names)):
        raise BuildError("Contract identifiers collide after Python filename normalization")
    version = run_command(
        [sys.executable, "-I", "-B", "-m", "datamodel_code_generator", "--version"], directory
    )
    if version.strip().split()[-1:] != [CODEGEN_VERSION]:
        raise BuildError(f"Expected datamodel-code-generator {CODEGEN_VERSION}")
    outputs: dict[str, bytes] = {}
    documents = {}
    for entry in entries:
        if entry["kind"] == "openapi":
            document = export_openapi(root, entry, directory)
            outputs[entry["schema_path"]] = json_bytes(document)
        else:
            document = read_json(inside(root, entry["schema_path"]))
        errors = validate_contract_document(entry, document, root)
        if errors:
            raise BuildError(
                f"{entry['id']}: exported/source contract validation failed: " + "; ".join(errors)
            )
        documents[entry["schema_path"]] = document
    validate_staged_registry(root, documents, directory / "inventory")
    for entry, name in zip(entries, names, strict=True):
        document = documents[entry["schema_path"]]
        for profile in ("server", "client"):
            outputs[f"contracts/generated/python/{name}_{profile}.py"] = generate_models(
                root, entry, document, directory / f"{name}_{profile}", profile
            )
        outputs[f"contracts/generated/docs/{entry['id']}.html"] = render_contract(entry, document)
    outputs["contracts/generated/python/__init__.py"] = (
        b'"""Generated contract DTOs; do not edit."""\n'
    )
    outputs["contracts/generated/docs/index.html"] = render_index(entries)
    return outputs


def managed_files(root: Path) -> set[str]:
    found: set[str] = set()
    for relative in ("contracts/generated", "contracts/openapi"):
        base = inside(root, relative)
        for path in base.rglob("*"):
            if "__pycache__" not in path.parts and (path.is_file() or path.is_symlink()):
                found.add(path.relative_to(root).as_posix())
    return found


def build(root: Path, *, check: bool = False) -> list[str]:
    """Generate in a temporary workspace; check mode never rewrites repository files."""
    root = root.resolve()
    with tempfile.TemporaryDirectory(prefix="fcb-contracts-") as temporary:
        outputs = build_outputs(root, Path(temporary))
    stale = sorted(managed_files(root) - outputs.keys())
    errors = [
        f"Unexpected generated file: {path}; review and remove it explicitly" for path in stale
    ]
    paths = {relative: inside(root, relative) for relative in outputs}
    for relative, expected in outputs.items():
        path = paths[relative]
        if check:
            if not path.is_file() or path.read_bytes() != expected:
                errors.append(f"Generated file is missing or stale: {relative}")
        elif not stale:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(expected)
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)
    try:
        errors = build(args.root, check=args.check)
    except (BuildError, OSError, ValueError) as error:
        # Validation errors carry identifiers, not raw environment or subprocess logs.
        errors = [str(error) if isinstance(error, BuildError) else type(error).__name__]
    for error in errors:
        print(error, file=sys.stderr)
    if not errors:
        print("Contract artifacts are current." if args.check else "Contract artifacts generated.")
    return int(bool(errors))


if __name__ == "__main__":
    raise SystemExit(main())
