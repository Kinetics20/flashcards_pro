"""Deterministic generation, isolation, safe failure and read-only drift checks."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts.contracts import build as module


def save(path: Path, value: dict | str | bytes = b"") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(value, dict):
        value = module.json_bytes(value)
    if isinstance(value, str):
        value = value.encode()
    path.write_bytes(value)
    return path


@pytest.fixture
def entry():
    return {
        "id": "example-api",
        "kind": "openapi",
        "version": "1.0.0",
        "owner": "platform",
        "producer": "example-service",
        "consumers": [],
        "scope": "public",
        "schema_path": "contracts/openapi/example/1.0.0/openapi.json",
        "lifecycle": "active",
        "deprecation": None,
    }


def stub_build(monkeypatch, entry):
    monkeypatch.setattr(module, "load_registry", lambda root: {"contracts": [entry]})
    monkeypatch.setattr(module, "validate_registry_metadata", lambda *args: [])
    monkeypatch.setattr(module, "validate_contract_document", lambda *args: [])
    monkeypatch.setattr(module, "validate_staged_registry", lambda *args: None)
    monkeypatch.setattr(module, "run_command", lambda *args: module.CODEGEN_VERSION)
    monkeypatch.setattr(module, "export_openapi", lambda *args: {"info": {"version": "1.0.0"}})
    monkeypatch.setattr(module, "generate_models", lambda *args: b"types\n")


def test_json_is_deterministic_and_rejects_nan():
    assert module.json_bytes({"z": "ą", "a": 1}) == module.json_bytes({"a": 1, "z": "ą"})
    assert module.json_bytes({}).endswith(b"\n")
    with pytest.raises(ValueError):
        module.json_bytes({"bad": float("nan")})


def test_subprocess_environment_does_not_inherit_settings_or_hooks(tmp_path, monkeypatch):
    monkeypatch.setenv("APP_DATABASE_URL", "do-not-leak")
    monkeypatch.setenv("PYTHONPATH", "untrusted")
    observed = {}

    def run(command, **kwargs):
        observed.update(kwargs)
        return SimpleNamespace(returncode=0, stdout="safe result")

    monkeypatch.setattr(module.subprocess, "run", run)
    assert module.run_command(["python"], tmp_path) == "safe result"
    assert observed["cwd"] == tmp_path
    assert observed["timeout"] == 120
    assert observed["capture_output"] is True
    assert not {"APP_DATABASE_URL", "PYTHONPATH", "HOME"} & observed["env"].keys()


@pytest.mark.parametrize("failure", [OSError("do-not-leak"), subprocess.TimeoutExpired("x", 1)])
def test_subprocess_operational_failures_are_safe(tmp_path, monkeypatch, failure):
    def fail(*args, **kwargs):
        raise failure

    monkeypatch.setattr(module.subprocess, "run", fail)
    with pytest.raises(module.BuildError, match="could not complete") as error:
        module.run_command(["x"], tmp_path)
    assert "do-not-leak" not in str(error.value)


def test_subprocess_exit_failure_never_echoes_output(tmp_path, monkeypatch):
    monkeypatch.setattr(
        module.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=1,
            stdout="secret stdout",
            stderr="secret stderr",
        ),
    )
    with pytest.raises(module.BuildError, match="subprocess failed") as error:
        module.run_command(["x"], tmp_path)
    assert "secret" not in str(error.value)


@pytest.mark.parametrize("relative", ["/outside", "../outside", ".", "a/../../outside"])
def test_inside_rejects_unsafe_paths(tmp_path, relative):
    with pytest.raises(module.BuildError):
        module.inside(tmp_path, relative)


def test_inside_rejects_symlink_component(tmp_path):
    (tmp_path / "link").symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(module.BuildError, match="symlinks"):
        module.inside(tmp_path, "link/file")
    assert module.inside(tmp_path, "valid/file") == tmp_path / "valid/file"


def create_service(root):
    save(root / "services/example-service/.venv/bin/python")
    save(root / "services/example-service/src/app/main.py")


def test_export_runs_real_factory_without_lifespan_or_dotenv(tmp_path, monkeypatch, entry):
    create_service(tmp_path)
    commands = []

    def run(command, directory):
        commands.append(command)
        return '{"info":{"version":"1.0.0"},"paths":{}}'

    monkeypatch.setattr(module, "run_command", run)
    result = module.export_openapi(tmp_path, entry, tmp_path / "isolated")
    assert commands[0][1:3] == ["-I", "-B"]
    assert commands[0][-1] == "1.0.0"
    assert "_env_file=None" in module.EXPORT_SCRIPT
    assert "application.openapi()" in module.EXPORT_SCRIPT
    assert "lifespan" not in module.EXPORT_SCRIPT
    assert result["info"]["x-contract"]["owner"] == "platform"


@pytest.mark.parametrize("payload", ["broken", "[]", "{}", '{"info":null}'])
def test_export_rejects_invalid_output(tmp_path, monkeypatch, entry, payload):
    create_service(tmp_path)
    monkeypatch.setattr(module, "run_command", lambda *args: payload)
    with pytest.raises(module.BuildError):
        module.export_openapi(tmp_path, entry, tmp_path)


def test_export_requires_safe_existing_service(tmp_path, entry):
    with pytest.raises(module.BuildError, match="sync the service"):
        module.export_openapi(tmp_path, entry, tmp_path)
    entry["producer"] = "../outside"
    with pytest.raises(module.BuildError, match="service folder"):
        module.export_openapi(tmp_path, entry, tmp_path)


def test_copy_schema_inputs_excludes_generated_and_preserves_refs(tmp_path):
    root = tmp_path / "repository"
    save(root / "contracts/common/value.json", {"type": "string"})
    save(root / "contracts/generated/old.json", {})
    staged = tmp_path / "staged"
    module.copy_schema_inputs(root, staged)
    assert (staged / "contracts/common/value.json").is_file()
    assert not (staged / "contracts/generated/old.json").exists()


def test_codegen_staging_rewrites_external_refs_and_preserves_cycles(tmp_path, entry):
    root = tmp_path / "repo"
    path = "contracts/common/shared.json"
    save(
        root / path, {"type": "object", "$ref": "shared.json", "$defs": {"id": {"type": "string"}}}
    )
    directory = tmp_path / "generation"
    directory.mkdir()
    document = {
        "allOf": [{"$ref": "../../../common/shared.json#/$defs/id"}, {"$ref": "#/local"}],
        "local": {},
    }
    output = module.stage_codegen_schema(root, entry, document, directory)
    result = json.loads(output.read_text())
    reference = result["allOf"][0]["$ref"]
    assert "/" not in reference.split("#")[0]
    assert reference.endswith("#/$defs/id")
    assert (directory / reference.split("#")[0]).is_file()
    assert len(list(directory.glob("*.json"))) == 2
    assert result["allOf"][1]["$ref"] == "#/local"
    assert document["allOf"][0]["$ref"].startswith("../")


@pytest.mark.parametrize(
    "reference",
    [
        "https://example.invalid/schema",
        "//host/path",
        "local.json?query",
        "../../../../secret.json",
    ],
)
def test_codegen_staging_rejects_remote_and_escaping_refs(tmp_path, entry, reference):
    with pytest.raises(module.BuildError):
        module.stage_codegen_schema(tmp_path, entry, {"$ref": reference}, tmp_path)


def test_staged_validation_includes_sources_owners_and_fresh_export(tmp_path, monkeypatch):
    root, stage = tmp_path / "repo", tmp_path / "staged"
    save(root / "contracts/registry.json", {"schema_version": 1})
    save(root / "contracts/common/value.json", {})
    save(root / "services/example-service/pyproject.toml", "[project]\n")
    save(root / "services/example-service/OWNERS.yaml", "owner: example\n")
    exported = {"contracts/openapi/new.json": {"info": {"version": "1.0.0"}}}

    def validate(directory):
        assert directory == stage
        assert (stage / "services/example-service/OWNERS.yaml").is_file()
        assert (
            json.loads((stage / "contracts/openapi/new.json").read_text())
            == exported["contracts/openapi/new.json"]
        )
        return []

    monkeypatch.setattr(module, "validate_registry", validate)
    module.validate_staged_registry(root, exported, stage)
    monkeypatch.setattr(module, "validate_registry", lambda *args: ["orphan"])
    with pytest.raises(module.BuildError, match="orphan"):
        module.validate_staged_registry(root, exported, stage)


@pytest.mark.parametrize("profile,extra", [("server", "forbid"), ("client", "ignore")])
@pytest.mark.parametrize("kind,input_type", [("openapi", "openapi"), ("event", "jsonschema")])
def test_generated_models_use_locked_offline_profiles(
    tmp_path, monkeypatch, entry, profile, extra, kind, input_type
):
    entry["kind"] = kind
    commands = []

    def run(command, directory):
        commands.append(command)
        save(directory / "models.py", "from pydantic import BaseModel\n")
        return ""

    monkeypatch.setattr(module, "run_command", run)
    result = module.generate_models(tmp_path, entry, {}, tmp_path / "stage", profile)
    command = commands[0]
    assert command[command.index("--extra-fields") + 1] == extra
    assert command[command.index("--input-file-type") + 1] == input_type
    assert "--disable-timestamp" in command
    assert "--no-allow-remote-refs" in command
    assert "--ignore-pyproject" in command
    assert b"Transport DTOs only" in result
    assert module.CODEGEN_VERSION.encode() in result


def test_codegen_rejects_unknown_profile(tmp_path, entry):
    with pytest.raises(module.BuildError, match="Unknown"):
        module.generate_models(tmp_path, entry, {}, tmp_path, "unsafe")


@pytest.mark.parametrize("output", [None, "def broken syntax"])
def test_codegen_rejects_missing_or_invalid_output(tmp_path, monkeypatch, entry, output):
    def run(command, directory):
        if output is not None:
            save(directory / "models.py", output)
        return ""

    monkeypatch.setattr(module, "run_command", run)
    with pytest.raises(module.BuildError):
        module.generate_models(tmp_path, entry, {}, tmp_path / "stage", "server")


def test_html_is_offline_escaped_and_exposes_metadata(entry):
    entry["owner"] = "<script>bad</script>"
    entry["consumers"] = ["consumer-service"]
    entry["lifecycle"] = "deprecated"
    entry["deprecation"] = {"sunset_at": "2027-01-01"}
    document = {
        "paths": {
            "/status": {"get": {"summary": "<b>summary</b>"}, "parameters": []},
            "/health": {"get": {"operationId": "health"}},
        }
    }
    result = module.render_contract(entry, document).decode()
    assert "<script>" not in result
    assert "&lt;script&gt;" in result
    assert "&lt;b&gt;summary&lt;/b&gt;" in result
    assert "consumer-service" in result
    assert "2027-01-01" in result
    assert "Content-Security-Policy" in result
    assert "<td>GET</td>" in result
    assert "<td>health</td>" in result
    assert "cdn" not in result
    entry["scope"], entry["kind"] = "reference", "event"
    assert b"No production publisher" in module.render_contract(entry, {})
    index = module.render_index([entry]).decode()
    assert 'href="example-api.html"' in index
    assert "&lt;script&gt;" in index


def test_build_outputs_contains_all_profiles_and_docs(tmp_path, monkeypatch, entry):
    stub_build(monkeypatch, entry)
    outputs = module.build_outputs(tmp_path, tmp_path)
    assert set(outputs) == {
        entry["schema_path"],
        "contracts/generated/python/example_api_server.py",
        "contracts/generated/python/example_api_client.py",
        "contracts/generated/docs/example-api.html",
        "contracts/generated/python/__init__.py",
        "contracts/generated/docs/index.html",
    }


def test_build_outputs_reads_event_source_without_overwriting_it(tmp_path, monkeypatch, entry):
    entry.update(
        kind="event", scope="reference", schema_path="contracts/events/reference/1.0.0/schema.json"
    )
    save(tmp_path / entry["schema_path"], {"type": "object"})
    stub_build(monkeypatch, entry)
    outputs = module.build_outputs(tmp_path, tmp_path)
    assert entry["schema_path"] not in outputs
    save(tmp_path / entry["schema_path"], '{"duplicate":1,"duplicate":2}')
    with pytest.raises(ValueError):
        module.build_outputs(tmp_path, tmp_path)


@pytest.mark.parametrize(
    "mode,match",
    [
        ("metadata", "Registry validation"),
        ("version", "Expected datamodel"),
        ("document", "contract validation"),
        ("collision", "collide"),
    ],
)
def test_build_outputs_fails_closed(tmp_path, monkeypatch, entry, mode, match):
    stub_build(monkeypatch, entry)
    if mode == "metadata":
        monkeypatch.setattr(module, "validate_registry_metadata", lambda *args: ["invalid owner"])
    elif mode == "version":
        monkeypatch.setattr(module, "run_command", lambda *args: "0.1.0")
    elif mode == "document":
        monkeypatch.setattr(module, "validate_contract_document", lambda *args: ["invalid schema"])
    else:
        monkeypatch.setattr(module, "load_registry", lambda *args: {"contracts": [entry, entry]})
    with pytest.raises(module.BuildError, match=match):
        module.build_outputs(tmp_path, tmp_path)


def test_build_check_is_read_only_and_rejects_drift(tmp_path, monkeypatch):
    outputs = {"contracts/generated/python/one.py": b"new\n", "contracts/openapi/api.json": b"{}\n"}
    monkeypatch.setattr(module, "build_outputs", lambda *args: outputs)
    assert len(module.build(tmp_path, check=True)) == 2
    assert not (tmp_path / "contracts").exists()
    assert module.build(tmp_path) == []
    assert module.build(tmp_path, check=True) == []
    save(tmp_path / "contracts/generated/python/one.py", b"edited\n")
    assert len(module.build(tmp_path, check=True)) == 1
    assert (tmp_path / "contracts/generated/python/one.py").read_bytes() == b"edited\n"
    save(tmp_path / "contracts/generated/extra.txt", b"keep\n")
    assert any("Unexpected generated file" in error for error in module.build(tmp_path))
    assert (tmp_path / "contracts/generated/python/one.py").read_bytes() == b"edited\n"
    assert (tmp_path / "contracts/generated/extra.txt").read_bytes() == b"keep\n"


def test_output_symlink_fails_before_any_write(tmp_path, monkeypatch):
    outputs = {"contracts/generated/first.py": b"new", "contracts/generated/second.py": b"new"}
    monkeypatch.setattr(module, "build_outputs", lambda *args: outputs)
    save(tmp_path / "contracts/generated/first.py", b"keep")
    (tmp_path / "contracts/generated/second.py").symlink_to(tmp_path / "other.py")
    with pytest.raises(module.BuildError, match="symlinks"):
        module.build(tmp_path)
    assert (tmp_path / "contracts/generated/first.py").read_bytes() == b"keep"


def test_managed_files_ignores_bytecode(tmp_path):
    save(tmp_path / "contracts/generated/__pycache__/module.pyc")
    save(tmp_path / "contracts/generated/module.py")
    save(tmp_path / "unmanaged.txt")
    assert module.managed_files(tmp_path) == {"contracts/generated/module.py"}


@pytest.mark.parametrize("check", [True, False])
def test_main_reports_success(monkeypatch, capsys, check):
    monkeypatch.setattr(module, "build", lambda *args, **kwargs: [])
    assert module.main(["--root", ".", *(["--check"] if check else [])]) == 0
    assert "Contract artifacts" in capsys.readouterr().out


@pytest.mark.parametrize(
    "error", [module.BuildError("safe failure"), OSError("secret path"), ValueError("secret input")]
)
def test_main_reports_safe_failures(monkeypatch, capsys, error):
    def fail(*args, **kwargs):
        raise error

    monkeypatch.setattr(module, "build", fail)
    assert module.main([]) == 1
    assert "secret" not in capsys.readouterr().err


def test_main_reports_detected_drift(monkeypatch, capsys):
    monkeypatch.setattr(module, "build", lambda *args, **kwargs: ["stale output"])
    assert module.main(["--check"]) == 1
    assert "stale output" in capsys.readouterr().err
