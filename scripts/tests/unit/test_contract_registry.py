"""Offline validation tests; all mutations are confined to pytest temporary roots."""

from __future__ import annotations

import copy
import json
import shutil
from pathlib import Path

import pytest

from scripts.contracts import validate
from scripts.security.common import read_json, write_json

SOURCE_ROOT = Path(__file__).resolve().parents[3]


@pytest.fixture
def root(tmp_path):
    service = tmp_path / "services/content-service"
    service.mkdir(parents=True)
    (service / "pyproject.toml").write_text("[project]\nname='content-service'\n")
    (service / "OWNERS.yaml").write_text(
        'schemaVersion: "1"\nservice:\n  id: content-service\n  owner: backend-team\n',
    )
    (tmp_path / "services/README.md").write_text("Not a service.")
    (tmp_path / "services/empty-folder").mkdir()
    for folder in ("common", "events"):
        shutil.copytree(SOURCE_ROOT / "contracts" / folder, tmp_path / "contracts" / folder)
    registry = read_json(SOURCE_ROOT / "contracts/registry.json")
    write_json(tmp_path / "contracts/registry.json", registry)
    write_json(tmp_path / registry["contracts"][0]["schema_path"], api())
    return tmp_path


def api():
    return {
        "openapi": "3.1.0",
        "info": {"title": "Test API", "version": "0.1.0"},
        "paths": {"/status": {"get": {"responses": {"200": {"description": "OK"}}}}},
    }


def entry(root, index=0):
    return validate.load_registry(root)["contracts"][index]


def metadata(root, **updates):
    registry = validate.load_registry(root)
    registry["contracts"][0].update(updates)
    return validate.validate_registry_metadata(root, registry)


def test_valid_registry_and_cli(root, capsys):
    assert validate.validate_registry(root) == []
    assert validate.main(["--root", str(root)]) == 0
    assert "are valid" in capsys.readouterr().out


def test_bootstrap_document_without_root_file(root):
    declared = entry(root)
    (root / declared["schema_path"]).unlink()
    document = api()
    document["components"] = {"schemas": {"Status": {"type": "string"}}}
    document["paths"]["/status"]["get"]["responses"]["200"]["content"] = {
        "application/json": {"schema": {"$ref": "#/components/schemas/Status"}},
    }
    assert validate.validate_contract_document(declared, document, root) == []
    assert validate.validate_registry(root)


@pytest.mark.parametrize("contents", ['{"contracts":[],"contracts":[]}', "[]", "{", "NaN"])
def test_bad_registry_json(root, contents):
    (root / "contracts/registry.json").write_text(contents)
    assert validate.validate_registry(root)
    assert validate.main(["--root", str(root)]) == 1


def test_missing_registry(root):
    (root / "contracts/registry.json").unlink()
    assert validate.validate_registry(root) == ["Cannot read registry as strict JSON"]


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("id", "bad_name"),
        ("id", ""),
        ("kind", "graphql"),
        ("version", "01.0.0"),
        ("version", "1.0"),
        ("version", "1.0.0-01"),
        ("version", 1),
        ("owner", ""),
        ("producer", "unknown"),
        ("consumers", ["unknown"]),
        ("consumers", ["content-service", "content-service"]),
        ("scope", "unknown"),
        ("lifecycle", "retired"),
        ("extra", "unexpected"),
        ("owner", "other-team"),
        ("schema_path", "/tmp/contracts/openapi/0.1.0/schema.json"),
        ("schema_path", "contracts/../other/0.1.0/schema.json"),
        ("schema_path", "contracts\\openapi\\0.1.0\\schema.json"),
        ("schema_path", "contracts/openapi/0.1.0/schema.yaml"),
        ("schema_path", "contracts/events/0.1.0/schema.json"),
        ("schema_path", "contracts/openapi/1.0.0/schema.json"),
        ("schema_path", "elsewhere/0.1.0/schema.json"),
        ("schema_path", "contracts/openapi/0.1.0/\x00.json"),
    ],
)
def test_invalid_metadata(root, field, value):
    assert metadata(root, **{field: value})


def test_schema_version_bool_and_missing_metadata(root):
    registry = validate.load_registry(root)
    registry["schema_version"] = True
    assert validate.validate_registry_metadata(root, registry)
    registry["schema_version"] = 1
    del registry["contracts"][0]["owner"]
    write_json(root / "contracts/registry.json", registry)
    assert validate.validate_registry(root)


def test_valid_semver_prerelease(root):
    assert (
        metadata(
            root,
            version="1.2.3-alpha.0+build.123",
            schema_path="contracts/openapi/service/1.2.3-alpha.0+build.123/openapi.json",
        )
        == []
    )


def test_version_and_id_trailing_newline_rejected(root):
    assert metadata(root, version="0.1.0\n")
    assert metadata(root, id="content-api\n")


def test_duplicate_ids_and_paths(root):
    registry = validate.load_registry(root)
    registry["contracts"].append(copy.deepcopy(registry["contracts"][0]))
    errors = validate.validate_registry_metadata(root, registry)
    assert "Duplicate contract id" in errors
    assert "Duplicate contract schema_path" in errors


@pytest.mark.parametrize(
    "contents",
    [
        "[]",
        "schemaVersion: 1",
        'schemaVersion: "1"\nservice: []',
        'schemaVersion: "1"\nservice:\n  id: other\n  owner: backend-team',
        'schemaVersion: "1"\nservice:\n  id: content-service\n  owner: " "',
        "!unsafe value",
        "[broken",
    ],
)
def test_invalid_owners(root, contents):
    (root / "services/content-service/OWNERS.yaml").write_text(contents)
    assert metadata(root)


def test_missing_owners(root):
    (root / "services/content-service/OWNERS.yaml").unlink()
    assert metadata(root)


def test_owner_escape(root, tmp_path):
    owner = root / "services/content-service/OWNERS.yaml"
    owner.unlink()
    owner.symlink_to(tmp_path.parent / "outside-owners.yaml")
    assert metadata(root)


def test_contract_symlink_escape(root, tmp_path):
    path = root / entry(root)["schema_path"]
    path.unlink()
    path.symlink_to(tmp_path.parent / "outside.json")
    assert metadata(root)


def test_contract_directory_escape(tmp_path):
    (tmp_path / "contracts").symlink_to(tmp_path.parent)
    assert validate.validate_registry(tmp_path)


@pytest.mark.parametrize(
    "deprecation",
    [
        None,
        {"deprecated_since": "2026-10-01", "sunset_at": "2026-10-01", "replacement": None},
        {"deprecated_since": "2026-10-02", "sunset_at": "2026-10-01", "replacement": None},
        {"deprecated_since": "invalid", "sunset_at": "2026-10-01", "replacement": None},
        {"deprecated_since": "2026-10-01", "sunset_at": "2026-11-01", "replacement": "missing"},
        {"deprecated_since": "2026-10-01", "sunset_at": "2026-11-01", "replacement": "content-api"},
    ],
)
def test_bad_deprecation(root, deprecation):
    assert metadata(root, lifecycle="deprecated", deprecation=deprecation)


def test_valid_deprecation_and_active_rejection(root):
    deprecation = {
        "deprecated_since": "2026-10-01",
        "sunset_at": "2026-11-01",
        "replacement": None,
    }
    assert metadata(root, lifecycle="deprecated", deprecation=deprecation) == []
    assert metadata(root, deprecation=deprecation)
    deprecation["replacement"] = "reference-event"
    assert metadata(root, lifecycle="deprecated", deprecation=deprecation) == []


@pytest.mark.parametrize(
    "reference",
    [
        "https://example.org/schema.json",
        "file:///tmp/schema.json",
        "//example.org/schema.json",
        "../../../../../outside.json",
        "%2fetc%2fpasswd.json",
        "bad\\name.json",
        "foo.json?q=x",
        "foo.yaml",
        "schema%00.json",
        "#/missing",
        "#anchor",
        "#/bad~2escape",
        42,
    ],
)
def test_unsafe_or_missing_refs(root, reference):
    declared = entry(root, 1)
    document = read_json(root / declared["schema_path"])
    document["allOf"][0]["$ref"] = reference
    assert validate.validate_contract_document(declared, document, root)


@pytest.mark.parametrize("key", ["$id", "$dynamicRef", "$recursiveRef"])
def test_rebasing_and_dynamic_refs_rejected(root, key):
    declared = entry(root, 1)
    document = read_json(root / declared["schema_path"])
    document[key] = "https://example.org/schema.json"
    assert validate.validate_contract_document(declared, document, root)


def test_nested_remote_ref_prevents_validation(root, monkeypatch):
    document = api()
    document["components"] = {"schemas": {"Thing": {"$ref": "https://example.org/schema.json"}}}

    def forbidden(*args, **kwargs):
        pytest.fail("OpenAPI validator must never see an unsafe reference")

    monkeypatch.setattr(validate, "OpenAPIV31SpecValidator", forbidden)
    assert validate.validate_contract_document(entry(root), document, root)


def test_ref_symlink_escape_and_duplicate_keys(root, tmp_path):
    declared = entry(root, 1)
    path = root / declared["schema_path"]
    document = read_json(path)
    document["allOf"] = [{"$ref": "other.json"}]
    other = path.with_name("other.json")
    other.symlink_to(tmp_path.parent / "outside.json")
    assert validate.validate_contract_document(declared, document, root)
    other.unlink()
    other.write_text('{"type":"string","type":"integer"}')
    assert validate.validate_contract_document(declared, document, root)
    other.write_text("[]")
    assert validate.validate_contract_document(declared, document, root)


@pytest.mark.parametrize(
    "document",
    [
        [],
        {"openapi": "3.0.3"},
        {"openapi": "3.1.0", "info": {"version": "1.0.0"}},
        {"openapi": "3.1.0", "info": {"version": "0.1.0"}, "paths": {}},
    ],
)
def test_bad_openapi(root, document):
    assert validate.validate_contract_document(entry(root), document, root)


def test_missing_reference_marker_and_dialect(root):
    declared = entry(root, 1)
    document = read_json(root / declared["schema_path"])
    del document["x-reference-only"]
    assert validate.validate_contract_document(declared, document, root)
    document["x-reference-only"] = True
    del document["$schema"]
    assert validate.validate_contract_document(declared, document, root)
    document["$schema"] = validate.DIALECT
    document["properties"]["other"] = {"type": "nonsense"}
    assert validate.validate_contract_document(declared, document, root)


@pytest.mark.parametrize("change", ["version", "source", "required", "type"])
def test_event_registry_envelope_invariants(root, change):
    declared = entry(root, 1)
    document = read_json(root / declared["schema_path"])
    if change in {"version", "source"}:
        document["properties"][change]["const"] = "different"
    elif change == "required":
        document["required"] = []
    else:
        document["type"] = "array"
    assert validate.validate_contract_document(declared, document, root)


def test_moving_event_version_path_requires_schema_update(root):
    declared = entry(root, 1)
    document = read_json(root / declared["schema_path"])
    declared["version"] = "2.0.0"
    declared["schema_path"] = "contracts/events/reference/2.0.0/schema.json"
    assert validate.validate_contract_document(declared, document, root)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("id", "not-a-uuid"),
        ("occurred_at", "2026-99-99T00:00:00Z"),
        ("occurred_at", "2026-10-13T00:00:00+01:00"),
        ("data", {"status": "wrong"}),
        ("type", "deck.created"),
        ("version", "2.0.0"),
        ("source", "unknown-service"),
        ("trace", {"traceparent": "00-" + "0" * 32 + "-00f067aa0ba902b7-01"}),
        ("trace", {"traceparent": "00-4bf92f3577b34da6a3ce929d0e0e4736-" + "0" * 16 + "-01"}),
    ],
)
def test_reference_examples_enforce_actual_constraints(root, field, value):
    declared = entry(root, 1)
    document = read_json(root / declared["schema_path"])
    document["examples"][0][field] = value
    assert validate.validate_contract_document(declared, document, root)


def test_bad_examples_and_shared_schema(root):
    declared = entry(root, 1)
    document = read_json(root / declared["schema_path"])
    document["examples"] = "not-list"
    assert validate.validate_contract_document(declared, document, root)
    shared = root / "contracts/common/1.0.0/pagination.schema.json"
    shared.write_text("[]")
    assert validate.validate_registry(root)


def test_shared_schema_example_validation(root):
    shared = root / "contracts/common/1.0.0/pagination.schema.json"
    schema = read_json(shared)
    schema["examples"] = [{"limit": 0, "next_cursor": None}]
    write_json(shared, schema)
    assert any("Example" in error for error in validate.validate_registry(root))


def test_orphan_schema(root):
    write_json(root / "contracts/events/orphan.json", {"$schema": validate.DIALECT})
    assert any("orphan" in error for error in validate.validate_registry(root))


def test_reachable_components_are_not_orphans(root):
    declared = entry(root, 1)
    path = root / declared["schema_path"]
    document = read_json(path)
    document["allOf"].append({"$ref": "component.json"})
    write_json(path.with_name("component.json"), {"type": "object"})
    write_json(path, document)
    assert validate.validate_registry(root) == []


@pytest.mark.parametrize(
    ("document", "pointer"),
    [
        ({"a/b": {"~": ["value"]}}, "/a~1b/~0/0"),
        ({}, ""),
    ],
)
def test_json_pointer_success(document, pointer):
    assert validate._pointer(document, pointer) is None


@pytest.mark.parametrize("pointer", ["/0", "/1", "/-1", "/01", "/a", "/-", "bad", "/~3"])
def test_json_pointer_failure(pointer):
    with pytest.raises(ValueError):
        validate._pointer([], pointer)


def test_json_pointer_cycles_resolve_without_recursion(root):
    path = root / "contracts/events/cycle.json"
    document = {"$ref": "#"}
    assert validate._documents(root, path, document) == {path: document}


def test_json_loader_rejects_nested_duplicate_keys(root):
    (root / "contracts/registry.json").write_text(
        '{"schema_version":1,"contracts":[{"id":"a","id":"b"}]}',
    )
    with pytest.raises(ValueError, match="Duplicate"):
        validate.load_registry(root)


@pytest.mark.parametrize("value", ["", ".", "./"])
def test_empty_contract_path_rejected(root, value):
    with pytest.raises(ValueError):
        validate._contract_path(root, value)
    assert metadata(root, schema_path=value)


def test_common_schema_duplicate_keys_rejected(root):
    (root / "contracts/common/1.0.0/bad.schema.json").write_text('{"a":1,"a":2}')
    assert validate.validate_registry(root)


def test_schema_examples_never_appear_in_error_text(root):
    declared = entry(root, 1)
    document = read_json(root / declared["schema_path"])
    sentinel = "private-example-content"
    document["examples"][0]["id"] = sentinel
    errors = validate.validate_contract_document(declared, document, root)
    assert errors
    assert sentinel not in json.dumps(errors)
