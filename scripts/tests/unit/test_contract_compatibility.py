"""Fail-closed compatibility decisions, exact baseline extraction and offline graphs."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from jsonschema import Draft202012Validator

from scripts.contracts import compatibility as subject
from scripts.contracts.validate import DIALECT
from scripts.security.common import read_json, write_json

COMMIT = "a" * 40


def contract(identifier="reference-event", kind="event", version="1.0.0"):
    directory = "events" if kind == "event" else "openapi"
    return {
        "id": identifier,
        "kind": kind,
        "version": version,
        "owner": "backend-team",
        "producer": "content-service",
        "consumers": [],
        "scope": "reference" if kind == "event" else "internal",
        "schema_path": f"contracts/{directory}/{identifier}/{version}/schema.json",
        "lifecycle": "active",
        "deprecation": None,
    }


def event(version="1.0.0"):
    return {
        "$schema": DIALECT,
        "title": "ReferenceStatus",
        "type": "object",
        "x-reference-only": True,
        "additionalProperties": False,
        "required": ["version", "source", "data"],
        "properties": {
            "version": {"const": version},
            "source": {"const": "content-service"},
            "data": {"type": "object", "properties": {"status": {"type": "string"}}},
        },
        "examples": [{"version": version, "source": "content-service", "data": {"status": "ok"}}],
    }


def make_tree(root: Path, *, with_api: bool = False):
    service = root / "services/content-service"
    service.mkdir(parents=True)
    (service / "pyproject.toml").write_text("[project]\nname='content-service'\n")
    (service / "OWNERS.yaml").write_text(
        'schemaVersion: "1"\nservice:\n  id: content-service\n  owner: backend-team\n',
    )
    entries = [contract()]
    bindings = [
        {
            "contract_id": "reference-event",
            "family": "reference-event",
            "version": "1.0.0",
            "transport": "nats",
            "locator": "reference.status.v1",
            "fixture": "status-event-v1",
        }
    ]
    write_json(root / entries[0]["schema_path"], event())
    if with_api:
        entry = contract("content-api", "openapi", "0.1.0")
        entries.append(entry)
        write_json(
            root / entry["schema_path"],
            {
                "openapi": "3.1.0",
                "info": {"title": "Test", "version": "0.1.0"},
                "paths": {"/api/v1/status": {"get": {"responses": {"200": {"description": "OK"}}}}},
            },
        )
        bindings.append(
            {
                "contract_id": "content-api",
                "family": "content-api",
                "version": "0.1.0",
                "transport": "http",
                "locator": "/api/v1/status",
                "fixture": "status-http",
            }
        )
    write_json(root / "contracts/registry.json", {"schema_version": 1, "contracts": entries})
    write_json(root / "contracts/support.json", {"schema_version": 1, "bindings": bindings})
    return root


@pytest.fixture
def trees(tmp_path):
    return make_tree(tmp_path / "candidate"), make_tree(tmp_path / "baseline")


def change_event(root, update):
    entry = read_json(root / "contracts/registry.json")["contracts"][0]
    schema = read_json(root / entry["schema_path"])
    update(schema)
    write_json(root / entry["schema_path"], schema)


def test_identical_and_annotation_only_changes(trees):
    root, baseline = trees
    assert subject.compare(root, baseline)["status"] == "ok"
    change_event(root, lambda schema: schema.update(description="New prose"))
    assert subject.compare(root, baseline)["status"] == "ok"


def test_required_property_removed_is_blocking(trees):
    root, baseline = trees
    change_event(root, lambda schema: schema["properties"]["data"]["properties"].clear())
    report = subject.compare(root, baseline)
    assert report["status"] == "error"
    assert not report["comparisons"][0]["compatible"]


def test_optional_property_addition_for_additive_reader(trees):
    root, baseline = trees
    change_event(root, lambda schema: schema["properties"].update(extra={"type": "string"}))
    assert subject.compare(root, baseline)["status"] == "ok"


@pytest.mark.parametrize("name", ["title", "description", "examples", "$comment"])
def test_annotation_named_properties_are_not_discarded(trees, name):
    root, baseline = trees
    for tree in trees:
        change_event(tree, lambda schema: schema["properties"].update({name: {"type": "string"}}))
    change_event(root, lambda schema: schema["properties"][name].update(type="integer"))
    assert subject.compare(root, baseline)["status"] == "error"


@pytest.mark.parametrize("keyword", ["const", "enum"])
def test_annotation_named_object_data_is_not_discarded(trees, keyword):
    root, baseline = trees
    for tree in trees:

        def initial(schema):
            value = {"description": "old"}
            schema["properties"]["data"] = {keyword: value if keyword == "const" else [value]}
            schema["examples"] = []

        change_event(tree, initial)

    def update(schema):
        value = schema["properties"]["data"][keyword]
        (value if keyword == "const" else value[0])["description"] = "new"

    change_event(root, update)
    assert subject.compare(root, baseline)["status"] == "error"


def test_schema_valued_extra_fields_make_additions_unsafe():
    old = {"type": "object", "properties": {}, "additionalProperties": {"type": "integer"}}
    new = {**old, "properties": {"extra": {"type": "string"}}}
    assert Draft202012Validator(new).is_valid({"extra": "value"})
    assert not Draft202012Validator(old).is_valid({"extra": "value"})
    assert subject.event_changes(old, new)


@pytest.mark.parametrize(
    ("old", "new"),
    [
        ({"const": True}, {"const": 1}),
        ({"enum": [False]}, {"enum": [0]}),
        ({"const": {"description": [True]}}, {"const": {"description": [1]}}),
        ({"enum": [1]}, {"enum": [1.0]}),
        ({"enum": [1]}, {"enum": [1, 2]}),
    ],
)
def test_json_value_kind_changes_are_not_hidden_by_python_equality(old, new):
    assert subject.event_changes(old, new)


@pytest.mark.parametrize(
    ("old", "new"),
    [
        ({"type": "string"}, {"type": "integer"}),
        ({"type": "string"}, {"type": "string", "minLength": 1}),
        (True, False),
        ({"properties": {"a": {}}}, {"properties": {}}),
        ({"properties": {}, "required": ["a"]}, {"properties": {"a": {}}, "required": ["a"]}),
        ({"properties": {}, "if": {}}, {"properties": {"a": {}}, "if": {}}),
        ({"items": {"type": "string"}}, {"items": {"type": "integer"}}),
        ({"allOf": [{"type": "string"}]}, {"allOf": [{"type": "integer"}]}),
        ({"allOf": [{}]}, {"allOf": [{}, {}]}),
        ({"properties": {"a": {"type": "string"}}}, {"properties": {"a": {"type": "number"}}}),
    ],
)
def test_changed_or_unproven_constraints_fail_closed(old, new):
    assert subject.event_changes(old, new)


def test_shared_ref_expansion_and_siblings(tmp_path):
    entry = contract()
    source = tmp_path / entry["schema_path"]
    write_json(source, {"$ref": "shared.json#/$defs/value", "maxLength": 10})
    write_json(source.with_name("shared.json"), {"$defs": {"value": {"type": "string"}}})
    assert subject.expanded(tmp_path, entry) == {
        "allOf": [{"type": "string"}, {"maxLength": 10}],
    }


def test_expansion_walks_schema_maps_arrays_values_and_keeps_data(tmp_path):
    entry = contract()
    source = tmp_path / entry["schema_path"]
    write_json(
        source,
        {
            "$defs": {"description": {"title": "Annotation", "type": "string"}},
            "allOf": [True, {"items": {"$ref": "#/$defs/description"}}],
            "const": {"description": "Data"},
        },
    )
    result = subject.expanded(tmp_path, entry)
    assert result["$defs"]["description"] == {"type": "string"}
    assert result["allOf"] == [True, {"items": {"type": "string"}}]
    assert result["const"] == {"description": "Data"}


def test_ref_pointer_list_and_cycle(tmp_path):
    entry = contract()
    source = tmp_path / entry["schema_path"]
    write_json(source, {"allOf": [{"type": "string"}], "$ref": "#/allOf/0"})
    assert subject.expanded(tmp_path, entry)
    write_json(source, {"$ref": "#"})
    with pytest.raises(ValueError, match="Recursive"):
        subject.expanded(tmp_path, entry)


def test_invalid_baseline_and_candidate(trees):
    root, baseline = trees
    (baseline / "contracts/registry.json").write_text("{}")
    with pytest.raises(ValueError, match="baseline"):
        subject.compare(root, baseline)
    (baseline / "contracts/registry.json").write_bytes(
        (root / "contracts/registry.json").read_bytes()
    )
    (root / "contracts/registry.json").write_text("{}")
    with pytest.raises(ValueError, match="candidate"):
        subject.compare(root, baseline)


def test_bootstrap_requires_registry_not_support_sidecar(trees):
    root, baseline = trees
    (baseline / "contracts/support.json").unlink()
    assert subject.compare(root, baseline)["status"] == "ok"
    (baseline / "contracts/registry.json").unlink()
    with pytest.raises(ValueError, match="baseline"):
        subject.compare(root, baseline)


def test_removed_contract_is_blocking(tmp_path):
    root = make_tree(tmp_path / "candidate", with_api=True)
    baseline = make_tree(tmp_path / "baseline", with_api=True)
    registry = read_json(root / "contracts/registry.json")
    removed = registry["contracts"].pop()
    write_json(root / "contracts/registry.json", registry)
    (root / removed["schema_path"]).unlink()
    support = read_json(root / "contracts/support.json")
    support["bindings"].pop()
    write_json(root / "contracts/support.json", support)
    assert any("removed" in error for error in subject.compare(root, baseline)["errors"])


def test_changed_version_in_place_is_blocking(trees):
    root, baseline = trees
    registry = read_json(root / "contracts/registry.json")
    previous_path = root / registry["contracts"][0]["schema_path"]
    registry["contracts"][0] = contract(version="2.0.0")
    write_json(root / "contracts/registry.json", registry)
    previous_path.unlink()
    write_json(root / registry["contracts"][0]["schema_path"], event("2.0.0"))
    support = read_json(root / "contracts/support.json")
    support["bindings"][0].update(
        version="2.0.0", fixture="status-event-v2", locator="reference.status.v2"
    )
    write_json(root / "contracts/support.json", support)
    assert any(
        "keep the old binding" in error for error in subject.compare(root, baseline)["errors"]
    )


def test_changed_supported_binding_is_blocking(trees, monkeypatch):
    root, baseline = trees
    support = read_json(root / "contracts/support.json")
    support["bindings"][0]["family"] = "renamed-family"
    original = subject.load_support
    monkeypatch.setattr(
        subject, "load_support", lambda path: support if path == root else original(path)
    )
    assert any("supported binding" in error for error in subject.compare(root, baseline)["errors"])


def test_parallel_major_version_preserves_old_binding(trees):
    root, baseline = trees
    registry = read_json(root / "contracts/registry.json")
    new = contract("reference-event-v2", version="2.0.0")
    registry["contracts"].append(new)
    write_json(root / "contracts/registry.json", registry)
    write_json(root / new["schema_path"], event("2.0.0"))
    support = read_json(root / "contracts/support.json")
    support["bindings"].append(
        {
            "contract_id": new["id"],
            "family": "reference-event",
            "version": "2.0.0",
            "transport": "nats",
            "locator": "reference.status.v2",
            "fixture": "status-event-v2",
        }
    )
    write_json(root / "contracts/support.json", support)
    result = subject.compare(root, baseline)
    assert result["status"] == "ok"
    assert result["required_bindings"] == ["reference-event", "reference-event-v2"]


def test_parallel_same_major_is_rejected(trees, monkeypatch):
    root, baseline = trees
    registry = read_json(root / "contracts/registry.json")
    new = contract("reference-event-v2", version="1.1.0")
    registry["contracts"].append(new)
    write_json(root / "contracts/registry.json", registry)
    write_json(root / new["schema_path"], event("1.1.0"))
    current_support = read_json(root / "contracts/support.json")
    current_support["bindings"].append(
        {
            "contract_id": new["id"],
            "family": "reference-event",
            "version": "1.1.0",
            "transport": "nats",
            "locator": "reference.status.v2",
            "fixture": "status-event-v2",
        }
    )
    original = subject.load_support
    monkeypatch.setattr(
        subject, "load_support", lambda path: current_support if path == root else original(path)
    )
    assert any("new major" in error for error in subject.compare(root, baseline)["errors"])


@pytest.mark.parametrize(("exit_code", "expected"), [(0, "ok"), (1, "error")])
def test_openapi_diff_invocation(tmp_path, monkeypatch, exit_code, expected):
    root = make_tree(tmp_path / "candidate", with_api=True)
    baseline = make_tree(tmp_path / "baseline", with_api=True)
    calls = []
    monkeypatch.setattr(subject, "verified_tool", lambda *args, **kwargs: ("oasdiff", "1"))

    def runner(command, *args, **kwargs):
        calls.append(command)
        return SimpleNamespace(stdout="[]", returncode=exit_code)

    monkeypatch.setattr(subject, "run", runner)
    assert subject.compare(root, baseline)["status"] == expected
    assert "--allow-external-refs=false" in calls[0]
    assert calls[0][-2:] == [
        str(baseline / contract("content-api", "openapi", "0.1.0")["schema_path"]),
        str(root / contract("content-api", "openapi", "0.1.0")["schema_path"]),
    ]


@pytest.mark.parametrize("stdout", ["{}", "invalid json"])
def test_unexpected_oasdiff_output_rejected(tmp_path, monkeypatch, stdout):
    root = make_tree(tmp_path / "candidate", with_api=True)
    baseline = make_tree(tmp_path / "baseline", with_api=True)
    monkeypatch.setattr(subject, "verified_tool", lambda *args, **kwargs: ("oasdiff", "1"))
    monkeypatch.setattr(
        subject, "run", lambda *args, **kwargs: SimpleNamespace(stdout=stdout, returncode=0)
    )
    with pytest.raises(ValueError):
        subject.compare(root, baseline)


@pytest.mark.parametrize(
    "finding",
    [
        None,
        {},
        {"id": "valid", "level": True},
        {"id": "valid", "level": 4},
        {"id": "bad id", "level": 3},
        {"id": 1, "level": 3},
        {"id": "valid", "level": 3, "path": []},
        {"id": "valid", "level": 3, "operationId": "x" * 2049},
    ],
)
def test_oasdiff_finding_shape_is_fail_closed(finding):
    with pytest.raises(ValueError):
        subject.oasdiff_findings(json.dumps([finding]))


@pytest.mark.parametrize("stdout", ["", "[] trailing", '[{"id":"a","id":"b","level":3}]', "[NaN]"])
def test_oasdiff_json_must_be_complete_and_unambiguous(stdout):
    with pytest.raises(ValueError):
        subject.oasdiff_findings(stdout)


def test_oasdiff_report_preserves_safe_coordinates_not_spec_text(tmp_path, monkeypatch):
    root = make_tree(tmp_path / "candidate", with_api=True)
    baseline = make_tree(tmp_path / "baseline", with_api=True)
    finding = {
        "id": "api-path-removed-without-deprecation",
        "level": 3,
        "operation": "GET",
        "operationId": "get_api_v1_status",
        "path": "/api/v1/status",
        "section": "paths",
        "fingerprint": "096c5823a743",
        "text": "DO_NOT_COPY_SPEC_TEXT",
        "baseSource": {"file": "DO_NOT_COPY_SOURCE"},
    }
    monkeypatch.setattr(subject, "verified_tool", lambda *args, **kwargs: ("oasdiff", "1"))
    monkeypatch.setattr(
        subject,
        "run",
        lambda *args, **kwargs: SimpleNamespace(stdout=json.dumps([finding]), returncode=0),
    )
    report = subject.compare(root, baseline)
    assert report["status"] == "error"  # Findings still block if an exit code is inconsistent.
    recorded = report["comparisons"][1]["findings"][0]
    assert recorded["id"] == finding["id"] and recorded["path"] == finding["path"]
    assert "text" not in recorded and "baseSource" not in recorded
    assert "DO_NOT_COPY" not in json.dumps(report)


def test_informational_oasdiff_finding_does_not_block(tmp_path, monkeypatch):
    root = make_tree(tmp_path / "candidate", with_api=True)
    baseline = make_tree(tmp_path / "baseline", with_api=True)
    monkeypatch.setattr(subject, "verified_tool", lambda *args, **kwargs: ("oasdiff", "1"))
    monkeypatch.setattr(
        subject,
        "run",
        lambda *args, **kwargs: SimpleNamespace(
            stdout='[{"id":"info-change","level":1}]', returncode=0
        ),
    )
    assert subject.compare(root, baseline)["status"] == "ok"


def test_openapi_external_local_ref_rejected_before_scanner(tmp_path, monkeypatch):
    root = make_tree(tmp_path / "candidate", with_api=True)
    baseline = make_tree(tmp_path / "baseline", with_api=True)
    entry = contract("content-api", "openapi", "0.1.0")
    path = root / entry["schema_path"]
    doc = read_json(path)
    doc["paths"]["/api/v1/status"]["get"]["responses"]["200"] = {"$ref": "response.json"}
    write_json(path, doc)
    write_json(path.with_name("response.json"), {"description": "OK"})
    monkeypatch.setattr(subject, "verified_tool", lambda *args, **kwargs: ("oasdiff", "1"))
    with pytest.raises(ValueError, match="offline bundler"):
        subject.compare(root, baseline)


def test_git_wrapper_success_error_and_timeout(tmp_path, monkeypatch):
    monkeypatch.setattr(
        subject.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout=b"data"),
    )
    assert subject.git(tmp_path, "show") == b"data"
    monkeypatch.setattr(
        subject.subprocess, "run", lambda *args, **kwargs: SimpleNamespace(returncode=1)
    )
    with pytest.raises(ValueError, match="exact Git"):
        subject.git(tmp_path, "show")


def tree_git(records, *, resolved=COMMIT, content=b"{}"):
    def fake(root, command, *arguments):
        if command == "rev-parse":
            return resolved.encode()
        if command == "ls-tree":
            return records
        assert command == "cat-file"
        return content

    return fake


def test_baseline_extracts_only_selected_regular_blobs(tmp_path, monkeypatch):
    records = b"\0".join(
        [
            b"100644 blob abc\tcontracts/registry.json",
            b"100644 blob abc\tcontracts/generated/data.json",
            b"100644 blob abc\tservices/content-service/OWNERS.yaml",
            b"100644 blob abc\tservices/content-service/pyproject.toml",
            b"100644 blob abc\tservices/content-service/src/main.py",
            b"100644 blob abc\tcontracts/README.md",
            b"",
        ]
    )
    monkeypatch.setattr(subject, "git", tree_git(records))
    destination = tmp_path / "output"
    subject.baseline_tree(tmp_path, COMMIT, destination)
    assert (destination / "contracts/registry.json").read_text() == "{}"
    assert (destination / "services/content-service/OWNERS.yaml").exists()
    assert not (destination / "contracts/generated").exists()
    assert not (destination / "services/content-service/src").exists()


@pytest.mark.parametrize("commit", ["main", "a" * 39, "A" * 40, "a" * 40 + "\n"])
def test_baseline_requires_exact_commit_sha(tmp_path, commit):
    with pytest.raises(ValueError, match="40-character"):
        subject.baseline_tree(tmp_path, commit, tmp_path / "output")


def test_baseline_commit_mismatch_symlink_and_size_limit(tmp_path, monkeypatch):
    monkeypatch.setattr(subject, "git", tree_git(b"", resolved="b" * 40))
    with pytest.raises(ValueError, match="exact commit"):
        subject.baseline_tree(tmp_path, COMMIT, tmp_path / "output")
    monkeypatch.setattr(subject, "git", tree_git(b"120000 blob abc\tcontracts/registry.json\0"))
    with pytest.raises(ValueError, match="regular files"):
        subject.baseline_tree(tmp_path, COMMIT, tmp_path / "output")
    monkeypatch.setattr(
        subject,
        "git",
        tree_git(b"100644 blob abc\tcontracts/registry.json\0", content=b"x" * 8_000_001),
    )
    with pytest.raises(ValueError, match="safety limit"):
        subject.baseline_tree(tmp_path, COMMIT, tmp_path / "output")


def test_cli_success_and_failure(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(subject, "baseline_tree", lambda *args: None)
    monkeypatch.setattr(subject, "compare", lambda *args, **kwargs: {"status": "ok", "errors": []})
    output = tmp_path / "reports/result.json"
    assert subject.main(["--root", str(tmp_path), "--base", COMMIT, "--output", str(output)]) == 0
    assert read_json(output)["base_commit"] == COMMIT
    assert json.loads(capsys.readouterr().out)["status"] == "ok"

    def invalid(*args, **kwargs):
        raise ValueError("Invalid baseline")

    monkeypatch.setattr(subject, "compare", invalid)
    assert subject.main(["--root", str(tmp_path), "--base", COMMIT]) == 1
    assert json.loads(capsys.readouterr().out)["status"] == "error"
