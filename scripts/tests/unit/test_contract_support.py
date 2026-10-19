"""Supported-version declarations must correspond to actual reference adapters."""

from __future__ import annotations

import copy

import pytest

from scripts.contracts.support import load_support
from scripts.security.common import read_json, write_json


@pytest.fixture
def root(tmp_path):
    entries = [
        {"id": "content-api", "kind": "openapi", "version": "0.1.0", "scope": "internal"},
        {"id": "reference-event", "kind": "event", "version": "1.0.0", "scope": "reference"},
        {"id": "reference-event-v2", "kind": "event", "version": "2.0.0", "scope": "reference"},
    ]
    write_json(tmp_path / "contracts/registry.json", {"schema_version": 1, "contracts": entries})
    bindings = [
        {
            "contract_id": "content-api",
            "family": "content-api",
            "version": "0.1.0",
            "transport": "http",
            "locator": "/api/v1/status",
            "fixture": "status-http",
        },
        {
            "contract_id": "reference-event",
            "family": "reference-event",
            "version": "1.0.0",
            "transport": "nats",
            "locator": "reference.status.v1",
            "fixture": "status-event-v1",
        },
        {
            "contract_id": "reference-event-v2",
            "family": "reference-event",
            "version": "2.0.0",
            "transport": "nats",
            "locator": "reference.status.v2",
            "fixture": "status-event-v2",
        },
    ]
    write_json(tmp_path / "contracts/support.json", {"schema_version": 1, "bindings": bindings})
    return tmp_path


def test_every_registry_entry_has_an_explicit_implemented_binding(root):
    assert len(load_support(root)["bindings"]) == 3


@pytest.mark.parametrize("mutation", ["missing", "duplicate", "unknown", "duplicate_endpoint"])
def test_binding_inventory_rejects_gaps_and_ambiguity(root, mutation):
    document = read_json(root / "contracts/support.json")
    bindings = document["bindings"]
    if mutation == "missing":
        bindings.pop()
    elif mutation == "duplicate":
        bindings.append(copy.deepcopy(bindings[0]))
    elif mutation == "unknown":
        bindings[0]["contract_id"] = "missing"
    else:
        bindings[2]["locator"] = bindings[1]["locator"]
    write_json(root / "contracts/support.json", document)
    with pytest.raises(ValueError):
        load_support(root)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("fixture", "unknown-fixture"),
        ("transport", "kafka"),
        ("version", "1.0"),
        ("family", "bad_name"),
        ("locator", ""),
        ("extra", True),
        ("locator", "/wrong/path"),
        ("fixture", "status-event-v1"),
        ("version", "2.0.0"),
    ],
)
def test_invalid_and_unimplemented_bindings_rejected(root, field, value):
    document = read_json(root / "contracts/support.json")
    document["bindings"][0][field] = value
    write_json(root / "contracts/support.json", document)
    with pytest.raises(ValueError):
        load_support(root)


def test_reference_fixture_must_not_claim_production_events(root):
    document = read_json(root / "contracts/registry.json")
    document["contracts"][1]["scope"] = "internal"
    write_json(root / "contracts/registry.json", document)
    with pytest.raises(ValueError, match="production"):
        load_support(root)


@pytest.mark.parametrize("contents", ['{"bindings":[],"bindings":[]}', "[]", "NaN", "{"])
def test_support_is_strict_json(root, contents):
    (root / "contracts/support.json").write_text(contents)
    with pytest.raises(ValueError):
        load_support(root)


def test_missing_support_is_not_silently_empty(root):
    (root / "contracts/support.json").unlink()
    with pytest.raises(FileNotFoundError):
        load_support(root)


@pytest.mark.parametrize(("field", "value"), [("version", "2.0.0"), ("family", "other-family")])
def test_implemented_fixture_version_and_family_are_fixed(root, field, value):
    document = read_json(root / "contracts/support.json")
    document["bindings"][1][field] = value
    write_json(root / "contracts/support.json", document)
    if field == "version":
        registry = read_json(root / "contracts/registry.json")
        registry["contracts"][1]["version"] = value
        write_json(root / "contracts/registry.json", registry)
    with pytest.raises(ValueError, match="implemented fixture"):
        load_support(root)


def test_support_symlink_escape_rejected(root):
    path = root / "contracts/support.json"
    path.unlink()
    path.symlink_to(root.parent / "outside-support.json")
    with pytest.raises(ValueError, match="symlink"):
        load_support(root)


def test_registered_version_must_match_implemented_binding(root):
    registry = read_json(root / "contracts/registry.json")
    registry["contracts"][0]["version"] = "0.2.0"
    write_json(root / "contracts/registry.json", registry)
    with pytest.raises(ValueError, match="exactly match"):
        load_support(root)
