"""Strict supported-version bindings for executable reference contract fixtures."""

from pathlib import Path

from jsonschema import Draft202012Validator

from scripts.contracts.build import inside
from scripts.contracts.validate import ID, SEMVER, load_registry
from scripts.security.common import read_json

# Explicit adapters, never arbitrary module names or shell commands from a manifest.
FIXTURES = {
    "status-http": ("openapi", "http", "/api/v1/status", "0.1.0", "content-api"),
    "status-event-v1": ("event", "nats", "reference.status.v1", "1.0.0", "reference-event"),
    "status-event-v2": ("event", "nats", "reference.status.v2", "2.0.0", "reference-event"),
}
FIELDS = ("contract_id", "family", "version", "transport", "locator", "fixture")
SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["schema_version", "bindings"],
    "properties": {
        "schema_version": {"type": "integer", "const": 1},
        "bindings": {
            "type": "array",
            "minItems": 1,
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": list(FIELDS),
                "properties": {
                    "contract_id": {"type": "string", "pattern": ID},
                    "family": {"type": "string", "pattern": ID},
                    "version": {"type": "string", "pattern": "^" + SEMVER + "$"},
                    "transport": {"enum": ["http", "nats"]},
                    "locator": {"type": "string", "minLength": 1},
                    "fixture": {"enum": sorted(FIXTURES)},
                },
            },
        },
    },
}


def load_support(root: Path) -> dict:
    document = read_json(inside(root, "contracts/support.json"))
    errors = list(Draft202012Validator(SCHEMA).iter_errors(document))
    if errors:
        raise ValueError("Support bindings violate their strict schema")
    entries = {entry["id"]: entry for entry in load_registry(root)["contracts"]}
    bindings = document["bindings"]
    ids = [item["contract_id"] for item in bindings]
    if len(set(ids)) != len(ids) or set(ids) != entries.keys():
        raise ValueError("Every registered contract needs exactly one supported binding")
    endpoints = [(item["transport"], item["locator"]) for item in bindings]
    if len(set(endpoints)) != len(endpoints):
        raise ValueError("Supported transport bindings must be unique")
    for item in bindings:
        entry = entries[item["contract_id"]]
        expected = FIXTURES[item["fixture"]]
        if (
            entry["kind"],
            item["transport"],
            item["locator"],
            item["version"],
            item["family"],
        ) != expected:
            raise ValueError("Support binding does not match its implemented fixture")
        if item["version"] != entry["version"]:
            raise ValueError("Support version must exactly match the registry")
        if item["transport"] == "nats" and entry["scope"] != "reference":
            raise ValueError("The reference fixture cannot claim a production event binding")
    return document
