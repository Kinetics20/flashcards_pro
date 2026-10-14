"""Exercise actual reference API responses and generated transport DTOs offline."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest
from pydantic import ValidationError

from scripts.contracts.build import run_command
from scripts.contracts.validate import load_registry, validate_contract_document, validate_registry

ROOT = Path(__file__).resolve().parents[3]
pytestmark = pytest.mark.integration

API_PROBE = """
import contextlib
import json
import sys

sys.path.insert(0, sys.argv[1])
with contextlib.redirect_stdout(sys.stderr):
    from fastapi.testclient import TestClient
    from app.core.config import Settings
    from app.main import create_app
    application = create_app(Settings(_env_file=None, environment="test"))
    with TestClient(application) as client:
        results = {}
        for path in ("/api/v1/status", "/health/live", "/health/ready"):
            response = client.get(path)
            assert response.status_code == 200, (path, response.status_code)
            results[path] = response.json()
print(json.dumps(results))
"""


def load_models(name: str):
    path = ROOT / "contracts/generated/python" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def responses(tmp_path_factory):
    directory = tmp_path_factory.mktemp("contract-http")
    service = ROOT / "services/content-service"
    output = run_command(
        [str(service / ".venv/bin/python"), "-I", "-B", "-c", API_PROBE, str(service / "src")],
        directory,
    )
    return json.loads(output)


def test_registry_matches_committed_sources():
    assert validate_registry(ROOT) == []


@pytest.mark.parametrize("route", ["/api/v1/status", "/health/live", "/health/ready"])
def test_actual_http_payload_round_trips_through_generated_models(responses, route):
    document = json.loads(
        (ROOT / "contracts/openapi/content-service/0.1.0/openapi.json").read_text()
    )
    schema = document["paths"][route]["get"]["responses"]["200"]["content"]["application/json"][
        "schema"
    ]
    name = schema["$ref"].rsplit("/", 1)[1]
    server = getattr(load_models("content_api_server"), name)
    client = getattr(load_models("content_api_client"), name)
    payload = responses[route]
    produced = server.model_validate(payload)
    consumed = client.model_validate_json(produced.model_dump_json())
    assert consumed.model_dump(mode="json") == payload


def test_generated_api_boundary_preserves_required_nullable_and_extra_fields(responses):
    server = load_models("content_api_server")
    client = load_models("content_api_client")
    payload = responses["/api/v1/status"]
    with pytest.raises(ValidationError):
        server.ServiceStatusResponse.model_validate({**payload, "future_field": True})
    assert client.ServiceStatusResponse.model_validate({**payload, "future_field": True}).name
    with pytest.raises(ValidationError):
        client.ServiceStatusResponse.model_validate({"name": "incomplete"})
    with pytest.raises(ValidationError):
        client.ServiceStatusResponse.model_validate({**payload, "environment": "unknown"})
    # Preserve the existing API: request IDs need not be UUIDs; details are not dict-only.
    error = {"error": {"code": "validation_error", "message": "Invalid input", "details": [1, "x"]}}
    produced = server.ErrorResponse.model_validate(error)
    consumed = client.ErrorResponse.model_validate_json(produced.model_dump_json())
    assert consumed.error.request_id is None
    assert consumed.model_dump(mode="json")["error"]["details"] == [1, "x"]


def test_reference_event_round_trip_and_constraints():
    document = json.loads((ROOT / "contracts/events/reference/1.0.0/schema.json").read_text())
    payload = document["examples"][0]
    server = load_models("reference_event_server").ReferenceServiceStatusObserved
    client = load_models("reference_event_client").ReferenceServiceStatusObserved
    produced = server.model_validate(payload)
    wire = produced.model_dump_json(exclude_none=True)
    entry = next(item for item in load_registry(ROOT)["contracts"] if item["kind"] == "event")
    assert (
        validate_contract_document(entry, {**document, "examples": [json.loads(wire)]}, ROOT) == []
    )
    consumed = client.model_validate_json(wire)
    assert consumed.model_dump(mode="json", exclude_none=True) == payload
    assert client.model_validate({**payload, "future_field": "ignored"})
    for invalid in (
        {**payload, "future_field": True},
        {**payload, "id": "not-a-uuid"},
        {**payload, "occurred_at": "not-a-timestamp"},
        {**payload, "version": "9.0.0"},
        {**payload, "source": "unknown-service"},
        {**payload, "data": {"status": "unavailable"}},
    ):
        with pytest.raises(ValidationError):
            server.model_validate(invalid)


@pytest.mark.parametrize("changes", [{"trace": None}, {"occurred_at": "2026-10-13T02:00:00+02:00"}])
def test_canonical_schema_enforces_constraints_beyond_generated_dtos(changes):
    document = json.loads((ROOT / "contracts/events/reference/1.0.0/schema.json").read_text())
    payload = {**document["examples"][0], **changes}
    server = load_models("reference_event_server").ReferenceServiceStatusObserved
    # The code generator cannot preserve every JSON Schema constraint in Pydantic.
    # A future publisher must validate canonical wire JSON, not only instantiate a DTO.
    assert server.model_validate(payload)
    entry = next(item for item in load_registry(ROOT)["contracts"] if item["kind"] == "event")
    assert validate_contract_document(entry, {**document, "examples": [payload]}, ROOT)
