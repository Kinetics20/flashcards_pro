from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from app.core.config import Settings
from app.main import create_app


async def test_health_and_status_contracts(test_settings: Settings) -> None:
    application = create_app(test_settings)

    async with AsyncClient(
        transport=ASGITransport(app=application),
        base_url="http://test",
    ) as client:
        live = await client.get("/health/live")
        ready = await client.get("/health/ready")
        service_status = await client.get("/api/v1/status")

    assert live.status_code == 200
    assert live.json() == {"status": "ok", "checks": {"process": {"status": "ok"}}}
    assert ready.status_code == 200
    assert ready.json() == {
        "status": "ok",
        "checks": {"application": {"status": "ok"}},
    }
    assert service_status.json() == {
        "name": "Flashcards Content Service",
        "version": "0.1.0",
        "environment": "test",
        "status": "ok",
    }


def test_openapi_has_stable_operation_ids(test_settings: Settings) -> None:
    application = create_app(test_settings)
    schema = application.openapi()

    assert schema["paths"]["/health/live"]["get"]["operationId"] == "get_health_live"
    assert schema["paths"]["/api/v1/status"]["get"]["operationId"] == "get_api_v1_status"


def test_settings_are_available_as_application_state(test_settings: Settings) -> None:
    application: FastAPI = create_app(test_settings)

    assert application.state.settings is test_settings
