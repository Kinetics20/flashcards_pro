import asyncio
from unittest.mock import create_autospec

from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from pytest import LogCaptureFixture, MonkeyPatch

from app.core.config import Settings
from app.http.dependencies import optional_database_runtime_from_request
from app.main import create_app
from app.modules.health import router as health_router_module
from app.platform.database import DatabaseRuntime

_SECRET = "FCB61_READINESS_SECRET_MUST_NOT_APPEAR"


def application_with_database(
    settings: Settings,
    database: DatabaseRuntime,
) -> FastAPI:
    """Return an application whose readiness dependency uses a test double."""
    application = create_app(settings)
    application.dependency_overrides[optional_database_runtime_from_request] = lambda: database
    return application


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
        "name": "FastAPI Microservice",
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


async def test_liveness_never_pings_database(test_settings: Settings) -> None:
    database = create_autospec(DatabaseRuntime, instance=True)
    application = application_with_database(test_settings, database)

    async with AsyncClient(
        transport=ASGITransport(app=application),
        base_url="http://test",
    ) as client:
        response = await client.get("/health/live")

    assert response.status_code == 200
    database.ping.assert_not_awaited()


async def test_readiness_reports_available_database(test_settings: Settings) -> None:
    database = create_autospec(DatabaseRuntime, instance=True)
    application = application_with_database(test_settings, database)

    async with AsyncClient(
        transport=ASGITransport(app=application),
        base_url="http://test",
    ) as client:
        response = await client.get("/health/ready")

    assert response.status_code == 200
    assert response.json() == {
        "status": "ok",
        "checks": {
            "application": {"status": "ok"},
            "database": {"status": "ok"},
        },
    }
    database.ping.assert_awaited_once_with()


async def test_readiness_reports_unavailable_database_without_leaking_details(
    test_settings: Settings,
    caplog: LogCaptureFixture,
) -> None:
    database = create_autospec(DatabaseRuntime, instance=True)
    database.ping.side_effect = RuntimeError(f"connection failed: {_SECRET}")
    application = application_with_database(test_settings, database)

    async with AsyncClient(
        transport=ASGITransport(app=application),
        base_url="http://test",
    ) as client:
        response = await client.get("/health/ready")

    assert response.status_code == 503
    assert response.json() == {
        "status": "unavailable",
        "checks": {
            "application": {"status": "ok"},
            "database": {"status": "unavailable"},
        },
    }
    assert _SECRET not in response.text
    assert _SECRET not in caplog.text


async def test_readiness_times_out_database_ping(
    test_settings: Settings,
    monkeypatch: MonkeyPatch,
) -> None:
    database = create_autospec(DatabaseRuntime, instance=True)

    async def wait_forever() -> None:
        await asyncio.Event().wait()

    database.ping.side_effect = wait_forever
    application = application_with_database(test_settings, database)
    monkeypatch.setattr(
        health_router_module,
        "_DATABASE_READINESS_TIMEOUT_SECONDS",
        0.001,
    )

    async with AsyncClient(
        transport=ASGITransport(app=application),
        base_url="http://test",
    ) as client:
        response = await client.get("/health/ready")

    assert response.status_code == 503
