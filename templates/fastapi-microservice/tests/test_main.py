from unittest.mock import Mock, create_autospec

import pytest
from pytest import MonkeyPatch

from app import main
from app.core.config import Environment, Settings
from app.platform.database import DatabaseRuntime
from app.platform.telemetry import TelemetryRuntime

_DATABASE_URL = "postgresql+asyncpg://flashcards:test-only@localhost:5432/flashcards"


def test_application_factory_configures_identity_and_documentation() -> None:
    hidden_settings = Settings(
        _env_file=None,
        name="Orders API",
        version="2.3.4",
        environment=Environment.TEST,
        docs_enabled=False,
    )
    exposed_settings = Settings(
        _env_file=None,
        environment=Environment.TEST,
        docs_enabled=True,
    )

    hidden = main.create_app(hidden_settings)
    exposed = main.create_app(exposed_settings)

    assert hidden.title == "Orders API"
    assert hidden.version == "2.3.4"
    assert hidden.docs_url is None
    assert hidden.redoc_url is None
    assert hidden.openapi_url is None
    assert exposed.docs_url == "/docs"
    assert exposed.redoc_url == "/redoc"
    assert exposed.openapi_url == "/openapi.json"
    assert hidden.state.database is None
    assert exposed.state.database is None


async def test_lifespan_configures_logging_and_reports_lifecycle(
    test_settings: Settings,
    monkeypatch: MonkeyPatch,
) -> None:
    configure_logging = Mock()
    info = Mock()
    app = main.create_app(test_settings)
    monkeypatch.setattr(main, "configure_logging", configure_logging)
    monkeypatch.setattr(main.logger, "info", info)

    async with main.lifespan(app):
        configure_logging.assert_called_once_with("INFO")

    assert info.call_count == 2
    assert info.call_args_list[0].args == ("Application started",)
    assert info.call_args_list[1].args == ("Application stopped",)


def test_application_factory_binds_enabled_database_runtime(
    monkeypatch: MonkeyPatch,
) -> None:
    settings = Settings(
        _env_file=None,
        environment=Environment.TEST,
        database_enabled=True,
        database_url=_DATABASE_URL,
    )
    database = create_autospec(DatabaseRuntime, instance=True)
    create_runtime = Mock(return_value=database)
    monkeypatch.setattr(main, "create_database_runtime", create_runtime)

    application = main.create_app(settings)

    create_runtime.assert_called_once_with(settings.database)
    assert application.state.database is database


def test_application_factory_binds_and_instruments_telemetry(
    test_settings: Settings,
    monkeypatch: MonkeyPatch,
) -> None:
    telemetry = create_autospec(TelemetryRuntime, instance=True)
    create_runtime = Mock(return_value=telemetry)
    monkeypatch.setattr(main, "create_telemetry_runtime", create_runtime)

    application = main.create_app(test_settings)

    create_runtime.assert_called_once_with(
        test_settings.observability,
        test_settings.runtime,
    )
    assert application.state.telemetry is telemetry
    telemetry.instrument.assert_called_once_with(application, None)


async def test_lifespan_pings_and_closes_enabled_database(
    test_settings: Settings,
) -> None:
    application = main.create_app(test_settings)
    database = create_autospec(DatabaseRuntime, instance=True)
    telemetry = create_autospec(TelemetryRuntime, instance=True)
    application.state.database = database
    application.state.telemetry = telemetry

    async with main.lifespan(application):
        database.ping.assert_awaited_once_with()
        database.close.assert_not_awaited()

    database.close.assert_awaited_once_with()
    telemetry.shutdown.assert_awaited_once_with()


async def test_lifespan_closes_database_after_startup_failure(
    test_settings: Settings,
) -> None:
    application = main.create_app(test_settings)
    database = create_autospec(DatabaseRuntime, instance=True)
    telemetry = create_autospec(TelemetryRuntime, instance=True)
    database.ping.side_effect = RuntimeError("database startup failed")
    application.state.database = database
    application.state.telemetry = telemetry

    with pytest.raises(RuntimeError, match="database startup failed"):
        async with main.lifespan(application):
            pytest.fail("lifespan yielded despite failed database startup")

    database.ping.assert_awaited_once_with()
    database.close.assert_awaited_once_with()
    telemetry.shutdown.assert_awaited_once_with()
