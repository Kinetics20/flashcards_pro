import asyncio
import logging
import time
from unittest.mock import Mock

from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from opentelemetry.sdk.metrics.export import InMemoryMetricReader
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from pytest import LogCaptureFixture, MonkeyPatch

import app.platform.telemetry as telemetry_module
from app.core.config import Environment, Settings
from app.platform.database import DatabaseRuntime
from app.platform.telemetry import TelemetryRuntime, create_telemetry_runtime

_DATABASE_URL = "postgresql+asyncpg://flashcards:test-only@localhost:5432/flashcards"
_OTLP_ENDPOINT = "http://localhost:4317"
_SECRET = "FCB61_TELEMETRY_SECRET_MUST_NOT_APPEAR"


def enabled_settings(
    *,
    tracing: bool = True,
    metrics: bool = False,
    timeout_seconds: float = 1.0,
) -> Settings:
    """Return isolated settings for telemetry tests."""
    return Settings(
        _env_file=None,
        environment=Environment.TEST,
        telemetry_enabled=tracing,
        metrics_enabled=metrics,
        telemetry_otlp_endpoint=_OTLP_ENDPOINT,
        telemetry_export_timeout_seconds=timeout_seconds,
    )


async def test_disabled_runtime_is_an_idempotent_noop() -> None:
    settings = Settings(_env_file=None, environment=Environment.TEST)
    runtime = create_telemetry_runtime(settings.observability, settings.runtime)
    application = FastAPI()

    runtime.instrument(application, None)
    runtime.instrument(application, None)
    await runtime.shutdown()
    await runtime.shutdown()

    assert runtime.enabled is False
    assert runtime.tracer_provider is None
    assert runtime.meter_provider is None


async def test_in_memory_providers_instrument_fastapi_without_capturing_secrets() -> None:
    settings = enabled_settings(tracing=True, metrics=True)
    span_exporter = InMemorySpanExporter()
    metric_reader = InMemoryMetricReader()
    runtime = TelemetryRuntime(
        settings.observability,
        settings.runtime,
        span_exporter=span_exporter,
        metric_reader=metric_reader,
    )
    application = FastAPI()

    @application.get("/items")
    async def items() -> dict[str, str]:  # pyright: ignore[reportUnusedFunction]
        return {"status": "ok"}

    @application.get("/health/live")
    async def health() -> dict[str, str]:  # pyright: ignore[reportUnusedFunction]
        return {"status": "ok"}

    runtime.instrument(application, None)
    runtime.instrument(application, None)
    tracer_provider = runtime.tracer_provider
    meter_provider = runtime.meter_provider

    assert tracer_provider is not None
    assert meter_provider is not None
    assert tracer_provider.resource.attributes["service.name"] == settings.runtime.name
    assert tracer_provider.resource.attributes["service.version"] == settings.runtime.version
    assert (
        tracer_provider.resource.attributes["deployment.environment.name"]
        == settings.runtime.environment
    )

    try:
        async with AsyncClient(
            transport=ASGITransport(app=application),
            base_url="http://test",
        ) as client:
            response = await client.get(
                "/items",
                headers={
                    "Authorization": f"Bearer {_SECRET}",
                    "Cookie": f"session={_SECRET}",
                },
            )
            health_response = await client.get("/health/live")
    finally:
        await runtime.shutdown()

    assert response.status_code == 200
    assert health_response.status_code == 200
    spans = span_exporter.get_finished_spans()
    serialized_spans = repr([(span.name, span.attributes) for span in spans])
    assert any("/items" in span.name for span in spans)
    assert all("/health/live" not in span.name for span in spans)
    assert _SECRET not in serialized_spans


async def test_database_instrumentation_and_cleanup_failures_are_safe(
    monkeypatch: MonkeyPatch,
    caplog: LogCaptureFixture,
) -> None:
    settings = enabled_settings()
    database_settings = Settings(
        _env_file=None,
        database_enabled=True,
        database_url=_DATABASE_URL,
    )
    database = DatabaseRuntime(database_settings.database)
    span_exporter = InMemorySpanExporter()
    runtime = TelemetryRuntime(
        settings.observability,
        settings.runtime,
        span_exporter=span_exporter,
    )
    fastapi_instrumentor = Mock()
    sqlalchemy_instrumentor = Mock()
    sqlalchemy_instrumentor.uninstrument.side_effect = RuntimeError(_SECRET)
    fastapi_instrumentor.uninstrument_app.side_effect = RuntimeError(_SECRET)
    sqlalchemy_factory = Mock(return_value=sqlalchemy_instrumentor)
    monkeypatch.setattr(telemetry_module, "FastAPIInstrumentor", fastapi_instrumentor)
    monkeypatch.setattr(telemetry_module, "SQLAlchemyInstrumentor", sqlalchemy_factory)
    caplog.set_level(logging.WARNING, logger="app.platform.telemetry")

    try:
        application = FastAPI()
        runtime.instrument(application, database)
        await runtime.shutdown()
    finally:
        await database.close()

    fastapi_instrumentor.instrument_app.assert_called_once()
    sqlalchemy_factory.assert_called_once_with()
    instrumentation_call = sqlalchemy_instrumentor.instrument.call_args
    assert instrumentation_call.kwargs["engine"] is database.engine.sync_engine
    assert instrumentation_call.kwargs["enable_commenter"] is False
    sqlalchemy_instrumentor.uninstrument.assert_called_once_with()
    fastapi_instrumentor.uninstrument_app.assert_called_once_with(application)
    assert "SQLAlchemy telemetry cleanup failed" in caplog.text
    assert "FastAPI telemetry cleanup failed" in caplog.text
    assert _SECRET not in caplog.text


async def test_exporter_initialization_failure_does_not_stop_application(
    monkeypatch: MonkeyPatch,
    caplog: LogCaptureFixture,
) -> None:
    settings = enabled_settings()
    exporter_factory = Mock(side_effect=RuntimeError(_SECRET))
    monkeypatch.setattr(telemetry_module, "OTLPSpanExporter", exporter_factory)
    caplog.set_level(logging.WARNING, logger="app.platform.telemetry")
    runtime = TelemetryRuntime(settings.observability, settings.runtime)

    runtime.instrument(FastAPI(), None)
    await runtime.shutdown()

    exporter_factory.assert_called_once_with(
        endpoint=_OTLP_ENDPOINT,
        insecure=True,
        timeout=1.0,
    )
    assert runtime.tracer_provider is None
    assert "Telemetry initialization failed; continuing without export" in caplog.text
    assert _SECRET not in caplog.text


async def test_default_metric_exporter_receives_validated_configuration(
    monkeypatch: MonkeyPatch,
) -> None:
    settings = enabled_settings(tracing=False, metrics=True, timeout_seconds=2.0)
    metric_exporter = Mock()
    metric_exporter_factory = Mock(return_value=metric_exporter)
    metric_reader = Mock()
    metric_reader_factory = Mock(return_value=metric_reader)
    meter_provider = Mock()
    meter_provider.force_flush.return_value = True
    meter_provider_factory = Mock(return_value=meter_provider)
    fastapi_instrumentor = Mock()
    monkeypatch.setattr(telemetry_module, "OTLPMetricExporter", metric_exporter_factory)
    monkeypatch.setattr(
        telemetry_module,
        "PeriodicExportingMetricReader",
        metric_reader_factory,
    )
    monkeypatch.setattr(telemetry_module, "MeterProvider", meter_provider_factory)
    monkeypatch.setattr(telemetry_module, "FastAPIInstrumentor", fastapi_instrumentor)
    runtime = TelemetryRuntime(settings.observability, settings.runtime)
    application = FastAPI()

    runtime.instrument(application, None)
    await runtime.shutdown()

    metric_exporter_factory.assert_called_once_with(
        endpoint=_OTLP_ENDPOINT,
        insecure=True,
        timeout=2.0,
    )
    metric_reader_factory.assert_called_once_with(
        metric_exporter,
        export_timeout_millis=2_000.0,
    )
    meter_provider_factory.assert_called_once()
    fastapi_instrumentor.instrument_app.assert_called_once()
    fastapi_instrumentor.uninstrument_app.assert_called_once_with(application)
    meter_provider.force_flush.assert_called_once_with(timeout_millis=2_000)
    meter_provider.shutdown.assert_called_once_with(timeout_millis=2_000)


async def test_provider_shutdown_failures_are_logged_without_details(
    caplog: LogCaptureFixture,
) -> None:
    settings = enabled_settings(tracing=True, metrics=True)
    runtime = TelemetryRuntime(settings.observability, settings.runtime)
    tracer_provider = Mock()
    tracer_provider.force_flush.return_value = False
    tracer_provider.shutdown.side_effect = RuntimeError(_SECRET)
    meter_provider = Mock()
    meter_provider.force_flush.side_effect = RuntimeError(_SECRET)
    meter_provider.shutdown.side_effect = RuntimeError(_SECRET)
    runtime._tracer_provider = tracer_provider  # pyright: ignore[reportPrivateUsage]
    runtime._meter_provider = meter_provider  # pyright: ignore[reportPrivateUsage]
    caplog.set_level(logging.WARNING, logger="app.platform.telemetry")

    await runtime.shutdown()

    tracer_provider.force_flush.assert_called_once_with(timeout_millis=1_000)
    tracer_provider.shutdown.assert_called_once_with()
    meter_provider.force_flush.assert_called_once_with(timeout_millis=1_000)
    meter_provider.shutdown.assert_called_once_with(timeout_millis=1_000)
    assert "Telemetry shutdown failed" in caplog.text
    assert _SECRET not in caplog.text


async def test_telemetry_shutdown_timeout_is_bounded_and_safe(
    monkeypatch: MonkeyPatch,
    caplog: LogCaptureFixture,
) -> None:
    settings = enabled_settings(timeout_seconds=0.001)
    runtime = TelemetryRuntime(settings.observability, settings.runtime)
    runtime._tracer_provider = Mock()  # pyright: ignore[reportPrivateUsage]

    def slow_shutdown() -> None:
        time.sleep(0.02)

    monkeypatch.setattr(runtime, "_flush_and_shutdown", slow_shutdown)
    caplog.set_level(logging.WARNING, logger="app.platform.telemetry")

    await runtime.shutdown()
    await asyncio.sleep(0.03)

    assert "Telemetry shutdown timed out" in caplog.text
