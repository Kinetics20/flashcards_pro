import asyncio
import logging

from fastapi import FastAPI
from opentelemetry.exporter.otlp.proto.grpc.metric_exporter import OTLPMetricExporter
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.instrumentation.fastapi import (  # pyright: ignore[reportMissingTypeStubs]
    FastAPIInstrumentor,
)
from opentelemetry.instrumentation.sqlalchemy import (  # pyright: ignore[reportMissingTypeStubs]
    SQLAlchemyInstrumentor,
)
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import MetricReader, PeriodicExportingMetricReader
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor, SpanExporter

from app.core.config import ObservabilitySettings, RuntimeSettings
from app.platform.database import DatabaseRuntime

logger = logging.getLogger(__name__)


_DISABLED_HEADER_CAPTURE_PATTERN = "__flashcards_header_capture_disabled__"
_EXCLUDED_HTTP_URLS = "/health/live,/health/ready"


class TelemetryRuntime:
    """Own OpenTelemetry provides and application instrumentation."""

    def __init__(
        self,
        settings: ObservabilitySettings,
        runtime_settings: RuntimeSettings,
        *,
        span_exporter: SpanExporter | None = None,
        metric_reader: MetricReader | None = None,
    ) -> None:
        self._settings = settings
        self._span_exporter_override = span_exporter
        self._metric_reader_override = metric_reader
        self._resource = Resource.create(
            {
                "service.name": runtime_settings.name,
                "service.version": runtime_settings.version,
                "deployment.environment.name": str(runtime_settings.environment),
            }
        )
        self._tracer_provider: TracerProvider | None = None
        self._meter_provider: MeterProvider | None = None
        self._sqlalchemy_instrumentor: SQLAlchemyInstrumentor | None = None
        self._application: FastAPI | None = None
        self._fastapi_instrumented = False
        self._shutdown_started = False

    @property
    def enabled(self) -> bool:
        """Return whether tracing or metrics export is enabled."""
        return self._settings.telemetry_enabled or self._settings.metrics_enabled

    @property
    def tracer_provider(self) -> TracerProvider | None:
        """Expose the owned tracer provider for instrumentation and tests."""
        return self._tracer_provider

    @property
    def meter_provider(self) -> MeterProvider | None:
        """Expose the owned meter provider for instrumentation and tests."""
        return self._meter_provider

    def instrument(
        self,
        application: FastAPI,
        database: DatabaseRuntime | None,
    ) -> None:
        """Configure exporters and instrument enabled application components."""
        if not self.enabled or self._application is not None:
            return

        try:
            self._create_providers()
            FastAPIInstrumentor.instrument_app(
                application,
                tracer_provider=self._tracer_provider,
                meter_provider=self._meter_provider,
                excluded_urls=_EXCLUDED_HTTP_URLS,
                http_capture_headers_server_request=[_DISABLED_HEADER_CAPTURE_PATTERN],
                http_capture_headers_server_response=[_DISABLED_HEADER_CAPTURE_PATTERN],
                http_capture_headers_sanitize_fields=[
                    "authorization",
                    "cookie",
                    "set-cookie",
                ],
                exclude_spans=["receive", "send"],
            )
            self._application = application
            self._fastapi_instrumented = True

            if database is not None:
                instrumentor = SQLAlchemyInstrumentor()
                instrumentor.instrument(
                    engine=database.engine.sync_engine,
                    tracer_provider=self._tracer_provider,
                    meter_provider=self._meter_provider,
                    enable_commenter=False,
                )
                self._sqlalchemy_instrumentor = instrumentor
        except Exception:
            logger.warning("Telemetry initialization failed; continuing without export")
            self._safe_uninstrument()

    async def shutdown(self) -> None:
        """Stop instrumentation and flush providers within the configured timeout."""
        if self._shutdown_started:
            return
        self._shutdown_started = True

        self._safe_uninstrument()

        if self._tracer_provider is None and self._meter_provider is None:
            return

        try:
            async with asyncio.timeout(self._settings.telemetry_export_timeout_seconds):
                await asyncio.to_thread(self._flush_and_shutdown)
        except TimeoutError:
            logger.warning("Telemetry shutdown timed out")
        except Exception:
            logger.warning("Telemetry shutdown failed")

    def _create_providers(self) -> None:
        endpoint_value = self._settings.telemetry_otlp_endpoint
        if endpoint_value is None:
            raise RuntimeError("OTLP endpoint is required when telemetry export is enabled")

        endpoint = endpoint_value.unicode_string().rstrip("/")
        insecure = endpoint_value.scheme == "http"
        timeout_seconds = self._settings.telemetry_export_timeout_seconds
        timeout_millis = timeout_seconds * 1000

        if self._settings.telemetry_enabled:
            span_exporter = self._span_exporter_override
            if span_exporter is None:
                span_exporter = OTLPSpanExporter(
                    endpoint=endpoint,
                    insecure=insecure,
                    timeout=timeout_seconds,
                )
            tracer_provider = TracerProvider(resource=self._resource)
            tracer_provider.add_span_processor(
                BatchSpanProcessor(
                    span_exporter,
                    export_timeout_millis=timeout_millis,
                )
            )
            self._tracer_provider = tracer_provider

        if self._settings.metrics_enabled:
            metric_reader = self._metric_reader_override
            if metric_reader is None:
                metric_exporter = OTLPMetricExporter(
                    endpoint=endpoint,
                    insecure=insecure,
                    timeout=timeout_seconds,
                )
                metric_reader = PeriodicExportingMetricReader(
                    metric_exporter,
                    export_timeout_millis=timeout_millis,
                )
            self._meter_provider = MeterProvider(
                resource=self._resource,
                metric_readers=(metric_reader,),
            )

    def _safe_uninstrument(self) -> None:
        if self._sqlalchemy_instrumentor is not None:
            try:
                self._sqlalchemy_instrumentor.uninstrument()
            except Exception:
                logger.warning("SQLAlchemy telemetry cleanup failed")
            finally:
                self._sqlalchemy_instrumentor = None

        if self._fastapi_instrumented and self._application is not None:
            try:
                FastAPIInstrumentor.uninstrument_app(self._application)
            except Exception:
                logger.warning("FastAPI telemetry cleanup failed")
            finally:
                self._fastapi_instrumented = False
                self._application = None

    def _flush_and_shutdown(self) -> None:
        timeout_millis = int(self._settings.telemetry_export_timeout_seconds * 1000)
        failures = 0

        if self._tracer_provider is not None:
            try:
                if not self._tracer_provider.force_flush(timeout_millis=timeout_millis):
                    failures += 1
            except Exception:
                failures += 1
            try:
                self._tracer_provider.shutdown()
            except Exception:
                failures += 1

        if self._meter_provider is not None:
            try:
                if not self._meter_provider.force_flush(timeout_millis=timeout_millis):
                    failures += 1
            except Exception:
                failures += 1
            try:
                self._meter_provider.shutdown(timeout_millis=timeout_millis)
            except Exception:
                failures += 1

        if failures:
            raise RuntimeError("one or more telemetry providers failed to shut down")


def create_telemetry_runtime(
    settings: ObservabilitySettings,
    runtime_settings: RuntimeSettings,
) -> TelemetryRuntime:
    """Create the process-owned telemetry runtime."""
    return TelemetryRuntime(settings, runtime_settings)
