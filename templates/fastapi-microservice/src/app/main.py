import logging
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.core.config import Settings, get_settings
from app.core.logging import configure_logging
from app.http.exception_handlers import register_exception_handlers
from app.http.middleware import register_middleware
from app.http.openapi import stable_operation_id
from app.http.router import root_router
from app.platform.database import DatabaseRuntime, create_database_runtime
from app.platform.telemetry import TelemetryRuntime, create_telemetry_runtime

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(application: FastAPI) -> AsyncGenerator[None]:
    """Validate configuration and manage process-level resources."""
    settings: Settings = application.state.settings
    database: DatabaseRuntime | None = application.state.database
    telemetry: TelemetryRuntime = application.state.telemetry

    try:
        configure_logging(settings.runtime.log_level)

        if database is not None:
            await database.ping()

        logger.info(
            "Application started",
            extra={
                "environment": settings.runtime.environment,
                "service_name": settings.runtime.name,
                "service_version": settings.runtime.version,
            },
        )

        yield
    finally:
        try:
            if database is not None:
                await database.close()
        finally:
            try:
                await telemetry.shutdown()
            finally:
                logger.info("Application stopped")


def create_app(settings: Settings | None = None) -> FastAPI:
    """Create and configure the FastAPI application."""
    resolved = settings or get_settings()
    docs_enabled = resolved.http.docs_enabled
    application = FastAPI(
        title=resolved.runtime.name,
        version=resolved.runtime.version,
        lifespan=lifespan,
        docs_url="/docs" if docs_enabled else None,
        redoc_url="/redoc" if docs_enabled else None,
        openapi_url="/openapi.json" if docs_enabled else None,
        generate_unique_id_function=stable_operation_id,
    )

    database = create_database_runtime(resolved.database)
    telemetry = create_telemetry_runtime(resolved.observability, resolved.runtime)

    application.state.settings = resolved
    application.state.database = database
    application.state.telemetry = telemetry

    register_middleware(application, resolved.http)
    register_exception_handlers(application)

    application.include_router(root_router)

    telemetry.instrument(application, database)
    return application


app = create_app()
