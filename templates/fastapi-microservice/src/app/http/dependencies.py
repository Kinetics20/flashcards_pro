from collections.abc import AsyncGenerator
from typing import Annotated, cast

from fastapi import Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.platform.database import DatabaseRuntime


def settings_from_request(request: Request) -> Settings:
    """Return the validated settings bound to the current application."""
    return cast(Settings, request.app.state.settings)


def optional_database_runtime_from_request(request: Request) -> DatabaseRuntime | None:
    """Return the optional database runtime bound to the application."""
    runtime = getattr(request.app.state, "database", None)

    if runtime is not None and not isinstance(runtime, DatabaseRuntime):
        raise RuntimeError("application database runtime is invalid")

    return runtime


def database_runtime_from_request(request: Request) -> DatabaseRuntime:
    """Return the configured database runtime."""
    runtime = optional_database_runtime_from_request(request)

    if runtime is None:
        raise RuntimeError("database is not enabled for this service")

    return runtime


async def database_session(request: Request) -> AsyncGenerator[AsyncSession]:
    """Provide one request-scoped database session."""
    runtime = database_runtime_from_request(request)

    async with runtime.session() as session:
        yield session


SettingsDependency = Annotated[Settings, Depends(settings_from_request)]
OptionalDatabaseRuntimeDependency = Annotated[
    DatabaseRuntime | None,
    Depends(optional_database_runtime_from_request),
]
DatabaseSession = Annotated[AsyncSession, Depends(database_session)]
