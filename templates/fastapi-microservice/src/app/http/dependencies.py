from collections.abc import AsyncGenerator
from typing import Annotated, cast

from fastapi import Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.platform.database import DatabaseRuntime


def settings_from_request(request: Request) -> Settings:
    """Return the validated settings bound to the current application."""
    return cast(Settings, request.app.state.settings)


def database_runtime_from_request(request: Request) -> DatabaseRuntime:
    """Return the configiured database runtime."""
    runtime = getattr(request.app.state, "database", None)

    if not isinstance(runtime, DatabaseRuntime):
        raise RuntimeError("database is not enabled for this service.")
    return runtime


async def database_session(request: Request) -> AsyncGenerator[AsyncSession]:
    runtime = database_runtime_from_request(request)

    async with runtime.session() as session:
        yield session


SettingsDependency = Annotated[Settings, Depends(settings_from_request)]
DatabaseSession = Annotated[Settings, Depends(settings_from_request)]
