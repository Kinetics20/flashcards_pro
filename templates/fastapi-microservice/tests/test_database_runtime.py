import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.platform.database import (
    DatabaseRuntime,
    create_database_runtime,
)

_DATABASE_URL = (
    "postgresql+asyncpg://flashcards:"
    "FCB61_SECRET_MUST_NOT_APPEAR@localhost:5432/flashcards"
)


def test_disabled_database_does_not_create_runtime() -> None:
    settings = Settings(_env_file=None)

    runtime = create_database_runtime(settings.database)

    assert runtime is None


async def test_enabled_database_creates_runtime_without_connecting() -> None:
    settings = Settings(
        _env_file=None,
        database_enabled=True,
        database_url=_DATABASE_URL,
    )

    runtime = create_database_runtime(settings.database)

    assert isinstance(runtime, DatabaseRuntime)
    assert runtime.engine.url.drivername == "postgresql+asyncpg"
    assert "FCB61_SECRET_MUST_NOT_APPEAR" not in str(runtime.engine.url)

    await runtime.close()


async def test_session_context_provides_async_session() -> None:
    settings = Settings(
        _env_file=None,
        database_enabled=True,
        database_url=_DATABASE_URL,
    )
    runtime = create_database_runtime(settings.database)

    assert runtime is not None

    try:
        async with runtime.session() as session:
            assert isinstance(session, AsyncSession)
            assert session.bind is runtime.engine
    finally:
        await runtime.close()


async def test_session_context_propagates_exceptions() -> None:
    settings = Settings(
        _env_file=None,
        database_enabled=True,
        database_url=_DATABASE_URL,
    )
    runtime = create_database_runtime(settings.database)

    assert runtime is not None

    try:
        with pytest.raises(RuntimeError, match="expected failure"):
            async with runtime.session():
                raise RuntimeError("expected failure")
    finally:
        await runtime.close()
