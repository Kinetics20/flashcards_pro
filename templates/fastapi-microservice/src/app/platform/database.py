from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from sqlalchemy import text
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.core.config import DatabaseSettings


class DatabaseRuntime:
    """Own the database engine and session factory for one process."""

    def __init__(self, settings: DatabaseSettings) -> None:
        if not settings.database_enabled:
            raise ValueError("database runtime cannot be created when persistence is disabled.")

        database_url = settings.database_url
        if database_url is None:
            raise ValueError("database URL is required.")

        self.engine: AsyncEngine = create_async_engine(
            database_url.get_secret_value(),
            pool_pre_ping=True,
            pool_size=settings.database_pool_size,
            max_overflow=settings.database_max_overflow,
            pool_timeout=settings.database_pool_timeout_seconds,
            connect_args={"timeout": settings.database_connect_timeout_seconds},
        )

        self._session_factory: async_sessionmaker[AsyncSession] = async_sessionmaker(
            bind=self.engine, class_=AsyncSession, expire_on_commit=False, autoflush=False
        )

    async def ping(self) -> None:
        """Verify that PostgreSQL accepts queries."""
        async with self.engine.connect() as connection:
            await connection.execute(text("SELECT 1"))

    @asynccontextmanager
    async def session(self) -> AsyncGenerator[AsyncSession]:
        """Provide one session and roll it back after an exception."""
        async with self._session_factory() as session:
            try:
                yield session
            except BaseException:
                await session.rollback()
                raise

    async def close(self) -> None:
        """Close all pooled database connections."""
        await self.engine.dispose()


def create_database_runtime(settings: DatabaseSettings) -> DatabaseRuntime | None:
    """Create a database runtime only when persistance is enabled."""
    if not settings.database_enabled:
        return None

    return DatabaseRuntime(settings)
