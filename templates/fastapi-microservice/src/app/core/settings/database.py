from typing import Self

from pydantic import (
    Field,
    PostgresDsn,
    SecretStr,
    TypeAdapter,
    ValidationError,
    field_validator,
    model_validator,
)
from pydantic_settings import SettingsConfigDict

from app.core.settings.base import ComponentSettings

_POSTGRES_DSN_ADAPTER: TypeAdapter[PostgresDsn] = TypeAdapter(PostgresDsn)
_ASYNC_POSTGRES_SCHEME = "postgresql+asyncpg"


class DatabaseSettings(ComponentSettings):
    """Optional PostgreSQL runtime configuration."""

    model_config = SettingsConfigDict(hide_input_in_errors=True)

    database_enabled: bool = False
    database_url: SecretStr | None = None
    database_pool_size: int = Field(default=5, ge=1, le=50)
    database_max_overflow: int = Field(default=5, ge=0, le=50)
    database_pool_timeout_seconds: float = Field(default=5.0, gt=0, le=60)
    database_connect_timeout_seconds: float = Field(default=5.0, gt=0, le=60)

    @field_validator("database_url")
    @classmethod
    def validate_database_url(cls, value: SecretStr | None) -> SecretStr | None:
        """Require a valid PostgreSQL DNS using the asyncpg driver."""

        if value is None:
            return None

        try:
            dsn = _POSTGRES_DSN_ADAPTER.validate_python(value.get_secret_value())
        except ValidationError:
            raise ValueError("database URL must be a valid PostgreSQL DSN.") from None

        if dsn.scheme != _ASYNC_POSTGRES_SCHEME:
            raise ValueError("database URL must use the postgresql+asyncpg scheme.")

        return value

    @model_validator(mode="after")
    def require_url_when_enabled(self) -> Self:
        """Require a database URL when persistance is enabled"""
        if self.database_enabled and self.database_url is None:
            raise ValueError("database URL is required when the database is enabled.")

        return self
