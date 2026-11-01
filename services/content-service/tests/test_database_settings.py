import pytest
from pydantic import ValidationError
from pytest import MonkeyPatch

from app.core.config import Settings

_SECRET = "FCB61_SECRET_MUST_NOT_APPEAR"
_VALID_DATABASE_URL = f"postgresql+asyncpg://flashcards:{_SECRET}@localhost:5432/flashcards"


def test_database_is_disabled_by_default() -> None:
    settings = Settings(_env_file=None)

    assert settings.database.database_enabled is False
    assert settings.database.database_url is None
    assert settings.database.database_pool_size == 5
    assert settings.database.database_max_overflow == 5
    assert settings.database.database_pool_timeout_seconds == 5.0
    assert settings.database.database_connect_timeout_seconds == 5.0


def test_database_can_be_enabled_with_valid_asyncpg_url() -> None:
    settings = Settings(
        _env_file=None,
        database_enabled=True,
        database_url=_VALID_DATABASE_URL,
    )

    database_url = settings.database.database_url

    assert settings.database.database_enabled is True
    assert database_url is not None
    assert database_url.get_secret_value() == _VALID_DATABASE_URL


def test_enabled_database_requires_url() -> None:
    with pytest.raises(
        ValidationError,
        match="database URL is required when the database is enabled",
    ):
        Settings(
            _env_file=None,
            database_enabled=True,
        )


@pytest.mark.parametrize(
    ("database_url", "expected_message"),
    [
        (
            f"not-a-dsn-{_SECRET}",
            "database URL must be a valid PostgreSQL DSN",
        ),
        (
            f"postgresql://flashcards:{_SECRET}@localhost:5432/flashcards",
            "database URL must use the postgresql\\+asyncpg scheme",
        ),
    ],
)
def test_database_rejects_invalid_or_synchronous_url(
    database_url: str,
    expected_message: str,
) -> None:
    with pytest.raises(ValidationError, match=expected_message) as error:
        Settings(
            _env_file=None,
            database_url=database_url,
        )

    assert _SECRET not in str(error.value)


def test_database_secret_is_hidden_in_settings_representation() -> None:
    settings = Settings(
        _env_file=None,
        database_enabled=True,
        database_url=_VALID_DATABASE_URL,
    )

    assert _SECRET not in repr(settings)
    assert _SECRET not in str(settings)


@pytest.mark.parametrize(
    ("field_name", "field_value"),
    [
        ("database_pool_size", 0),
        ("database_pool_size", 51),
        ("database_max_overflow", -1),
        ("database_max_overflow", 51),
        ("database_pool_timeout_seconds", 0),
        ("database_pool_timeout_seconds", 61),
        ("database_connect_timeout_seconds", 0),
        ("database_connect_timeout_seconds", 61),
    ],
)
def test_database_rejects_pool_values_outside_limits(
    field_name: str,
    field_value: int,
) -> None:
    with pytest.raises(ValidationError):
        Settings(
            _env_file=None,
            **{field_name: field_value},
        )


def test_database_settings_load_from_environment(
    monkeypatch: MonkeyPatch,
) -> None:
    monkeypatch.setenv("APP_DATABASE_ENABLED", "true")
    monkeypatch.setenv("APP_DATABASE_URL", _VALID_DATABASE_URL)
    monkeypatch.setenv("APP_DATABASE_POOL_SIZE", "8")
    monkeypatch.setenv("APP_DATABASE_MAX_OVERFLOW", "3")
    monkeypatch.setenv("APP_DATABASE_POOL_TIMEOUT_SECONDS", "4")
    monkeypatch.setenv("APP_DATABASE_CONNECT_TIMEOUT_SECONDS", "6")

    settings = Settings(_env_file=None)

    assert settings.database.database_enabled is True
    assert settings.database.database_pool_size == 8
    assert settings.database.database_max_overflow == 3
    assert settings.database.database_pool_timeout_seconds == 4.0
    assert settings.database.database_connect_timeout_seconds == 6.0
