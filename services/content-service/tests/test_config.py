from pathlib import Path

import pytest
from pydantic import ValidationError
from pytest import MonkeyPatch

from app.core.config import Environment, HttpSettings, Settings, get_settings


def test_settings_load_flat_environment_contract(monkeypatch: MonkeyPatch) -> None:
    monkeypatch.setenv("APP_NAME", "Billing API")
    monkeypatch.setenv("APP_ENVIRONMENT", "test")
    monkeypatch.setenv("APP_DOCS_ENABLED", "false")
    monkeypatch.setenv("APP_REQUEST_BODY_MAX_BYTES", "2048")

    settings = get_settings()

    assert settings.runtime.name == "Billing API"
    assert settings.runtime.environment is Environment.TEST
    assert settings.http.docs_enabled is False
    assert settings.http.request_body_max_bytes == 2048
    assert get_settings() is settings


def test_settings_reject_unknown_app_environment(monkeypatch: MonkeyPatch) -> None:
    monkeypatch.setenv("APP_LOG_LEVLE", "DEBUG")

    with pytest.raises(ValueError, match="APP_LOG_LEVLE"):
        Settings(_env_file=None)


def test_settings_reject_unknown_app_dotenv(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text("APP_DOCS_ENABELD=true\n", encoding="utf-8")

    with pytest.raises(ValueError, match="APP_DOCS_ENABELD"):
        Settings(_env_file=env_file)


def test_production_requires_disabled_documentation() -> None:
    with pytest.raises(ValidationError, match="documentation must be disabled"):
        Settings(_env_file=None, environment=Environment.PRODUCTION)

    settings = Settings(
        _env_file=None,
        environment=Environment.PRODUCTION,
        docs_enabled=False,
    )
    assert settings.runtime.environment is Environment.PRODUCTION


def test_cors_rejects_wildcard_with_credentials() -> None:
    with pytest.raises(ValidationError, match="wildcard CORS"):
        HttpSettings(
            _env_file=None,  # pyright: ignore[reportCallIssue]
            cors_allowed_origins=["*"],
            cors_allow_credentials=True,
        )


def test_nested_and_flat_settings_cannot_be_combined() -> None:
    with pytest.raises(ValueError, match="nested http"):
        Settings(
            _env_file=None,
            http=HttpSettings(
                _env_file=None,  # pyright: ignore[reportCallIssue]
            ),
            docs_enabled=False,
        )
