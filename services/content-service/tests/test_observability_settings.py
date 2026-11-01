import pytest
from pydantic import ValidationError
from pytest import MonkeyPatch

from app.core.config import Settings

_SECRET = "FCB61_SECRET_MUST_NOT_APPEAR"


def test_observability_is_disabled_by_default() -> None:
    settings = Settings(_env_file=None)

    assert settings.observability.telemetry_enabled is False
    assert settings.observability.metrics_enabled is False
    assert settings.observability.telemetry_otlp_endpoint is None
    assert settings.observability.telemetry_export_timeout_seconds == 5.0


@pytest.mark.parametrize(
    "enabled_field",
    [
        "telemetry_enabled",
        "metrics_enabled",
    ],
)
def test_enabled_telemetry_export_requires_endpoint(
    enabled_field: str,
) -> None:
    with pytest.raises(
        ValidationError,
        match="OTLP endpoint is required when telemetry export is enabled",
    ):
        Settings(
            _env_file=None,
            **{enabled_field: True},
        )


def test_observability_accepts_valid_otlp_endpoint() -> None:
    settings = Settings(
        _env_file=None,
        telemetry_enabled=True,
        metrics_enabled=True,
        telemetry_otlp_endpoint="http://localhost:4317",
        telemetry_export_timeout_seconds=10,
    )

    endpoint = settings.observability.telemetry_otlp_endpoint

    assert settings.observability.telemetry_enabled is True
    assert settings.observability.metrics_enabled is True
    assert endpoint is not None
    assert endpoint.scheme == "http"
    assert endpoint.host == "localhost"
    assert endpoint.port == 4317
    assert settings.observability.telemetry_export_timeout_seconds == 10.0


@pytest.mark.parametrize(
    "timeout",
    [
        0,
        31,
    ],
)
def test_observability_rejects_export_timeout_outside_limits(
    timeout: int,
) -> None:
    with pytest.raises(ValidationError):
        Settings(
            _env_file=None,
            telemetry_export_timeout_seconds=timeout,
        )


def test_invalid_otlp_endpoint_does_not_leak_input() -> None:
    invalid_endpoint = f"not-a-valid-url-{_SECRET}"

    with pytest.raises(ValidationError) as error:
        Settings(
            _env_file=None,
            telemetry_enabled=True,
            telemetry_otlp_endpoint=invalid_endpoint,
        )

    assert _SECRET not in str(error.value)


@pytest.mark.parametrize(
    ("endpoint", "expected_message"),
    [
        (
            f"http://user:{_SECRET}@localhost:4317",
            "OTLP endpoint must not contain credentials",
        ),
        (
            f"http://localhost:4317?token={_SECRET}",
            "OTLP endpoint must not contain a query or fragment",
        ),
        (
            f"http://localhost:4317/#{_SECRET}",
            "OTLP endpoint must not contain a query or fragment",
        ),
        (
            f"http://localhost:4317/v1/{_SECRET}",
            "OTLP gRPC endpoint must not contain a path",
        ),
    ],
)
def test_otlp_endpoint_rejects_unsafe_components_without_leaking_input(
    endpoint: str,
    expected_message: str,
) -> None:
    with pytest.raises(ValidationError, match=expected_message) as error:
        Settings(
            _env_file=None,
            telemetry_enabled=True,
            telemetry_otlp_endpoint=endpoint,
        )

    assert _SECRET not in str(error.value)


def test_observability_settings_load_from_environment(
    monkeypatch: MonkeyPatch,
) -> None:
    monkeypatch.setenv("APP_TELEMETRY_ENABLED", "true")
    monkeypatch.setenv("APP_METRICS_ENABLED", "true")
    monkeypatch.setenv(
        "APP_TELEMETRY_OTLP_ENDPOINT",
        "http://localhost:4317",
    )
    monkeypatch.setenv(
        "APP_TELEMETRY_EXPORT_TIMEOUT_SECONDS",
        "12",
    )

    settings = Settings(_env_file=None)

    assert settings.observability.telemetry_enabled is True
    assert settings.observability.metrics_enabled is True
    assert settings.observability.telemetry_otlp_endpoint is not None
    assert settings.observability.telemetry_export_timeout_seconds == 12.0
