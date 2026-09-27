from typing import Self

from pydantic import AnyHttpUrl, Field, field_validator, model_validator
from pydantic_settings import SettingsConfigDict

from app.core.settings.base import ComponentSettings


class ObservabilitySettings(ComponentSettings):
    """Tracing and metrics export configuration."""

    model_config = SettingsConfigDict(hide_input_in_errors=True)

    telemetry_enabled: bool = False
    metrics_enabled: bool = False
    telemetry_otlp_endpoint: AnyHttpUrl | None = None
    telemetry_export_timeout_seconds: float = Field(default=5.0, gt=0, le=30)

    @field_validator("telemetry_otlp_endpoint")
    @classmethod
    def reject_endpoint_secrets(cls, value: AnyHttpUrl | None) -> AnyHttpUrl | None:
        """Reject endpoint components that could expose secrets or unsupported paths."""
        if value is None:
            return None
        if value.username is not None or value.password is not None:
            raise ValueError("OTLP endpoint must not contain credentials.")
        if value.query is not None or value.fragment is not None:
            raise ValueError("OTLP endpoint must not contain a query or fragment.")
        if value.path not in (None, "", "/"):
            raise ValueError("OTLP gRPC endpoint must not contain a path.")
        return value

    @model_validator(mode="after")
    def require_endpoint_when_export_is_enabled(self) -> Self:
        """Require an OTLP endpoint when exporting telemetry."""

        export_enabled = self.telemetry_enabled or self.metrics_enabled

        if export_enabled and self.telemetry_otlp_endpoint is None:
            raise ValueError("OTLP endpoint is required when telemetry export is enabled.")

        return self
