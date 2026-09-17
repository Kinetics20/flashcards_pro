from typing import Self

from pydantic import AnyHttpUrl, Field, model_validator
from pydantic_settings import SettingsConfigDict

from app.core.settings.base import ComponentSettings


class ObservabilitySettings(ComponentSettings):
    """Tracing and metrics export configuration."""

    model_config = SettingsConfigDict(hide_input_in_errors=True)

    telemetry_enabled: bool = False
    metrics_enabled: bool = False
    telemetry_otlp_endpoint: AnyHttpUrl | None = None
    telemetry_export_timeout_seconds: float = Field(default=5.0, gt=0, le=30)

    @model_validator(mode="after")
    def require_endpoint_when_export_is_enabled(self) -> Self:
        """Require an OTLP endpoint when exporting telemetry."""

        export_enabled = self.telemetry_enabled or self.metrics_enabled

        if export_enabled and self.telemetry_otlp_endpoint is None:
            raise ValueError("OTLP endpoint is required when telemetry export is enabled.")

        return self
