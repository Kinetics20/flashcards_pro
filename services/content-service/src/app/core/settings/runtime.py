from __future__ import annotations

from typing import Literal, Self

from pydantic import Field, model_validator

from app.core.settings.base import ComponentSettings, Environment


class RuntimeSettings(ComponentSettings):
    """Process identity and runtime settings."""

    name: str = Field(default="FastAPI Microservice", min_length=1, max_length=100)
    version: str = Field(default="0.1.0", pattern=r"^[0-9A-Za-z][0-9A-Za-z.+-]*$")
    environment: Environment = Environment.LOCAL
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"


class HttpSettings(ComponentSettings):
    """HTTP exposure, browser access, and request limits."""

    cors_allowed_origins: list[str] = Field(default_factory=list)
    cors_allow_credentials: bool = False
    docs_enabled: bool = True
    request_body_max_bytes: int = Field(default=1_048_576, ge=1_024, le=104_857_600)

    @model_validator(mode="after")
    def validate_cors(self) -> Self:
        if self.cors_allow_credentials and "*" in self.cors_allowed_origins:
            raise ValueError("wildcard CORS origins cannot be used with credentials")
        return self
