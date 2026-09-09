from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class HealthStatus(StrEnum):
    """Health endpoint states."""

    OK = "ok"
    UNAVAILABLE = "unavailable"


class HealthCheck(BaseModel):
    """Safe status of one process or dependency check."""

    model_config = ConfigDict(extra="forbid")

    status: HealthStatus


class HealthResponse(BaseModel):
    """Response returned by health endpoints."""

    model_config = ConfigDict(extra="forbid")

    status: HealthStatus
    checks: dict[str, HealthCheck] = Field(default_factory=dict)
