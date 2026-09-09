from pydantic import BaseModel, ConfigDict

from app.core.config import Environment


class ServiceStatusResponse(BaseModel):
    """Public service identity and availability."""

    model_config = ConfigDict(extra="forbid")

    name: str
    version: str
    environment: Environment
    status: str = "ok"
