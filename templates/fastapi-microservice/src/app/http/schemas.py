from pydantic import BaseModel, ConfigDict


class ErrorDetail(BaseModel):
    """Stable machine- and human-readable description of an API error."""

    model_config = ConfigDict(extra="forbid")

    code: str
    message: str
    request_id: str | None = None
    details: object | None = None


class ErrorResponse(BaseModel):
    """Envelope returned by global exception handlers."""

    model_config = ConfigDict(extra="forbid")

    error: ErrorDetail
