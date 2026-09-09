from __future__ import annotations

import logging
import re
from http import HTTPStatus
from typing import TYPE_CHECKING, TypedDict, cast

from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from app.core.context import get_request_id
from app.core.errors import (
    ApplicationError,
    AuthenticationError,
    AuthorizationError,
    ConflictError,
    DependencyUnavailableError,
    NotFoundError,
)
from app.http.schemas import ErrorDetail, ErrorResponse

if TYPE_CHECKING:
    from fastapi import FastAPI, Request

logger = logging.getLogger(__name__)

_SAFE_VALIDATION_COMPONENT = re.compile(r"[A-Za-z0-9_.-]{1,128}").fullmatch
_SAFE_VALIDATION_TYPE = re.compile(r"[a-z0-9_.-]{1,128}").fullmatch
_VALIDATION_MESSAGES = {
    "extra_forbidden": "Unexpected field",
    "json_invalid": "Request body is not valid JSON",
    "missing": "Field is required",
}


class _PublicValidationDetail(TypedDict):
    """Allowlisted subset of a Pydantic validation error."""

    loc: list[str | int]
    type: str
    msg: str


def _safe_validation_location(value: object) -> list[str | int]:
    if not isinstance(value, (list, tuple)):
        return ["request"]

    location: list[str | int] = []
    for component in cast("list[object] | tuple[object, ...]", value):
        if isinstance(component, bool):
            continue
        if isinstance(component, int) or (
            isinstance(component, str) and _SAFE_VALIDATION_COMPONENT(component) is not None
        ):
            location.append(component)
    return location or ["request"]


def _safe_validation_details(error: RequestValidationError) -> list[_PublicValidationDetail]:
    """Return safe metadata without reflecting request values or validator context."""
    details: list[_PublicValidationDetail] = []
    for validation_error in error.errors():
        raw_type = validation_error.get("type")
        error_type = (
            raw_type
            if isinstance(raw_type, str) and _SAFE_VALIDATION_TYPE(raw_type) is not None
            else "value_error"
        )
        details.append(
            {
                "loc": _safe_validation_location(validation_error.get("loc")),
                "type": error_type,
                "msg": _VALIDATION_MESSAGES.get(error_type, "Invalid value"),
            }
        )
    return details


def _request_id(request: Request) -> str | None:
    value = getattr(request.state, "request_id", None)
    return value if isinstance(value, str) else get_request_id()


def _response(
    *,
    status_code: int,
    code: str,
    message: str,
    request_id: str | None,
    details: object | None = None,
) -> JSONResponse:
    body = ErrorResponse(
        error=ErrorDetail(
            code=code,
            message=message,
            request_id=request_id,
            details=details,
        )
    )
    return JSONResponse(
        status_code=status_code,
        content=jsonable_encoder(body.model_dump(exclude_none=True)),
    )


def _application_error_status(error: ApplicationError) -> HTTPStatus:
    if isinstance(error, NotFoundError):
        return HTTPStatus.NOT_FOUND
    if isinstance(error, ConflictError):
        return HTTPStatus.CONFLICT
    if isinstance(error, AuthenticationError):
        return HTTPStatus.UNAUTHORIZED
    if isinstance(error, AuthorizationError):
        return HTTPStatus.FORBIDDEN
    if isinstance(error, DependencyUnavailableError):
        return HTTPStatus.SERVICE_UNAVAILABLE
    return HTTPStatus.BAD_REQUEST


async def handle_application_error(request: Request, error: Exception) -> JSONResponse:
    """Translate an expected application exception into the public contract."""
    if not isinstance(error, ApplicationError):
        raise TypeError("expected ApplicationError")
    response = _response(
        status_code=_application_error_status(error),
        code=error.code,
        message=error.public_message,
        request_id=_request_id(request),
    )
    if isinstance(error, AuthenticationError):
        response.headers["WWW-Authenticate"] = "Bearer"
        response.headers["Cache-Control"] = "no-store"
    return response


async def handle_validation_error(request: Request, error: Exception) -> JSONResponse:
    """Translate request validation failures without exposing request values."""
    if not isinstance(error, RequestValidationError):
        raise TypeError("expected RequestValidationError")
    return _response(
        status_code=HTTPStatus.UNPROCESSABLE_ENTITY,
        code="validation_error",
        message="Request validation failed",
        request_id=_request_id(request),
        details=_safe_validation_details(error),
    )


async def handle_unexpected_error(request: Request, error: Exception) -> JSONResponse:
    """Log an unexpected exception once and return a safe generic response."""
    request_id = _request_id(request)
    logger.error(
        "Unhandled application error",
        extra={"request_id": request_id or "-"},
        exc_info=(type(error), error, error.__traceback__),
    )
    return _response(
        status_code=HTTPStatus.INTERNAL_SERVER_ERROR,
        code="internal_error",
        message="An unexpected error occurred",
        request_id=request_id,
    )


def register_exception_handlers(application: FastAPI) -> None:
    """Register the API-wide exception-to-HTTP translation policy."""
    application.add_exception_handler(ApplicationError, handle_application_error)
    application.add_exception_handler(RequestValidationError, handle_validation_error)
    application.add_exception_handler(Exception, handle_unexpected_error)
