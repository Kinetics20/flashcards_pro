import asyncio
import logging
from http import HTTPStatus

from fastapi import APIRouter
from fastapi.responses import JSONResponse

from app.http.dependencies import OptionalDatabaseRuntimeDependency
from app.modules.health.schemas import HealthCheck, HealthResponse, HealthStatus

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/health", tags=["health"])

_DATABASE_READINESS_TIMEOUT_SECONDS = 2.0


def _readiness_response(
    *, status: HealthStatus, checks: dict[str, HealthCheck], status_code: HTTPStatus
) -> JSONResponse:
    payload = HealthResponse(status=status, checks=checks)

    return JSONResponse(status_code=status_code, content=payload.model_dump(mode="json"))


@router.get("/live", response_model=HealthResponse, summary="Check process liveness")
async def liveness() -> HealthResponse:
    """Report whether the API process is running."""
    return HealthResponse(
        status=HealthStatus.OK,
        checks={"process": HealthCheck(status=HealthStatus.OK)},
    )


@router.get(
    "/ready",
    response_model=HealthResponse,
    responses={
        HTTPStatus.SERVICE_UNAVAILABLE: {
            "model": HealthResponse,
            "description": "A required dependency is unavailable.",
        }
    },
    summary="Check traffic readiness",
)
async def readiness(database: OptionalDatabaseRuntimeDependency) -> JSONResponse:
    """Report whether required process resources can serve traffic."""

    checks = {"application": HealthCheck(status=HealthStatus.OK)}

    if database is None:
        return _readiness_response(status=HealthStatus.OK, checks=checks, status_code=HTTPStatus.OK)

    try:
        async with asyncio.timeout(_DATABASE_READINESS_TIMEOUT_SECONDS):
            await database.ping()
    except Exception:
        logger.warning("Database readiness check failed", extra={"dependency": "database"})
        checks["database"] = HealthCheck(status=HealthStatus.UNAVAILABLE)
        return _readiness_response(
            status=HealthStatus.UNAVAILABLE,
            checks=checks,
            status_code=HTTPStatus.SERVICE_UNAVAILABLE,
        )

    checks["database"] = HealthCheck(status=HealthStatus.OK)
    return _readiness_response(status=HealthStatus.OK, checks=checks, status_code=HTTPStatus.OK)
