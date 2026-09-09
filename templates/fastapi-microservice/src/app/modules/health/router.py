from fastapi import APIRouter

from app.modules.health.schemas import HealthCheck, HealthResponse, HealthStatus

router = APIRouter(prefix="/health", tags=["health"])


@router.get("/live", response_model=HealthResponse, summary="Check process liveness")
async def liveness() -> HealthResponse:
    """Report whether the API process is running."""
    return HealthResponse(
        status=HealthStatus.OK,
        checks={"process": HealthCheck(status=HealthStatus.OK)},
    )


@router.get("/ready", response_model=HealthResponse, summary="Check traffic readiness")
async def readiness() -> HealthResponse:
    """Report whether configured resources can serve traffic.

    Add required dependency checks here when the service gains a database or
    another startup-critical resource. Transient downstream services should
    normally be reported separately and should not remove a replica from load.
    """
    return HealthResponse(
        status=HealthStatus.OK,
        checks={"application": HealthCheck(status=HealthStatus.OK)},
    )
