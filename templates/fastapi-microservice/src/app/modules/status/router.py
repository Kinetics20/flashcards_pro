from fastapi import APIRouter

from app.http.dependencies import SettingsDependency
from app.modules.status.schemas import ServiceStatusResponse

router = APIRouter(prefix="/status", tags=["status"])


@router.get("", response_model=ServiceStatusResponse, summary="Get service status")
async def get_status(settings: SettingsDependency) -> ServiceStatusResponse:
    """Return non-secret service identity and availability metadata."""
    return ServiceStatusResponse(
        name=settings.runtime.name,
        version=settings.runtime.version,
        environment=settings.runtime.environment,
    )
