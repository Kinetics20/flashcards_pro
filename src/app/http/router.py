from fastapi import APIRouter

from app.http.schemas import ErrorResponse
from app.modules.health.router import router as health_router
from app.modules.status.router import router as status_router

root_router = APIRouter()
versioned_router = APIRouter(
    prefix="/api/v1",
    responses={
        400: {"model": ErrorResponse, "description": "The request cannot be completed."},
        401: {"model": ErrorResponse, "description": "Authentication failed."},
        403: {"model": ErrorResponse, "description": "The operation is not permitted."},
        422: {"model": ErrorResponse, "description": "Request validation failed."},
        503: {"model": ErrorResponse, "description": "A dependency is unavailable."},
    },
)

# Process probes stay outside the versioned public API contract.
root_router.include_router(health_router)
versioned_router.include_router(status_router)
root_router.include_router(versioned_router)
