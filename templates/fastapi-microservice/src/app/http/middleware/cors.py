from __future__ import annotations

from typing import TYPE_CHECKING

from fastapi.middleware.cors import CORSMiddleware

from app.core.config import HttpSettings

if TYPE_CHECKING:
    from starlette.types import ASGIApp, Receive, Scope, Send


class ConfiguredCORSMiddleware:
    """Apply CORS only when origins are explicitly configured."""

    def __init__(self, app: ASGIApp, *, settings: HttpSettings) -> None:
        if settings.cors_allowed_origins:
            self.app = CORSMiddleware(
                app,
                allow_origins=settings.cors_allowed_origins,
                allow_credentials=settings.cors_allow_credentials,
                allow_methods=["*"],
                allow_headers=["*"],
            )
        else:
            self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        await self.app(scope, receive, send)
