from __future__ import annotations

import logging
from time import perf_counter
from typing import TYPE_CHECKING

from app.core.context import get_request_id

if TYPE_CHECKING:
    from starlette.types import ASGIApp, Message, Receive, Scope, Send

logger = logging.getLogger("app.access")


class AccessLogMiddleware:
    """Emit one structured completion record for every HTTP request."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        started_at = perf_counter()
        status_code = 500

        async def capture_status(message: Message) -> None:
            nonlocal status_code
            if message["type"] == "http.response.start":
                status_code = message["status"]
            await send(message)

        try:
            await self.app(scope, receive, capture_status)
        finally:
            route = scope.get("route")
            route_path = getattr(route, "path", None)
            logger.info(
                "HTTP request completed",
                extra={
                    "duration_ms": round((perf_counter() - started_at) * 1000, 3),
                    "http_method": str(scope.get("method", "")),
                    "http_path": str(scope.get("path", "")),
                    "http_route": str(route_path) if route_path is not None else "unmatched",
                    "http_status": status_code,
                    "request_id": get_request_id() or "-",
                },
            )
