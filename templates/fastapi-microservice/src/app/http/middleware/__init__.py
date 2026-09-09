from fastapi import FastAPI

from app.core.config import HttpSettings
from app.http.middleware.access_log import AccessLogMiddleware
from app.http.middleware.cors import ConfiguredCORSMiddleware
from app.http.middleware.request_context import RequestContextMiddleware
from app.http.middleware.request_limits import RequestLimitsMiddleware


def register_middleware(application: FastAPI, settings: HttpSettings) -> None:
    """Register cross-cutting HTTP behavior in deliberate execution order."""
    # Starlette executes the most recently added middleware first. Request
    # context therefore surrounds access logging, request limits, and CORS.
    application.add_middleware(ConfiguredCORSMiddleware, settings=settings)
    application.add_middleware(RequestLimitsMiddleware, settings=settings)
    application.add_middleware(AccessLogMiddleware)
    application.add_middleware(RequestContextMiddleware)
