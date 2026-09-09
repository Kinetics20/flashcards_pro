from __future__ import annotations

import json
import logging
from collections.abc import AsyncIterator

from fastapi import Request
from httpx import ASGITransport, AsyncClient
from pydantic import BaseModel, ConfigDict
from pytest import LogCaptureFixture

from app.core.config import HttpSettings, Settings
from app.core.context import get_request_id, reset_request_id, set_request_id
from app.core.errors import AuthenticationError, NotFoundError
from app.core.http import outbound_correlation_headers
from app.core.logging import RequestContextFilter
from app.main import create_app


class Payload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str


async def test_request_id_is_preserved_or_safely_replaced(test_settings: Settings) -> None:
    application = create_app(test_settings)

    async with AsyncClient(
        transport=ASGITransport(app=application),
        base_url="http://test",
    ) as client:
        preserved = await client.get("/health/live", headers={"X-Request-ID": "request-123"})
        replaced = await client.get("/health/live", headers={"X-Request-ID": "unsafe value"})

    assert preserved.headers["X-Request-ID"] == "request-123"
    assert replaced.headers["X-Request-ID"] != "unsafe value"
    assert len(replaced.headers["X-Request-ID"]) == 36


async def test_expected_and_validation_errors_use_safe_envelope(
    test_settings: Settings,
) -> None:
    application = create_app(test_settings)

    async def missing() -> None:
        raise NotFoundError("Widget does not exist")

    async def secured() -> None:
        raise AuthenticationError

    async def accept_payload(payload: Payload) -> Payload:
        return payload

    application.add_api_route("/missing", missing, methods=["GET"])
    application.add_api_route("/secured", secured, methods=["GET"])
    application.add_api_route("/payload", accept_payload, methods=["POST"])

    async with AsyncClient(
        transport=ASGITransport(app=application),
        base_url="http://test",
    ) as client:
        not_found = await client.get("/missing", headers={"X-Request-ID": "trace-1"})
        unauthorized = await client.get("/secured")
        invalid = await client.post(
            "/payload",
            json={"unexpected": "must-not-be-reflected"},
        )

    assert not_found.status_code == 404
    assert not_found.json()["error"] == {
        "code": "not_found",
        "message": "Widget does not exist",
        "request_id": "trace-1",
    }
    assert unauthorized.status_code == 401
    assert unauthorized.headers["WWW-Authenticate"] == "Bearer"
    assert unauthorized.headers["Cache-Control"] == "no-store"
    assert invalid.status_code == 422
    assert invalid.json()["error"]["details"] == [
        {"loc": ["body", "name"], "type": "missing", "msg": "Field is required"},
        {
            "loc": ["body", "unexpected"],
            "type": "extra_forbidden",
            "msg": "Unexpected field",
        },
    ]
    assert "must-not-be-reflected" not in invalid.text


async def test_unexpected_errors_are_hidden_and_logged(
    test_settings: Settings,
    caplog: LogCaptureFixture,
) -> None:
    application = create_app(test_settings)

    async def broken() -> None:
        raise RuntimeError("private implementation detail")

    application.add_api_route("/broken", broken, methods=["GET"])
    caplog.set_level(logging.ERROR)

    async with AsyncClient(
        transport=ASGITransport(app=application, raise_app_exceptions=False),
        base_url="http://test",
    ) as client:
        response = await client.get("/broken", headers={"X-Request-ID": "failure-1"})

    assert response.status_code == 500
    assert response.json()["error"] == {
        "code": "internal_error",
        "message": "An unexpected error occurred",
        "request_id": "failure-1",
    }
    assert "private implementation detail" not in response.text
    assert "Unhandled application error" in caplog.text


async def test_content_length_and_streamed_bodies_are_limited() -> None:
    settings = Settings(
        _env_file=None,
        environment="test",
        request_body_max_bytes=1_024,
    )
    application = create_app(settings)

    async def echo(request: Request) -> dict[str, int]:
        return {"size": len(await request.body())}

    application.add_api_route("/echo", echo, methods=["POST"])

    async def streamed_body() -> AsyncIterator[bytes]:
        yield b"x" * 800
        yield b"y" * 800

    async with AsyncClient(
        transport=ASGITransport(app=application),
        base_url="http://test",
    ) as client:
        declared = await client.post("/echo", content=b"x" * 1_025)
        streamed = await client.post("/echo", content=streamed_body())

    for response in (declared, streamed):
        assert response.status_code == 413
        assert response.json()["error"]["code"] == "request_too_large"
        assert response.json()["error"]["details"] == {"max_bytes": 1_024}


async def test_configured_cors_adds_response_headers() -> None:
    settings = Settings(
        _env_file=None,
        environment="test",
        http=HttpSettings(
            _env_file=None,  # pyright: ignore[reportCallIssue]
            docs_enabled=True,
            cors_allowed_origins=["https://client.example"],
        ),
    )
    application = create_app(settings)

    async with AsyncClient(
        transport=ASGITransport(app=application),
        base_url="http://test",
    ) as client:
        response = await client.get(
            "/health/live",
            headers={"Origin": "https://client.example"},
        )

    assert response.headers["Access-Control-Allow-Origin"] == "https://client.example"


def test_outbound_headers_and_log_filter_follow_request_context() -> None:
    record = logging.LogRecord("test", logging.INFO, __file__, 1, "message", (), None)
    request_filter = RequestContextFilter()
    assert get_request_id() is None
    assert outbound_correlation_headers() == {}
    assert request_filter.filter(record) is True
    assert record.request_id == "-"  # type: ignore[attr-defined]

    token = set_request_id("outbound-1")
    try:
        assert outbound_correlation_headers() == {"X-Request-ID": "outbound-1"}
        correlated = logging.LogRecord(
            "test", logging.INFO, __file__, 1, json.dumps({"ok": True}), (), None
        )
        assert request_filter.filter(correlated) is True
        assert correlated.request_id == "outbound-1"  # type: ignore[attr-defined]
    finally:
        reset_request_id(token)

    assert get_request_id() is None
