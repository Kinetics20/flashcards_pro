from contextvars import ContextVar, Token

_request_id: ContextVar[str | None] = ContextVar("request_id", default=None)


def get_request_id() -> str | None:
    """Return the request identifier bound to the current async context."""
    return _request_id.get()


def set_request_id(request_id: str) -> Token[str | None]:
    """Bind a request identifier and return the token used to restore context."""
    return _request_id.set(request_id)


def reset_request_id(token: Token[str | None]) -> None:
    """Restore the request context that existed before ``set_request_id``."""
    _request_id.reset(token)
