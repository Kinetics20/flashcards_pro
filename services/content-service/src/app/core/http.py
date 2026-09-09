from app.core.context import get_request_id

REQUEST_ID_HEADER = "X-Request-ID"


def outbound_correlation_headers() -> dict[str, str]:
    """Propagate the current request identifier to an HTTP dependency."""
    request_id = get_request_id()
    return {REQUEST_ID_HEADER: request_id} if request_id is not None else {}
