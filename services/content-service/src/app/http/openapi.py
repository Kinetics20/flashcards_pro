import re

from fastapi.routing import APIRoute

_NON_IDENTIFIER = re.compile(r"[^a-zA-Z0-9]+")


def stable_operation_id(route: APIRoute) -> str:
    """Generate a deterministic SDK-safe identifier from a method and route."""
    method = min(route.methods).casefold() if route.methods else "call"
    path = _NON_IDENTIFIER.sub("_", route.path_format).strip("_").casefold()
    return f"{method}_{path}"
