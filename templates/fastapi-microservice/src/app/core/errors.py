class ApplicationError(Exception):
    """Base class for expected errors that may be exposed to API clients."""

    code = "application_error"
    default_message = "The operation could not be completed"

    def __init__(self, message: str | None = None) -> None:
        self.public_message = message or self.default_message
        super().__init__(self.public_message)


class NotFoundError(ApplicationError):
    """Indicate that a requested resource does not exist."""

    code = "not_found"
    default_message = "The requested resource was not found"


class ConflictError(ApplicationError):
    """Indicate that an operation conflicts with current domain state."""

    code = "conflict"
    default_message = "The operation conflicts with the current resource state"


class AuthenticationError(ApplicationError):
    """Indicate that valid authentication is required."""

    code = "authentication_required"
    default_message = "Authentication is required"


class AuthorizationError(ApplicationError):
    """Indicate that the current principal cannot perform an operation."""

    code = "forbidden"
    default_message = "The operation is not permitted"


class DependencyUnavailableError(ApplicationError):
    """Indicate that a required dependency cannot serve the request."""

    code = "service_unavailable"
    default_message = "A required service is temporarily unavailable"
