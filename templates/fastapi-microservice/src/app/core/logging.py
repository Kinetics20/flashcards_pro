import logging
import logging.config

from opentelemetry.trace import get_current_span
from pythonjsonlogger import json

from app.core.context import get_request_id


class RequestContextFilter(logging.Filter):
    """Attach the current request identifier to every emitted log record."""

    def filter(self, record: logging.LogRecord) -> bool:
        """Enrich a record without suppressing it."""
        if not hasattr(record, "request_id"):
            record.request_id = get_request_id() or "-"

        span_context = get_current_span().get_span_context()
        trace_id = f"{span_context.trace_id:032x}" if span_context.is_valid else "-"
        span_id = f"{span_context.span_id:016x}" if span_context.is_valid else "-"

        if not hasattr(record, "trace_id"):
            record.trace_id = trace_id
        if not hasattr(record, "span_id"):
            record.span_id = span_id

        return True


def configure_logging(level: str = "INFO") -> None:
    """Configure structured application and server logging on standard output."""
    logging.config.dictConfig(
        {
            "version": 1,
            "disable_existing_loggers": False,
            "filters": {"request_context": {"()": RequestContextFilter}},
            "formatters": {
                "json": {
                    "()": json.JsonFormatter,
                    "format": (
                        "%(asctime)s %(name)s %(levelname)s %(message)s %(module)s "
                        "%(request_id)s %(trace_id)s %(span_id)s"
                    ),
                }
            },
            "handlers": {
                "console": {
                    "class": "logging.StreamHandler",
                    "filters": ["request_context"],
                    "formatter": "json",
                    "level": level,
                    "stream": "ext://sys.stdout",
                }
            },
            "root": {"handlers": ["console"], "level": level},
            "loggers": {
                "uvicorn": {
                    "handlers": ["console"],
                    "level": level,
                    "propagate": False,
                },
                "uvicorn.error": {
                    "handlers": [],
                    "level": level,
                    "propagate": True,
                },
                "uvicorn.access": {
                    "handlers": [],
                    "level": level,
                    "propagate": False,
                },
            },
        }
    )
