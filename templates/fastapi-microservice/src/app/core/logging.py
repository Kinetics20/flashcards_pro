import logging
import logging.config

from pythonjsonlogger import json

from app.core.context import get_request_id


class RequestContextFilter(logging.Filter):
    """Attach the current request identifier to every emitted log record."""

    def filter(self, record: logging.LogRecord) -> bool:
        """Enrich a record without suppressing it."""
        if not hasattr(record, "request_id"):
            record.request_id = get_request_id() or "-"
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
                        "%(asctime)s %(name)s %(levelname)s %(message)s %(module)s %(request_id)s"
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
