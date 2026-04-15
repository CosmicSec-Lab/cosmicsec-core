"""
CosmicSec Advanced Structured Logging System
Provides JSON-structured logging with correlation IDs and performance tracking
"""

import json
import logging
import time
import traceback
import uuid
from contextvars import ContextVar
from datetime import UTC, datetime
from typing import Any

# Context variables for tracking
TRACE_ID: ContextVar[str] = ContextVar("trace_id", default=None)
REQUEST_ID: ContextVar[str] = ContextVar("request_id", default=None)
USER_ID: ContextVar[str | None] = ContextVar("user_id", default=None)


class StructuredLogger(logging.Logger):
    """Enhanced logger with structured JSON output and context tracking."""

    def _log_structured(
        self,
        level: int,
        message: str,
        args: tuple = (),
        exc_info: tuple | None = None,
        extra: dict[str, Any] | None = None,
        **kwargs,
    ):
        """Log with structured JSON format."""
        timestamp = datetime.now(tz=UTC).isoformat() + "Z"

        # Build context
        context = {
            "timestamp": timestamp,
            "level": logging.getLevelName(level),
            "logger": self.name,
            "message": message % args if args else message,
        }

        # Add trace context
        trace_id = TRACE_ID.get()
        if trace_id:
            context["trace_id"] = trace_id

        request_id = REQUEST_ID.get()
        if request_id:
            context["request_id"] = request_id

        user_id = USER_ID.get()
        if user_id:
            context["user_id"] = user_id

        # Add extra fields
        if extra:
            context.update(extra)

        # Add exception info if present
        if exc_info:
            context["exception"] = {
                "type": exc_info[0].__name__,
                "message": str(exc_info[1]),
                "traceback": traceback.format_exception(*exc_info),
            }

        # Log as JSON
        log_entry = json.dumps(context, default=str)
        super().log(level, log_entry)

    def debug(self, message: str, *args, **extra):
        """Log debug level with structured format."""
        self._log_structured(logging.DEBUG, message, args=args, extra=extra)

    def info(self, message: str, *args, **extra):
        """Log info level with structured format."""
        self._log_structured(logging.INFO, message, args=args, extra=extra)

    def warning(self, message: str, *args, **extra):
        """Log warning level with structured format."""
        self._log_structured(logging.WARNING, message, args=args, extra=extra)

    def error(self, message: str, *args, exc_info: bool = False, **extra):
        """Log error level with structured format."""
        if exc_info:
            import sys

            exc_info_tuple = sys.exc_info()
        else:
            exc_info_tuple = None
        self._log_structured(
            logging.ERROR, message, args=args, exc_info=exc_info_tuple, extra=extra
        )

    def critical(self, message: str, *args, exc_info: bool = False, **extra):
        """Log critical level with structured format."""
        if exc_info:
            import sys

            exc_info_tuple = sys.exc_info()
        else:
            exc_info_tuple = None
        self._log_structured(
            logging.CRITICAL,
            message,
            args=args,
            exc_info=exc_info_tuple,
            extra=extra,
        )


def setup_structured_logging(name: str, level: int = logging.INFO) -> StructuredLogger:
    """Initialize structured logging for a service."""
    logging.setLoggerClass(StructuredLogger)
    logger = logging.getLogger(name)
    logger.setLevel(level)

    # Attach handler once to avoid duplicate log lines on module reload.
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setLevel(level)
        logger.addHandler(handler)
    return logger


def set_trace_id(trace_id: str | None = None) -> str:
    """Set the trace ID for current context."""
    if trace_id is None:
        trace_id = str(uuid.uuid4())
    TRACE_ID.set(trace_id)
    return trace_id


def set_request_id(request_id: str | None = None) -> str:
    """Set the request ID for current context."""
    if request_id is None:
        request_id = str(uuid.uuid4())
    REQUEST_ID.set(request_id)
    return request_id


def set_user_id(user_id: str | None) -> None:
    """Set the user ID for current context."""
    if user_id:
        USER_ID.set(user_id)


def clear_context() -> None:
    """Clear all context variables."""
    TRACE_ID.set(None)
    REQUEST_ID.set(None)
    USER_ID.set(None)


class PerformanceTimer:
    """Context manager for timing code blocks."""

    def __init__(self, logger: logging.Logger, operation_name: str, **extra):
        self.logger = logger
        self.operation_name = operation_name
        self.extra = extra
        self.start_time = None
        self.duration = None

    def __enter__(self):
        self.start_time = time.time()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.duration = (time.time() - self.start_time) * 1000  # Convert to ms

        if exc_type:
            self.logger.error(
                f"Operation '{self.operation_name}' failed",
                duration_ms=self.duration,
                error_type=exc_type.__name__,
                **self.extra,
            )
        else:
            self.logger.info(
                f"Operation '{self.operation_name}' completed",
                duration_ms=self.duration,
                **self.extra,
            )
