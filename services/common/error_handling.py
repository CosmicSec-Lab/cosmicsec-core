"""
CosmicSec Advanced Error Handling and Response Models

Provides consistent error handling, custom exceptions, and standardized responses
for the entire platform.
"""

from __future__ import annotations

import logging
import traceback
from enum import Enum
from typing import Any, Generic, TypeVar

from fastapi import Request, status
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

T = TypeVar("T")


class ErrorSeverity(str, Enum):
    """Error severity levels for better categorization."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ErrorCode(str, Enum):
    """Standardized error codes for API responses."""

    INTERNAL_ERROR = "INTERNAL_ERROR"
    VALIDATION_ERROR = "VALIDATION_ERROR"
    AUTHENTICATION_ERROR = "AUTHENTICATION_ERROR"
    AUTHORIZATION_ERROR = "AUTHORIZATION_ERROR"
    NOT_FOUND = "NOT_FOUND"
    CONFLICT = "CONFLICT"
    RATE_LIMIT = "RATE_LIMIT"
    SERVICE_UNAVAILABLE = "SERVICE_UNAVAILABLE"
    TIMEOUT = "TIMEOUT"
    INVALID_REQUEST = "INVALID_REQUEST"


class ErrorResponse(BaseModel):
    """Standardized error response model."""

    error: str
    code: ErrorCode = Field(default=ErrorCode.INTERNAL_ERROR)
    severity: ErrorSeverity = Field(default=ErrorSeverity.MEDIUM)
    request_id: str | None = None
    trace_id: str | None = None
    timestamp: str | None = None
    details: dict[str, Any] | None = None
    suggestion: str | None = None


class SuccessResponse(BaseModel, Generic[T]):
    """Standardized success response model."""

    success: bool = True
    data: T | None = None
    message: str | None = None
    timestamp: str | None = None
    request_id: str | None = None


class CosmicSecException(Exception):
    """Base exception for CosmicSec services."""

    def __init__(
        self,
        message: str,
        code: ErrorCode = ErrorCode.INTERNAL_ERROR,
        severity: ErrorSeverity = ErrorSeverity.MEDIUM,
        status_code: int = status.HTTP_500_INTERNAL_SERVER_ERROR,
        details: dict[str, Any] | None = None,
        suggestion: str | None = None,
    ):
        self.message = message
        self.code = code
        self.severity = severity
        self.status_code = status_code
        self.details = details or {}
        self.suggestion = suggestion
        super().__init__(message)


class ValidationException(CosmicSecException):
    """Exception for validation errors."""

    def __init__(
        self,
        message: str,
        details: dict[str, Any] | None = None,
        suggestion: str | None = None,
    ):
        super().__init__(
            message=message,
            code=ErrorCode.VALIDATION_ERROR,
            severity=ErrorSeverity.LOW,
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            details=details,
            suggestion=suggestion,
        )


class AuthenticationException(CosmicSecException):
    """Exception for authentication errors."""

    def __init__(
        self,
        message: str = "Authentication failed",
        details: dict[str, Any] | None = None,
    ):
        super().__init__(
            message=message,
            code=ErrorCode.AUTHENTICATION_ERROR,
            severity=ErrorSeverity.MEDIUM,
            status_code=status.HTTP_401_UNAUTHORIZED,
            details=details,
        )


class AuthorizationException(CosmicSecException):
    """Exception for authorization errors."""

    def __init__(
        self,
        message: str = "Insufficient permissions",
        details: dict[str, Any] | None = None,
    ):
        super().__init__(
            message=message,
            code=ErrorCode.AUTHORIZATION_ERROR,
            severity=ErrorSeverity.MEDIUM,
            status_code=status.HTTP_403_FORBIDDEN,
            details=details,
        )


class ResourceNotFoundException(CosmicSecException):
    """Exception for when a resource is not found."""

    def __init__(
        self,
        resource: str = "Resource",
        identifier: str | int | None = None,
        suggestion: str | None = None,
    ):
        message = f"{resource} not found"
        if identifier:
            message += f" (ID: {identifier})"
        super().__init__(
            message=message,
            code=ErrorCode.NOT_FOUND,
            severity=ErrorSeverity.LOW,
            status_code=status.HTTP_404_NOT_FOUND,
            suggestion=suggestion,
        )


class ServiceUnavailableException(CosmicSecException):
    """Exception for when a service is unavailable."""

    def __init__(
        self,
        service: str,
        message: str | None = None,
        retry_after: int | None = None,
    ):
        full_message = message or f"{service} is currently unavailable"
        super().__init__(
            message=full_message,
            code=ErrorCode.SERVICE_UNAVAILABLE,
            severity=ErrorSeverity.HIGH,
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            details={"retry_after": retry_after} if retry_after else None,
        )


async def cosmic_sec_exception_handler(request: Request, exc: CosmicSecException) -> JSONResponse:
    """Handle CosmicSec exceptions with proper formatting."""
    logger.error(
        f"CosmicSec exception: {exc.code} - {exc.message}",
        extra={
            "code": exc.code,
            "severity": exc.severity,
            "details": exc.details,
        },
    )

    error_response = ErrorResponse(
        error=exc.message,
        code=exc.code,
        severity=exc.severity,
        request_id=request.headers.get("X-Request-ID"),
        trace_id=request.headers.get("X-Trace-ID"),
        details=exc.details if exc.details else None,
        suggestion=exc.suggestion,
    )

    return JSONResponse(
        status_code=exc.status_code,
        content=jsonable_encoder(error_response),
    )


async def general_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Handle unexpected exceptions with proper logging."""
    logger.exception(
        "Unhandled exception",
        extra={
            "path": request.url.path,
            "method": request.method,
            "client": request.client.host if request.client else None,
            "traceback": traceback.format_exc(),
        },
    )

    error_response = ErrorResponse(
        error="An unexpected error occurred",
        code=ErrorCode.INTERNAL_ERROR,
        severity=ErrorSeverity.HIGH,
        request_id=request.headers.get("X-Request-ID"),
        trace_id=request.headers.get("X-Trace-ID"),
        suggestion="Please try again later or contact support if the issue persists",
    )

    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content=jsonable_encoder(error_response),
    )


def register_exception_handlers(app: Any) -> None:
    """Register all exception handlers with FastAPI app."""
    app.add_exception_handler(CosmicSecException, cosmic_sec_exception_handler)
    app.add_exception_handler(Exception, general_exception_handler)
