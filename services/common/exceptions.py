"""
CosmicSec Advanced Error Handling System
Provides standardized error responses, custom exceptions, and error tracking
"""

import logging
from datetime import datetime
from enum import Enum
from typing import Any, Optional

from fastapi import status

logger = logging.getLogger(__name__)


class ErrorCode(str, Enum):
    """Standard error codes used throughout CosmicSec."""

    # Authentication & Authorization
    AUTH_INVALID_CREDENTIALS = "AUTH_INVALID_CREDENTIALS"
    AUTH_MISSING_TOKEN = "AUTH_MISSING_TOKEN"
    AUTH_EXPIRED_TOKEN = "AUTH_EXPIRED_TOKEN"
    AUTH_INVALID_TOKEN = "AUTH_INVALID_TOKEN"
    AUTH_INSUFFICIENT_PERMISSIONS = "AUTH_INSUFFICIENT_PERMISSIONS"
    AUTH_ACCOUNT_DISABLED = "AUTH_ACCOUNT_DISABLED"
    AUTH_MFA_REQUIRED = "AUTH_MFA_REQUIRED"

    # Resource
    RESOURCE_NOT_FOUND = "RESOURCE_NOT_FOUND"
    RESOURCE_ALREADY_EXISTS = "RESOURCE_ALREADY_EXISTS"
    RESOURCE_CONFLICT = "RESOURCE_CONFLICT"

    # Validation
    VALIDATION_ERROR = "VALIDATION_ERROR"
    INVALID_INPUT = "INVALID_INPUT"
    MISSING_PARAMETER = "MISSING_PARAMETER"

    # Rate limiting
    RATE_LIMIT_EXCEEDED = "RATE_LIMIT_EXCEEDED"
    QUOTA_EXCEEDED = "QUOTA_EXCEEDED"

    # Service errors
    SERVICE_UNAVAILABLE = "SERVICE_UNAVAILABLE"
    SERVICE_TIMEOUT = "SERVICE_TIMEOUT"
    SERVICE_DEGRADED = "SERVICE_DEGRADED"

    # External service
    EXTERNAL_SERVICE_ERROR = "EXTERNAL_SERVICE_ERROR"
    EXTERNAL_SERVICE_TIMEOUT = "EXTERNAL_SERVICE_TIMEOUT"

    # Database errors
    DATABASE_ERROR = "DATABASE_ERROR"
    DATABASE_CONSTRAINT_VIOLATION = "DATABASE_CONSTRAINT_VIOLATION"

    # Business logic
    INVALID_STATE = "INVALID_STATE"
    OPERATION_NOT_ALLOWED = "OPERATION_NOT_ALLOWED"
    DEPENDENCY_NOT_SATISFIED = "DEPENDENCY_NOT_SATISFIED"

    # Configuration
    CONFIGURATION_ERROR = "CONFIGURATION_ERROR"
    MISSING_CONFIGURATION = "MISSING_CONFIGURATION"

    # Scan/Tool related
    SCAN_FAILED = "SCAN_FAILED"
    SCAN_TIMEOUT = "SCAN_TIMEOUT"
    TOOL_NOT_AVAILABLE = "TOOL_NOT_AVAILABLE"

    # Generic
    INTERNAL_SERVER_ERROR = "INTERNAL_SERVER_ERROR"
    UNKNOWN_ERROR = "UNKNOWN_ERROR"


class ErrorSeverity(str, Enum):
    """Error severity levels."""

    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class CosmicSecException(Exception):
    """Base exception for all CosmicSec errors."""

    def __init__(
        self,
        message: str,
        error_code: ErrorCode,
        status_code: int = status.HTTP_500_INTERNAL_SERVER_ERROR,
        severity: ErrorSeverity = ErrorSeverity.ERROR,
        details: Optional[dict[str, Any]] = None,
        suggestion: Optional[str] = None,
    ):
        self.message = message
        self.error_code = error_code
        self.status_code = status_code
        self.severity = severity
        self.details = details or {}
        self.suggestion = suggestion
        self.timestamp = datetime.utcnow().isoformat() + "Z"
        super().__init__(message)

    def to_dict(self) -> dict[str, Any]:
        """Convert exception to response dictionary."""
        response = {
            "detail": self.message,
            "error_code": self.error_code.value,
            "timestamp": self.timestamp,
        }

        if self.details:
            response["details"] = self.details

        if self.suggestion:
            response["suggestion"] = self.suggestion

        return response


class ValidationError(CosmicSecException):
    """Raised when input validation fails."""

    def __init__(self, message: str, fields: Optional[dict[str, str]] = None, **kwargs):
        details = {"validation_errors": fields or {}}
        super().__init__(
            message,
            ErrorCode.VALIDATION_ERROR,
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            details=details,
            **kwargs,
        )


class AuthenticationError(CosmicSecException):
    """Raised when authentication fails."""

    def __init__(self, message: str, error_code: ErrorCode = ErrorCode.AUTH_INVALID_CREDENTIALS):
        super().__init__(
            message,
            error_code,
            status.HTTP_401_UNAUTHORIZED,
            ErrorSeverity.WARNING,
        )


class AuthorizationError(CosmicSecException):
    """Raised when user lacks required permissions."""

    def __init__(self, message: str, required_role: Optional[str] = None):
        super().__init__(
            message,
            ErrorCode.AUTH_INSUFFICIENT_PERMISSIONS,
            status.HTTP_403_FORBIDDEN,
            ErrorSeverity.WARNING,
            details={"required_role": required_role},
        )


class NotFoundError(CosmicSecException):
    """Raised when resource is not found."""

    def __init__(self, resource_type: str, resource_id: Any):
        super().__init__(
            f"{resource_type} with ID '{resource_id}' not found",
            ErrorCode.RESOURCE_NOT_FOUND,
            status.HTTP_404_NOT_FOUND,
            ErrorSeverity.INFO,
            details={"resource_type": resource_type, "resource_id": str(resource_id)},
        )


class ConflictError(CosmicSecException):
    """Raised when operation conflicts with existing state."""

    def __init__(self, message: str, details: Optional[dict[str, Any]] = None):
        super().__init__(
            message,
            ErrorCode.RESOURCE_CONFLICT,
            status.HTTP_409_CONFLICT,
            ErrorSeverity.WARNING,
            details=details,
        )


class RateLimitError(CosmicSecException):
    """Raised when rate limit is exceeded."""

    def __init__(
        self, message: str = "Rate limit exceeded", retry_after: Optional[int] = None, **kwargs
    ):
        details = {}
        if retry_after:
            details["retry_after_seconds"] = retry_after

        super().__init__(
            message,
            ErrorCode.RATE_LIMIT_EXCEEDED,
            status.HTTP_429_TOO_MANY_REQUESTS,
            ErrorSeverity.INFO,
            details=details,
            **kwargs,
        )


class ServiceUnavailableError(CosmicSecException):
    """Raised when a required service is unavailable."""

    def __init__(
        self,
        service_name: str,
        message: Optional[str] = None,
        retry_after: Optional[int] = None,
    ):
        msg = message or f"Service '{service_name}' is temporarily unavailable"
        details = {"service": service_name}
        if retry_after:
            details["retry_after_seconds"] = retry_after

        super().__init__(
            msg,
            ErrorCode.SERVICE_UNAVAILABLE,
            status.HTTP_503_SERVICE_UNAVAILABLE,
            ErrorSeverity.ERROR,
            details=details,
            suggestion="Please try again in a few moments",
        )


class ExternalServiceError(CosmicSecException):
    """Raised when external API call fails."""

    def __init__(self, service_name: str, original_error: Optional[str] = None, **kwargs):
        super().__init__(
            f"External service '{service_name}' returned an error",
            ErrorCode.EXTERNAL_SERVICE_ERROR,
            status.HTTP_502_BAD_GATEWAY,
            ErrorSeverity.ERROR,
            details={"external_service": service_name, "original_error": original_error},
            suggestion="The issue is with an external service. Please try again later.",
            **kwargs,
        )


class ErrorResponse:
    """Standard error response builder."""

    @staticmethod
    def build(
        message: str,
        error_code: ErrorCode,
        details: Optional[dict[str, Any]] = None,
        suggestion: Optional[str] = None,
    ) -> dict[str, Any]:
        """Build a standard error response."""
        response = {
            "detail": message,
            "error_code": error_code.value,
            "timestamp": datetime.utcnow().isoformat() + "Z",
        }

        if details:
            response["details"] = details

        if suggestion:
            response["suggestion"] = suggestion

        return response


def log_exception(
    exception: Exception,
    context: Optional[dict[str, Any]] = None,
    level: int = logging.ERROR,
) -> None:
    """Log exception with context."""
    error_info = {
        "exception_type": type(exception).__name__,
        "exception_message": str(exception),
    }

    if context:
        error_info.update(context)

    if isinstance(exception, CosmicSecException):
        error_info.update(
            {
                "error_code": exception.error_code.value,
                "status_code": exception.status_code,
                "severity": exception.severity.value,
            }
        )

    logger.log(level, f"Exception occurred: {error_info}", exc_info=True)
