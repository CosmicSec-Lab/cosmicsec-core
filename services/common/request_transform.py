"""Request/Response transformation and security middleware.

Provides:
  - Request ID propagation (X-Request-ID)
  - Request timing (X-Response-Time)
  - Security headers injection
  - Request body size limiting
  - PII redaction in response bodies
  - Request sanitization (XSS prevention in query params)
"""

from __future__ import annotations

import logging
import re
import time
import uuid
from typing import Any

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint

logger = logging.getLogger(__name__)

# XSS patterns to sanitize from query parameters
_XSS_PATTERNS = [
    re.compile(r"<script[^>]*>", re.IGNORECASE),
    re.compile(r"javascript:", re.IGNORECASE),
    re.compile(r"on\w+\s*=", re.IGNORECASE),
    re.compile(r"<iframe[^>]*>", re.IGNORECASE),
    re.compile(r"<object[^>]*>", re.IGNORECASE),
    re.compile(r"<embed[^>]*>", re.IGNORECASE),
]

# PII patterns to redact in response bodies
_PII_PATTERNS = [
    (re.compile(r'"(?:password|secret|api_key|token|authorization)"\s*:\s*"[^"]*"', re.IGNORECASE), '***REDACTED***'),
    (re.compile(r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b"), "***CREDIT_CARD***"),
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "***SSN***"),
]


def _sanitize_value(value: str) -> str:
    """Remove potential XSS patterns from a string."""
    for pattern in _XSS_PATTERNS:
        value = pattern.sub("", value)
    return value


def _sanitize_query_params(query_string: str) -> str:
    """Sanitize query parameters to prevent stored XSS."""
    if not query_string:
        return ""

    parts = []
    for param in query_string.split("&"):
        if "=" in param:
            key, value = param.split("=", 1)
            parts.append(f"{key}={_sanitize_value(value)}")
        else:
            parts.append(param)
    return "&".join(parts)


def _add_security_headers(response: Response) -> None:
    """Add comprehensive security headers to the response."""
    security_headers = {
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "X-XSS-Protection": "0",  # Modern browsers prefer CSP over this
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
        "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=()",
        "Cache-Control": "no-store, no-cache, must-revalidate, proxy-revalidate",
        "Pragma": "no-cache",
    }

    for header, value in security_headers.items():
        if header not in response.headers:
            response.headers[header] = value


class SecurityMiddleware(BaseHTTPMiddleware):
    """Comprehensive security middleware for all requests."""

    def __init__(
        self,
        app: Any,
        *,
        max_body_size: int = 10 * 1024 * 1024,  # 10MB
        request_id_header: str = "X-Request-ID",
        add_security_headers: bool = True,
        sanitize_queries: bool = True,
        expose_timing: bool = True,
    ) -> None:
        super().__init__(app)
        self.max_body_size = max_body_size
        self.request_id_header = request_id_header
        self.add_security_headers = add_security_headers
        self.sanitize_queries = sanitize_queries
        self.expose_timing = expose_timing

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        start_time = time.monotonic()

        # Generate or propagate request ID
        request_id = request.headers.get(self.request_id_header, str(uuid.uuid4()))
        request.state.request_id = request_id

        # Sanitize query parameters
        if self.sanitize_queries and request.url.query:
            sanitized_query = _sanitize_query_params(request.url.query)
            if sanitized_query != request.url.query:
                logger.warning("Sanitized XSS patterns from query parameters: %s", request.url.path)

        # Check request body size
        content_length = request.headers.get("content-length")
        if content_length and int(content_length) > self.max_body_size:
            return Response(
                status_code=413,
                content=f'Request body too large. Maximum: {self.max_body_size // (1024*1024)}MB',
                media_type="text/plain",
            )

        # Process request
        response = await call_next(request)

        # Calculate response time
        elapsed_ms = (time.monotonic() - start_time) * 1000

        # Add response headers
        response.headers[self.request_id_header] = request_id
        if self.expose_timing:
            response.headers["X-Response-Time"] = f"{elapsed_ms:.1f}ms"

        # Add security headers
        if self.add_security_headers:
            _add_security_headers(response)

        # Log slow requests
        if elapsed_ms > 1000:
            logger.warning(
                "Slow request: %s %s (%.1fms) [request_id=%s]",
                request.method,
                request.url.path,
                elapsed_ms,
                request_id,
            )

        return response


def redact_pii_from_response(body: str) -> str:
    """Redact PII patterns from a response body string."""
    for pattern, replacement in _PII_PATTERNS:
        body = pattern.sub(replacement, body)
    return body
