"""
CosmicSec API Documentation and Versioning Support

Provides enhanced API documentation generation and API versioning capabilities.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Callable

from fastapi import APIRouter, FastAPI
from fastapi.openapi.utils import get_openapi
from pydantic import BaseModel, Field


class APIVersion(str, Enum):
    """API versions."""

    V1 = "v1"
    V2 = "v2"


class APIEndpointMetadata(BaseModel):
    """Metadata for API endpoints."""

    version: APIVersion = Field(default=APIVersion.V1)
    deprecated: bool = False
    stability: str = Field(default="stable")  # stable, beta, experimental
    requires_auth: bool = True
    rate_limit: int | None = None
    examples: dict[str, Any] | None = None


def add_openapi_info(
    app: FastAPI,
    title: str,
    description: str,
    version: str,
    contact: dict[str, str] | None = None,
    license_info: dict[str, str] | None = None,
) -> None:
    """Add enhanced OpenAPI/Swagger documentation."""

    def custom_openapi() -> dict[str, Any]:
        if app.openapi_schema:
            return app.openapi_schema

        output = get_openapi(
            title=title,
            version=version,
            description=description,
            routes=app.routes,
        )

        # Add contact info
        if contact:
            output["info"]["contact"] = contact

        # Add license info
        if license_info:
            output["info"]["license"] = license_info

        # Add security schemes
        output["components"]["securitySchemes"] = {
            "bearerAuth": {
                "type": "http",
                "scheme": "bearer",
                "bearerFormat": "JWT",
                "description": "JWT Bearer token",
            },
            "apiKey": {
                "type": "apiKey",
                "in": "header",
                "name": "X-API-Key",
                "description": "API Key authentication",
            },
        }

        # Add server URLs
        output["servers"] = [
            {
                "url": "https://api.cosmicsec.io",
                "description": "Production",
            },
            {
                "url": "https://staging-api.cosmicsec.io",
                "description": "Staging",
            },
            {
                "url": "http://localhost:8000",
                "description": "Local development",
            },
        ]

        # Add response headers
        output["components"]["headers"] = {
            "X-Request-ID": {
                "schema": {"type": "string", "format": "uuid"},
                "description": "Request ID for tracking",
            },
            "X-Trace-ID": {
                "schema": {"type": "string", "format": "uuid"},
                "description": "Trace ID for distributed tracing",
            },
            "X-Response-Time-Ms": {
                "schema": {"type": "number"},
                "description": "Response time in milliseconds",
            },
        }

        app.openapi_schema = output
        return app.openapi_schema

    app.openapi = custom_openapi


def create_versioned_router(
    prefix: str,
    tags: list[str],
    version: APIVersion = APIVersion.V1,
) -> APIRouter:
    """Create a versioned API router."""
    return APIRouter(
        prefix=f"/api/{version.value}{prefix}",
        tags=tags,
    )


class APIDocumentationHelper:
    """Helper class for API documentation."""

    @staticmethod
    def get_example_responses(
        success_status: int = 200,
        success_example: dict[str, Any] | None = None,
    ) -> dict[int, dict[str, Any]]:
        """Generate standardized example responses."""
        return {
            success_status: {
                "description": "Successful response",
                "content": {
                    "application/json": {
                        "example": success_example
                        or {
                            "success": True,
                            "data": {},
                            "message": "Operation completed successfully",
                        }
                    }
                },
            },
            400: {
                "description": "Bad Request",
                "content": {
                    "application/json": {
                        "example": {
                            "error": "Invalid request parameters",
                            "code": "VALIDATION_ERROR",
                            "severity": "low",
                        }
                    }
                },
            },
            401: {
                "description": "Unauthorized",
                "content": {
                    "application/json": {
                        "example": {
                            "error": "Authentication required",
                            "code": "AUTHENTICATION_ERROR",
                            "severity": "medium",
                        }
                    }
                },
            },
            403: {
                "description": "Forbidden",
                "content": {
                    "application/json": {
                        "example": {
                            "error": "Insufficient permissions",
                            "code": "AUTHORIZATION_ERROR",
                            "severity": "medium",
                        }
                    }
                },
            },
            404: {
                "description": "Not Found",
                "content": {
                    "application/json": {
                        "example": {
                            "error": "Resource not found",
                            "code": "NOT_FOUND",
                            "severity": "low",
                        }
                    }
                },
            },
            429: {
                "description": "Too Many Requests",
                "content": {
                    "application/json": {
                        "example": {
                            "error": "Rate limit exceeded",
                            "code": "RATE_LIMIT",
                            "severity": "medium",
                        }
                    }
                },
            },
            500: {
                "description": "Internal Server Error",
                "content": {
                    "application/json": {
                        "example": {
                            "error": "An unexpected error occurred",
                            "code": "INTERNAL_ERROR",
                            "severity": "high",
                        }
                    }
                },
            },
        }

    @staticmethod
    def add_deprecation_notice(
        func: Callable, message: str
    ) -> Callable:
        """Add deprecation notice to endpoint."""
        func.deprecated = True
        if not hasattr(func, "deprecation_message"):
            func.deprecation_message = message
        return func
