"""
CosmicSec API Versioning System
Provides support for multiple API versions with deprecation notices
"""

import logging
from enum import Enum
from typing import Callable, Optional

from fastapi import Header, HTTPException, status

logger = logging.getLogger(__name__)


class APIVersion(str, Enum):
    """Supported API versions."""

    V1 = "v1"
    V2 = "v2"
    V3 = "v3"  # Future


class DeprecationStatus(str, Enum):
    """Deprecation status of an endpoint."""

    ACTIVE = "active"
    DEPRECATED = "deprecated"
    SUNSETTED = "sunsetted"


class APIEndpointMetadata:
    """Metadata for an API endpoint."""

    def __init__(
        self,
        version: APIVersion,
        status: DeprecationStatus = DeprecationStatus.ACTIVE,
        deprecation_date: Optional[str] = None,
        sunset_date: Optional[str] = None,
        replacement_endpoint: Optional[str] = None,
        migration_guide: Optional[str] = None,
    ):
        self.version = version
        self.status = status
        self.deprecation_date = deprecation_date
        self.sunset_date = sunset_date
        self.replacement_endpoint = replacement_endpoint
        self.migration_guide = migration_guide

    def to_headers(self) -> dict:
        """Convert metadata to response headers."""
        headers = {
            "API-Version": self.version.value,
        }

        if self.status == DeprecationStatus.DEPRECATED:
            headers["Deprecation"] = "true"
            if self.deprecation_date:
                headers["Sunset"] = self.sunset_date or "2026-12-31T23:59:59Z"
            if self.replacement_endpoint:
                headers["Link"] = f'<{self.replacement_endpoint}>; rel="successor-version"'

        return headers


class APIVersionManager:
    """Manages API versions and deprecation."""

    _endpoints: dict = {}

    @classmethod
    def register_endpoint(
        cls,
        endpoint_path: str,
        metadata: APIEndpointMetadata,
    ) -> None:
        """Register an endpoint with version metadata."""
        if endpoint_path not in cls._endpoints:
            cls._endpoints[endpoint_path] = {}
        cls._endpoints[endpoint_path][metadata.version] = metadata

    @classmethod
    def get_metadata(
        cls,
        endpoint_path: str,
        version: APIVersion,
    ) -> Optional[APIEndpointMetadata]:
        """Get metadata for an endpoint version."""
        return cls._endpoints.get(endpoint_path, {}).get(version)

    @classmethod
    def validate_version(
        cls,
        requested_version: str,
        supported_versions: list[APIVersion],
    ) -> APIVersion:
        """Validate and normalize requested version."""
        try:
            version = APIVersion(requested_version)
            if version not in supported_versions:
                raise HTTPException(
                    status_code=status.HTTP_406_NOT_ACCEPTABLE,
                    detail=f"API version {requested_version} is not supported",
                )
            return version
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid API version: {requested_version}",
            )


# Decorator for versioned endpoints
def versioned_endpoint(
    supported_versions: list[APIVersion] = None,
    default_version: APIVersion = APIVersion.V1,
):
    """
    Decorator for versioned endpoints.

    Usage:
        @versioned_endpoint(
            supported_versions=[APIVersion.V1, APIVersion.V2],
            default_version=APIVersion.V2,
        )
        async def get_scans(api_version: str = Header(default="v1")):
            ...
    """
    if supported_versions is None:
        supported_versions = [APIVersion.V1]

    def decorator(func: Callable) -> Callable:
        async def wrapper(
            *args, api_version: str = Header(default=default_version.value), **kwargs
        ):
            # Validate version
            version = APIVersionManager.validate_version(api_version, supported_versions)

            # Get metadata and add to response context
            # This should be handled by middleware to add headers

            # Log version usage
            logger.info(f"Endpoint called with API version: {version}")

            # Call original function
            return await func(*args, api_version=version, **kwargs)

        wrapper.__wrapped__ = func
        return wrapper

    return decorator


class APIVersionMiddleware:
    """Middleware for API version handling."""

    @staticmethod
    async def process_request(request, call_next):
        """Process API version from request headers."""
        # Extract version from header or default to v1
        api_version = request.headers.get("API-Version", "v1")

        # Store in request state for access in endpoints
        request.state.api_version = api_version

        # Process request
        response = await call_next(request)

        # Add version to response headers
        response.headers["API-Version"] = api_version

        return response


# Pre-defined metadata for common endpoints
ENDPOINT_REGISTRY = {
    "/api/scans": {
        APIVersion.V1: APIEndpointMetadata(
            version=APIVersion.V1,
            status=DeprecationStatus.ACTIVE,
        ),
        APIVersion.V2: APIEndpointMetadata(
            version=APIVersion.V2,
            status=DeprecationStatus.ACTIVE,
        ),
    },
    "/api/findings": {
        APIVersion.V1: APIEndpointMetadata(
            version=APIVersion.V1,
            status=DeprecationStatus.DEPRECATED,
            deprecation_date="2026-01-01T00:00:00Z",
            sunset_date="2026-12-31T23:59:59Z",
            replacement_endpoint="/api/v2/findings",
            migration_guide="https://docs.cosmicsec.io/api/v1-to-v2-migration",
        ),
        APIVersion.V2: APIEndpointMetadata(
            version=APIVersion.V2,
            status=DeprecationStatus.ACTIVE,
        ),
    },
}


def get_version_metadata_for_response(
    endpoint_path: str,
    version: APIVersion,
) -> dict:
    """Get version metadata to include in API response."""
    metadata = ENDPOINT_REGISTRY.get(endpoint_path, {}).get(version)

    if metadata:
        response_meta = {
            "api_version": version.value,
            "status": metadata.status.value,
        }

        if metadata.status == DeprecationStatus.DEPRECATED:
            response_meta["deprecation_warning"] = {
                "message": "This API version is deprecated",
                "deprecation_date": metadata.deprecation_date,
                "sunset_date": metadata.sunset_date,
                "migration_guide": metadata.migration_guide,
            }

            if metadata.replacement_endpoint:
                response_meta["replacement_endpoint"] = metadata.replacement_endpoint

        return response_meta

    return {"api_version": version.value, "status": DeprecationStatus.ACTIVE.value}
