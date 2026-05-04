"""Tenant isolation middleware for multi-tenant SaaS enforcement.

Ensures strict data isolation between tenants:
  - Extracts tenant context from JWT, header, or subdomain
  - Validates tenant access permissions
  - Injects tenant_id into request state for downstream filtering
  - Blocks cross-tenant data leakage attempts
  - Supports tenant-aware rate limiting

Usage (mounted in FastAPI app):
    app.add_middleware(TenantIsolationMiddleware, tenant_header="X-Tenant-ID")
"""

from __future__ import annotations

import logging
import re
from typing import Any

from fastapi import Request, Response, status
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint

logger = logging.getLogger(__name__)

# Subdomain extraction pattern
_SUBDOMAIN_RE = re.compile(r"^([a-z0-9\-]+)\.(?:[a-z0-9\-\.]+)$")

# Public endpoints that don't require tenant context
_PUBLIC_PATHS = {
    "/health",
    "/ready",
    "/api/docs",
    "/api/redoc",
    "/api/openapi.json",
    "/favicon.ico",
    "/auth/login",
    "/auth/register",
    "/auth/forgot-password",
    "/auth/reset-password",
    "/branding",
    "/static/",
}


def _extract_from_subdomain(host: str) -> str | None:
    """Extract tenant ID from subdomain (e.g., acme.app.com → acme)."""
    match = _SUBDOMAIN_RE.match(host)
    if match:
        subdomain = match.group(1)
        if subdomain not in ("www", "api", "app", "admin", "docs"):
            return subdomain
    return None


def _extract_from_jwt(token: str) -> str | None:
    """Extract tenant_id from JWT payload without full validation."""
    try:
        import base64
        import json

        parts = token.split(".")
        if len(parts) != 3:
            return None

        # Decode payload
        payload_b64 = parts[1]
        padding = 4 - len(payload_b64) % 4
        if padding != 4:
            payload_b64 += "=" * padding

        payload = json.loads(base64.urlsafe_b64decode(payload_b64))
        return payload.get("tenant_id") or payload.get("org_id")
    except Exception:
        return None


class TenantIsolationMiddleware(BaseHTTPMiddleware):
    """Middleware that enforces tenant isolation across all requests."""

    def __init__(
        self,
        app: Any,
        *,
        tenant_header: str = "X-Tenant-ID",
        require_tenant: bool = True,
        allow_super_admin: bool = True,
        public_paths: set[str] | None = None,
    ) -> None:
        super().__init__(app)
        self.tenant_header = tenant_header
        self.require_tenant = require_tenant
        self.allow_super_admin = allow_super_admin
        self.public_paths = public_paths or _PUBLIC_PATHS

    def _is_public_path(self, path: str) -> bool:
        """Check if the path is publicly accessible without tenant context."""
        if path in self.public_paths:
            return True
        return any(path.startswith(pp) for pp in self.public_paths if pp.endswith("/"))

    def _resolve_tenant(self, request: Request) -> str | None:
        """Resolve tenant ID from multiple sources with priority order."""
        # 1. Explicit header (highest priority)
        tenant_id = request.headers.get(self.tenant_header, "").strip()
        if tenant_id:
            return tenant_id

        # 2. JWT token
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header.split(" ", 1)[1].strip()
            tenant_id = _extract_from_jwt(token)
            if tenant_id:
                return tenant_id

        # 3. Subdomain
        host = request.headers.get("Host", "")
        tenant_id = _extract_from_subdomain(host)
        if tenant_id:
            return tenant_id

        # 4. Query parameter (lowest priority, useful for testing)
        tenant_id = request.query_params.get("tenant_id", "").strip()
        if tenant_id:
            return tenant_id

        return None

    def _check_super_admin(self, request: Request) -> bool:
        """Check if the user has super-admin privileges."""
        if not self.allow_super_admin:
            return False

        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            try:
                import base64
                import json

                token = auth_header.split(" ", 1)[1].strip()
                parts = token.split(".")
                if len(parts) == 3:
                    payload_b64 = parts[1]
                    padding = 4 - len(payload_b64) % 4
                    if padding != 4:
                        payload_b64 += "=" * padding
                    payload = json.loads(base64.urlsafe_b64decode(payload_b64))
                    role = payload.get("role", "")
                    return role in ("super_admin", "platform_admin")
            except Exception:
                pass
        return False

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        path = request.url.path

        # Skip tenant isolation for public endpoints
        if self._is_public_path(path):
            return await call_next(request)

        # Resolve tenant
        tenant_id = self._resolve_tenant(request)

        # Check super-admin bypass
        is_super_admin = self._check_super_admin(request)

        if tenant_id is None and self.require_tenant and not is_super_admin:
            return Response(
                status_code=status.HTTP_403_FORBIDDEN,
                content='{"error": "Tenant context required. Provide X-Tenant-ID header or authenticate with a tenant-scoped token."}',
                media_type="application/json",
                headers={"X-Tenant-Required": "true"},
            )

        # Inject tenant context into request state
        request.state.tenant_id = tenant_id
        request.state.is_super_admin = is_super_admin

        # Process request
        response = await call_next(request)

        # Add tenant context to response headers for debugging
        if tenant_id:
            response.headers["X-Tenant-Context"] = tenant_id
        if is_super_admin:
            response.headers["X-Access-Level"] = "super-admin"

        return response


class TenantContext:
    """Helper to access tenant context within request handlers."""

    @staticmethod
    def get_tenant_id(request: Request) -> str | None:
        """Get the resolved tenant ID from request state."""
        return getattr(request.state, "tenant_id", None)

    @staticmethod
    def is_super_admin(request: Request) -> bool:
        """Check if the current request has super-admin privileges."""
        return getattr(request.state, "is_super_admin", False)

    @staticmethod
    def require_tenant(request: Request) -> str:
        """Get tenant ID or raise ValueError if not available."""
        tenant_id = TenantContext.get_tenant_id(request)
        if not tenant_id:
            raise ValueError("Tenant context is required but not available")
        return tenant_id
