import os
import time
import uuid
import re
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from slowapi.errors import RateLimitExceeded
from slowapi import _rate_limit_exceeded_handler

from services.api_gateway.core_deps import logger, limiter, SERVICE_URLS, hybrid_router
from cosmicsec_platform.config import get_config
from cosmicsec_platform.service_discovery import log_service_config
from services.api_gateway.graphql_runtime import mount_graphql
from services.api_gateway.white_label import WhiteLabelMiddleware, mount_branding_routes
from services.common.logging import clear_context, set_request_id, set_trace_id
from services.common.observability import setup_observability
from services.common.versioning import APIVersionMiddleware
from services.common.exceptions import CosmicSecException
from services.common.request_transform import SecurityMiddleware
from services.common.rate_limiting import RateLimitMiddleware, get_rate_limiter
from services.common.circuit_breaker import CircuitBreakerRegistry
from services.common.feature_flags import get_feature_flags
from services.common.service_discovery_advanced import ServiceDiscovery, LoadBalancingStrategy
from services.common.tenant_isolation import TenantIsolationMiddleware
from services.common.audit_logger import get_audit_logger, EventCategory, SeverityLevel

# Initialize FastAPI app
app = FastAPI(
    title="CosmicSec API Gateway",
    description="GuardAxisSphere Platform - Universal Cybersecurity Intelligence Platform powered by Helix AI",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# CORS
_cors_origins_raw = os.environ.get("COSMICSEC_CORS_ORIGINS", "http://localhost:3000,http://localhost:4173")
_cors_origins = [o.strip() for o in _cors_origins_raw.split(",") if o.strip()]
if "*" in _cors_origins:
    _cors_origins = [o for o in _cors_origins if o != "*"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Security middleware (headers, request ID, XSS protection, PII redaction)
app.add_middleware(
    SecurityMiddleware,
    max_body_size=int(os.getenv("MAX_REQUEST_BODY", "10485760")),
    add_security_headers=True,
    sanitize_queries=True,
    expose_timing=True,
)

# Tenant isolation middleware
_tenant_enabled = os.getenv("TENANT_ISOLATION_ENABLED", "false").lower() == "true"
if _tenant_enabled:
    app.add_middleware(
        TenantIsolationMiddleware,
        tenant_header=os.getenv("TENANT_HEADER", "X-Tenant-ID"),
        require_tenant=os.getenv("TENANT_REQUIRED", "true").lower() == "true",
    )

# Rate limiting middleware (Redis-backed, replaces slowapi for API routes)
_rate_limit_enabled = os.getenv("RATE_LIMIT_ENABLED", "true").lower() == "true"
if _rate_limit_enabled:
    app.add_middleware(
        RateLimitMiddleware,
        limiter=get_rate_limiter(),
    )

# White-label branding
app.add_middleware(GZipMiddleware, minimum_size=1000)
app.add_middleware(WhiteLabelMiddleware)
mount_branding_routes(app)

# Include the massive extracted router
from services.api_gateway.routers.core_routes import router as core_router
app.include_router(core_router)

# Include premium platform management routes
from services.api_gateway.routers.platform_routes import router as platform_router
app.include_router(platform_router)

# Observability and GraphQL
_observability_state = setup_observability(app, service_name="api-gateway", logger=logger)
_graphql_enabled = mount_graphql(app, service_urls=SERVICE_URLS, logger=logger)

# Initialize advanced service discovery with load balancing
try:
    _adv_sd = ServiceDiscovery(
        SERVICE_URLS,
        health_check_interval=float(os.getenv("HEALTH_CHECK_INTERVAL", "30")),
        load_balancing=LoadBalancingStrategy(os.getenv("LOAD_BALANCING", "round_robin")),
    )
    # Register dependencies for topology visualization
    for svc in ("auth", "scan", "ai", "recon", "report", "collab"):
        _adv_sd.register_dependency("api_gateway", svc)
except Exception as exc:
    logger.warning("Advanced service discovery init failed: %s", exc)

# Register startup/shutdown events
@app.on_event("startup")
async def startup_advanced_services():
    """Initialize background monitoring services."""
    # Start health monitoring
    try:
        await _adv_sd.start_health_monitoring()
        logger.info("Advanced service discovery health monitoring started")
    except Exception as exc:
        logger.warning("Health monitoring startup failed: %s", exc)

    # Log platform initialization
    logger.info(
        "CosmicSec API Gateway initialized [security=%s, tenant=%s, rate_limit=%s]",
        "enabled" if _tenant_enabled else "standard",
        "enabled" if _tenant_enabled else "disabled",
        "enabled" if _rate_limit_enabled else "disabled",
    )

@app.on_event("shutdown")
async def shutdown_advanced_services():
    """Clean up background services."""
    try:
        _adv_sd.stop_health_monitoring()
    except Exception:
        pass

logger.info(f"Platform Config: {get_config()}")
log_service_config()
logger.info("API Gateway successfully initialized and modularized!")
