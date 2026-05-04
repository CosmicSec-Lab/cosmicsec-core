"""Premium platform management routes for API gateway.

Provides endpoints for:
  - Circuit breaker status and control
  - Feature flag management
  - Audit log access
  - Service discovery dashboard
  - Cache statistics
  - Platform configuration
  - Rate limit status
"""

from __future__ import annotations

import logging
import time
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field

from services.common.circuit_breaker import CircuitBreakerRegistry
from services.common.feature_flags import FeatureFlag, FeatureFlagManager, get_feature_flags
from services.common.audit_logger import EventCategory, SeverityLevel, get_audit_logger
from services.common.cache_multilevel import get_multi_cache
from services.common.rate_limiting import get_rate_limiter

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/platform", tags=["platform-management"])


# --- Circuit Breaker Routes ---


@router.get("/circuit-breakers")
async def list_circuit_breakers() -> dict[str, Any]:
    """Get status of all circuit breakers."""
    registry = CircuitBreakerRegistry.get_instance()
    return {"circuit_breakers": registry.get_all_stats()}


@router.post("/circuit-breakers/{service_name}/reset")
async def reset_circuit_breaker(service_name: str) -> dict[str, str]:
    """Manually reset a circuit breaker to CLOSED state."""
    registry = CircuitBreakerRegistry.get_instance()
    registry.reset_service(service_name)
    return {"status": "reset", "service": service_name}


@router.post("/circuit-breakers/reset-all")
async def reset_all_circuit_breakers() -> dict[str, str]:
    """Reset all circuit breakers to CLOSED state."""
    registry = CircuitBreakerRegistry.get_instance()
    registry.reset_all()
    return {"status": "all_reset"}


# --- Feature Flag Routes ---


@router.get("/feature-flags")
async def list_feature_flags() -> dict[str, Any]:
    """List all feature flags."""
    manager = get_feature_flags()
    flags = manager.get_all_flags()
    return {
        "flags": {name: vars(f) for name, f in flags.items()},
        "stats": manager.get_stats(),
    }


@router.post("/feature-flags")
async def create_feature_flag(flag: FeatureFlag) -> dict[str, str]:
    """Create or update a feature flag."""
    manager = get_feature_flags()
    await manager.set_flag(flag)
    return {"status": "created", "name": flag.name}


@router.delete("/feature-flags/{flag_name}")
async def delete_feature_flag(flag_name: str) -> dict[str, str]:
    """Delete a feature flag."""
    manager = get_feature_flags()
    deleted = await manager.delete_flag(flag_name)
    if not deleted:
        raise HTTPException(status_code=404, detail=f"Flag '{flag_name}' not found")
    return {"status": "deleted", "name": flag_name}


# --- Audit Log Routes ---


@router.get("/audit-log")
async def get_audit_log(
    limit: int = Query(50, ge=1, le=500),
    category: str | None = None,
    actor: str | None = None,
) -> dict[str, Any]:
    """Retrieve recent audit events."""
    audit = get_audit_logger()
    cat = EventCategory(category) if category else None
    events = audit.get_recent_events(limit=limit, category=cat, actor=actor)
    return {"events": events, "total": len(events)}


@router.get("/audit-log/stats")
async def get_audit_stats() -> dict[str, Any]:
    """Get audit log statistics."""
    audit = get_audit_logger()
    return audit.get_stats()


@router.post("/audit-log/verify")
async def verify_audit_chain() -> dict[str, Any]:
    """Verify the integrity of the audit event chain."""
    audit = get_audit_logger()
    return await audit.verify_chain()


# --- Cache Routes ---


@router.get("/cache/stats")
async def get_cache_stats() -> dict[str, Any]:
    """Get multi-level cache statistics."""
    cache = get_multi_cache()
    return await cache.get_stats()


@router.post("/cache/clear")
async def clear_cache() -> dict[str, str]:
    """Clear all cache tiers."""
    cache = get_multi_cache()
    await cache.clear()
    return {"status": "cleared"}


@router.delete("/cache/{key}")
async def delete_cache_key(key: str) -> dict[str, str]:
    """Delete a specific cache key."""
    cache = get_multi_cache()
    await cache.delete(key)
    return {"status": "deleted", "key": key}


# --- Service Discovery Routes ---


@router.get("/services/status")
async def get_services_status() -> dict[str, Any]:
    """Get real-time service status dashboard data."""
    try:
        from services.api_gateway.core_deps import _adv_sd

        return _adv_sd.get_dashboard_data()
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Service discovery unavailable: {exc}")


@router.get("/services/dependencies")
async def get_service_dependencies() -> dict[str, Any]:
    """Get the service dependency graph."""
    try:
        from services.api_gateway.core_deps import _adv_sd

        return {"dependency_graph": _adv_sd.get_dependency_graph()}
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Service discovery unavailable: {exc}")


# --- Platform Info ---


@router.get("/info")
async def get_platform_info() -> dict[str, Any]:
    """Get comprehensive platform information."""
    from services.common.caching import CacheManager, get_redis

    info = {
        "platform": "CosmicSec",
        "version": "1.0.0",
        "components": {
            "api_gateway": "operational",
            "circuit_breakers": "active",
            "feature_flags": "active",
            "audit_logging": "active",
            "multi_level_cache": "active",
            "rate_limiting": "active",
            "tenant_isolation": "configured",
        },
        "features": {
            "circuit_breaker_pattern": True,
            "distributed_locking": True,
            "tamper_proof_audit": True,
            "feature_flags": True,
            "multi_level_cache": True,
            "load_balancing": True,
            "health_monitoring": True,
            "pii_redaction": True,
            "xss_protection": True,
            "security_headers": True,
        },
        "timestamp": time.time(),
    }

    # Check Redis connectivity
    try:
        redis = await get_redis()
        await redis.ping()
        info["components"]["redis"] = "connected"
    except Exception:
        info["components"]["redis"] = "disconnected"

    return info
