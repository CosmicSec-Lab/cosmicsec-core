"""CosmicSec shared services — common utilities used across all platform microservices."""

# Database
from services.common.db import Base, SessionLocal, engine, get_db, get_read_db

# Caching
from services.common.caching import (
    CacheKey,
    CacheManager,
    cache_result,
    cache_result_sync,
    close_redis_pool,
    get_redis,
    init_redis_pool,
)

# Multi-level cache
from services.common.cache_multilevel import MultiLevelCache, get_multi_cache

# Security Utils (existing)
from services.common.security_utils import (
    sanitize_for_log,
    normalize_org_slug,
    sanitize_scan_id,
    validate_outbound_url,
    ensure_safe_child_path,
)

# JWT
from services.common.jwt_utils import decode_token as decode_jwt

# Logging
from services.common.logging import setup_structured_logging

# Observability
from services.common.observability import setup_observability

# Health Checks
from services.common.health_checks import (
    HealthStatus,
    ServiceHealth,
    ServiceHealthChecker,
    DependencyMapper,
    SystemHealthReport,
)

# Exceptions (from exceptions.py)
from services.common.exceptions import (
    AuthenticationError,
    AuthorizationError,
    ConflictError,
    CosmicSecException,
    ErrorCode,
    ErrorResponse as ExceptionErrorResponse,
    ErrorSeverity,
    ExternalServiceError,
    NotFoundError,
    RateLimitError,
    ServiceUnavailableError,
    ValidationError,
    log_exception,
)

# Error Handling (from error_handling.py)
from services.common.error_handling import (
    CosmicSecException as ErrorHandlingCosmicSecException,
    ErrorCode as ErrorHandlingErrorCode,
    ErrorResponse,
    ErrorSeverity as ErrorHandlingErrorSeverity,
    ResourceNotFoundException,
    SuccessResponse,
    ValidationException,
    register_exception_handlers,
)

# Events
from services.common.events import (
    publish,
    subscribe,
    close as close_events,
)

# Egress
from services.common.egress import create_async_client

# Versioning
from services.common.versioning import APIVersionMiddleware

# Startup
from services.common.startup import StartupValidator

# Session Store
from services.common.session_store import SessionStore, generate_session_id

# Request Middleware
from services.common.request_middleware import (
    RequestEnhancementMiddleware,
    RequestLoggingMiddleware,
    InputValidationMiddleware,
    mask_sensitive_data,
)

# Models
from services.common.models import (
    UserModel,
    SessionModel,
    APIKeyModel,
    AuditLogModel,
    ScanModel,
    FindingModel,
)

# API Documentation
from services.common.api_documentation import (
    APIVersion as ApiDocVersion,
    APIEndpointMetadata,
    APIDocumentationHelper,
    add_openapi_info,
    create_versioned_router,
)

# --- New premium modules ---

# Circuit Breaker
from services.common.circuit_breaker import (
    CircuitBreaker,
    CircuitBreakerError,
    CircuitBreakerRegistry,
    CircuitState,
    circuit_breaker,
)

# Rate Limiting
from services.common.rate_limiting import (
    RateLimitAlgorithm,
    RateLimitConfig,
    RateLimitMiddleware,
    RateLimiter,
    get_rate_limiter,
)

# Distributed Lock
from services.common.distributed_lock import (
    DistributedLock,
    LockAcquisitionError,
    LockRegistry,
    distributed_lock,
)

# Audit Logger
from services.common.audit_logger import (
    AuditEvent,
    AuditLogger,
    EventCategory,
    SeverityLevel,
    get_audit_logger,
)

# Feature Flags
from services.common.feature_flags import FeatureFlag, FeatureFlagManager, get_feature_flags

# Service Discovery Advanced
from services.common.service_discovery_advanced import (
    LoadBalancingStrategy,
    ServiceDiscovery,
    ServiceHealth as AdvServiceHealth,
    ServiceInstance,
)

# Tenant Isolation
from services.common.tenant_isolation import TenantContext, TenantIsolationMiddleware

# Request Transformation & Security
from services.common.request_transform import (
    SecurityMiddleware,
    redact_pii_from_response,
)

__all__ = [
    # Database
    "Base",
    "SessionLocal",
    "engine",
    "get_db",
    "get_read_db",
    # Caching
    "CacheKey",
    "CacheManager",
    "cache_result",
    "cache_result_sync",
    "close_redis_pool",
    "get_redis",
    "init_redis_pool",
    "MultiLevelCache",
    "get_multi_cache",
    # Security
    "sanitize_for_log",
    "normalize_org_slug",
    "sanitize_scan_id",
    "validate_outbound_url",
    "ensure_safe_child_path",
    # JWT
    "decode_jwt",
    # Logging
    "setup_structured_logging",
    # Observability
    "setup_observability",
    # Health
    "HealthStatus",
    "ServiceHealth",
    "ServiceHealthChecker",
    "DependencyMapper",
    "SystemHealthReport",
    # Exceptions
    "CosmicSecException",
    "AuthenticationError",
    "AuthorizationError",
    "ConflictError",
    "ErrorCode",
    "ErrorSeverity",
    "ExternalServiceError",
    "NotFoundError",
    "RateLimitError",
    "ServiceUnavailableError",
    "ValidationError",
    "log_exception",
    # Error Handling
    "ErrorHandlingCosmicSecException",
    "ErrorHandlingErrorCode",
    "ErrorResponse",
    "ErrorHandlingErrorSeverity",
    "ResourceNotFoundException",
    "SuccessResponse",
    "ValidationException",
    "register_exception_handlers",
    # Events
    "publish",
    "subscribe",
    "close_events",
    # Egress
    "create_async_client",
    # Versioning
    "APIVersionMiddleware",
    # Startup
    "StartupValidator",
    # Session
    "SessionStore",
    "generate_session_id",
    # Request Middleware
    "RequestEnhancementMiddleware",
    "RequestLoggingMiddleware",
    "InputValidationMiddleware",
    "mask_sensitive_data",
    # Models
    "UserModel",
    "SessionModel",
    "APIKeyModel",
    "AuditLogModel",
    "ScanModel",
    "FindingModel",
    # API Docs
    "ApiDocVersion",
    "APIEndpointMetadata",
    "APIDocumentationHelper",
    "add_openapi_info",
    "create_versioned_router",
    # Premium modules
    "CircuitBreaker",
    "CircuitBreakerError",
    "CircuitBreakerRegistry",
    "CircuitState",
    "circuit_breaker",
    "RateLimitAlgorithm",
    "RateLimitConfig",
    "RateLimitMiddleware",
    "RateLimiter",
    "get_rate_limiter",
    "DistributedLock",
    "LockAcquisitionError",
    "LockRegistry",
    "distributed_lock",
    "AuditEvent",
    "AuditLogger",
    "EventCategory",
    "SeverityLevel",
    "get_audit_logger",
    "FeatureFlag",
    "FeatureFlagManager",
    "get_feature_flags",
    "LoadBalancingStrategy",
    "ServiceDiscovery",
    "AdvServiceHealth",
    "ServiceInstance",
    "TenantContext",
    "TenantIsolationMiddleware",
    "SecurityMiddleware",
    "redact_pii_from_response",
]
