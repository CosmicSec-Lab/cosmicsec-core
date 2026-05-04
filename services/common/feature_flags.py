"""Feature flags system for controlled rollouts and A/B testing.

Provides:
  - Boolean flags for gradual feature rollouts
  - Percentage-based rollouts (e.g., enable for 25% of users)
  - User-targeted flags (enable for specific users/tenants)
  - Environment-scoped flags (dev, staging, prod)
  - Redis-backed persistence with local cache fallback

Usage:
    if await feature_flags.is_enabled("dark_mode", user_id="user-123"):
        # Show dark mode
        pass
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import time
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class FeatureFlag:
    """Definition of a single feature flag."""

    name: str
    enabled: bool = False
    description: str = ""
    rollout_percentage: float | None = None  # 0-100, None means no restriction
    allowed_users: list[str] = field(default_factory=list)
    allowed_tenants: list[str] = field(default_factory=list)
    environments: list[str] = field(default_factory=lambda: ["dev", "development", "staging", "prod"])
    created_at: str = ""
    updated_at: str = ""
    tags: list[str] = field(default_factory=list)
    owner: str = ""


class FeatureFlagManager:
    """Manages feature flags with Redis persistence and local cache."""

    def __init__(self, *, cache_ttl: int = 60) -> None:
        self.cache_ttl = cache_ttl
        self._flags: dict[str, FeatureFlag] = {}
        self._cache_time: float = 0.0
        self._redis: Any | None = None
        self._evaluations: dict[str, int] = {}
        self._evaluation_count: int = 0

    async def _get_redis(self) -> Any | None:
        if self._redis is None:
            try:
                from services.common.caching import get_redis

                self._redis = await get_redis()
            except Exception:
                return None
        return self._redis

    async def _load_flags(self) -> None:
        """Load flags from Redis or initialize defaults."""
        now = time.time()
        if now - self._cache_time < self.cache_ttl:
            return  # Cache still valid

        redis = await self._get_redis()
        if redis:
            try:
                flags_json = await redis.get("feature_flags:all")
                if flags_json:
                    data = json.loads(flags_json)
                    for name, flag_data in data.items():
                        self._flags[name] = FeatureFlag(**flag_data)
                    self._cache_time = now
                    return
            except Exception as exc:
                logger.warning("Failed to load feature flags from Redis: %s", exc)

        # Initialize defaults from environment only if no flags are loaded yet
        if not self._flags:
            self._load_env_flags()
        self._cache_time = now

    def _load_env_flags(self) -> None:
        """Load feature flags from environment variables."""
        env = os.getenv("APP_ENV", "development")

        # Parse COSMICSEC_FEATURE_FLAGS env var (JSON format)
        flags_json = os.getenv("COSMICSEC_FEATURE_FLAGS", "{}")
        try:
            flags_data = json.loads(flags_json)
            for name, config in flags_data.items():
                self._flags[name] = FeatureFlag(
                    name=name,
                    enabled=config.get("enabled", False),
                    description=config.get("description", ""),
                    rollout_percentage=config.get("rollout_percentage"),
                    allowed_users=config.get("allowed_users", []),
                    allowed_tenants=config.get("allowed_tenants", []),
                    environments=config.get("environments", ["dev", "development", "staging", "prod"]),
                    tags=config.get("tags", []),
                    owner=config.get("owner", ""),
                )
        except json.JSONDecodeError:
            logger.warning("Invalid COSMICSEC_FEATURE_FLAGS JSON")

        # Individual flag overrides: COSMICSEC_FLAG_<NAME>=true/false
        for key, value in os.environ.items():
            if key.startswith("COSMICSEC_FLAG_"):
                flag_name = key[len("COSMICSEC_FLAG_") :].lower()
                self._flags[flag_name] = FeatureFlag(
                    name=flag_name,
                    enabled=value.lower() in ("true", "1", "yes", "on"),
                    description=f"Flag from env var {key}",
                    environments=["dev", "development", "staging", "prod"],
                )

    def _is_in_rollout(self, flag: FeatureFlag, user_id: str | None = None) -> bool:
        """Deterministic check if user falls within rollout percentage."""
        if flag.rollout_percentage <= 0:
            return False
        if flag.rollout_percentage >= 100:
            return True

        if user_id is None:
            return False

        # Use hash for deterministic assignment
        hash_value = int(hashlib.sha256(f"{flag.name}:{user_id}".encode()).hexdigest(), 16)
        return (hash_value % 100) < flag.rollout_percentage

    async def is_enabled(
        self,
        flag_name: str,
        *,
        user_id: str | None = None,
        tenant_id: str | None = None,
        environment: str | None = None,
    ) -> bool:
        """Check if a feature flag is enabled for the given context."""
        self._evaluation_count += 1
        key = flag_name
        self._evaluations[key] = self._evaluations.get(key, 0) + 1

        await self._load_flags()

        flag = self._flags.get(flag_name)
        if flag is None:
            return False

        # Environment check
        env = environment or os.getenv("APP_ENV", "development")
        if env not in flag.environments:
            return False

        # Explicitly disabled
        if not flag.enabled:
            return False

        # Allowed users check
        if flag.allowed_users:
            if user_id is None:
                return False
            if user_id not in flag.allowed_users:
                return False

        # Allowed tenants check
        if flag.allowed_tenants:
            if tenant_id is None:
                return False
            if tenant_id not in flag.allowed_tenants:
                return False

        # Rollout percentage check (None means no restriction)
        if flag.rollout_percentage is not None:
            return self._is_in_rollout(flag, user_id)

        return True

    async def set_flag(self, flag: FeatureFlag) -> None:
        """Create or update a feature flag."""
        flag.updated_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        if not flag.created_at:
            flag.created_at = flag.updated_at

        self._flags[flag.name] = flag
        self._cache_time = 0  # Invalidate cache

        # Persist to Redis
        redis = await self._get_redis()
        if redis:
            try:
                data = {name: vars(f) for name, f in self._flags.items()}
                await redis.set("feature_flags:all", json.dumps(data), ex=300)
            except Exception as exc:
                logger.warning("Failed to persist feature flags to Redis: %s", exc)

    async def delete_flag(self, flag_name: str) -> bool:
        """Delete a feature flag."""
        if flag_name in self._flags:
            del self._flags[flag_name]
            self._cache_time = 0

            redis = await self._get_redis()
            if redis:
                try:
                    data = {name: vars(f) for name, f in self._flags.items()}
                    await redis.set("feature_flags:all", json.dumps(data), ex=300)
                except Exception:
                    pass
            return True
        return False

    def get_all_flags(self) -> dict[str, FeatureFlag]:
        """Return all registered feature flags."""
        return dict(self._flags)

    def get_stats(self) -> dict[str, Any]:
        """Get feature flag evaluation statistics."""
        return {
            "total_flags": len(self._flags),
            "enabled_flags": sum(1 for f in self._flags.values() if f.enabled),
            "total_evaluations": self._evaluation_count,
            "evaluations_per_flag": dict(self._evaluations),
        }


# Global feature flag manager singleton
_feature_flags: FeatureFlagManager | None = None


def get_feature_flags() -> FeatureFlagManager:
    global _feature_flags
    if _feature_flags is None:
        _feature_flags = FeatureFlagManager()
    return _feature_flags
