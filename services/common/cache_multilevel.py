"""Multi-level caching with in-memory LRU + Redis backend.

Provides a tiered caching strategy:
  L1: In-memory LRU cache (fast, limited size)
  L2: Redis cache (shared, larger capacity)

Benefits:
  - Reduced Redis load for hot keys
  - Graceful degradation if Redis is unavailable
  - Configurable TTL per tier
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections import OrderedDict
from datetime import timedelta
from typing import Any

logger = logging.getLogger(__name__)


class LRUCache:
    """Thread-safe LRU cache with TTL support."""

    def __init__(self, max_size: int = 1000) -> None:
        self.max_size = max_size
        self._cache: OrderedDict[str, tuple[Any, float]] = OrderedDict()
        self._lock = asyncio.Lock()

    async def get(self, key: str) -> Any | None:
        async with self._lock:
            if key not in self._cache:
                return None
            value, expiry = self._cache[key]
            if expiry > 0 and time.time() > expiry:
                self._cache.pop(key, None)
                return None
            # Move to end (most recently used)
            self._cache.move_to_end(key)
            return value

    async def put(self, key: str, value: Any, ttl: float = 0) -> None:
        async with self._lock:
            if key in self._cache:
                self._cache.move_to_end(key)
            expiry = time.time() + ttl if ttl > 0 else 0
            self._cache[key] = (value, expiry)
            # Evict oldest if over capacity
            while len(self._cache) > self.max_size:
                self._cache.popitem(last=False)

    async def delete(self, key: str) -> bool:
        async with self._lock:
            return self._cache.pop(key, None) is not None

    async def clear(self) -> None:
        async with self._lock:
            self._cache.clear()

    def size(self) -> int:
        return len(self._cache)

    async def get_stats(self) -> dict[str, Any]:
        async with self._lock:
            total = len(self._cache)
            expired = sum(1 for _, (_, exp) in self._cache.items() if exp > 0 and time.time() > exp)
            return {
                "size": total,
                "max_size": self.max_size,
                "expired": expired,
                "utilization": round(total / self.max_size * 100, 1) if self.max_size > 0 else 0,
            }


class MultiLevelCache:
    """Two-tier cache: L1 (memory LRU) + L2 (Redis).

    Read path: L1 → L2 → miss
    Write path: L1 + L2 (async)
    """

    def __init__(
        self,
        *,
        l1_max_size: int = 1000,
        l1_ttl: float = 60.0,
        l2_ttl: timedelta = timedelta(hours=1),
    ) -> None:
        self.l1 = LRUCache(max_size=l1_max_size)
        self.l1_ttl = l1_ttl
        self.l2_ttl = l2_ttl
        self._redis: Any | None = None
        self._stats = {"l1_hits": 0, "l2_hits": 0, "misses": 0, "writes": 0}

    async def _get_redis(self) -> Any | None:
        if self._redis is None:
            try:
                from services.common.caching import get_redis

                self._redis = await get_redis()
            except Exception:
                return None
        return self._redis

    async def get(self, key: str) -> Any | None:
        """Get value from cache, checking L1 then L2."""
        # L1 check
        value = await self.l1.get(key)
        if value is not None:
            self._stats["l1_hits"] += 1
            return value

        # L2 check
        redis = await self._get_redis()
        if redis:
            try:
                raw = await redis.get(key)
                if raw is not None:
                    import json

                    try:
                        value = json.loads(raw)
                    except (json.JSONDecodeError, TypeError):
                        value = raw

                    # Populate L1
                    await self.l1.put(key, value, ttl=self.l1_ttl)
                    self._stats["l2_hits"] += 1
                    return value
            except Exception as exc:
                logger.warning("L2 cache read failed for key %s: %s", key, exc)

        self._stats["misses"] += 1
        return None

    async def set(
        self,
        key: str,
        value: Any,
        *,
        l1_ttl: float | None = None,
        l2_ttl: timedelta | None = None,
    ) -> bool:
        """Set value in both L1 and L2 caches."""
        l1_t = l1_ttl or self.l1_ttl
        l2_t = l2_ttl or self.l2_ttl

        # Write to L1
        await self.l1.put(key, value, ttl=l1_t)

        # Write to L2 (async, don't block)
        redis = await self._get_redis()
        if redis:
            try:
                import json

                serialized = json.dumps(value, default=str) if isinstance(value, (dict, list)) else value
                await redis.set(key, serialized, ex=int(l2_t.total_seconds()))
                self._stats["writes"] += 1
                return True
            except Exception as exc:
                logger.warning("L2 cache write failed for key %s: %s", key, exc)

        return False

    async def delete(self, key: str) -> bool:
        """Delete from both L1 and L2."""
        l1_deleted = await self.l1.delete(key)

        redis = await self._get_redis()
        if redis:
            try:
                await redis.delete(key)
                return True
            except Exception:
                pass

        return l1_deleted

    async def invalidate_pattern(self, pattern: str) -> int:
        """Delete all keys matching a pattern (Redis only)."""
        redis = await self._get_redis()
        if not redis:
            return 0

        try:
            keys = await redis.keys(pattern)
            if keys:
                await redis.delete(*keys)
                return len(keys)
        except Exception as exc:
            logger.warning("Pattern invalidation failed for %s: %s", pattern, exc)

        return 0

    async def clear(self) -> None:
        """Clear both cache tiers."""
        await self.l1.clear()
        redis = await self._get_redis()
        if redis:
            try:
                await redis.flushdb()
            except Exception:
                pass

    async def get_stats(self) -> dict[str, Any]:
        total = self._stats["l1_hits"] + self._stats["l2_hits"] + self._stats["misses"]
        hit_rate = round(
            (self._stats["l1_hits"] + self._stats["l2_hits"]) / total * 100, 1
        ) if total > 0 else 0

        return {
            "l1": await self.l1.get_stats(),
            "l1_hits": self._stats["l1_hits"],
            "l2_hits": self._stats["l2_hits"],
            "misses": self._stats["misses"],
            "writes": self._stats["writes"],
            "total_requests": total,
            "hit_rate_percent": hit_rate,
        }


# Global multi-level cache singleton
_multi_cache: MultiLevelCache | None = None


def get_multi_cache() -> MultiLevelCache:
    global _multi_cache
    if _multi_cache is None:
        _multi_cache = MultiLevelCache()
    return _multi_cache
