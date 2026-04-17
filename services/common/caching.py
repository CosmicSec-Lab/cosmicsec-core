"""
CosmicSec Advanced Caching System
Provides Redis-based caching with automatic expiration, tags, and invalidation
"""

import hashlib
import json
import os
from collections.abc import Callable
from datetime import timedelta
from functools import wraps
from typing import Any, TypeVar

import redis
import redis.asyncio as aioredis

# Using redis.asyncio (official async client)
try:
    from redis.asyncio import Redis as AsyncRedis
except ImportError:
    AsyncRedis = None  # type: ignore

T = TypeVar("T")

# Redis connection pool
_redis_pool: AsyncRedis | None = None


async def init_redis_pool(
    host: str = "localhost",
    port: int = 6379,
    password: str | None = None,
    db: int = 0,
) -> None:
    """Initialize Redis connection pool."""
    global _redis_pool
    if _redis_pool is None:
        _redis_pool = await aioredis.from_url(
            f"redis://:{password}@{host}:{port}/{db}"
            if password
            else f"redis://{host}:{port}/{db}",
            encoding="utf-8",
            decode_responses=True,
            socket_connect_timeout=5,
            socket_keepalive=True,
            socket_keepalive_inactivity_ms=300000,
        )


async def close_redis_pool() -> None:
    """Close Redis connection pool."""
    global _redis_pool
    if _redis_pool:
        await _redis_pool.close()
        _redis_pool = None


async def get_redis() -> AsyncRedis:
    """Get Redis client from pool."""
    global _redis_pool
    if _redis_pool is None:
        await init_redis_pool(
            host=os.getenv("REDIS_HOST", "localhost"),
            port=int(os.getenv("REDIS_PORT", 6379)),
            password=os.getenv("REDIS_PASSWORD"),
            db=int(os.getenv("REDIS_DB", 0)),
        )
    return _redis_pool


class CacheKey:
    """Helper for building consistent cache keys."""

    @staticmethod
    def make(prefix: str, *parts: Any) -> str:
        """Create a cache key from prefix and parts."""
        key_parts = [prefix] + [str(p) for p in parts]
        return ":".join(key_parts)

    @staticmethod
    def hash_args(*args: Any, **kwargs: Any) -> str:
        """Hash arguments for cache key."""
        key_data = json.dumps(
            {"args": args, "kwargs": kwargs},
            sort_keys=True,
            default=str,
        )
        return hashlib.sha256(key_data.encode()).hexdigest()[:16]


class CacheManager:
    """Manages caching operations with tagging and invalidation."""

    def __init__(self, redis_client: AsyncRedis):
        self.redis = redis_client

    async def get(self, key: str) -> Any | None:
        """Get value from cache."""
        try:
            value = await self.redis.get(key)
            if value:
                try:
                    return json.loads(value)
                except json.JSONDecodeError:
                    return value
            return None
        except Exception:
            return None

    async def set(
        self,
        key: str,
        value: Any,
        ttl: timedelta | None = None,
        tags: list[str] | None = None,
    ) -> bool:
        """Set value in cache with optional TTL and tags."""
        try:
            # Serialize value
            if isinstance(value, (dict, list)):
                serialized = json.dumps(value, default=str)
            else:
                serialized = value

            # Set main key
            kwargs = {}
            if ttl:
                kwargs["ex"] = int(ttl.total_seconds())

            await self.redis.set(key, serialized, **kwargs)

            # Track tags for invalidation
            if tags:
                for tag in tags:
                    await self.redis.sadd(f"tag:{tag}", key)
                    if ttl:
                        await self.redis.expire(f"tag:{tag}", int(ttl.total_seconds()))

            return True
        except Exception:
            return False

    async def delete(self, key: str) -> bool:
        """Delete key from cache."""
        try:
            await self.redis.delete(key)
            return True
        except Exception:
            return False

    async def invalidate_tag(self, tag: str) -> int:
        """Invalidate all keys with a specific tag."""
        try:
            keys = await self.redis.smembers(f"tag:{tag}")
            if keys:
                await self.redis.delete(*keys)
                await self.redis.delete(f"tag:{tag}")
                return len(keys)
            return 0
        except Exception:
            return 0

    async def clear_all(self) -> bool:
        """Clear all cache (use with caution)."""
        try:
            await self.redis.flushdb()
            return True
        except Exception:
            return False

    async def get_stats(self) -> dict:
        """Get cache statistics."""
        try:
            info = await self.redis.info()
            return {
                "used_memory": info.get("used_memory_human"),
                "used_memory_peak": info.get("used_memory_peak_human"),
                "connected_clients": info.get("connected_clients"),
                "total_commands_processed": info.get("total_commands_processed"),
            }
        except Exception:
            return {}


def cache_result(
    ttl: timedelta = timedelta(hours=1),
    tags: list[str] | None = None,
    cache_on_exception: bool = False,
):
    """
    Decorator for caching async function results.

    Args:
        ttl: Time to live for cached result
        tags: List of tags for cache invalidation
        cache_on_exception: Whether to cache exception responses
    """

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs) -> Any:
            try:
                redis_client = await get_redis()
                cache_manager = CacheManager(redis_client)

                # Generate cache key
                cache_key = (
                    f"{func.__module__}:{func.__name__}:{CacheKey.hash_args(*args, **kwargs)}"
                )

                # Try to get from cache
                cached = await cache_manager.get(cache_key)
                if cached is not None:
                    return cached

                # Call function
                result = await func(*args, **kwargs)

                # Cache result
                await cache_manager.set(cache_key, result, ttl=ttl, tags=tags)

                return result
            except Exception:
                if cache_on_exception:
                    # Try to return cached error response
                    pass
                raise

        return wrapper

    return decorator


# Simplified sync wrapper for sync functions
def cache_result_sync(
    ttl: timedelta = timedelta(hours=1),
    tags: list[str] | None = None,
):
    """Decorator for caching sync function results."""

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            try:
                # Use Redis sync client
                redis_client = redis.from_url(
                    f"redis://{os.getenv('REDIS_HOST', 'localhost')}:{os.getenv('REDIS_PORT', 6379)}"
                )

                # Generate cache key
                cache_key = (
                    f"{func.__module__}:{func.__name__}:{CacheKey.hash_args(*args, **kwargs)}"
                )

                # Try to get from cache
                try:
                    cached = redis_client.get(cache_key)
                    if cached:
                        return json.loads(cached)
                except Exception:
                    logger.debug("Sync cache read failed for key %s", cache_key, exc_info=True)

                # Call function
                result = func(*args, **kwargs)

                # Cache result
                if isinstance(result, (dict, list)):
                    redis_client.setex(
                        cache_key,
                        int(ttl.total_seconds()),
                        json.dumps(result, default=str),
                    )
                else:
                    redis_client.setex(cache_key, int(ttl.total_seconds()), result)

                # Track tags
                if tags:
                    for tag in tags:
                        redis_client.sadd(f"tag:{tag}", cache_key)

                return result
            except Exception:
                return func(*args, **kwargs)

        return wrapper

    return decorator
