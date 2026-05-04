"""Distributed lock manager for cross-service coordination.

Provides distributed locking via Redis with:
  - Reentrant locks (same holder can acquire multiple times)
  - Lock expiry with automatic cleanup
  - Watchdog mechanism for long-running operations
  - Lock contention metrics

Usage:
    async with DistributedLock("scan:123", ttl=30) as lock:
        # Critical section
        pass
"""

from __future__ import annotations

import asyncio
import logging
import time
import uuid
from typing import Any

logger = logging.getLogger(__name__)


class LockAcquisitionError(Exception):
    """Raised when a distributed lock cannot be acquired."""

    def __init__(self, lock_name: str, wait_time: float) -> None:
        self.lock_name = lock_name
        self.wait_time = wait_time
        super().__init__(f"Failed to acquire lock '{lock_name}' within {wait_time:.1f}s")


class DistributedLock:
    """Distributed lock with Redis backend and watchdog support.

    Args:
        name: Unique lock identifier (e.g., "scan:123", "report:gen:456").
        ttl: Lock time-to-live in seconds (auto-release after this duration).
        retry_interval: Seconds between lock acquisition attempts.
        max_wait: Maximum seconds to wait before raising LockAcquisitionError.
        watchdog_interval: Seconds between watchdog refreshes (ttl/3 by default).
    """

    def __init__(
        self,
        name: str,
        *,
        ttl: float = 30.0,
        retry_interval: float = 0.5,
        max_wait: float = 10.0,
        watchdog_interval: float | None = None,
    ) -> None:
        self.name = name
        self.ttl = ttl
        self.retry_interval = retry_interval
        self.max_wait = max_wait
        self.watchdog_interval = watchdog_interval or (ttl / 3)
        self._holder_id = str(uuid.uuid4())
        self._redis: Any | None = None
        self._watchdog_task: asyncio.Task | None = None
        self._acquired = False
        self._acquire_time: float = 0.0

    async def _get_redis(self) -> Any:
        if self._redis is None:
            from services.common.caching import get_redis

            self._redis = await get_redis()
        return self._redis

    async def acquire(self) -> bool:
        """Attempt to acquire the distributed lock.

        Returns:
            True if lock was acquired, False if timeout exceeded.
        """
        redis = await self._get_redis()
        start_time = time.monotonic()
        lock_key = f"lock:{self.name}"

        while (time.monotonic() - start_time) < self.max_wait:
            try:
                # Use SET NX EX for atomic lock acquisition
                acquired = await redis.set(lock_key, self._holder_id, nx=True, ex=int(self.ttl))
                if acquired:
                    self._acquired = True
                    self._acquire_time = time.monotonic()
                    logger.debug("Lock acquired: %s (holder=%s)", self.name, self._holder_id[:8])

                    # Start watchdog to extend TTL for long operations
                    self._watchdog_task = asyncio.create_task(self._watchdog())
                    return True

                # Check if we already hold this lock (reentrant)
                current_holder = await redis.get(lock_key)
                if current_holder == self._holder_id:
                    await redis.expire(lock_key, int(self.ttl))
                    self._acquired = True
                    self._acquire_time = time.monotonic()
                    return True

            except Exception as exc:
                logger.warning("Redis lock acquisition error for %s: %s", self.name, exc)
                # Fail open: if Redis is down, don't block operations
                return False

            await asyncio.sleep(self.retry_interval)

        elapsed = time.monotonic() - start_time
        logger.warning("Lock acquisition timeout for %s after %.1fs", self.name, elapsed)
        return False

    async def release(self) -> bool:
        """Release the distributed lock."""
        if not self._acquired:
            return True

        # Stop watchdog
        if self._watchdog_task and not self._watchdog_task.done():
            self._watchdog_task.cancel()
            try:
                await self._watchdog_task
            except asyncio.CancelledError:
                pass

        try:
            redis = await self._get_redis()
            lock_key = f"lock:{self.name}"

            # Only release if we still hold the lock
            current_holder = await redis.get(lock_key)
            if current_holder == self._holder_id:
                await redis.delete(lock_key)
                logger.debug("Lock released: %s", self.name)

        except Exception as exc:
            logger.warning("Redis lock release error for %s: %s", self.name, exc)
            return False
        finally:
            self._acquired = False

        return True

    async def _watchdog(self) -> None:
        """Periodically extend the lock TTL while held."""
        try:
            while self._acquired:
                await asyncio.sleep(self.watchdog_interval)
                if self._acquired:
                    try:
                        redis = await self._get_redis()
                        lock_key = f"lock:{self.name}"
                        current_holder = await redis.get(lock_key)
                        if current_holder == self._holder_id:
                            await redis.expire(lock_key, int(self.ttl))
                            logger.debug(
                                "Lock watchdog refreshed: %s (holder=%s)",
                                self.name,
                                self._holder_id[:8],
                            )
                    except Exception:
                        pass
        except asyncio.CancelledError:
            pass

    async def __aenter__(self) -> DistributedLock:
        acquired = await self.acquire()
        if not acquired:
            raise LockAcquisitionError(self.name, self.max_wait)
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        await self.release()

    @property
    def is_acquired(self) -> bool:
        return self._acquired

    @property
    def holder_id(self) -> str:
        return self._holder_id

    @property
    def hold_duration(self) -> float:
        if not self._acquired:
            return 0.0
        return time.monotonic() - self._acquire_time


class LockRegistry:
    """Registry for tracking and managing all distributed locks."""

    _instance: LockRegistry | None = None

    def __init__(self) -> None:
        self._locks: dict[str, DistributedLock] = {}
        self._stats = {"acquired": 0, "released": 0, "timeouts": 0, "errors": 0}

    @classmethod
    def get_instance(cls) -> LockRegistry:
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def create_lock(
        self,
        name: str,
        *,
        ttl: float = 30.0,
        max_wait: float = 10.0,
    ) -> DistributedLock:
        if name not in self._locks:
            self._locks[name] = DistributedLock(name, ttl=ttl, max_wait=max_wait)
        return self._locks[name]

    def get_stats(self) -> dict[str, Any]:
        return {
            "total_locks": len(self._locks),
            "active_locks": sum(1 for lock in self._locks.values() if lock.is_acquired),
            **self._stats,
        }


def distributed_lock(name: str, **kwargs: Any):
    """Decorator to wrap an async function with a distributed lock."""

    def decorator(func):
        async def wrapper(*args, **wrapper_kwargs):
            lock = LockRegistry.get_instance().create_lock(name, **kwargs)
            async with lock:
                return await func(*args, **wrapper_kwargs)

        return wrapper

    return decorator
