"""Advanced rate limiting with Redis backend and sliding window algorithm.

Provides per-user, per-IP, and per-endpoint rate limiting with:
  - Fixed window counter
  - Sliding window log
  - Token bucket algorithm
  - Rate limit headers (X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset)
"""

from __future__ import annotations

import logging
import time
from collections.abc import Awaitable, Callable
from enum import Enum
from typing import Any

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint

logger = logging.getLogger(__name__)


class RateLimitAlgorithm(str, Enum):
    FIXED_WINDOW = "fixed_window"
    SLIDING_WINDOW = "sliding_window"
    TOKEN_BUCKET = "token_bucket"


class RateLimitConfig:
    """Configuration for a rate limit rule."""

    def __init__(
        self,
        max_requests: int,
        window_seconds: int,
        algorithm: RateLimitAlgorithm = RateLimitAlgorithm.SLIDING_WINDOW,
    ) -> None:
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.algorithm = algorithm


# Default rate limit rules (can be overridden via env vars)
_DEFAULT_LIMITS: dict[str, RateLimitConfig] = {
    "default": RateLimitConfig(max_requests=100, window_seconds=60),
    "auth": RateLimitConfig(max_requests=10, window_seconds=60),
    "scan": RateLimitConfig(max_requests=20, window_seconds=3600),
    "ai": RateLimitConfig(max_requests=50, window_seconds=60),
    "api": RateLimitConfig(max_requests=200, window_seconds=60),
    "admin": RateLimitConfig(max_requests=500, window_seconds=60),
}


class RateLimiter:
    """Redis-backed rate limiter with multiple algorithm support."""

    def __init__(self, redis_client: Any | None = None) -> None:
        self.redis = redis_client
        self._local_store: dict[str, list[float]] = {}
        self._local_tokens: dict[str, dict[str, float]] = {}
        self._local_windows: dict[str, dict[str, int]] = {}

    async def _get_redis(self) -> Any | None:
        if self.redis is None:
            try:
                from services.common.caching import get_redis

                self.redis = await get_redis()
            except Exception:
                return None
        return self.redis

    def _check_local_sliding_window(
        self, key: str, max_requests: int, window_seconds: int
    ) -> tuple[bool, int, float]:
        """Check rate limit using in-memory sliding window."""
        now = time.time()
        cutoff = now - window_seconds

        if key not in self._local_store:
            self._local_store[key] = []

        # Remove expired entries
        self._local_store[key] = [t for t in self._local_store[key] if t > cutoff]

        current_count = len(self._local_store[key])
        remaining = max(0, max_requests - current_count)
        reset_time = cutoff + window_seconds if self._local_store[key] else now + window_seconds

        if current_count >= max_requests:
            return False, remaining, reset_time

        self._local_store[key].append(now)
        return True, remaining, reset_time

    def _check_local_token_bucket(
        self, key: str, max_requests: int, window_seconds: int
    ) -> tuple[bool, int, float]:
        """Check rate limit using in-memory token bucket."""
        now = time.time()
        refill_rate = max_requests / window_seconds

        if key not in self._local_tokens:
            self._local_tokens[key] = {"tokens": float(max_requests), "last_refill": now}

        bucket = self._local_tokens[key]
        elapsed = now - bucket["last_refill"]
        bucket["tokens"] = min(max_requests, bucket["tokens"] + elapsed * refill_rate)
        bucket["last_refill"] = now

        if bucket["tokens"] >= 1.0:
            bucket["tokens"] -= 1.0
            remaining = int(bucket["tokens"])
            return True, remaining, now + (1.0 / refill_rate)

        remaining = 0
        reset_time = now + ((1.0 - bucket["tokens"]) / refill_rate)
        return False, remaining, reset_time

    async def check(
        self,
        key: str,
        max_requests: int = 100,
        window_seconds: int = 60,
        algorithm: RateLimitAlgorithm = RateLimitAlgorithm.SLIDING_WINDOW,
    ) -> tuple[bool, int, float]:
        """
        Check if a request is within rate limits.

        Returns:
            Tuple of (allowed, remaining_requests, reset_timestamp)
        """
        redis_client = await self._get_redis()

        if redis_client is not None:
            return await self._check_redis(key, redis_client, max_requests, window_seconds, algorithm)

        # Fallback to local in-memory rate limiting
        if algorithm == RateLimitAlgorithm.TOKEN_BUCKET:
            return self._check_local_token_bucket(key, max_requests, window_seconds)
        return self._check_local_sliding_window(key, max_requests, window_seconds)

    async def _check_redis(
        self,
        key: str,
        redis_client: Any,
        max_requests: int,
        window_seconds: int,
        algorithm: RateLimitAlgorithm,
    ) -> tuple[bool, int, float]:
        """Redis-based rate limiting."""
        try:
            if algorithm == RateLimitAlgorithm.FIXED_WINDOW:
                return await self._fixed_window_redis(
                    key, redis_client, max_requests, window_seconds
                )
            elif algorithm == RateLimitAlgorithm.SLIDING_WINDOW:
                return await self._sliding_window_redis(
                    key, redis_client, max_requests, window_seconds
                )
            else:
                return await self._token_bucket_redis(
                    key, redis_client, max_requests, window_seconds
                )
        except Exception as exc:
            logger.warning("Redis rate limit check failed, using local fallback: %s", exc)
            return self._check_local_sliding_window(key, max_requests, window_seconds)

    async def _fixed_window_redis(
        self, key: str, redis: Any, max_requests: int, window_seconds: int
    ) -> tuple[bool, int, float]:
        now = time.time()
        window_key = f"rl:fw:{key}:{int(now // window_seconds)}"

        pipe = redis.pipeline()
        pipe.incr(window_key)
        pipe.expire(window_key, window_seconds)
        results = await pipe.execute()

        current_count = results[0]
        remaining = max(0, max_requests - current_count)
        reset_time = ((int(now // window_seconds) + 1) * window_seconds)

        return current_count <= max_requests, remaining, reset_time

    async def _sliding_window_redis(
        self, key: str, redis: Any, max_requests: int, window_seconds: int
    ) -> tuple[bool, int, float]:
        now = time.time()
        window_key = f"rl:sw:{key}"
        cutoff = now - window_seconds

        pipe = redis.pipeline()
        pipe.zremrangebyscore(window_key, 0, cutoff)
        pipe.zcard(window_key)
        pipe.zadd(window_key, {str(now): now})
        pipe.expire(window_key, window_seconds)
        results = await pipe.execute()

        current_count = results[1]
        remaining = max(0, max_requests - current_count - 1)
        reset_time = now + window_seconds

        return current_count < max_requests, remaining, reset_time

    async def _token_bucket_redis(
        self, key: str, redis: Any, max_requests: int, window_seconds: int
    ) -> tuple[bool, int, float]:
        now = time.time()
        bucket_key = f"rl:tb:{key}"
        refill_rate = max_requests / window_seconds

        pipe = redis.pipeline()
        pipe.hgetall(bucket_key)
        pipe.expire(bucket_key, window_seconds * 2)
        results = await pipe.execute()

        data = results[0]
        if data:
            tokens = float(data.get(b"tokens", max_requests))
            last_refill = float(data.get(b"last_refill", now))
        else:
            tokens = float(max_requests)
            last_refill = now

        elapsed = now - last_refill
        tokens = min(max_requests, tokens + elapsed * refill_rate)

        if tokens >= 1.0:
            tokens -= 1.0
            pipe = redis.pipeline()
            pipe.hset(bucket_key, mapping={"tokens": str(tokens), "last_refill": str(now)})
            pipe.expire(bucket_key, window_seconds * 2)
            await pipe.execute()
            remaining = int(tokens)
            return True, remaining, now + (1.0 / refill_rate)

        pipe = redis.pipeline()
        pipe.hset(bucket_key, mapping={"tokens": str(tokens), "last_refill": str(now)})
        pipe.expire(bucket_key, window_seconds * 2)
        await pipe.execute()

        reset_time = now + ((1.0 - tokens) / refill_rate)
        return False, 0, reset_time


class RateLimitMiddleware(BaseHTTPMiddleware):
    """FastAPI middleware that applies rate limiting based on request attributes."""

    def __init__(
        self,
        app: Any,
        limiter: RateLimiter | None = None,
        rules: dict[str, RateLimitConfig] | None = None,
        key_prefix: str = "cosmicsec",
    ) -> None:
        super().__init__(app)
        self.limiter = limiter or RateLimiter()
        self.rules = rules or dict(_DEFAULT_LIMITS)
        self.key_prefix = key_prefix

    def _get_route_category(self, path: str) -> str:
        """Determine rate limit category from request path."""
        path_lower = path.lower()
        if "/auth" in path_lower or "/login" in path_lower or "/register" in path_lower:
            return "auth"
        if "/scan" in path_lower:
            return "scan"
        if "/ai" in path_lower or "/analyze" in path_lower:
            return "ai"
        if "/admin" in path_lower:
            return "admin"
        return "api"

    def _get_client_key(self, request: Request) -> str:
        """Extract unique client identifier."""
        # Try API key first
        api_key = request.headers.get("X-API-Key", "")
        if api_key:
            return f"apikey:{api_key}"

        # Try authenticated user
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token_part = auth_header.split(" ", 1)[1][:64]
            return f"token:{token_part}"

        # Fall back to IP address
        forwarded = request.headers.get("X-Forwarded-For", "")
        if forwarded:
            client_ip = forwarded.split(",")[0].strip()
        else:
            client_ip = request.client.host if request.client else "unknown"

        return f"ip:{client_ip}"

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        # Skip rate limiting for health checks and docs
        path = request.url.path
        if path in ("/health", "/ready", "/api/docs", "/api/redoc", "/api/openapi.json", "/favicon.ico"):
            return await call_next(request)

        category = self._get_route_category(path)
        config = self.rules.get(category, self.rules["default"])
        client_key = self._get_client_key(request)
        rate_key = f"{self.key_prefix}:{category}:{client_key}"

        allowed, remaining, reset_time = await self.limiter.check(
            key=rate_key,
            max_requests=config.max_requests,
            window_seconds=config.window_seconds,
            algorithm=config.algorithm,
        )

        # Build response with rate limit headers
        headers = {
            "X-RateLimit-Limit": str(config.max_requests),
            "X-RateLimit-Remaining": str(max(0, remaining)),
            "X-RateLimit-Reset": str(int(reset_time)),
            "X-RateLimit-Category": category,
        }

        if not allowed:
            return Response(
                status_code=429,
                content=f'Rate limit exceeded. Retry after {int(reset_time - time.time())}s',
                media_type="text/plain",
                headers={**headers, "Retry-After": str(int(reset_time - time.time()))},
            )

        response = await call_next(request)
        for header_name, header_value in headers.items():
            response.headers[header_name] = header_value

        return response


# Global rate limiter singleton
_rate_limiter: RateLimiter | None = None


def get_rate_limiter() -> RateLimiter:
    global _rate_limiter
    if _rate_limiter is None:
        _rate_limiter = RateLimiter()
    return _rate_limiter
