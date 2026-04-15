"""
CosmicSec Session Store — Redis-backed session management with in-memory fallback.

Provides a unified interface for session CRUD operations.  When Redis is
available it is used as the primary store.  If Redis is unreachable, a local
in-memory store with TTL-based expiration is used, and a warning is logged.
"""

from __future__ import annotations

import logging
import os
import threading
import time
import uuid
from abc import ABC, abstractmethod
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Session store interface
# ---------------------------------------------------------------------------


class SessionStore(ABC):
    """Abstract session storage backend."""

    @abstractmethod
    async def store_session(
        self,
        user_id: str,
        session_id: str,
        token_hash: str,
        ttl: int = 86400,
        *,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> bool:
        ...

    @abstractmethod
    async def validate_session(self, session_id: str) -> bool:
        ...

    @abstractmethod
    async def get_session(self, session_id: str) -> dict[str, Any] | None:
        ...

    @abstractmethod
    async def revoke_session(self, session_id: str) -> bool:
        ...

    @abstractmethod
    async def revoke_all_sessions(self, user_id: str) -> int:
        ...

    @abstractmethod
    async def get_active_sessions(self, user_id: str) -> list[dict[str, Any]]:
        ...


# ---------------------------------------------------------------------------
# Redis implementation
# ---------------------------------------------------------------------------

_SESSION_PREFIX = "cosmicsec:session:"
_USER_SESSIONS_PREFIX = "cosmicsec:user_sessions:"


class RedisSessionStore(SessionStore):
    """Redis-backed session storage with automatic TTL."""

    def __init__(self, redis_client: Any) -> None:
        self._redis = redis_client

    async def store_session(
        self,
        user_id: str,
        session_id: str,
        token_hash: str,
        ttl: int = 86400,
        *,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> bool:
        import json

        key = f"{_SESSION_PREFIX}{session_id}"
        data = json.dumps(
            {
                "user_id": user_id,
                "session_id": session_id,
                "token_hash": token_hash,
                "ip_address": ip_address,
                "user_agent": user_agent,
                "created_at": time.time(),
            }
        )
        await self._redis.setex(key, ttl, data)
        # Track per-user session set
        user_key = f"{_USER_SESSIONS_PREFIX}{user_id}"
        await self._redis.sadd(user_key, session_id)
        await self._redis.expire(user_key, ttl)
        return True

    async def validate_session(self, session_id: str) -> bool:
        key = f"{_SESSION_PREFIX}{session_id}"
        return await self._redis.exists(key) > 0

    async def get_session(self, session_id: str) -> dict[str, Any] | None:
        import json

        key = f"{_SESSION_PREFIX}{session_id}"
        raw = await self._redis.get(key)
        if raw is None:
            return None
        return json.loads(raw)

    async def revoke_session(self, session_id: str) -> bool:
        key = f"{_SESSION_PREFIX}{session_id}"
        deleted = await self._redis.delete(key)
        return deleted > 0

    async def revoke_all_sessions(self, user_id: str) -> int:
        user_key = f"{_USER_SESSIONS_PREFIX}{user_id}"
        session_ids = await self._redis.smembers(user_key)
        count = 0
        for sid in session_ids:
            sid_str = sid if isinstance(sid, str) else sid.decode()
            key = f"{_SESSION_PREFIX}{sid_str}"
            count += await self._redis.delete(key)
        await self._redis.delete(user_key)
        return count

    async def get_active_sessions(self, user_id: str) -> list[dict[str, Any]]:
        import json

        user_key = f"{_USER_SESSIONS_PREFIX}{user_id}"
        session_ids = await self._redis.smembers(user_key)
        sessions: list[dict[str, Any]] = []
        for sid in session_ids:
            sid_str = sid if isinstance(sid, str) else sid.decode()
            key = f"{_SESSION_PREFIX}{sid_str}"
            raw = await self._redis.get(key)
            if raw:
                sessions.append(json.loads(raw))
            else:
                # Session expired; clean up set
                await self._redis.srem(user_key, sid_str)
        return sessions


# ---------------------------------------------------------------------------
# In-memory fallback implementation
# ---------------------------------------------------------------------------


class LocalSessionStore(SessionStore):
    """In-memory session store with TTL-based expiration (not persistent)."""

    def __init__(self) -> None:
        self._sessions: dict[str, dict[str, Any]] = {}
        self._user_sessions: dict[str, set[str]] = {}
        self._lock = threading.Lock()
        logger.warning(
            "Redis unavailable, using in-memory sessions (not persistent across restarts)"
        )

    def _prune_expired(self) -> None:
        now = time.time()
        expired = [
            sid
            for sid, data in self._sessions.items()
            if now > data.get("_expires_at", float("inf"))
        ]
        for sid in expired:
            data = self._sessions.pop(sid, None)
            if data:
                uid = data.get("user_id", "")
                if uid in self._user_sessions:
                    self._user_sessions[uid].discard(sid)

    async def store_session(
        self,
        user_id: str,
        session_id: str,
        token_hash: str,
        ttl: int = 86400,
        *,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> bool:
        with self._lock:
            self._prune_expired()
            self._sessions[session_id] = {
                "user_id": user_id,
                "session_id": session_id,
                "token_hash": token_hash,
                "ip_address": ip_address,
                "user_agent": user_agent,
                "created_at": time.time(),
                "_expires_at": time.time() + ttl,
            }
            self._user_sessions.setdefault(user_id, set()).add(session_id)
        return True

    async def validate_session(self, session_id: str) -> bool:
        with self._lock:
            self._prune_expired()
            return session_id in self._sessions

    async def get_session(self, session_id: str) -> dict[str, Any] | None:
        with self._lock:
            self._prune_expired()
            data = self._sessions.get(session_id)
            if data is None:
                return None
            return {k: v for k, v in data.items() if not k.startswith("_")}

    async def revoke_session(self, session_id: str) -> bool:
        with self._lock:
            data = self._sessions.pop(session_id, None)
            if data:
                uid = data.get("user_id", "")
                if uid in self._user_sessions:
                    self._user_sessions[uid].discard(session_id)
                return True
        return False

    async def revoke_all_sessions(self, user_id: str) -> int:
        with self._lock:
            sids = self._user_sessions.pop(user_id, set())
            count = 0
            for sid in sids:
                if self._sessions.pop(sid, None) is not None:
                    count += 1
            return count

    async def get_active_sessions(self, user_id: str) -> list[dict[str, Any]]:
        with self._lock:
            self._prune_expired()
            sids = self._user_sessions.get(user_id, set())
            return [
                {k: v for k, v in self._sessions[sid].items() if not k.startswith("_")}
                for sid in sids
                if sid in self._sessions
            ]


# ---------------------------------------------------------------------------
# Factory — returns the best available session store
# ---------------------------------------------------------------------------

_store_instance: SessionStore | None = None


async def get_session_store() -> SessionStore:
    """Return a session store instance (Redis if available, local otherwise)."""
    global _store_instance
    if _store_instance is not None:
        return _store_instance

    try:
        import redis.asyncio as aioredis

        redis_url = os.getenv("REDIS_URL") or (
            f"redis://:{os.getenv('REDIS_PASSWORD', '')}@"
            f"{os.getenv('REDIS_HOST', 'localhost')}:"
            f"{os.getenv('REDIS_PORT', '6379')}/0"
        )
        client = aioredis.from_url(redis_url, decode_responses=True, socket_connect_timeout=3)
        await client.ping()
        _store_instance = RedisSessionStore(client)
        logger.info("Session store: Redis connected")
    except Exception:
        logger.warning("Redis not available — falling back to in-memory session store")
        _store_instance = LocalSessionStore()

    return _store_instance


def generate_session_id() -> str:
    """Generate a cryptographically secure session identifier."""
    return uuid.uuid4().hex
