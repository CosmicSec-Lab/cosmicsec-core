"""Circuit breaker pattern for resilient inter-service communication.

Implements the circuit breaker state machine:
  CLOSED → OPEN (on failure threshold) → HALF_OPEN (after timeout) → CLOSED (on success)

Usage:
    breaker = CircuitBreaker(name="auth-service", failure_threshold=5, recovery_timeout=30)
    async with breaker:
        response = await httpx.AsyncClient().get(url)
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Callable
from enum import Enum
from functools import wraps
from typing import Any, TypeVar

logger = logging.getLogger(__name__)

T = TypeVar("T")


class CircuitState(str, Enum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class CircuitBreakerError(Exception):
    """Raised when circuit breaker is open and request is rejected."""

    def __init__(self, service_name: str, remaining_seconds: float) -> None:
        self.service_name = service_name
        self.remaining_seconds = remaining_seconds
        super().__init__(
            f"Circuit breaker OPEN for '{service_name}'. Retry in {remaining_seconds:.1f}s"
        )


class CircuitBreakerStats:
    """Track circuit breaker metrics for observability."""

    def __init__(self) -> None:
        self.total_requests = 0
        self.successful_requests = 0
        self.failed_requests = 0
        self.rejected_requests = 0
        self.last_state_change: float = time.monotonic()

    @property
    def failure_rate(self) -> float:
        if self.total_requests == 0:
            return 0.0
        return self.failed_requests / self.total_requests

    @property
    def success_rate(self) -> float:
        if self.total_requests == 0:
            return 0.0
        return self.successful_requests / self.total_requests

    def record_success(self) -> None:
        self.total_requests += 1
        self.successful_requests += 1

    def record_failure(self) -> None:
        self.total_requests += 1
        self.failed_requests += 1

    def record_rejection(self) -> None:
        self.total_requests += 1
        self.rejected_requests += 1

    def reset(self) -> None:
        self.total_requests = 0
        self.successful_requests = 0
        self.failed_requests = 0
        self.rejected_requests = 0
        self.last_state_change = time.monotonic()

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_requests": self.total_requests,
            "successful_requests": self.successful_requests,
            "failed_requests": self.failed_requests,
            "rejected_requests": self.rejected_requests,
            "failure_rate": round(self.failure_rate, 4),
            "success_rate": round(self.success_rate, 4),
        }


class CircuitBreaker:
    """Resilience circuit breaker for downstream service calls.

    Args:
        name: Identifier for this circuit breaker (usually service name).
        failure_threshold: Number of consecutive failures before opening circuit.
        recovery_timeout: Seconds to wait before transitioning to HALF_OPEN.
        success_threshold: Consecutive successes needed in HALF_OPEN to close.
    """

    def __init__(
        self,
        name: str,
        *,
        failure_threshold: int = 5,
        recovery_timeout: float = 30.0,
        success_threshold: int = 2,
    ) -> None:
        self.name = name
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.success_threshold = success_threshold

        self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._success_count = 0
        self._last_failure_time: float = 0.0
        self._stats = CircuitBreakerStats()
        self._lock = __import__("threading").Lock()

    @property
    def state(self) -> CircuitState:
        with self._lock:
            if self._state == CircuitState.OPEN:
                elapsed = time.monotonic() - self._last_failure_time
                if elapsed >= self.recovery_timeout:
                    self._transition_to(CircuitState.HALF_OPEN)
            return self._state

    def _transition_to(self, new_state: CircuitState) -> None:
        old_state = self._state
        self._state = new_state
        self._stats.last_state_change = time.monotonic()
        logger.info(
            "CircuitBreaker[%s]: %s → %s",
            self.name,
            old_state.value,
            new_state.value,
        )

    def _record_success(self) -> None:
        self._stats.record_success()
        with self._lock:
            if self._state == CircuitState.HALF_OPEN:
                self._success_count += 1
                if self._success_count >= self.success_threshold:
                    self._failure_count = 0
                    self._success_count = 0
                    self._transition_to(CircuitState.CLOSED)
            else:
                self._failure_count = 0

    def _record_failure(self) -> None:
        self._stats.record_failure()
        with self._lock:
            self._last_failure_time = time.monotonic()
            self._failure_count += 1
            if self._state == CircuitState.HALF_OPEN:
                self._transition_to(CircuitState.OPEN)
            elif self._failure_count >= self.failure_threshold:
                self._transition_to(CircuitState.OPEN)

    def can_execute(self) -> bool:
        """Return True if the circuit allows a request."""
        return self.state != CircuitState.OPEN

    def remaining_recovery_time(self) -> float:
        """Seconds until circuit transitions from OPEN to HALF_OPEN."""
        if self._state != CircuitState.OPEN:
            return 0.0
        elapsed = time.monotonic() - self._last_failure_time
        return max(0.0, self.recovery_timeout - elapsed)

    async def call(self, func: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        """Execute a function through the circuit breaker."""
        current_state = self.state
        if current_state == CircuitState.OPEN:
            self._stats.record_rejection()
            remaining = self.remaining_recovery_time()
            raise CircuitBreakerError(self.name, remaining)

        try:
            if asyncio.iscoroutinefunction(func):
                result = await func(*args, **kwargs)
            else:
                result = func(*args, **kwargs)
            self._record_success()
            return result
        except Exception as exc:
            self._record_failure()
            raise

    def get_stats(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "state": self.state.value,
            "failure_count": self._failure_count,
            "success_count": self._success_count,
            "failure_threshold": self.failure_threshold,
            "recovery_timeout": self.recovery_timeout,
            **self._stats.to_dict(),
        }

    def reset(self) -> None:
        with self._lock:
            self._state = CircuitState.CLOSED
            self._failure_count = 0
            self._success_count = 0
            self._last_failure_time = 0.0
            self._stats.reset()


class CircuitBreakerRegistry:
    """Central registry of circuit breakers for all downstream services."""

    _instance: CircuitBreakerRegistry | None = None

    def __init__(self) -> None:
        self._breakers: dict[str, CircuitBreaker] = {}
        self._default_config = {
            "failure_threshold": 5,
            "recovery_timeout": 30.0,
            "success_threshold": 2,
        }

    @classmethod
    def get_instance(cls) -> CircuitBreakerRegistry:
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def get_or_create(
        self,
        service_name: str,
        *,
        failure_threshold: int | None = None,
        recovery_timeout: float | None = None,
        success_threshold: int | None = None,
    ) -> CircuitBreaker:
        if service_name not in self._breakers:
            self._breakers[service_name] = CircuitBreaker(
                name=service_name,
                failure_threshold=failure_threshold or self._default_config["failure_threshold"],
                recovery_timeout=recovery_timeout or self._default_config["recovery_timeout"],
                success_threshold=success_threshold or self._default_config["success_threshold"],
            )
        return self._breakers[service_name]

    def get_all_stats(self) -> dict[str, dict[str, Any]]:
        return {name: cb.get_stats() for name, cb in self._breakers.items()}

    def reset_all(self) -> None:
        for cb in self._breakers.values():
            cb.reset()

    def reset_service(self, service_name: str) -> None:
        if service_name in self._breakers:
            self._breakers[service_name].reset()


def circuit_breaker(service_name: str, **kwargs: Any):
    """Decorator to wrap an async function with a circuit breaker."""

    def decorator(func: Callable) -> Callable:
        cb = CircuitBreakerRegistry.get_instance().get_or_create(service_name, **kwargs)

        @wraps(func)
        async def wrapper(*args: Any, **wrapper_kwargs: Any) -> Any:
            return await cb.call(func, *args, **wrapper_kwargs)

        return wrapper

    return decorator
