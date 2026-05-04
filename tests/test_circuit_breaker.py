"""Tests for circuit breaker pattern."""

import asyncio
import pytest

from services.common.circuit_breaker import (
    CircuitBreaker,
    CircuitBreakerError,
    CircuitBreakerRegistry,
    CircuitState,
)


class TestCircuitBreaker:
    @pytest.mark.asyncio
    async def test_closed_state_allows_calls(self):
        cb = CircuitBreaker(name="test", failure_threshold=3)
        assert cb.state == CircuitState.CLOSED
        result = await cb.call(lambda: "ok")
        assert result == "ok"

    @pytest.mark.asyncio
    async def test_opens_after_threshold(self):
        cb = CircuitBreaker(name="test", failure_threshold=3, recovery_timeout=999)

        async def failing():
            raise ValueError("fail")

        for _ in range(3):
            try:
                await cb.call(failing)
            except ValueError:
                pass

        assert cb.state == CircuitState.OPEN

    @pytest.mark.asyncio
    async def test_open_state_rejects_calls(self):
        cb = CircuitBreaker(name="test", failure_threshold=1, recovery_timeout=999)

        async def failing():
            raise ValueError("fail")

        try:
            await cb.call(failing)
        except ValueError:
            pass

        assert cb.state == CircuitState.OPEN
        with pytest.raises(CircuitBreakerError):
            await cb.call(lambda: "ok")

    @pytest.mark.asyncio
    async def test_half_open_after_timeout(self):
        cb = CircuitBreaker(name="test", failure_threshold=1, recovery_timeout=0.01)

        async def failing():
            raise ValueError("fail")

        try:
            await cb.call(failing)
        except ValueError:
            pass

        assert cb.state == CircuitState.OPEN
        await asyncio.sleep(0.02)
        assert cb.state == CircuitState.HALF_OPEN

    @pytest.mark.asyncio
    async def test_closes_after_successes_in_half_open(self):
        cb = CircuitBreaker(
            name="test",
            failure_threshold=1,
            recovery_timeout=0.01,
            success_threshold=1,
        )

        async def failing():
            raise ValueError("fail")

        try:
            await cb.call(failing)
        except ValueError:
            pass

        await asyncio.sleep(0.02)
        assert cb.state == CircuitState.HALF_OPEN

        result = await cb.call(lambda: "ok")
        assert result == "ok"
        assert cb.state == CircuitState.CLOSED

    def test_stats_tracking(self):
        cb = CircuitBreaker(name="test")
        stats = cb.get_stats()
        assert stats["name"] == "test"
        assert stats["state"] == "closed"

    def test_reset(self):
        cb = CircuitBreaker(name="test")
        cb._state = CircuitState.OPEN
        cb.reset()
        assert cb._state == CircuitState.CLOSED
        assert cb._failure_count == 0


class TestCircuitBreakerRegistry:
    def test_get_or_create(self):
        registry = CircuitBreakerRegistry()
        cb1 = registry.get_or_create("auth", failure_threshold=3)
        cb2 = registry.get_or_create("auth")
        assert cb1 is cb2  # Same instance

    def test_get_all_stats(self):
        registry = CircuitBreakerRegistry()
        registry.get_or_create("auth")
        registry.get_or_create("scan")
        stats = registry.get_all_stats()
        assert "auth" in stats
        assert "scan" in stats

    def test_reset_all(self):
        registry = CircuitBreakerRegistry()
        cb = registry.get_or_create("auth")
        cb._state = CircuitState.OPEN
        registry.reset_all()
        assert cb._state == CircuitState.CLOSED
