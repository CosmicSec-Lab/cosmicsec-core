"""Tests for multi-level cache system."""

import pytest

from services.common.cache_multilevel import LRUCache, MultiLevelCache


class TestLRUCache:
    @pytest.mark.asyncio
    async def test_basic_get_put(self):
        cache = LRUCache(max_size=10)
        await cache.put("key1", "value1")
        assert await cache.get("key1") == "value1"

    @pytest.mark.asyncio
    async def test_returns_none_for_missing(self):
        cache = LRUCache(max_size=10)
        assert await cache.get("nonexistent") is None

    @pytest.mark.asyncio
    async def test_evicts_oldest_when_full(self):
        cache = LRUCache(max_size=2)
        await cache.put("a", 1)
        await cache.put("b", 2)
        await cache.put("c", 3)  # Should evict "a"
        assert await cache.get("a") is None
        assert await cache.get("b") == 2
        assert await cache.get("c") == 3

    @pytest.mark.asyncio
    async def test_delete(self):
        cache = LRUCache(max_size=10)
        await cache.put("key1", "value1")
        assert await cache.delete("key1") is True
        assert await cache.get("key1") is None

    @pytest.mark.asyncio
    async def test_clear(self):
        cache = LRUCache(max_size=10)
        await cache.put("a", 1)
        await cache.put("b", 2)
        await cache.clear()
        assert cache.size() == 0

    @pytest.mark.asyncio
    async def test_ttl_expiry(self):
        cache = LRUCache(max_size=10)
        await cache.put("key1", "value1", ttl=0.01)  # 10ms TTL
        assert await cache.get("key1") == "value1"
        import asyncio
        await asyncio.sleep(0.02)
        assert await cache.get("key1") is None

    @pytest.mark.asyncio
    async def test_lru_order(self):
        cache = LRUCache(max_size=2)
        await cache.put("a", 1)
        await cache.put("b", 2)
        await cache.get("a")  # Access "a" to make it recently used
        await cache.put("c", 3)  # Should evict "b", not "a"
        assert await cache.get("a") == 1
        assert await cache.get("b") is None
        assert await cache.get("c") == 3


class TestMultiLevelCache:
    @pytest.mark.asyncio
    async def test_l1_get_put(self):
        cache = MultiLevelCache(l1_max_size=100)
        await cache.set("key1", {"data": "test"})
        result = await cache.get("key1")
        assert result == {"data": "test"}

    @pytest.mark.asyncio
    async def test_delete(self):
        cache = MultiLevelCache(l1_max_size=100)
        await cache.set("key1", "value1")
        await cache.delete("key1")
        assert await cache.get("key1") is None

    @pytest.mark.asyncio
    async def test_clear(self):
        cache = MultiLevelCache(l1_max_size=100)
        await cache.set("key1", "value1")
        await cache.set("key2", "value2")
        await cache.clear()
        assert await cache.get("key1") is None
        assert await cache.get("key2") is None

    @pytest.mark.asyncio
    async def test_stats(self):
        cache = MultiLevelCache(l1_max_size=100)
        await cache.set("key1", "value1")
        await cache.get("key1")
        stats = await cache.get_stats()
        assert "l1_hits" in stats
        assert "hit_rate_percent" in stats
