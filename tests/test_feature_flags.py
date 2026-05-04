"""Tests for feature flags system."""

import pytest

from services.common.feature_flags import FeatureFlag, FeatureFlagManager


class TestFeatureFlags:
    @pytest.mark.asyncio
    async def test_disabled_flag(self):
        manager = FeatureFlagManager()
        flag = FeatureFlag(name="dark_mode", enabled=False)
        await manager.set_flag(flag)
        assert await manager.is_enabled("dark_mode") is False

    @pytest.mark.asyncio
    async def test_enabled_flag(self):
        manager = FeatureFlagManager()
        flag = FeatureFlag(name="dark_mode", enabled=True)
        await manager.set_flag(flag)
        assert await manager.is_enabled("dark_mode") is True

    @pytest.mark.asyncio
    async def test_environment_restriction(self):
        manager = FeatureFlagManager()
        flag = FeatureFlag(
            name="beta_feature",
            enabled=True,
            environments=["dev", "staging"],
        )
        await manager.set_flag(flag)
        assert await manager.is_enabled("beta_feature", environment="prod") is False
        assert await manager.is_enabled("beta_feature", environment="dev") is True

    @pytest.mark.asyncio
    async def test_allowed_users(self):
        manager = FeatureFlagManager()
        flag = FeatureFlag(
            name="admin_panel",
            enabled=True,
            allowed_users=["admin@cosmicsec.com"],
        )
        await manager.set_flag(flag)
        assert await manager.is_enabled("admin_panel", user_id="admin@cosmicsec.com") is True
        assert await manager.is_enabled("admin_panel", user_id="user@other.com") is False

    @pytest.mark.asyncio
    async def test_allowed_tenants(self):
        manager = FeatureFlagManager()
        flag = FeatureFlag(
            name="enterprise_feature",
            enabled=True,
            allowed_tenants=["acme", "globex"],
        )
        await manager.set_flag(flag)
        assert await manager.is_enabled("enterprise_feature", tenant_id="acme") is True
        assert await manager.is_enabled("enterprise_feature", tenant_id="initech") is False

    @pytest.mark.asyncio
    async def test_rollout_percentage_zero(self):
        manager = FeatureFlagManager()
        flag = FeatureFlag(name="test_flag", enabled=True, rollout_percentage=0)
        await manager.set_flag(flag)
        assert await manager.is_enabled("test_flag", user_id="user-1") is False

    @pytest.mark.asyncio
    async def test_rollout_percentage_hundred(self):
        manager = FeatureFlagManager()
        flag = FeatureFlag(name="test_flag", enabled=True, rollout_percentage=100)
        await manager.set_flag(flag)
        assert await manager.is_enabled("test_flag", user_id="user-1") is True

    @pytest.mark.asyncio
    async def test_delete_flag(self):
        manager = FeatureFlagManager()
        flag = FeatureFlag(name="to_delete", enabled=True)
        await manager.set_flag(flag)
        assert await manager.is_enabled("to_delete") is True
        await manager.delete_flag("to_delete")
        assert await manager.is_enabled("to_delete") is False

    def test_get_all_flags(self):
        manager = FeatureFlagManager()
        flags = manager.get_all_flags()
        assert isinstance(flags, dict)

    def test_stats(self):
        manager = FeatureFlagManager()
        stats = manager.get_stats()
        assert "total_flags" in stats
        assert "enabled_flags" in stats
