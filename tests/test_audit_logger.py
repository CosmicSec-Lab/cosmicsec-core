"""Tests for audit logging system."""

import pytest

from services.common.audit_logger import (
    AuditEvent,
    AuditLogger,
    EventCategory,
    SeverityLevel,
    _redact_pii,
)


class TestRedactPII:
    def test_redacts_password(self):
        data = {"username": "test", "password": "secret123"}
        result = _redact_pii(data)
        assert result["password"] == "***REDACTED***"
        assert result["username"] == "test"

    def test_redacts_nested(self):
        data = {"config": {"api_key": "abc123", "name": "test"}}
        result = _redact_pii(data)
        assert result["config"]["api_key"] == "***REDACTED***"

    def test_preserves_safe_fields(self):
        data = {"name": "test", "email": "user@example.com", "age": 25}
        result = _redact_pii(data)
        assert result["name"] == "test"
        assert result["email"] == "user@example.com"
        assert result["age"] == 25


class TestAuditEvent:
    def test_compute_hash(self):
        event = AuditEvent(
            event_id="evt-1",
            timestamp="2024-01-01T00:00:00",
            event="login",
            category=EventCategory.AUTH,
            severity=SeverityLevel.INFO,
            actor="user@test.com",
            target="system",
            action="login",
        )
        hash1 = event.compute_hash()
        hash2 = event.compute_hash()
        assert hash1 == hash2
        assert len(hash1) == 64  # SHA-256 hex

    def test_hash_changes_with_content(self):
        event1 = AuditEvent(
            event_id="evt-1",
            timestamp="2024-01-01T00:00:00",
            event="login",
            category=EventCategory.AUTH,
            severity=SeverityLevel.INFO,
            actor="user@test.com",
            target="system",
            action="login",
        )
        event2 = AuditEvent(
            event_id="evt-1",
            timestamp="2024-01-01T00:00:00",
            event="login",
            category=EventCategory.AUTH,
            severity=SeverityLevel.WARNING,  # Different severity
            actor="user@test.com",
            target="system",
            action="login",
        )
        assert event1.compute_hash() != event2.compute_hash()

    def test_to_dict(self):
        event = AuditEvent(
            event_id="evt-1",
            timestamp="2024-01-01T00:00:00",
            event="login",
            category=EventCategory.AUTH,
            severity=SeverityLevel.INFO,
            actor="user@test.com",
            target="system",
            action="login",
            source_ip="1.2.3.4",
        )
        d = event.to_dict()
        assert d["event_id"] == "evt-1"
        assert d["source_ip"] == "1.2.3.4"

    def test_chain_linking(self):
        event1 = AuditEvent(
            event_id="evt-1",
            timestamp="2024-01-01T00:00:00",
            event="login",
            category=EventCategory.AUTH,
            severity=SeverityLevel.INFO,
            actor="user@test.com",
            target="system",
            action="login",
        )
        event1.event_hash = event1.compute_hash()

        event2 = AuditEvent(
            event_id="evt-2",
            timestamp="2024-01-01T00:00:01",
            event="logout",
            category=EventCategory.AUTH,
            severity=SeverityLevel.INFO,
            actor="user@test.com",
            target="system",
            action="logout",
            previous_hash=event1.event_hash,
        )
        assert event2.previous_hash == event1.event_hash


class TestAuditLogger:
    @pytest.mark.asyncio
    async def test_log_event(self):
        logger = AuditLogger()
        event = await logger.log(
            event="user_login",
            category=EventCategory.AUTH,
            actor="user@test.com",
            target="system",
        )
        assert event.event is not None
        assert event.category == EventCategory.AUTH
        assert event.event_hash != ""
        assert len(logger._storage) == 1

    @pytest.mark.asyncio
    async def test_chain_integrity(self):
        logger = AuditLogger()
        await logger.log(event="e1", actor="user1", category=EventCategory.AUTH)
        await logger.log(event="e2", actor="user1", category=EventCategory.DATA)
        await logger.log(event="e3", actor="user2", category=EventCategory.ADMIN)

        result = await logger.verify_chain()
        assert result["is_valid"] is True
        assert result["total_events"] == 3
        assert result["errors"] == 0

    @pytest.mark.asyncio
    async def test_filter_by_category(self):
        logger = AuditLogger()
        await logger.log(event="login", actor="user1", category=EventCategory.AUTH)
        await logger.log(event="scan", actor="user1", category=EventCategory.SYSTEM)
        await logger.log(event="logout", actor="user1", category=EventCategory.AUTH)

        events = logger.get_recent_events(category=EventCategory.AUTH)
        assert len(events) == 2

    @pytest.mark.asyncio
    async def test_stats(self):
        logger = AuditLogger()
        await logger.log(event="login", actor="user1", category=EventCategory.AUTH)
        await logger.log(event="scan", actor="user1", category=EventCategory.SYSTEM)

        stats = logger.get_stats()
        assert stats["total_events"] == 2
        assert stats["category_counts"]["auth"] == 1
        assert stats["category_counts"]["system"] == 1
