"""Tamper-proof audit logging system with cryptographic chain verification.

Provides:
  - Immutable audit event chain with hash linking (blockchain-like)
  - Event categories: auth, data, config, admin, security, compliance
  - Automatic PII redaction in log payloads
  - Chain integrity verification
  - Export to SIEM-compatible formats (CEF, LEEF)

Usage:
    await audit_logger.log(
        event="user_login",
        category=EventCategory.AUTH,
        actor="user@example.com",
        details={"ip": "1.2.3.4", "method": "password"},
    )
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


class EventCategory(str, Enum):
    AUTH = "auth"
    DATA = "data"
    CONFIG = "config"
    ADMIN = "admin"
    SECURITY = "security"
    COMPLIANCE = "compliance"
    SYSTEM = "system"
    API = "api"


class SeverityLevel(str, Enum):
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


# PII fields that should be redacted in audit logs
_PII_FIELDS = {
    "password",
    "secret",
    "token",
    "api_key",
    "access_key",
    "ssn",
    "credit_card",
    "cvv",
    "pin",
    "authorization",
}


@dataclass
class AuditEvent:
    """Single audit log event with cryptographic hash linking."""

    event_id: str
    timestamp: str
    event: str
    category: EventCategory
    severity: SeverityLevel
    actor: str
    target: str
    action: str
    details: dict[str, Any] = field(default_factory=dict)
    source_ip: str = ""
    user_agent: str = ""
    request_id: str = ""
    tenant_id: str = ""
    previous_hash: str = ""
    event_hash: str = ""

    def compute_hash(self) -> str:
        """Compute SHA-256 hash of this event for chain integrity."""
        payload = json.dumps(
            {
                "event_id": self.event_id,
                "timestamp": self.timestamp,
                "event": self.event,
                "category": self.category.value,
                "severity": self.severity.value,
                "actor": self.actor,
                "target": self.target,
                "action": self.action,
                "details": self.details,
                "previous_hash": self.previous_hash,
            },
            sort_keys=True,
            default=str,
        )
        return hashlib.sha256(payload.encode()).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "event": self.event,
            "category": self.category.value,
            "severity": self.severity.value,
            "actor": self.actor,
            "target": self.target,
            "action": self.action,
            "details": self.details,
            "source_ip": self.source_ip,
            "user_agent": self.user_agent,
            "request_id": self.request_id,
            "tenant_id": self.tenant_id,
            "event_hash": self.event_hash,
            "previous_hash": self.previous_hash,
        }

    def to_cef(self) -> str:
        """Export to Common Event Format (CEF) for SIEM integration."""
        return (
            f"CEF:0|CosmicSec|GuardAxisSphere|1.0|"
            f"{self.category.value}|{self.event}|{self.severity.value}|"
            f"act={self.action} src={self.source_ip} "
            f"dst={self.target} suser={self.actor} "
            f"rt={self.timestamp} externalId={self.event_id}"
        )

    def to_leef(self) -> str:
        """Export to Log Event Extended Format (LEEF) for QRadar."""
        return (
            f"LEEF:1.0|CosmicSec|GuardAxisSphere|1.0|"
            f"{self.event}\t"
            f"cat={self.category.value}\t"
            f"severity={self.severity.value}\t"
            f"src={self.source_ip}\t"
            f"usrName={self.actor}\t"
            f"dst={self.target}"
        )


def _redact_pii(data: dict[str, Any]) -> dict[str, Any]:
    """Recursively redact PII fields from a dictionary."""
    result = {}
    for key, value in data.items():
        key_lower = key.lower()
        if any(pii in key_lower for pii in _PII_FIELDS):
            result[key] = "***REDACTED***"
        elif isinstance(value, dict):
            result[key] = _redact_pii(value)
        else:
            result[key] = value
    return result


class AuditLogger:
    """Tamper-proof audit logger with cryptographic chain verification."""

    def __init__(
        self,
        *,
        storage_backend: str = "memory",
        chain_file: str | None = None,
        auto_verify: bool = True,
    ) -> None:
        self.storage_backend = storage_backend
        self.chain_file = chain_file or os.getenv("AUDIT_CHAIN_FILE")
        self.auto_verify = auto_verify
        self._last_hash: str = ""
        self._event_count: int = 0
        self._storage: list[AuditEvent] = []

    def _generate_event_id(self) -> str:
        self._event_count += 1
        timestamp = datetime.now(tz=UTC).strftime("%Y%m%d%H%M%S")
        return f"evt-{timestamp}-{self._event_count:06d}"

    async def log(
        self,
        event: str,
        *,
        category: EventCategory = EventCategory.SYSTEM,
        severity: SeverityLevel = SeverityLevel.INFO,
        actor: str = "system",
        target: str = "",
        action: str = "",
        details: dict[str, Any] | None = None,
        source_ip: str = "",
        user_agent: str = "",
        request_id: str = "",
        tenant_id: str = "",
    ) -> AuditEvent:
        """Create and store an audit event."""
        event_id = self._generate_event_id()
        timestamp = datetime.now(tz=UTC).isoformat()

        audit_event = AuditEvent(
            event_id=event_id,
            timestamp=timestamp,
            event=event,
            category=category,
            severity=severity,
            actor=actor,
            target=target,
            action=action or event,
            details=_redact_pii(details or {}),
            source_ip=source_ip,
            user_agent=user_agent,
            request_id=request_id,
            tenant_id=tenant_id,
            previous_hash=self._last_hash,
        )

        audit_event.event_hash = audit_event.compute_hash()

        # Store event
        self._storage.append(audit_event)
        self._last_hash = audit_event.event_hash

        # Log to standard logger
        logger.info(
            "AUDIT [%s] %s: %s by %s on %s",
            category.value,
            severity.value,
            event,
            actor,
            target,
        )

        # Persist to file if configured
        if self.chain_file:
            try:
                with open(self.chain_file, "a") as f:
                    f.write(json.dumps(audit_event.to_dict()) + "\n")
            except OSError as exc:
                logger.error("Failed to persist audit event to file: %s", exc)

        # Async persist to Redis if available
        try:
            from services.common.caching import get_redis

            redis = await get_redis()
            await redis.lpush("audit:events", json.dumps(audit_event.to_dict(), default=str))
            await redis.expire("audit:events", 86400 * 90)  # 90 days retention
        except Exception:
            pass

        return audit_event

    async def verify_chain(self) -> dict[str, Any]:
        """Verify the integrity of the entire audit event chain."""
        errors = []
        for i, event in enumerate(self._storage):
            computed = event.compute_hash()
            if computed != event.event_hash:
                errors.append(
                    {
                        "event_id": event.event_id,
                        "error": "hash_mismatch",
                        "index": i,
                    }
                )
            if i > 0 and event.previous_hash != self._storage[i - 1].event_hash:
                errors.append(
                    {
                        "event_id": event.event_id,
                        "error": "chain_break",
                        "index": i,
                    }
                )

        return {
            "total_events": len(self._storage),
            "errors": len(errors),
            "is_valid": len(errors) == 0,
            "details": errors,
        }

    def get_recent_events(
        self,
        limit: int = 50,
        category: EventCategory | None = None,
        actor: str | None = None,
    ) -> list[dict[str, Any]]:
        """Retrieve recent audit events with optional filtering."""
        events = self._storage

        if category:
            events = [e for e in events if e.category == category]
        if actor:
            events = [e for e in events if e.actor == actor]

        return [e.to_dict() for e in events[-limit:]]

    def get_stats(self) -> dict[str, Any]:
        """Get audit log statistics."""
        category_counts: dict[str, int] = {}
        severity_counts: dict[str, int] = {}

        for event in self._storage:
            cat = event.category.value
            sev = event.severity.value
            category_counts[cat] = category_counts.get(cat, 0) + 1
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        return {
            "total_events": len(self._storage),
            "last_event_hash": self._last_hash,
            "category_counts": category_counts,
            "severity_counts": severity_counts,
        }


# Global audit logger singleton
_audit_logger: AuditLogger | None = None


def get_audit_logger() -> AuditLogger:
    global _audit_logger
    if _audit_logger is None:
        _audit_logger = AuditLogger()
    return _audit_logger


async def audit_log(event: str, **kwargs: Any) -> AuditEvent:
    """Convenience function for quick audit logging."""
    return await get_audit_logger().log(event, **kwargs)
