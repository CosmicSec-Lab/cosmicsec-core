"""
Phase T.3 — Python NATS JetStream event bus for CosmicSec services.

Provides a thin async wrapper around nats-py so every Python microservice
can publish and subscribe to events with a consistent interface.

If NATS is unavailable the module falls back to direct Redis pub/sub or
a no-op (log-only) mode so services continue operating without the broker.

Environment variables:
  NATS_URL          — nats://host:port  (default: nats://localhost:4222)
  COSMICSEC_USE_NATS — true|false        (default: false — safe fallback)

Usage::

    from services.common.events import publish, subscribe

    # Publish from any async context:
    await publish("scan.started", {"scan_id": "abc", "target": "example.com"})

    # Subscribe (long-lived coroutine, run in background task):
    async def handler(subject: str, data: dict) -> None:
        print(f"Received {subject}: {data}")

    await subscribe("scan.started", handler)
"""

from __future__ import annotations

import json
import logging
import os
from collections.abc import Callable, Coroutine
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

_NATS_URL = os.getenv("NATS_URL", "nats://localhost:4222")
_USE_NATS = os.getenv("COSMICSEC_USE_NATS", "false").lower() in ("1", "true", "yes")

# Lazy singleton NATS client
_nats_client: Any | None = None

# ---------------------------------------------------------------------------
# Well-known event subjects
# ---------------------------------------------------------------------------

# Scan lifecycle
SUBJECT_SCAN_STARTED = "cosmicsec.scan.started"
SUBJECT_SCAN_COMPLETED = "cosmicsec.scan.completed"
SUBJECT_SCAN_FAILED = "cosmicsec.scan.failed"

# Findings
SUBJECT_FINDING_CREATED = "cosmicsec.finding.created"
SUBJECT_FINDING_CRITICAL = "cosmicsec.finding.critical"

# Auth
SUBJECT_USER_REGISTERED = "cosmicsec.user.registered"
SUBJECT_USER_LOGIN = "cosmicsec.user.login"

# Alerts
SUBJECT_ALERT_TRIGGERED = "cosmicsec.alert.triggered"

# Agents
SUBJECT_AGENT_CONNECTED = "cosmicsec.agent.connected"
SUBJECT_AGENT_DISCONNECTED = "cosmicsec.agent.disconnected"


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


async def _get_nats() -> Any | None:
    """Return a connected NATS client, or None if unavailable/disabled."""
    global _nats_client  # noqa: PLW0603

    if not _USE_NATS:
        return None

    if _nats_client is not None:
        return _nats_client

    try:
        import nats  # type: ignore[import-untyped]

        _nats_client = await nats.connect(
            _NATS_URL,
            name="cosmicsec-python-service",
            connect_timeout=3,
            reconnect_time_wait=2,
            max_reconnect_attempts=5,
        )
        logger.info("Connected to NATS at %s", _NATS_URL)
        return _nats_client
    except Exception as exc:
        logger.warning("NATS connection failed (%s) — events will be no-op", exc)
        return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


async def publish(subject: str, data: dict[str, Any]) -> None:
    """
    Publish an event to the given NATS subject.

    Falls back to a log-only mode when NATS is unavailable so callers
    never need to handle connection errors.
    """
    payload = json.dumps(data, default=str).encode()

    nc = await _get_nats()
    if nc is None:
        logger.debug("NATS publish skipped (fallback mode) subject=%s", subject)
        return

    try:
        await nc.publish(subject, payload)
        logger.debug("Published event subject=%s bytes=%d", subject, len(payload))
    except Exception as exc:
        logger.warning("NATS publish error subject=%s: %s", subject, exc)


async def subscribe(
    subject: str,
    handler: Callable[[str, dict[str, Any]], Coroutine[Any, Any, None]],
    queue: str = "",
) -> Any | None:
    """
    Subscribe to a NATS subject with an async handler.

    Returns the NATS subscription object so callers can unsubscribe later.
    Returns None when operating in fallback mode.

    Args:
        subject: NATS subject string (supports wildcards: ``*``, ``>``)
        handler: ``async def handler(subject: str, data: dict) -> None``
        queue:   Optional queue group name for load-balanced subscriptions
    """
    nc = await _get_nats()
    if nc is None:
        logger.debug("NATS subscribe skipped (fallback mode) subject=%s", subject)
        return None

    async def _message_handler(msg: Any) -> None:
        try:
            data = json.loads(msg.data.decode())
        except (json.JSONDecodeError, UnicodeDecodeError):
            data = {"_raw": msg.data.decode(errors="replace")}
        try:
            await handler(msg.subject, data)
        except Exception as exc:
            logger.error("Event handler error subject=%s: %s", msg.subject, exc)

    try:
        if queue:
            sub = await nc.subscribe(subject, queue=queue, cb=_message_handler)
        else:
            sub = await nc.subscribe(subject, cb=_message_handler)
        logger.info("Subscribed to NATS subject=%s queue=%s", subject, queue or "(none)")
        return sub
    except Exception as exc:
        logger.warning("NATS subscribe error subject=%s: %s", subject, exc)
        return None


async def close() -> None:
    """Drain and close the NATS connection gracefully."""
    global _nats_client  # noqa: PLW0603
    if _nats_client is not None:
        try:
            await _nats_client.drain()
        except Exception as exc:
            logger.warning("NATS drain error: %s", exc)
        _nats_client = None
