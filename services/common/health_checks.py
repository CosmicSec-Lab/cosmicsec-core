"""
CosmicSec Service Health Checks and Monitoring

Provides comprehensive health checking for all internal services with
detailed status reporting, metrics, and dependency mapping.
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass
from enum import Enum
from typing import Any

import httpx

logger = logging.getLogger(__name__)


class HealthStatus(str, Enum):
    """Health status levels."""

    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"


@dataclass
class ServiceHealth:
    """Health status for a single service."""

    name: str
    status: HealthStatus
    response_time_ms: float | None = None
    last_checked: float | None = None
    error_message: str | None = None
    details: dict[str, Any] | None = None


class ServiceHealthChecker:
    """Checks health of internal microservices."""

    def __init__(self, timeout: int = 5):
        self.timeout = timeout
        self.client = httpx.AsyncClient(timeout=timeout)

    async def check_service(
        self, name: str, url: str, health_endpoint: str = "/health"
    ) -> ServiceHealth:
        """Check the health of a single service."""
        full_url = f"{url}{health_endpoint}"
        start_time = time.time()

        try:
            response = await self.client.get(full_url)
            response_time_ms = (time.time() - start_time) * 1000

            if response.status_code == 200:
                try:
                    data = response.json()
                    status = (
                        HealthStatus.HEALTHY
                        if data.get("status") == "healthy"
                        else HealthStatus.DEGRADED
                    )
                    return ServiceHealth(
                        name=name,
                        status=status,
                        response_time_ms=response_time_ms,
                        last_checked=time.time(),
                        details=data,
                    )
                except Exception as e:
                    return ServiceHealth(
                        name=name,
                        status=HealthStatus.DEGRADED,
                        response_time_ms=response_time_ms,
                        last_checked=time.time(),
                        error_message=f"Could not parse health response: {e}",
                    )
            else:
                return ServiceHealth(
                    name=name,
                    status=HealthStatus.UNHEALTHY,
                    response_time_ms=response_time_ms,
                    last_checked=time.time(),
                    error_message=f"HTTP {response.status_code}",
                )

        except asyncio.TimeoutError:
            return ServiceHealth(
                name=name,
                status=HealthStatus.UNHEALTHY,
                last_checked=time.time(),
                error_message="Health check timeout",
            )
        except Exception as e:
            return ServiceHealth(
                name=name,
                status=HealthStatus.UNHEALTHY,
                last_checked=time.time(),
                error_message=str(e),
            )

    async def check_multiple(
        self, services: dict[str, str]
    ) -> dict[str, ServiceHealth]:
        """Check health of multiple services concurrently."""
        tasks = [
            self.check_service(name, url) for name, url in services.items()
        ]
        results = await asyncio.gather(*tasks)
        return {service.name: service for service in results}

    async def close(self):
        """Close the HTTP client."""
        await self.client.aclose()


class DependencyMapper:
    """Maps service dependencies and detects cascading failures."""

    # Define service dependencies
    DEPENDENCIES = {
        "api-gateway": ["auth-service", "scan-service", "ai-service"],
        "auth-service": ["postgres", "redis"],
        "scan-service": ["postgres", "redis", "broker"],
        "ai-service": ["postgres", "redis"],
        "recon-service": ["postgres", "mongodb"],
        "report-service": ["postgres", "elasticsearch"],
        "collab-service": ["postgres", "redis"],
        "notification-service": ["postgres", "rabbitmq"],
    }

    @staticmethod
    def get_dependencies(service: str) -> list[str]:
        """Get dependencies for a service."""
        return DependencyMapper.DEPENDENCIES.get(service, [])

    @staticmethod
    def check_cascading_failures(
        health_status: dict[str, ServiceHealth],
    ) -> dict[str, list[str]]:
        """Identify which services are affected by unhealthy dependencies."""
        affected_services = {}

        for service, deps in DependencyMapper.DEPENDENCIES.items():
            failed_deps = [
                dep
                for dep in deps
                if dep in health_status
                and health_status[dep].status == HealthStatus.UNHEALTHY
            ]

            if failed_deps:
                affected_services[service] = failed_deps

        return affected_services


class SystemHealthReport:
    """Comprehensive system health report."""

    def __init__(self, services: dict[str, ServiceHealth]):
        self.services = services
        self.generated_at = time.time()

    @property
    def overall_status(self) -> HealthStatus:
        """Determine overall system health."""
        statuses = [s.status for s in self.services.values()]

        if HealthStatus.UNHEALTHY in statuses:
            return HealthStatus.UNHEALTHY
        elif HealthStatus.DEGRADED in statuses:
            return HealthStatus.DEGRADED
        elif HealthStatus.HEALTHY in statuses:
            return HealthStatus.HEALTHY
        else:
            return HealthStatus.UNKNOWN

    @property
    def healthy_count(self) -> int:
        """Count of healthy services."""
        return sum(
            1 for s in self.services.values()
            if s.status == HealthStatus.HEALTHY
        )

    @property
    def degraded_count(self) -> int:
        """Count of degraded services."""
        return sum(
            1 for s in self.services.values()
            if s.status == HealthStatus.DEGRADED
        )

    @property
    def unhealthy_count(self) -> int:
        """Count of unhealthy services."""
        return sum(
            1 for s in self.services.values()
            if s.status == HealthStatus.UNHEALTHY
        )

    @property
    def cascading_failures(self) -> dict[str, list[str]]:
        """Get cascading failure analysis."""
        return DependencyMapper.check_cascading_failures(self.services)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "overall_status": self.overall_status.value,
            "timestamp": self.generated_at,
            "summary": {
                "total": len(self.services),
                "healthy": self.healthy_count,
                "degraded": self.degraded_count,
                "unhealthy": self.unhealthy_count,
            },
            "services": {
                name: {
                    "status": service.status.value,
                    "response_time_ms": service.response_time_ms,
                    "last_checked": service.last_checked,
                    "error": service.error_message,
                    "details": service.details,
                }
                for name, service in self.services.items()
            },
            "cascading_failures": self.cascading_failures,
        }
