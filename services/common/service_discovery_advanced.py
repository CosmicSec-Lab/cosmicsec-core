"""Advanced service discovery with health monitoring, load balancing, and dependency tracking.

Extends the base service registry with:
  - Active health checks with configurable intervals
  - Circuit breaker integration per service
  - Load balancing strategies (round-robin, least-connections, random)
  - Service dependency graph
  - Real-time service status dashboard data
"""

from __future__ import annotations

import asyncio
import logging
import random
import time
from collections import defaultdict
from enum import Enum
from typing import Any

import httpx

logger = logging.getLogger(__name__)


class ServiceHealth(str, Enum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"


class LoadBalancingStrategy(str, Enum):
    ROUND_ROBIN = "round_robin"
    LEAST_CONNECTIONS = "least_connections"
    RANDOM = "random"


class ServiceInstance:
    """Represents a single service instance with health tracking."""

    def __init__(self, url: str, *, is_primary: bool = True) -> None:
        self.url = url.rstrip("/")
        self.is_primary = is_primary
        self.health = ServiceHealth.UNKNOWN
        self.last_check: float = 0.0
        self.response_time_ms: float = 0.0
        self.consecutive_failures: int = 0
        self.total_requests: int = 0
        self.active_connections: int = 0
        self.uptime_start: float | None = None
        self.version: str = ""
        self.metadata: dict[str, Any] = {}

    def record_success(self, response_time_ms: float) -> None:
        self.health = ServiceHealth.HEALTHY
        self.last_check = time.time()
        self.response_time_ms = response_time_ms
        self.consecutive_failures = 0
        self.total_requests += 1

    def record_failure(self) -> None:
        self.consecutive_failures += 1
        self.last_check = time.time()
        self.total_requests += 1

        if self.consecutive_failures >= 5:
            self.health = ServiceHealth.UNHEALTHY
        elif self.consecutive_failures >= 2:
            self.health = ServiceHealth.DEGRADED

    def to_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "health": self.health.value,
            "last_check": self.last_check,
            "response_time_ms": round(self.response_time_ms, 1),
            "consecutive_failures": self.consecutive_failures,
            "total_requests": self.total_requests,
            "active_connections": self.active_connections,
            "is_primary": self.is_primary,
            "version": self.version,
            "uptime_seconds": round(time.time() - self.uptime_start, 1) if self.uptime_start else 0,
        }


class ServiceDiscovery:
    """Enhanced service discovery with health monitoring and load balancing."""

    def __init__(
        self,
        base_urls: dict[str, str],
        *,
        health_check_interval: float = 30.0,
        health_check_timeout: float = 5.0,
        load_balancing: LoadBalancingStrategy = LoadBalancingStrategy.ROUND_ROBIN,
    ) -> None:
        self.base_urls = base_urls
        self.health_check_interval = health_check_interval
        self.health_check_timeout = health_check_timeout
        self.load_balancing = load_balancing

        # Service instances per service key
        self._instances: dict[str, list[ServiceInstance]] = {}
        self._rr_counters: dict[str, int] = defaultdict(int)
        self._dependencies: dict[str, set[str]] = defaultdict(set)
        self._health_task: asyncio.Task | None = None

        # Initialize instances from base URLs
        for key, url in base_urls.items():
            self._instances[key] = [ServiceInstance(url, is_primary=True)]

    def register_instance(self, service_key: str, url: str, *, is_primary: bool = False) -> None:
        """Register a new service instance (for load balancing across replicas)."""
        if service_key not in self._instances:
            self._instances[service_key] = []
        instance = ServiceInstance(url, is_primary=is_primary)
        self._instances[service_key].append(instance)
        logger.info("Registered service instance: %s -> %s", service_key, url)

    def register_dependency(self, service_key: str, depends_on: str) -> None:
        """Track service dependencies for topology visualization."""
        self._dependencies[service_key].add(depends_on)

    def get_healthy_instance(self, service_key: str) -> ServiceInstance | None:
        """Get a healthy service instance using the configured load balancing strategy."""
        instances = self._instances.get(service_key, [])
        healthy = [i for i in instances if i.health != ServiceHealth.UNHEALTHY]

        if not healthy:
            # Fall back to any instance
            return instances[0] if instances else None

        if self.load_balancing == LoadBalancingStrategy.ROUND_ROBIN:
            idx = self._rr_counters[service_key] % len(healthy)
            self._rr_counters[service_key] = idx + 1
            return healthy[idx]

        if self.load_balancing == LoadBalancingStrategy.LEAST_CONNECTIONS:
            return min(healthy, key=lambda i: i.active_connections)

        # Random
        return random.choice(healthy)

    def get_url(self, service_key: str) -> str:
        """Get the URL for a service (with load balancing)."""
        instance = self.get_healthy_instance(service_key)
        if instance is None:
            raise KeyError(f"No instances registered for service '{service_key}'")
        return instance.url

    def get_instance(self, service_key: str) -> ServiceInstance | None:
        """Get the selected service instance."""
        return self.get_healthy_instance(service_key)

    async def check_health(self, service_key: str) -> dict[str, Any]:
        """Perform a health check on a service."""
        instances = self._instances.get(service_key, [])
        results = []

        async with httpx.AsyncClient(timeout=self.health_check_timeout) as client:
            for instance in instances:
                try:
                    start = time.monotonic()
                    resp = await client.get(f"{instance.url}/health")
                    elapsed_ms = (time.monotonic() - start) * 1000

                    if resp.status_code == 200:
                        instance.record_success(elapsed_ms)
                        try:
                            data = resp.json()
                            instance.version = data.get("version", "")
                            instance.uptime_start = time.time() - data.get("uptime_seconds", 0)
                        except Exception:
                            pass
                        results.append({"url": instance.url, "status": "healthy", "ms": round(elapsed_ms, 1)})
                    else:
                        instance.record_failure()
                        results.append({"url": instance.url, "status": "unhealthy", "http_status": resp.status_code})
                except Exception as exc:
                    instance.record_failure()
                    results.append({"url": instance.url, "status": "unreachable", "error": str(exc)})

        return {"service": service_key, "instances": results}

    async def check_all_health(self) -> dict[str, Any]:
        """Health check all registered services."""
        results = {}
        for key in self._instances:
            results[key] = await self.check_health(key)
        return results

    async def start_health_monitoring(self) -> None:
        """Start periodic health checks in the background."""
        async def _monitor():
            while True:
                await asyncio.sleep(self.health_check_interval)
                try:
                    for key in self._instances:
                        await self.check_health(key)
                except Exception as exc:
                    logger.warning("Health monitoring error: %s", exc)

        self._health_task = asyncio.create_task(_monitor())
        logger.info("Health monitoring started (interval=%.1fs)", self.health_check_interval)

    def stop_health_monitoring(self) -> None:
        """Stop periodic health checks."""
        if self._health_task:
            self._health_task.cancel()
            self._health_task = None

    def get_dependency_graph(self) -> dict[str, list[str]]:
        """Get the service dependency graph."""
        return {k: sorted(v) for k, v in self._dependencies.items()}

    def get_dashboard_data(self) -> dict[str, Any]:
        """Get real-time service status for dashboard display."""
        services = {}
        for key, instances in self._instances.items():
            services[key] = {
                "instances": [i.to_dict() for i in instances],
                "healthy_count": sum(1 for i in instances if i.health == ServiceHealth.HEALTHY),
                "total_count": len(instances),
            }
        return {
            "services": services,
            "dependency_graph": self.get_dependency_graph(),
            "load_balancing": self.load_balancing.value,
            "total_services": len(self._instances),
            "healthy_services": sum(
                1 for s in services.values() if s["healthy_count"] > 0
            ),
        }
