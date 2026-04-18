"""
CosmicSec Startup Health Checks and Initialization

Provides comprehensive startup validation for all services including:
- Database connectivity verification
- Cache/Redis health checks
- Required environment variables validation
- Service dependencies check
- Schema initialization
"""

from __future__ import annotations

import logging
import os
from typing import Any

import redis
from sqlalchemy import create_engine, text
from sqlalchemy.exc import SQLAlchemyError

logger = logging.getLogger(__name__)


class StartupValidator:
    """Validates service startup requirements and dependencies."""

    def __init__(self):
        self.errors: list[str] = []
        self.warnings: list[str] = []

    def check_environment_variables(self, required_vars: list[str]) -> bool:
        """Validate required environment variables are set."""
        missing = [var for var in required_vars if not os.getenv(var)]
        if missing:
            msg = f"Missing required environment variables: {', '.join(missing)}"
            self.errors.append(msg)
            logger.error(msg)
            return False
        logger.info(f"✓ All {len(required_vars)} required environment variables present")
        return True

    def check_database_connectivity(self, database_url: str, timeout: int = 10) -> bool:
        """Check PostgreSQL connectivity and basic query."""
        try:
            engine = create_engine(database_url, connect_args={"timeout": timeout})
            with engine.connect() as conn:
                conn.execute(text("SELECT 1"))
            logger.info("✓ Database connectivity verified")
            return True
        except SQLAlchemyError as e:
            msg = f"Database connectivity failed: {e}"
            self.errors.append(msg)
            logger.error(msg)
            return False
        except Exception as e:
            msg = f"Unexpected database check error: {e}"
            self.errors.append(msg)
            logger.error(msg)
            return False

    def check_redis_connectivity(self, redis_url: str, timeout: int = 5) -> bool:
        """Check Redis/cache connectivity."""
        try:
            client = redis.from_url(redis_url, socket_connect_timeout=timeout)
            client.ping()
            logger.info("✓ Redis connectivity verified")
            return True
        except redis.ConnectionError as e:
            msg = f"Redis connectivity failed: {e}"
            self.errors.append(msg)
            logger.error(msg)
            return False
        except Exception as e:
            msg = f"Unexpected Redis check error: {e}"
            self.errors.append(msg)
            logger.error(msg)
            return False

    def check_mongodb_connectivity(self, mongodb_url: str) -> bool:
        """Check MongoDB connectivity."""
        try:
            from pymongo import MongoClient

            client = MongoClient(mongodb_url, serverSelectionTimeoutMS=5000)
            client.admin.command("ping")
            logger.info("✓ MongoDB connectivity verified")
            return True
        except Exception as e:
            msg = f"MongoDB connectivity check failed: {e}"
            self.warnings.append(msg)
            logger.warning(msg)
            return False

    def validate_ports(self, required_ports: dict[str, int]) -> bool:
        """Validate that required ports are not in use (basic check)."""
        import socket

        all_available = True
        for service, port in required_ports.items():
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    result = sock.connect_ex(("127.0.0.1", port))
                    if result == 0:
                        msg = f"Port {port} ({service}) already in use"
                        self.warnings.append(msg)
                        logger.warning(msg)
                        all_available = False
            except Exception as e:
                logger.debug(f"Could not check port {port}: {e}")

        if all_available:
            logger.info(f"✓ All {len(required_ports)} required ports available")
        return all_available

    def get_report(self) -> dict[str, Any]:
        """Generate startup validation report."""
        return {
            "errors": self.errors,
            "warnings": self.warnings,
            "passed": len(self.errors) == 0,
            "ready": len(self.errors) == 0,
        }

    def assert_ready(self) -> None:
        """Raise exception if startup validation failed."""
        if self.errors:
            error_msg = "Startup validation failed:\n" + "\n".join(f"  ✗ {e}" for e in self.errors)
            logger.error(error_msg)
            raise RuntimeError(error_msg)

        if self.warnings:
            warning_msg = "Startup warnings:\n" + "\n".join(f"  ! {w}" for w in self.warnings)
            logger.warning(warning_msg)


async def run_startup_checks(
    check_db: bool = True,
    check_redis: bool = True,
    check_mongodb: bool = False,
) -> dict[str, Any]:
    """Run all startup checks asynchronously."""
    validator = StartupValidator()

    # Check environment variables
    required_vars = ["COSMICSEC_ENV", "LOG_LEVEL"]
    validator.check_environment_variables(required_vars)

    # Check database if requested
    if check_db:
        db_url = os.getenv("DATABASE_URL")
        if db_url:
            validator.check_database_connectivity(db_url)
        else:
            logger.info("Database check skipped (DATABASE_URL not set)")

    # Check Redis if requested
    if check_redis:
        redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
        validator.check_redis_connectivity(redis_url)

    # Check MongoDB if requested
    if check_mongodb:
        mongodb_url = os.getenv("MONGODB_URL")
        if mongodb_url:
            validator.check_mongodb_connectivity(mongodb_url)

    report = validator.get_report()
    logger.info(f"Startup validation complete: {report}")

    return report
