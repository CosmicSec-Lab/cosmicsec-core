"""Runtime observability bootstrap for FastAPI services."""

from __future__ import annotations

import logging
import os
from typing import Any, Dict

from fastapi import FastAPI


def _as_bool(value: str, default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def setup_observability(app: FastAPI, service_name: str, logger: logging.Logger) -> Dict[str, Any]:
    """Initialize optional Sentry + OpenTelemetry instrumentation.

    This function is safe to call even when dependencies are missing.
    """
    state: Dict[str, Any] = {
        "service": service_name,
        "sentry_enabled": False,
        "otel_enabled": False,
    }

    # -----------------------------
    # Sentry
    # -----------------------------
    sentry_dsn = os.getenv("SENTRY_DSN", "").strip()
    if sentry_dsn:
        try:
            import sentry_sdk
            from sentry_sdk.integrations.fastapi import FastApiIntegration

            traces_sample_rate = float(os.getenv("SENTRY_TRACES_SAMPLE_RATE", "0.1"))
            profiles_sample_rate = float(os.getenv("SENTRY_PROFILES_SAMPLE_RATE", "0.0"))
            sentry_sdk.init(
                dsn=sentry_dsn,
                environment=os.getenv("APP_ENV", "development"),
                integrations=[FastApiIntegration()],
                traces_sample_rate=traces_sample_rate,
                profiles_sample_rate=profiles_sample_rate,
            )
            state["sentry_enabled"] = True
            logger.info("Sentry instrumentation enabled", service=service_name)
        except Exception as exc:  # pragma: no cover - dependency/runtime optional
            logger.warning("Sentry initialization skipped: %s", exc, service=service_name)

    # -----------------------------
    # OpenTelemetry + Jaeger
    # -----------------------------
    otel_enabled = _as_bool(os.getenv("OTEL_ENABLED", "true"), default=True)
    if otel_enabled:
        try:
            from opentelemetry import trace
            from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
            from opentelemetry.sdk.resources import Resource
            from opentelemetry.sdk.trace import TracerProvider
            from opentelemetry.sdk.trace.export import BatchSpanProcessor

            resource = Resource.create(
                {
                    "service.name": service_name,
                    "service.version": os.getenv("SERVICE_VERSION", "1.0.0"),
                    "deployment.environment": os.getenv("APP_ENV", "development"),
                }
            )
            provider = TracerProvider(resource=resource)

            jaeger_host = os.getenv("JAEGER_AGENT_HOST", "jaeger")
            jaeger_port = int(os.getenv("JAEGER_AGENT_PORT", "6831"))
            exporter = None
            exporter_name = "none"
            try:
                from opentelemetry.exporter.jaeger.thrift import JaegerExporter

                exporter = JaegerExporter(agent_host_name=jaeger_host, agent_port=jaeger_port)
                exporter_name = "jaeger"
            except Exception as exc:  # pragma: no cover - depends on optional exporter versions
                logger.warning("Jaeger exporter unavailable; traces will stay local: %s", exc, service=service_name)
            if exporter is not None:
                provider.add_span_processor(BatchSpanProcessor(exporter))
            current_provider = trace.get_tracer_provider()
            if type(current_provider).__name__ == "ProxyTracerProvider":
                trace.set_tracer_provider(provider)
            else:
                provider = current_provider

            FastAPIInstrumentor.instrument_app(app, tracer_provider=provider)
            state["otel_enabled"] = True
            state["otel_exporter"] = exporter_name
            logger.info(
                "OpenTelemetry instrumentation enabled",
                service=service_name,
                exporter=exporter_name,
                jaeger_host=jaeger_host,
                jaeger_port=jaeger_port,
            )
        except Exception as exc:  # pragma: no cover - dependency/runtime optional
            logger.warning("OpenTelemetry initialization skipped: %s", exc, service=service_name)

    return state
