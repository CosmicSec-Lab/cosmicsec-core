import os
import time
import uuid
import re
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from slowapi.errors import RateLimitExceeded
from slowapi import _rate_limit_exceeded_handler

from services.api_gateway.core_deps import logger, limiter, SERVICE_URLS, hybrid_router
from cosmicsec_platform.config import get_config
from cosmicsec_platform.service_discovery import log_service_config
from services.api_gateway.graphql_runtime import mount_graphql
from services.api_gateway.white_label import WhiteLabelMiddleware, mount_branding_routes
from services.common.logging import clear_context, set_request_id, set_trace_id
from services.common.observability import setup_observability
from services.common.versioning import APIVersionMiddleware
from services.common.exceptions import CosmicSecException

# Initialize FastAPI app
app = FastAPI(
    title="CosmicSec API Gateway",
    description="GuardAxisSphere Platform - Universal Cybersecurity Intelligence Platform powered by Helix AI",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# CORS
_cors_origins_raw = os.environ.get("COSMICSEC_CORS_ORIGINS", "http://localhost:3000,http://localhost:4173")
_cors_origins = [o.strip() for o in _cors_origins_raw.split(",") if o.strip()]
if "*" in _cors_origins:
    _cors_origins = [o for o in _cors_origins if o != "*"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.add_middleware(GZipMiddleware, minimum_size=1000)
app.add_middleware(WhiteLabelMiddleware)
mount_branding_routes(app)

# Include the massive extracted router
from services.api_gateway.routers.core_routes import router as core_router
app.include_router(core_router)

# Observability and GraphQL
_observability_state = setup_observability(app, service_name="api-gateway", logger=logger)
_graphql_enabled = mount_graphql(app, service_urls=SERVICE_URLS, logger=logger)

logger.info(f"Platform Config: {get_config()}")
log_service_config()
logger.info("API Gateway successfully initialized and modularized!")
