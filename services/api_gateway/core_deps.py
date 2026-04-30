import asyncio
import ipaddress
import json
import logging
import os
import re
import socket
import time
import urllib.parse
import uuid
from datetime import UTC, datetime, timedelta

import httpx
from fastapi import FastAPI, APIRouter, HTTPException, Query, Request, WebSocket, WebSocketDisconnect, status
from fastapi.responses import JSONResponse, PlainTextResponse, StreamingResponse
from pydantic import BaseModel, Field
from slowapi import Limiter
from slowapi.util import get_remote_address

from cosmicsec_platform.config import get_config
from cosmicsec_platform.contracts.runtime_metadata import HYBRID_SCHEMA, HYBRID_VERSION
from cosmicsec_platform.middleware.hybrid_router import HybridRouter
from cosmicsec_platform.middleware.policy_registry import ROUTE_POLICIES
from cosmicsec_platform.middleware.static_profiles import STATIC_PROFILES
from cosmicsec_platform.service_discovery import get_registry

from services.common.caching import CacheManager, get_redis
from services.common.exceptions import CosmicSecException
from services.common.logging import setup_structured_logging

logger = setup_structured_logging("api_gateway")

def get_user_identifier(request: Request) -> str:
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        try:
            import base64 as _b64
            token = auth_header.split(" ", 1)[1]
            parts = token.split(".")
            if len(parts) == 3:
                payload_bytes = parts[1] + "=="
                decoded = _b64.urlsafe_b64decode(payload_bytes)
                import json as _json
                claims = _json.loads(decoded)
                sub = claims.get("sub") or claims.get("user_id")
                if sub:
                    return f"user:{sub}"
        except (ValueError, json.JSONDecodeError):
            pass
    return get_remote_address(request)

limiter = Limiter(key_func=get_user_identifier)

_RE_ALPHANUMERIC_ID = re.compile(r"^[A-Za-z0-9_\-]{1,128}$")
_RE_EMAIL = re.compile(r"^[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9.\-]{1,253}\.[A-Za-z]{2,}$")
_RE_PLUGIN_NAME = re.compile(r"^[A-Za-z0-9_\-]{1,128}$")
_RE_ORG_SLUG = re.compile(r"^[a-z0-9\-]{2,64}$")
_RE_DOMAIN = re.compile(r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$")
_RE_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE)

def _validate_path_id(value: str, label: str = "id") -> str:
    if not _RE_ALPHANUMERIC_ID.match(value):
        raise HTTPException(status_code=400, detail=f"Invalid {label}: must be alphanumeric")
    return value

def _validate_email_param(value: str) -> str:
    if not _RE_EMAIL.match(value):
        raise HTTPException(status_code=400, detail="Invalid email format")
    return value

def _validate_plugin_name(value: str) -> str:
    if not _RE_PLUGIN_NAME.match(value):
        raise HTTPException(status_code=400, detail="Invalid plugin name")
    return value

def _validate_uuid_param(value: str, label: str = "id") -> str:
    if not _RE_UUID.match(value):
        raise HTTPException(status_code=400, detail=f"Invalid {label}")
    return value

def _validate_org_slug(value: str) -> str:
    normalized = value.strip().lower()
    if not _RE_ORG_SLUG.match(normalized):
        raise HTTPException(status_code=400, detail="Invalid organization slug")
    return normalized

def _sanitize_log(value: object, max_len: int = 200) -> str:
    text = str(value) if value is not None else ""
    return text.replace("\n", "\\n").replace("\r", "\\r").replace("\x00", "")[:max_len]

_FROZEN_SERVICE_URLS: dict[str, str] = {}
def _init_service_urls(urls: dict[str, str]) -> None:
    global _FROZEN_SERVICE_URLS
    _FROZEN_SERVICE_URLS = dict(urls)

def _build_service_url(service: str, path: str) -> str:
    base = _FROZEN_SERVICE_URLS.get(service)
    if base is None:
        raise ValueError(f"Unknown service: {service}")
    if not path.startswith("/"):
        path = "/" + path
    return urllib.parse.urljoin(base, path)

async def _resolve_authenticated_user(request: Request) -> tuple[str, bool]:
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Bearer token required")
    token = auth[len("Bearer "):].strip()
    if not token:
        raise HTTPException(status_code=401, detail="Bearer token required")
    try:
        async with httpx.AsyncClient() as client:
            verify_resp = await client.get(_build_service_url("auth", "/me"), headers={"Authorization": f"Bearer {token}"}, timeout=5.0)
    except httpx.HTTPError:
        raise HTTPException(status_code=503, detail="Authentication service unavailable")
    if verify_resp.status_code != 200:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    me = verify_resp.json()
    principal = me.get("email") or me.get("user_id") or me.get("id")
    if not principal:
        raise HTTPException(status_code=401, detail="Invalid token payload")
    return str(principal), me.get("role") == "admin"

async def _resolve_websocket_user(websocket: WebSocket):
    token = websocket.query_params.get("token")
    if not token:
        auth_header = websocket.headers.get("authorization", "")
        if auth_header.lower().startswith("bearer "):
            token = auth_header.split(" ", 1)[1].strip()
    if not token: return None
    try:
        async with httpx.AsyncClient() as client:
            verify_resp = await client.get(_build_service_url("auth", "/me"), headers={"Authorization": f"Bearer {token}"}, timeout=5.0)
    except httpx.HTTPError:
        return None
    if verify_resp.status_code != 200: return None
    me = verify_resp.json()
    principal = me.get("email") or me.get("user_id") or me.get("id")
    if not principal: return None
    return str(principal), me.get("role") == "admin"

_service_registry = get_registry()
SERVICE_URLS = _service_registry.get_all_urls()
_init_service_urls(SERVICE_URLS)
hybrid_router = HybridRouter(SERVICE_URLS, static_profiles=STATIC_PROFILES)

_SEARCH_SCAN_FETCH_MULTIPLIER = 10
_SEARCH_FINDING_SCAN_CANDIDATES = 10
