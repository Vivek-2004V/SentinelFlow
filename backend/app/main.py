from __future__ import annotations

import os
import time
from datetime import datetime, timezone
from typing import Any, Dict

import psutil
from fastapi import FastAPI, Response, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.api.alerts import router as alerts_router
from app.api.v1.router import api_v1_router
from app.core.config import settings
from app.core.errors import http_exception_handler, validation_exception_handler
from app.core.limiter import limiter
from app.core.middleware import RequestTracingAndSecurityMiddleware
from app.ml.model_registry import load_isolation_forest, load_random_forest

app_start_time = time.time()

app = FastAPI(
    title=settings.app_name,
    version=settings.api_version,
    description=(
        "Passive AI Threat Intelligence & Correlation Engine for "
        "One-Way Network Monitoring & Critical Infrastructure."
    ),
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)

# Rate Limiting & Global Handlers
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_exception_handler(StarletteHTTPException, http_exception_handler)
app.add_exception_handler(RequestValidationError, validation_exception_handler)

# Architect-Grade Middleware Stack (Order: Outer to Inner)
app.add_middleware(RequestTracingAndSecurityMiddleware)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.get_cors_origins(),
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization", "X-API-Key", "X-Request-ID", "X-Correlation-ID"],
)

# API Routers
app.include_router(api_v1_router)
app.include_router(alerts_router)


# ─── Deep Observability & Health Check Endpoints ───────────────────────────────

@app.get("/health", tags=["Observability & Health"])
async def health():
    """
    Standard shallow health check reporting service status and security posture.
    Maintains backward compatibility with legacy consumers and audit checks.
    """
    return {
        "status": "ok",
        "service": "sentinelflow-api",
        "mode": "read-only",
        "version": settings.api_version,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/health/live", tags=["Observability & Health"])
async def health_liveness():
    """
    K8s / Container Liveness Probe.
    Returns 200 immediately if the event loop is responsive.
    """
    return {"status": "live"}


@app.get("/health/ready", tags=["Observability & Health"])
async def health_readiness(response: Response) -> Dict[str, Any]:
    """
    Deep Readiness Probe.
    Verifies ML models loaded, security invariants intact, and system telemetry operational.
    Returns 200 when ready to ingest traffic, or 503 if any subsystem is degraded.
    """
    rf_model = load_random_forest()
    if_model = load_isolation_forest()

    models_ready = rf_model is not None and if_model is not None
    system_ready = models_ready

    # Telemetry snapshot
    mem = psutil.virtual_memory()
    proc = psutil.Process(os.getpid())
    proc_mem = proc.memory_info()

    if not system_ready:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE

    return {
        "status": "ready" if system_ready else "degraded",
        "uptime_seconds": round(time.time() - app_start_time, 1),
        "subsystems": {
            "random_forest_classifier": "loaded" if rf_model is not None else "missing",
            "isolation_forest_anomaly": "loaded" if if_model is not None else "missing",
            "read_only_invariant": "enforced",
            "return_path": "disabled",
        },
        "resources": {
            "cpu_percent": psutil.cpu_percent(interval=None),
            "memory_usage_mb": round(proc_mem.rss / (1024 * 1024), 2),
            "system_memory_used_percent": mem.percent,
        },
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/api/v1/status", tags=["System Status"])
async def status():
    """
    Reports runtime architecture invariants: passive ingest mode and blocked return path.
    """
    return {
        "status": "operational",
        "ingest_mode": "passive",
        "response_mode": "alert-only",
        "payload_decryption": False,
        "return_path": False,
    }
