"""
API v1 Router.

Aggregates ingest and alerts endpoints under the /api/v1 prefix.
"""
from __future__ import annotations

from fastapi import APIRouter

from app.api.v1.endpoints.alerts import router as alerts_router
from app.api.v1.endpoints.chains import router as chains_router
from app.api.v1.endpoints.ingest import router as ingest_router
from app.api.v1.endpoints.metrics import router as metrics_router
from app.api.v1.endpoints.stream import router as stream_router

api_v1_router = APIRouter(prefix="/api/v1")

api_v1_router.include_router(ingest_router)
api_v1_router.include_router(alerts_router)
api_v1_router.include_router(stream_router)
api_v1_router.include_router(metrics_router)
api_v1_router.include_router(chains_router)
