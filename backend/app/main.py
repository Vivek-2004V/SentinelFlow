from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.alerts import router as alerts_router
from app.api.v1.router import api_v1_router
from app.core.config import settings

app = FastAPI(
    title=settings.app_name,
    version=settings.api_version,
    description=(
        "Passive AI threat intelligence for "
        "one-way network monitoring environments."
    ),
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins.split(","),
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "Authorization"],
)

app.include_router(api_v1_router)
app.include_router(alerts_router)


@app.get("/health")
async def health():
    return {
        "status": "ok",
        "service": "sentinelflow-api",
        "mode": "read-only",
    }


@app.get("/api/v1/status")
async def status():
    return {
        "status": "operational",
        "ingest_mode": "passive",
        "response_mode": "alert-only",
        "payload_decryption": False,
        "return_path": False,
    }
