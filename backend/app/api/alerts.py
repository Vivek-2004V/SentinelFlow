from __future__ import annotations

from fastapi import APIRouter, HTTPException

from app.alerts.service import build_alert
from app.detectors.engine import run_detectors
from app.features.feature_pipeline import extract_features
from app.schemas.alert import ThreatAlert

router = APIRouter(
    prefix="/api/v1/alerts",
    tags=["alerts"],
)


@router.post(
    "/analyze",
    response_model=ThreatAlert,
    responses={
        200: {"description": "Threat alert generated with explainability evidence"},
        204: {"description": "No significant threat detected (benign traffic)"},
    },
)
async def analyze_flow(
    flow: dict,
):
    features = extract_features(flow)

    results = run_detectors(features)

    alert = build_alert(
        flow,
        results,
    )

    if alert is None:
        raise HTTPException(
            status_code=204,
            detail="No significant threat detected",
        )

    return alert
