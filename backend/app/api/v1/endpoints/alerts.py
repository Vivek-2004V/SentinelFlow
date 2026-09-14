"""
Alerts API Endpoints.

Provides read-only access to emitted StandardAlert objects for the SOC dashboard.
"""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel

from app.schemas.alert import SeverityLevel, StandardAlert
from app.schemas.detection import ThreatType
from app.services.pipeline import pipeline_orchestrator

router = APIRouter(prefix="/alerts", tags=["SOC Alerts"])


class AlertStats(BaseModel):
    total_alerts: int
    by_severity: dict[str, int]
    by_threat_type: dict[str, int]
    recent_critical_count: int


@router.get("", response_model=list[StandardAlert])
async def list_alerts(
    limit: int = Query(50, ge=1, le=200),
    severity: SeverityLevel | None = None,
    threat_type: ThreatType | None = None,
):
    """
    Returns recent threat alerts emitted by the pipeline.
    """
    alerts = pipeline_orchestrator.get_recent_alerts(limit=limit)

    if severity:
        alerts = [a for a in alerts if a.severity == severity]
    if threat_type:
        target = threat_type.value if hasattr(threat_type, "value") else str(threat_type)
        alerts = [a for a in alerts if a.threat_class == target]

    return alerts


@router.get("/stats", response_model=AlertStats)
async def get_alert_statistics():
    """
    Calculates summary metrics for the SOC dashboard status tiles.
    """
    alerts = pipeline_orchestrator.get_recent_alerts(limit=500)

    by_severity: dict[str, int] = {s.value: 0 for s in SeverityLevel}
    by_threat: dict[str, int] = {t.value: 0 for t in ThreatType}
    recent_critical = 0

    for a in alerts:
        sev_val = a.severity.value if hasattr(a.severity, "value") else str(a.severity)
        by_severity[sev_val] = by_severity.get(sev_val, 0) + 1
        threat_val = a.threat_class
        by_threat[threat_val] = by_threat.get(threat_val, 0) + 1
        if a.severity == SeverityLevel.CRITICAL or sev_val == "CRITICAL":
            recent_critical += 1

    return AlertStats(
        total_alerts=len(alerts),
        by_severity=by_severity,
        by_threat_type=by_threat,
        recent_critical_count=recent_critical,
    )


@router.get("/{alert_id}", response_model=StandardAlert)
async def get_alert_by_id(alert_id: str):
    """
    Retrieves full details and evidence for a specific alert.
    """
    from app.db.database import db

    alert = db.get_alert_by_id(alert_id)
    if alert:
        return alert
    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")


@router.get("/{alert_id}/explanation")
async def get_alert_explanation_endpoint(alert_id: str):
    """
    Generates an advisory human-readable incident explanation and SOC triage briefing.
    Strictly post-alert and advisory only (carries zero control or mutation authority).
    """
    from app.db.database import db
    from app.services.llm_explainer import generate_alert_explanation

    alert = db.get_alert_by_id(alert_id)
    if not alert:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")

    return generate_alert_explanation(alert)


@router.delete("", status_code=status.HTTP_204_NO_CONTENT)
async def clear_all_alerts():
    """
    Resets in-memory alert history (used in test/lab workflows).
    """
    pipeline_orchestrator.clear_alerts()
