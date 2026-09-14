"""
Ingest API Endpoints.

Accepts passive flow records from sensors (Zeek, NetFlow, simulated traffic generator).
Operates strictly in one-way passive mode.
"""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Body, status
from pydantic import BaseModel

from app.ingest.parser import parse_zeek_conn_log
from app.schemas.alert import StandardAlert
from app.schemas.flow import RawFlow
from app.services.pipeline import pipeline_orchestrator

router = APIRouter(prefix="/ingest", tags=["Passive Ingest"])


class IngestResponse(BaseModel):
    status: str = "accepted"
    flows_processed: int
    alerts_generated: int
    alerts: list[StandardAlert] = []


class ZeekBundlePayload(BaseModel):
    conn_log: str
    dns_log: Optional[str] = None
    ssl_log: Optional[str] = None
    sensor_id: str = "zeek-sensor"


IngestResponse.model_rebuild()
ZeekBundlePayload.model_rebuild()


@router.post("/flow", response_model=IngestResponse, status_code=status.HTTP_200_OK)
async def ingest_single_flow(flow: RawFlow):
    """
    Ingests a single RawFlow telemetry record and passes it through
    the full threat detection and fusion pipeline.
    """
    alert = pipeline_orchestrator.process_flow(flow)
    alerts = [alert] if alert else []

    return IngestResponse(
        status="processed",
        flows_processed=1,
        alerts_generated=len(alerts),
        alerts=alerts,
    )


@router.post("/batch", response_model=IngestResponse, status_code=status.HTTP_200_OK)
async def ingest_batch_flows(flows: list[RawFlow]):
    """
    Ingests an array of RawFlow records.
    """
    alerts = []
    for flow in flows:
        alert = pipeline_orchestrator.process_flow(flow)
        if alert:
            alerts.append(alert)

    return IngestResponse(
        status="processed",
        flows_processed=len(flows),
        alerts_generated=len(alerts),
        alerts=alerts,
    )


@router.post("/zeek", response_model=IngestResponse)
async def ingest_zeek_log(payload: str = Body(..., media_type="text/plain")):
    """
    Ingests raw lines from a Zeek conn.log file.
    """
    lines = payload.splitlines()
    alerts = []
    processed = 0

    for line in lines:
        flow = parse_zeek_conn_log(line)
        if flow:
            processed += 1
            alert = pipeline_orchestrator.process_flow(flow)
            if alert:
                alerts.append(alert)

    return IngestResponse(
        status="processed",
        flows_processed=processed,
        alerts_generated=len(alerts),
        alerts=alerts,
    )


@router.post("/zeek/bundle", response_model=IngestResponse)
async def ingest_zeek_bundle(bundle: ZeekBundlePayload):
    """
    Ingests correlated Zeek telemetry (conn.log + dns.log + ssl.log).
    Correlates transport, DNS, and TLS attributes by Zeek connection UID.
    """
    from app.ingest.zeek import correlate_zeek_logs

    flows = correlate_zeek_logs(
        conn_content=bundle.conn_log,
        dns_content=bundle.dns_log,
        ssl_content=bundle.ssl_log,
        sensor_id=bundle.sensor_id,
    )

    alerts = []
    for flow in flows:
        alert = pipeline_orchestrator.process_flow(flow)
        if alert:
            alerts.append(alert)

    return IngestResponse(
        status="processed",
        flows_processed=len(flows),
        alerts_generated=len(alerts),
        alerts=alerts,
    )

