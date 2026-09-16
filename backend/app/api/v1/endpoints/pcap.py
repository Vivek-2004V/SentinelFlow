from __future__ import annotations

import logging
import tempfile
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, File, HTTPException, Request, UploadFile, status
from pydantic import BaseModel, Field

from app.core.auth import verify_api_key
from app.core.limiter import limiter
from app.ingest.pcap_reader import parse_pcap_file
from app.schemas.alert import StandardAlert
from app.services.llm.service import llm_service
from app.services.pipeline import pipeline_orchestrator

logger = logging.getLogger("sentinelflow.pcap_api")

router = APIRouter(prefix="/pcap", tags=["PCAP Analysis"])

ALLOWED_EXTENSIONS = {".pcap", ".pcapng"}
MAX_FILE_SIZE_BYTES = 50 * 1024 * 1024  # 50 MB

PCAP_MAGIC_HEADERS = (
    b"\xa1\xb2\xc3\xd4",  # Standard PCAP microsecond
    b"\xd4\xc3\xb2\xa1",  # Standard PCAP swapped
    b"\xa1\xb2\x3c\x4d",  # Nanosecond PCAP
    b"\x4d\x3c\xb2\xa1",  # Nanosecond PCAP swapped
    b"\x0a\x0d\x0d\x0a",  # PCAP-NG
)


class PcapSecurityInfo(BaseModel):
    passive_capture: bool = True
    read_only: bool = True
    payload_decrypted: bool = False
    active_probe: bool = False
    active_scan: bool = False
    packet_mitigation: bool = False
    action: str = "ALERT_ONLY"


class PcapAiAnalysis(BaseModel):
    random_forest_detected: int = 0
    isolation_forest_anomalies: int = 0
    top_threat: str = "BENIGN"


class PcapAnalysisResponse(BaseModel):
    filename: str
    mode: str = "PASSIVE"
    packets_analyzed: int
    flows_reconstructed: int
    threats_detected: int
    threat_breakdown: Dict[str, int] = Field(default_factory=dict)
    alerts: List[StandardAlert] = Field(default_factory=list)
    ai_analysis: PcapAiAnalysis = Field(default_factory=PcapAiAnalysis)
    llm_advisory: Optional[str] = None
    llm: Optional[Dict[str, Any]] = None
    security: PcapSecurityInfo = Field(default_factory=PcapSecurityInfo)
    disclaimer: str = (
        "Passive forensic analysis only. Telemetry ingested in read-only mode. "
        "Zero packet modification or active network counter-measures."
    )


@router.post(
    "/analyze",
    response_model=PcapAnalysisResponse,
    status_code=status.HTTP_200_OK,
    summary="Passively analyze a PCAP/PCAPNG capture file",
    dependencies=[Depends(verify_api_key)],
    description=(
        "Uploads a .pcap or .pcapng network capture file, reconstructs 5-tuple flows, "
        "and routes them through the SentinelFlow passive detection & threat fusion pipeline."
    ),
)
@limiter.limit("10/minute")
async def analyze_pcap(
    request: Request,
    file: UploadFile = File(...),
    _auth: str = Depends(verify_api_key),
) -> PcapAnalysisResponse:
    orig_filename = Path(file.filename or "capture.pcap").name
    extension = Path(orig_filename).suffix.lower()

    # 1. Extension validation
    if extension not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported file extension '{extension}'. Only .pcap and .pcapng are supported.",
        )

    # 2. Read with size limit validation
    content = await file.read()
    if len(content) > MAX_FILE_SIZE_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"PCAP file exceeds maximum allowed size ({MAX_FILE_SIZE_BYTES // (1024 * 1024)}MB).",
        )
    if len(content) == 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Uploaded PCAP file is empty.",
        )

    # 3. Magic byte header verification (CWE-434 defense-in-depth)
    if len(content) < 4 or not any(content.startswith(magic) for magic in PCAP_MAGIC_HEADERS):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Uploaded file has invalid magic byte header (not a valid PCAP/PCAPNG binary capture).",
        )

    # 3. Write securely to tempfile and process
    try:
        with tempfile.NamedTemporaryFile(suffix=extension, delete=True) as tmp:
            tmp.write(content)
            tmp.flush()

            raw_flows, packet_count = parse_pcap_file(tmp.name)
    except ValueError as val_err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"PCAP parsing failed: {val_err}",
        )
    except Exception as exc:
        logger.error("Internal error processing PCAP: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to process capture file: {exc}",
        )

    # 4. Route through the full passive detection pipeline
    alerts: List[StandardAlert] = []
    threat_counter: Counter[str] = Counter()

    for flow in raw_flows:
        alert = pipeline_orchestrator.process_flow(flow)
        if alert is not None:
            alerts.append(alert)
            threat_counter[alert.threat_class] += 1

    # 5. Advisory LLM explanation for the most severe alert if any detected
    llm_explanation: Optional[Dict[str, Any]] = None
    llm_advisory_text: Optional[str] = None
    if alerts:
        # Pick highest severity alert for explanation
        primary_alert = alerts[0]
        try:
            llm_explanation = await llm_service.explain(primary_alert.model_dump())
            if isinstance(llm_explanation, dict):
                llm_advisory_text = llm_explanation.get("explanation")
        except Exception as exc:
            logger.warning("LLM explanation generation skipped: %s", exc)

    # 6. AI & threat summary
    top_threat_name = threat_counter.most_common(1)[0][0] if threat_counter else "BENIGN"
    rf_threats = sum(1 for a in alerts if a.detector == "RandomForest" or a.confidence > 0.6)
    if_anomalies = sum(1 for a in alerts if "anomaly" in a.threat_class.lower() or a.severity in ("HIGH", "CRITICAL"))

    ai_analysis = PcapAiAnalysis(
        random_forest_detected=rf_threats,
        isolation_forest_anomalies=if_anomalies,
        top_threat=top_threat_name,
    )

    return PcapAnalysisResponse(
        filename=orig_filename,
        mode="PASSIVE",
        packets_analyzed=packet_count,
        flows_reconstructed=len(raw_flows),
        threats_detected=len(alerts),
        threat_breakdown=dict(threat_counter),
        alerts=alerts,
        ai_analysis=ai_analysis,
        llm_advisory=llm_advisory_text,
        llm=llm_explanation,
    )


@router.post(
    "/upload",
    response_model=PcapAnalysisResponse,
    status_code=status.HTTP_200_OK,
    summary="Upload & passively analyze a PCAP/PCAPNG capture file (alias to /analyze)",
    dependencies=[Depends(verify_api_key)],
)
@limiter.limit("10/minute")
async def upload_pcap(
    request: Request,
    file: UploadFile = File(...),
    _auth: str = Depends(verify_api_key),
) -> PcapAnalysisResponse:
    """Alias for /analyze endpoint for standard upload route conventions."""
    return await analyze_pcap(request=request, file=file, _auth=_auth)
