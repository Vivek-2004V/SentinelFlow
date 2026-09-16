"""
Attack Simulation Endpoint.

Generates authorized synthetic network telemetry and routes it through the
full SentinelFlow detection pipeline (Feature Engine → Detectors → Random
Forest → Isolation Forest → Threat Fusion → Attack Chain → Evidence).

This endpoint exists exclusively for demo / hackathon scenarios.
It does NOT inject any traffic onto a real network — all telemetry is
fabricated in memory and processed entirely within the backend process.
"""
from __future__ import annotations

import secrets
from datetime import datetime
from typing import Any, Literal, Optional

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel

from app.schemas.flow import RawFlow
from app.schemas.alert import StandardAlert
from app.services.pipeline import pipeline_orchestrator
from app.detectors.registry import detector_registry
from app.features.flow import extract_flow_features
from app.features.dns import extract_dns_features
from app.features.tls import extract_tls_features
from app.detectors.baseline import global_baseline
from app.services.llm.service import llm_service

router = APIRouter(prefix="/simulate", tags=["Attack Simulation"])

# ─── Supported attack types ──────────────────────────────────────────────────

AttackType = Literal[
    "DDOS",
    "C2_BEACON",
    "DGA",
    "DNS_TUNNEL",
    "RECON",
    "EXFIL",
]

SimMode = Literal["single", "chain"]

# ─── Pydantic models ─────────────────────────────────────────────────────────


class SimulateRequest(BaseModel):
    attack_type: AttackType = "DDOS"
    mode: SimMode = "single"
    src_ip: str = "10.0.0.77"
    dst_ip: str = "203.0.113.9"


class AIAnalysis(BaseModel):
    """Real model scores extracted from the detection pipeline."""
    rule_score: float
    ml_score: float
    anomaly_score: float
    baseline_deviation: float
    threat_fusion_confidence: float
    primary_threat: str
    detector_signals: list[str]


class SimulateResponse(BaseModel):
    attack_type: str
    mode: str
    flows_sent: int
    alerts_generated: int
    alerts: list[StandardAlert]
    alert: Optional[StandardAlert] = None
    ai_analysis: Optional[AIAnalysis] = None
    llm: Optional[dict[str, Any]] = None
    simulated: bool = True
    disclaimer: str = (
        "Authorized demo telemetry only. "
        "No real traffic injected. Read-only passive architecture."
    )


# ─── Synthetic flow factories ─────────────────────────────────────────────────

def _uid() -> str:
    return f"SIM-{secrets.token_hex(4).upper()}"


def _make_ddos_flow(src_ip: str, dst_ip: str) -> RawFlow:
    """DDoS: extreme packet rate, high bandwidth, small packet size."""
    return RawFlow(
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=None,
        dst_port=80,
        proto="UDP",
        bytes_sent=5_200_000,
        bytes_recv=8_000,
        pkts_sent=52_000,
        pkts_recv=10,
        start_time=datetime.utcnow(),
        duration_seconds=1.0,
        sensor_id="sim-lab",
        source_format="simulation",
    )


def _make_c2_flow(src_ip: str, dst_ip: str) -> RawFlow:
    """C2 Beacon: periodic low-volume heartbeat with high periodicity."""
    return RawFlow(
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=None,
        dst_port=8443,
        proto="TCP",
        bytes_sent=150,
        bytes_recv=120,
        pkts_sent=1,
        pkts_recv=1,
        start_time=datetime.utcnow(),
        duration_seconds=0.1,
        periodicity_score=0.96,
        sensor_id="sim-lab",
        source_format="simulation",
    )


def _make_dga_flow(src_ip: str, dst_ip: str) -> RawFlow:
    """DGA: high-entropy algorithmically generated domain name."""
    return RawFlow(
        src_ip=src_ip,
        dst_ip="8.8.8.8",
        src_port=None,
        dst_port=53,
        proto="UDP",
        bytes_sent=512,
        bytes_recv=128,
        pkts_sent=2,
        pkts_recv=1,
        start_time=datetime.utcnow(),
        duration_seconds=0.05,
        dns_query="x7kq91m2z8vp3n99w4b1c8.info",  # high entropy, high digit ratio, length 27
        sensor_id="sim-lab",
        source_format="simulation",
    )


def _make_dns_tunnel_flow(src_ip: str, dst_ip: str) -> RawFlow:
    """DNS Tunnel: oversized encoded TXT-style label, very long subdomain chain."""
    return RawFlow(
        src_ip=src_ip,
        dst_ip="8.8.8.8",
        src_port=None,
        dst_port=53,
        proto="UDP",
        bytes_sent=120_000,
        bytes_recv=512,
        pkts_sent=12,
        pkts_recv=4,
        start_time=datetime.utcnow(),
        duration_seconds=1.0,
        dns_query="u9x4k1m8p2q5w7z3.b6d8e2f4a1c3h5j7.l9n1o3r5t7v9x2z4.tunnel-endpoint.net",
        sensor_id="sim-lab",
        source_format="simulation",
    )


def _make_recon_flow(src_ip: str, dst_ip: str) -> RawFlow:
    """Recon: rapid port sweep on sensitive port."""
    return RawFlow(
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=None,
        dst_port=22,
        proto="TCP",
        bytes_sent=60,
        bytes_recv=0,
        pkts_sent=1,
        pkts_recv=0,
        start_time=datetime.utcnow(),
        duration_seconds=0.01,
        sensor_id="sim-lab",
        source_format="simulation",
    )


def _make_exfil_flow(src_ip: str, dst_ip: str) -> RawFlow:
    """Exfil: massive outbound volume, near-zero inbound (upload ratio ~0.99)."""
    return RawFlow(
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=None,
        dst_port=443,
        proto="TCP",
        bytes_sent=85_000_000,
        bytes_recv=4_096,
        pkts_sent=62_000,
        pkts_recv=30,
        start_time=datetime.utcnow(),
        duration_seconds=45.0,
        sensor_id="sim-lab",
        source_format="simulation",
    )


_FLOW_FACTORIES = {
    "DDOS": _make_ddos_flow,
    "C2_BEACON": _make_c2_flow,
    "DGA": _make_dga_flow,
    "DNS_TUNNEL": _make_dns_tunnel_flow,
    "RECON": _make_recon_flow,
    "EXFIL": _make_exfil_flow,
}

# Full attack chain progression order
_CHAIN_SEQUENCE: list[AttackType] = ["RECON", "DGA", "C2_BEACON", "EXFIL"]


# ─── AI Analysis extraction ───────────────────────────────────────────────────

def _extract_ai_analysis(raw_flow: RawFlow) -> AIAnalysis:
    """
    Run detectors on the flow to extract real model scores
    without committing the alert to the alert store (pure diagnostic).
    """
    features = extract_flow_features(raw_flow)

    if raw_flow.dns_query:
        dns_f = extract_dns_features(raw_flow.dns_query)
        features.dns_query_length = dns_f["dns_query_length"]
        features.dns_entropy = dns_f["dns_entropy"]
        features.dns_digit_ratio = dns_f["dns_digit_ratio"]
        features.dns_subdomain_depth = dns_f["dns_subdomain_depth"]

    tls_f = extract_tls_features(
        tls_sni=raw_flow.tls_sni,
        ja3_hash=raw_flow.ja3_hash,
        quic_version=raw_flow.quic_version,
    )
    features.has_tls = tls_f["has_tls"]
    features.tls_sni_length = tls_f["tls_sni_length"]

    detection_results = detector_registry.run_all(features)

    # Pick the highest-confidence detector result
    if not detection_results:
        rule_score = 0.0
        ml_score = 0.0
        stat_score = 0.0
        primary_threat = "UNKNOWN"
        signals: list[str] = []
    else:
        best = max(detection_results, key=lambda d: d.score)
        primary_threat = best.threat_type.value

        # raw_features from BaseHybridDetector.evaluate() contains component scores
        rf = best.raw_features
        rule_score = round(float(rf.get("rule_score", best.score)), 3)
        ml_score = round(float(rf.get("ml_score", best.score)), 3)
        stat_score = round(float(rf.get("stat_score", 0.0)), 3)

        # Collect all fired signal keys from all detectors
        signals = []
        for dr in detection_results:
            if dr.score >= 0.4:
                signals.extend(dr.evidence_keys[:3])

    # Anomaly / baseline deviation
    pps_dev = global_baseline.get_deviation("pkts_per_second", features.pkts_per_second)
    bps_dev = global_baseline.get_deviation("bytes_per_second", features.bytes_per_second)
    baseline_deviation = round(max(pps_dev, bps_dev), 2)
    # Scale stat_score OR deviation into anomaly score (0–1)
    anomaly_score = round(min(max(stat_score, baseline_deviation / 6.0), 1.0), 3)

    # Threat fusion confidence: best detection score (mirrors FusedThreat.max_score)
    fusion_confidence = round(max((d.score for d in detection_results), default=0.0), 3)

    return AIAnalysis(
        rule_score=rule_score,
        ml_score=ml_score,
        anomaly_score=anomaly_score,
        baseline_deviation=baseline_deviation,
        threat_fusion_confidence=fusion_confidence,
        primary_threat=primary_threat,
        detector_signals=signals[:6],
    )


# ─── Endpoint ────────────────────────────────────────────────────────────────

@router.post(
    "",
    response_model=SimulateResponse,
    status_code=status.HTTP_200_OK,
    summary="Run an authorized attack simulation",
    description=(
        "Generates synthetic in-memory telemetry for the requested attack type "
        "and routes it through the full SentinelFlow detection pipeline. "
        "Returns the generated alert(s) plus real AI/ML analysis values."
    ),
)
async def run_simulation(req: SimulateRequest) -> SimulateResponse:
    alerts: list[StandardAlert] = []
    ai_analysis: Optional[AIAnalysis] = None

    if req.mode == "chain":
        # Run the full kill-chain sequence
        for attack_type in _CHAIN_SEQUENCE:
            factory = _FLOW_FACTORIES[attack_type]
            flow = factory(req.src_ip, req.dst_ip)
            alert = pipeline_orchestrator.process_flow(flow)
            if alert:
                alerts.append(alert)

        # AI analysis from the last flow (C2 — most illustrative)
        c2_flow = _make_c2_flow(req.src_ip, req.dst_ip)
        ai_analysis = _extract_ai_analysis(c2_flow)

    else:
        # Single attack type
        factory = _FLOW_FACTORIES.get(req.attack_type)
        if factory is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Unknown attack type: {req.attack_type}",
            )
        flow = factory(req.src_ip, req.dst_ip)

        # Extract real AI analysis BEFORE committing to store
        ai_analysis = _extract_ai_analysis(flow)

        # Now run through the full pipeline (commits alert to store)
        alert = pipeline_orchestrator.process_flow(flow)
        if alert:
            alerts.append(alert)

    # LLM explanation layer: purely advisory, zero modification to alert data
    llm_result: Optional[dict[str, Any]] = None
    if alerts:
        llm_result = await llm_service.explain(alerts[0].model_dump())

    return SimulateResponse(
        attack_type=req.mode == "chain" and "FULL_CHAIN" or req.attack_type,
        mode=req.mode,
        flows_sent=len(_CHAIN_SEQUENCE) if req.mode == "chain" else 1,
        alerts_generated=len(alerts),
        alerts=alerts,
        alert=alerts[0] if alerts else None,
        ai_analysis=ai_analysis,
        llm=llm_result,
    )
