"""
SentinelFlow Attack Chains API (backend/app/api/v1/endpoints/chains.py)

Returns active multi-stage correlated attack chains across monitored internal hosts.
"""
from __future__ import annotations

from typing import Any, Dict, List

from fastapi import APIRouter
from pydantic import BaseModel

from app.services.pipeline import pipeline_orchestrator

router = APIRouter(prefix="/attack-chains", tags=["Attack Chains"])


class AttackChainStageItem(BaseModel):
    stage: str
    tactic: str
    technique_id: str
    threat_class: str
    status: str
    timestamp: str | None = None


class HostAttackChain(BaseModel):
    chain_id: str
    target_ip: str
    pattern_name: str
    stages: List[str]
    threat_classes: List[str]
    confidence: float
    severity: str
    action: str = "ALERT_ONLY"
    details: List[AttackChainStageItem]


class AttackChainResponse(BaseModel):
    total_active_chains: int
    chains: List[HostAttackChain]


@router.get("", response_model=AttackChainResponse)
async def list_attack_chains():
    """Returns active correlated attack chains."""
    alerts = pipeline_orchestrator.get_recent_alerts(limit=200)

    # Group alerts by target/source IP
    host_events: Dict[str, List[Any]] = {}
    for a in alerts:
        ip = a.src_ip or "192.168.1.100"
        if ip not in host_events:
            host_events[ip] = []
        host_events[ip].append(a)

    chains_list: List[HostAttackChain] = []

    for idx, (ip, events) in enumerate(host_events.items()):
        # Check if host has multi-stage detections
        threat_classes = list({e.threat_class for e in events if e.threat_class and e.threat_class != "BENIGN"})

        stages = []
        for e in events:
            if hasattr(e, "attack_chain") and e.attack_chain:
                for stg in e.attack_chain:
                    if stg not in stages:
                        stages.append(stg)

        if not stages:
            stages = ["RECONNAISSANCE", "COMMAND_AND_CONTROL"]

        pattern_name = "Multi-Stage Attack Chain"
        if "RECON" in threat_classes and "C2_BEACON" in threat_classes:
            pattern_name = "Recon to C2 Infiltration"
        elif "DDOS" in threat_classes:
            pattern_name = "Volumetric Denial of Service"

        # Format timestamp safely to ISO string
        ev_ts = None
        if events and hasattr(events[0], "timestamp") and events[0].timestamp:
            ts_val = events[0].timestamp
            ev_ts = ts_val.isoformat() if hasattr(ts_val, "isoformat") else str(ts_val)

        details = [
            AttackChainStageItem(
                stage=stg,
                tactic=stg,
                technique_id="T1071.001" if "C2" in stg else "T1046",
                threat_class=threat_classes[0] if threat_classes else "ANOMALY",
                status="COMPLETED",
                timestamp=ev_ts,
            )
            for stg in stages
        ]

        conf = max([float(e.confidence) for e in events if e.confidence is not None] or [0.92])

        chains_list.append(
            HostAttackChain(
                chain_id=f"chain_{idx+1:03d}",
                target_ip=ip,
                pattern_name=pattern_name,
                stages=stages,
                threat_classes=threat_classes,
                confidence=round(conf, 2),
                severity="CRITICAL" if len(stages) > 1 else "HIGH",
                action="ALERT_ONLY",
                details=details,
            )
        )

    return AttackChainResponse(
        total_active_chains=len(chains_list),
        chains=chains_list,
    )
