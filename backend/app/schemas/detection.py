"""
Detection-layer schemas.

ThreatType       — enum of all detectable threat classes.
DetectionResult  — output of a single detector.
FusedThreat      — output of threat fusion (multiple detectors, one host).
AttackChain      — sequenced kill-chain stages.
"""
from __future__ import annotations

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field


class ThreatType(str, Enum):
    DDOS = "DDOS"
    C2_BEACON = "C2_BEACON"
    DGA = "DGA"
    DNS_TUNNEL = "DNS_TUNNEL"
    RECON = "RECON"
    EXFIL = "EXFIL"
    TLS_ANOMALY = "TLS_ANOMALY"
    UNKNOWN = "UNKNOWN"


class KillChainStage(str, Enum):
    RECONNAISSANCE = "RECONNAISSANCE"
    WEAPONISATION = "WEAPONISATION"
    DELIVERY = "DELIVERY"
    EXPLOITATION = "EXPLOITATION"
    INSTALLATION = "INSTALLATION"
    C2 = "C2"
    ACTIONS_ON_OBJECTIVES = "ACTIONS_ON_OBJECTIVES"


# Map each threat type to its primary kill-chain stage
THREAT_TO_STAGE: dict[ThreatType, KillChainStage] = {
    ThreatType.RECON: KillChainStage.RECONNAISSANCE,
    ThreatType.DGA: KillChainStage.INSTALLATION,
    ThreatType.C2_BEACON: KillChainStage.C2,
    ThreatType.DNS_TUNNEL: KillChainStage.C2,
    ThreatType.TLS_ANOMALY: KillChainStage.C2,
    ThreatType.EXFIL: KillChainStage.ACTIONS_ON_OBJECTIVES,
    ThreatType.DDOS: KillChainStage.ACTIONS_ON_OBJECTIVES,
}


class DetectionResult(BaseModel):
    """Output of a single detector for one FlowFeatures record."""

    threat_type: ThreatType
    score: float = Field(..., ge=0.0, le=1.0, description="Confidence 0–1")
    triggered: bool = False            # score >= detector threshold
    threshold: float = 0.5
    detector_name: str = ""
    evidence_keys: list[str] = Field(
        default_factory=list,
        description="Feature names that drove this score",
    )
    raw_features: dict = Field(default_factory=dict)


class FusedThreat(BaseModel):
    """
    Cross-detector correlation for a single source IP / time window.
    Created by threat fusion layer.
    """

    src_ip: str
    window_start: datetime
    window_end: datetime
    detections: list[DetectionResult] = Field(default_factory=list)
    threat_types: list[ThreatType] = Field(default_factory=list)
    max_score: float = 0.0
    deviation_score: float = 0.0      # vs adaptive baseline
    is_multi_stage: bool = False      # multiple kill-chain stages found


class AttackChain(BaseModel):
    """Ordered kill-chain reconstruction."""

    src_ip: str
    stages: list[KillChainStage] = Field(default_factory=list)
    threat_types: list[ThreatType] = Field(default_factory=list)
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    duration_seconds: float = 0.0
    is_multi_stage: bool = False
