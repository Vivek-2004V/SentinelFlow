"""
Standard Alert Schema (Step 7.2 / Section 12).

Defines ThreatAlert, AlertEvidence, and severity calibration.
Enforces action='ALERT_ONLY' to guarantee strict passive, one-way architecture.
"""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, Field


class SeverityLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


def score_to_severity(score: float) -> str:
    """Maps continuous [0.0, 1.0] fused confidence score to discrete severity string."""
    if score >= 0.85:
        return "CRITICAL"
    if score >= 0.65:
        return "HIGH"
    if score >= 0.40:
        return "MEDIUM"
    return "LOW"


class AlertEvidence(BaseModel):
    feature: str
    value: Any
    description: str

    model_config = {"populate_by_name": True}

    def __init__(self, **data: Any):
        if "reason" in data and "description" not in data:
            data["description"] = data["reason"]
        super().__init__(**data)

    @property
    def reason(self) -> str:
        return self.description


class ThreatAlert(BaseModel):
    timestamp: datetime = Field(default_factory=datetime.utcnow)

    flow_id: str

    src_ip: str
    dst_ip: str

    src_port: int | None = None
    dst_port: int | None = None

    protocol: str = "TCP"

    threat_class: str

    severity: Literal[
        "LOW",
        "MEDIUM",
        "HIGH",
        "CRITICAL",
    ]

    confidence: float = Field(
        ge=0.0,
        le=1.0,
    )

    evidence: list[AlertEvidence] = Field(default_factory=list)

    attack_chain: list[str] = Field(default_factory=list)

    detector: str = "HYBRID_TRIAD"

    action: Literal["ALERT_ONLY"] = "ALERT_ONLY"

    model_config = {
        "json_schema_extra": {
            "example": {
                "timestamp": "2026-09-14T15:30:00Z",
                "flow_id": "flow_001",
                "src_ip": "10.0.0.15",
                "dst_ip": "10.0.0.20",
                "src_port": 52341,
                "dst_port": 443,
                "protocol": "TCP",
                "threat_class": "C2_BEACON",
                "severity": "HIGH",
                "confidence": 0.93,
                "evidence": [
                    {
                        "feature": "periodicity_score",
                        "value": 0.96,
                        "description": "Highly regular communication interval",
                    }
                ],
                "attack_chain": ["RECON", "C2_BEACON"],
                "detector": "c2_detector_v1",
                "action": "ALERT_ONLY",
            }
        }
    }

    @property
    def alert_id(self) -> str:
        """Backward-compatible alias for flow_id."""
        return self.flow_id

    @property
    def threat_type(self) -> str:
        """Backward-compatible alias for threat_class."""
        return self.threat_class

    @property
    def response_path(self) -> bool:
        """Backward-compatible check: response_path is strictly False."""
        return False

    @property
    def contains_payload(self) -> bool:
        """Backward-compatible check: contains_payload is strictly False."""
        return False

    @property
    def ingest_mode(self) -> str:
        return "passive"


# Backward-compatible aliases
StandardAlert = ThreatAlert
EvidenceItem = AlertEvidence
