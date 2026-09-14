"""
Standard Alert Final Schema (Section 12).

Canonical schema for SentinelFlow security notifications:
{
  "timestamp": "2026-09-14T10:30:00Z",
  "flow_id": "F-10021",
  "src_ip": "10.10.4.21",
  "dst_ip": "203.0.113.20",
  "threat_class": "LIKELY_COMPROMISED_HOST",
  "severity": "CRITICAL",
  "confidence": 0.96,
  "attack_chain": ["RECON", "C2_BEACON", "EXFILTRATION"],
  "evidence": [
    {"feature": "unique_dst_ports", "value": 187, "reason": "Unusual port fan-out"},
    {"feature": "periodicity", "value": 0.94, "reason": "Regular communication interval"},
    {"feature": "outbound_ratio", "value": 8.4, "reason": "Large outbound traffic deviation"}
  ],
  "action": "ALERT_ONLY"
}
"""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, List

from pydantic import BaseModel, Field


class SeverityLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


def score_to_severity(score: float) -> SeverityLevel:
    """Map 0–1 confidence score to standard severity level."""
    if score >= 0.85:
        return SeverityLevel.CRITICAL
    if score >= 0.65:
        return SeverityLevel.HIGH
    if score >= 0.40:
        return SeverityLevel.MEDIUM
    return SeverityLevel.LOW


class EvidenceItem(BaseModel):
    feature: str = Field(..., description="Telemetry metric or feature name")
    value: Any = Field(..., description="Observed feature value or ratio")
    reason: str = Field(..., description="Human-readable justification")


class StandardAlert(BaseModel):
    """
    Final canonical SentinelFlow alert contract.
    Enforces action='ALERT_ONLY' to guarantee passive one-way constraint.
    """
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    flow_id: str = Field(..., description="Unique flow alert identifier (e.g. F-10021)")
    src_ip: str
    dst_ip: str
    threat_class: str = Field(..., description="E.g. LIKELY_COMPROMISED_HOST, DDOS, C2_BEACON")
    severity: SeverityLevel
    confidence: float = Field(..., ge=0.0, le=1.0)
    attack_chain: List[str] = Field(default_factory=list)
    evidence: List[EvidenceItem] = Field(default_factory=list)
    action: str = Field("ALERT_ONLY", frozen=True)

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
        """Backward-compatible alias for response_path check (always False)."""
        return False

    @property
    def contains_payload(self) -> bool:
        """Backward-compatible alias for contains_payload check (always False)."""
        return False

    @property
    def ingest_mode(self) -> str:
        return "passive"

    model_config = {
        "json_schema_extra": {
            "example": {
                "timestamp": "2026-09-14T10:30:00Z",
                "flow_id": "F-10021",
                "src_ip": "10.10.4.21",
                "dst_ip": "203.0.113.20",
                "threat_class": "LIKELY_COMPROMISED_HOST",
                "severity": "CRITICAL",
                "confidence": 0.96,
                "attack_chain": ["RECON", "C2_BEACON", "EXFILTRATION"],
                "evidence": [
                    {"feature": "unique_dst_ports", "value": 187, "reason": "Unusual port fan-out"},
                    {"feature": "periodicity", "value": 0.94, "reason": "Regular communication interval"},
                    {"feature": "outbound_ratio", "value": 8.4, "reason": "Large outbound traffic deviation"},
                ],
                "action": "ALERT_ONLY",
            }
        }
    }
