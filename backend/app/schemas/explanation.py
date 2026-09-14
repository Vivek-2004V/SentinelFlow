"""
LLM Explanation Schemas.

Enforces the boundary:
LLM output is strictly advisory for SOC human analysts.
It carries ZERO authority to alter detection results or execute blocking actions.
"""
from __future__ import annotations

from typing import List

from pydantic import BaseModel, Field

DISCLAIMER_TEXT = (
    "Advisory Only: All threat detections, risk scores, and confidence ratings "
    "are deterministically computed by the SentinelFlow Hybrid Triad. "
    "This AI-generated incident briefing is provided solely for human analyst context "
    "and carries zero decision or inline blocking authority."
)


class AlertExplanation(BaseModel):
    alert_id: str
    threat_type: str
    severity: str
    confidence: float
    executive_summary: str = Field(..., description="Plain-English explanation of the observed event")
    technical_narrative: str = Field(..., description="Technical breakdown of telemetry markers")
    mitre_tactics: List[str] = Field(default_factory=list, description="MITRE ATT&CK framework alignments")
    triage_recommendations: List[str] = Field(default_factory=list, description="Manual SOC analyst checklist")
    authority_disclaimer: str = Field(default=DISCLAIMER_TEXT, frozen=True)
