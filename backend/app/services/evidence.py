"""
Evidence Engine.

Assembles human-readable justification, confidence weighting,
and severity metrics for SOC analysts.
"""
from __future__ import annotations

from pydantic import BaseModel, Field

from app.schemas.alert import SeverityLevel, score_to_severity
from app.schemas.detection import AttackChain, FusedThreat


class EvidenceSummary(BaseModel):
    """Internal intermediate evidence synthesis for confidence and severity scoring."""
    confidence: float
    severity: SeverityLevel
    reasons: list[str] = Field(default_factory=list)
    feature_contributions: dict[str, float] = Field(default_factory=dict)
    deviation_from_baseline: float = 0.0


# Backward compatibility alias within evidence module
Evidence = EvidenceSummary


def build_evidence(
    fused: FusedThreat,
    chain: AttackChain,
    baseline_deviation: float,
) -> EvidenceSummary:
    """
    Synthesizes concrete reasons and confidence levels from detector evidence keys and baseline deviations.
    """
    reasons: list[str] = []
    contributions: dict[str, float] = {}

    # Gather reasons from each triggered detector
    for det in fused.detections:
        for key in det.evidence_keys:
            readable_key = key.replace("_", " ").capitalize()
            reasons.append(f"{det.detector_name}: {readable_key} detected (score={det.score:.2f})")
            contributions[key] = det.score

    if baseline_deviation > 2.0:
        reasons.append(f"Behavioral deviation: {baseline_deviation:.1f}x standard deviations above normal baseline")

    if chain.is_multi_stage:
        stage_names = " -> ".join([s.value for s in chain.stages])
        reasons.append(f"Multi-stage attack progression observed: {stage_names}")

    # Confidence calculation: composite of max score boosted by multi-stage and baseline deviation
    base_conf = fused.max_score
    if chain.is_multi_stage:
        base_conf = min(1.0, base_conf + 0.10)
    if baseline_deviation > 3.0:
        base_conf = min(1.0, base_conf + 0.05)

    final_confidence = round(base_conf, 2)
    severity = score_to_severity(final_confidence)

    return EvidenceSummary(
        confidence=final_confidence,
        severity=severity,
        reasons=reasons,
        feature_contributions=contributions,
        deviation_from_baseline=baseline_deviation,
    )

