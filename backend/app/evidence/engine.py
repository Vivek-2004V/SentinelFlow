from __future__ import annotations

from app.detectors.base import DetectionResult
from app.schemas.alert import AlertEvidence


def build_evidence(
    results: list[DetectionResult],
) -> list[AlertEvidence]:

    evidence: list[AlertEvidence] = []

    for result in results:
        for item in result.evidence:
            desc = item.get("description") or item.get("reason") or "Abnormal behavior detected"
            evidence.append(
                AlertEvidence(
                    feature=str(item.get("feature", "unknown_feature")),
                    value=item.get("value", 0),
                    description=(
                        f"{result.threat_class}: "
                        f"{desc}"
                    ),
                )
            )

    return evidence


def calculate_severity(
    confidence: float,
    threat_class: str,
) -> str:

    if threat_class == "LIKELY_COMPROMISED_HOST":
        if confidence >= 0.90:
            return "CRITICAL"
        if confidence >= 0.75:
            return "HIGH"

    if confidence >= 0.90:
        return "HIGH"

    if confidence >= 0.70:
        return "MEDIUM"

    return "LOW"

