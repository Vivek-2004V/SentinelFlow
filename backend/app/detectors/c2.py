from __future__ import annotations

from typing import Any

from app.detectors.base import DetectionResult


def detect_c2(features: dict[str, Any]) -> DetectionResult:
    periodicity = float(
        features.get("periodicity_score", 0.0)
    )

    mean_iat = float(
        features.get("mean_iat", 0.0)
    )

    score = 0.0
    evidence = []

    if periodicity >= 0.80:
        score += 0.65

        evidence.append({
            "feature": "periodicity_score",
            "value": periodicity,
            "description": (
                "Highly regular communication intervals"
            ),
        })

    if mean_iat > 0:
        score += 0.35

        evidence.append({
            "feature": "mean_iat",
            "value": mean_iat,
            "description": "Repeated inter-arrival timing observed",
        })

    score = min(score, 1.0)

    return DetectionResult(
        threat_class="C2_BEACON",
        score=score,
        confidence=score,
        evidence=evidence,
        detector="c2_detector_v1",
    )
