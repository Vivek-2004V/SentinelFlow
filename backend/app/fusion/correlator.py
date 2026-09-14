"""
Threat Correlator.

Correlates multiple detection outputs for a given source host into a FusedThreat.
"""
from __future__ import annotations

from datetime import datetime, timedelta

from app.schemas.detection import DetectionResult, FusedThreat


def correlate_detections(
    src_ip: str,
    results: list[DetectionResult],
    timestamp: datetime | None = None,
) -> FusedThreat | None:
    """
    Evaluates detector outputs. Returns a FusedThreat if any detector triggered,
    or None if all detectors returned benign scores.
    """
    triggered_results = [r for r in results if r.triggered]
    if not triggered_results:
        # Check if multiple near-threshold results exist
        sub_threshold = [r for r in results if r.score >= 0.45]
        if len(sub_threshold) < 2:
            return None
        triggered_results = sub_threshold

    # Sort by score descending so highest confidence is first
    triggered_results.sort(key=lambda r: r.score, reverse=True)

    now = timestamp or datetime.utcnow()
    # Preserve score order while removing duplicates
    seen = set()
    threat_types = []
    for r in triggered_results:
        if r.threat_type not in seen:
            seen.add(r.threat_type)
            threat_types.append(r.threat_type)

    max_score = triggered_results[0].score

    # Multi-stage if more than one distinct threat category fired
    is_multi_stage = len(threat_types) > 1

    return FusedThreat(
        src_ip=src_ip,
        window_start=now - timedelta(seconds=60),
        window_end=now,
        detections=triggered_results,
        threat_types=threat_types,
        max_score=max_score,
        is_multi_stage=is_multi_stage,
    )
