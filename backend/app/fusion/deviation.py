"""
Behavioral Deviation Analysis.

Quantifies how severely an observed threat diverges from historical baseline norms.
"""
from __future__ import annotations

from app.detectors.baseline import AdaptiveBaseline, global_baseline
from app.schemas.detection import FusedThreat


def calculate_behavior_deviation(
    fused: FusedThreat,
    baseline: AdaptiveBaseline = global_baseline,
) -> float:
    """
    Computes a composite deviation score across all evidence keys in the fused threat.
    Returns normalized deviation value (standard deviations above baseline).
    """
    total_deviation = 0.0
    count = 0

    for det in fused.detections:
        for metric, val in det.raw_features.items():
            if isinstance(val, (int, float)):
                dev = baseline.get_deviation(metric, float(val))
                if dev > 0:
                    total_deviation += dev
                    count += 1

    if count == 0:
        return 0.0

    avg_deviation = total_deviation / count
    return round(max(0.0, avg_deviation), 3)
