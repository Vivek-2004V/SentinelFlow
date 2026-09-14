"""
Timing & Periodicity Feature Extractor.

Analyzes flow timestamps to detect regular heartbeat beacons (e.g. C2 frameworks).
"""
from __future__ import annotations

import math
from collections.abc import Sequence
from datetime import datetime


def extract_timing_features(timestamps: Sequence[datetime]) -> dict[str, float]:
    """
    Computes inter-arrival time stats and periodicity score from an ordered sequence of timestamps.
    Score close to 1.0 indicates high regularity (strong beaconing candidate).
    Score close to 0.0 indicates irregular/bursty traffic.
    """
    if len(timestamps) < 3:
        return {
            "inter_arrival_mean": 0.0,
            "inter_arrival_std": 0.0,
            "periodicity_score": 0.0,
        }

    # Sort timestamps chronologically
    sorted_ts = sorted(timestamps)
    deltas = [
        (sorted_ts[i] - sorted_ts[i - 1]).total_seconds()
        for i in range(1, len(sorted_ts))
    ]

    mean_delta = sum(deltas) / len(deltas)
    if mean_delta <= 0:
        return {
            "inter_arrival_mean": 0.0,
            "inter_arrival_std": 0.0,
            "periodicity_score": 0.0,
        }

    variance = sum((d - mean_delta) ** 2 for d in deltas) / len(deltas)
    std_delta = math.sqrt(variance)

    # Coefficient of variation (CV) = std / mean
    # Regular intervals have low CV (< 0.1) -> high periodicity score
    cv = std_delta / mean_delta
    # Sigmoidal decay for periodicity score bounded [0, 1]
    periodicity = max(0.0, min(1.0, 1.0 / (1.0 + cv)))

    return {
        "inter_arrival_mean": round(mean_delta, 3),
        "inter_arrival_std": round(std_delta, 3),
        "periodicity_score": round(periodicity, 4),
    }
