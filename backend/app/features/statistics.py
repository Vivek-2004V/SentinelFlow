"""
Statistical Feature Extractor.

Computes standard deviations, z-scores, and percentile metrics against baselines.
"""
from __future__ import annotations

import math


def compute_z_score(value: float, mean: float, std: float) -> float:
    """Computes Z-score of a value given baseline mean and standard deviation."""
    if std <= 0:
        return 0.0
    return round((value - mean) / std, 3)


def compute_statistical_features(
    value: float,
    baseline_mean: float,
    baseline_std: float,
) -> dict[str, float]:
    """
    Computes statistical indicators comparing an observed metric to an established baseline.
    """
    z_score = compute_z_score(value, baseline_mean, baseline_std)
    # Approximate normal CDF percentile rank
    percentile = 0.5 * (1.0 + math.erf(z_score / math.sqrt(2.0)))

    return {
        "z_score": z_score,
        "percentile_rank": round(percentile, 4),
    }
