from __future__ import annotations

import statistics


def calculate_iat_features(timestamps: list[float]) -> dict[str, float]:
    if len(timestamps) < 2:
        return {
            "mean_iat": 0.0,
            "iat_std": 0.0,
            "periodicity_score": 0.0,
        }

    timestamps = sorted(timestamps)

    intervals = [
        timestamps[index] - timestamps[index - 1]
        for index in range(1, len(timestamps))
    ]

    mean_iat = statistics.mean(intervals)

    if len(intervals) > 1:
        iat_std = statistics.pstdev(intervals)
    else:
        iat_std = 0.0

    if mean_iat == 0:
        periodicity_score = 0.0
    else:
        variation = iat_std / mean_iat
        periodicity_score = max(0.0, min(1.0, 1.0 - variation))

    return {
        "mean_iat": mean_iat,
        "iat_std": iat_std,
        "periodicity_score": periodicity_score,
    }
