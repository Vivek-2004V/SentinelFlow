from __future__ import annotations

DEFAULT_WEIGHTS: dict[str, float] = {
    "detector": 0.60,
    "ml": 0.25,
    "baseline": 0.15,
}


def calculate_fused_score(
    detector_score: float,
    ml_score: float,
    baseline_score: float,
    weights: dict[str, float] | None = None,
) -> float:
    w = weights or DEFAULT_WEIGHTS

    score = (
        w.get("detector", 0.60) * detector_score
        + w.get("ml", 0.25) * ml_score
        + w.get("baseline", 0.15) * baseline_score
    )

    return min(max(score, 0.0), 1.0)
