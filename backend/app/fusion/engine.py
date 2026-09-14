from __future__ import annotations

from typing import Any

CHAIN_PATTERNS: list[tuple[list[str], str]] = [
    (
        ["RECON", "C2_BEACON"],
        "LIKELY_COMPROMISED_HOST",
    ),
    (
        ["DGA", "C2_BEACON"],
        "LIKELY_COMPROMISED_HOST",
    ),
    (
        ["DNS_TUNNEL", "C2_BEACON", "EXFIL"],
        "LIKELY_COMPROMISED_HOST",
    ),
    (
        ["RECON", "C2_BEACON", "EXFIL"],
        "LIKELY_COMPROMISED_HOST",
    ),
]


def detect_attack_chain(
    threat_classes: list[str],
) -> dict[str, Any]:
    observed = set(threat_classes)

    # Check more specific (longer) attack chains first
    sorted_patterns = sorted(CHAIN_PATTERNS, key=lambda item: len(item[0]), reverse=True)

    for required, chain_name in sorted_patterns:
        if all(item in observed for item in required):
            return {
                "attack_chain": required,
                "assessment": chain_name,
            }

    return {
        "attack_chain": [],
        "assessment": None,
    }


def detect_temporal_attack_chain(
    events: list[dict[str, Any]],
    window_seconds: int = 300,
) -> dict[str, Any]:
    """
    Enforces temporal correlation:
    - Same host events must occur within `window_seconds` (default 5 minutes).
    - Events must reflect logical attack sequence.
    - Suppresses stale/disconnected events (e.g. Recon yesterday vs Exfil today).
    """
    if not events:
        return {"attack_chain": [], "assessment": None}

    # Sort events by timestamp
    sorted_events = sorted(
        events,
        key=lambda e: e["timestamp"] if hasattr(e["timestamp"], "timestamp") else float(e["timestamp"]),
    )

    # Convert timestamps to float seconds for delta calculation
    def to_epoch(ts: Any) -> float:
        return float(ts.timestamp()) if hasattr(ts, "timestamp") else float(ts)

    start_epoch = to_epoch(sorted_events[0]["timestamp"])
    end_epoch = to_epoch(sorted_events[-1]["timestamp"])

    # If events span beyond the temporal correlation window, avoid false association
    if (end_epoch - start_epoch) > window_seconds:
        return {
            "attack_chain": [],
            "assessment": None,
            "reason": f"Events span {round(end_epoch - start_epoch)}s (exceeds {window_seconds}s window)",
        }

    # Extract observed classes in order
    observed_classes = [e["threat_class"] for e in sorted_events]
    return detect_attack_chain(observed_classes)


def fuse_flow_threat(
    features: dict[str, Any],
    detector_score: float,
    baseline_deviation: float,
    recent_history: list[dict[str, Any]] | None = None,
    weights: dict[str, float] | None = None,
) -> dict[str, Any]:
    """
    Executes the Complete Final Fusion Flow:
    1. ML Inference (Random Forest threat probability + Isolation Forest anomaly)
    2. Combines Deterministic Detector + ML Confidence + Baseline Deviation into Fused Score
    3. Evaluates Temporal Attack Chain (Kill-Chain sequence)
    4. Emits Final Assessment
    """
    from app.fusion.scorer import calculate_fused_score
    from app.ml.predict import MLModels

    # 1. ML predictions
    try:
        models = MLModels()
        ml_pred = models.predict(features)
        ml_score = ml_pred.get("classification_confidence", 0.0)
        predicted_class = ml_pred.get("predicted_class", "BENIGN")
    except Exception:
        ml_score = 0.0
        predicted_class = "UNKNOWN"
        ml_pred = {}

    # 2. Normalize baseline deviation into [0.0, 1.0] score (e.g. z-score of 3.0+ is 1.0)
    norm_baseline = min(max(baseline_deviation / 3.0, 0.0), 1.0)

    # 3. Calculate Fused Threat Score
    fused_score = calculate_fused_score(
        detector_score=detector_score,
        ml_score=ml_score,
        baseline_score=norm_baseline,
        weights=weights,
    )

    # 4. Temporal Attack Chain Correlation
    if recent_history:
        chain_res = detect_temporal_attack_chain(recent_history)
    else:
        chain_res = detect_attack_chain([predicted_class])

    assessment = chain_res.get("assessment")
    if not assessment:
        if fused_score >= 0.70:
            assessment = "HIGH_CONFIDENCE_THREAT"
        elif fused_score >= 0.45:
            assessment = "SUSPICIOUS_ACTIVITY"
        else:
            assessment = "BENIGN"

    return {
        "fused_score": round(fused_score, 3),
        "detector_score": round(detector_score, 3),
        "ml_score": round(ml_score, 3),
        "ml_prediction": ml_pred,
        "baseline_score": round(norm_baseline, 3),
        "attack_chain": chain_res.get("attack_chain", []),
        "assessment": assessment,
    }


