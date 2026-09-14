"""
Tests for Step 6: Threat Fusion, Adaptive Baseline, and ML Correlation.
"""
from datetime import datetime, timedelta

from app.baseline.adaptive import AdaptiveBaseline
from app.fusion.engine import (
    detect_attack_chain,
    detect_temporal_attack_chain,
    fuse_flow_threat,
)
from app.fusion.scorer import calculate_fused_score
from app.ml.predict import MLModels


def test_adaptive_baseline_host_profiling():
    baseline = AdaptiveBaseline(window_size=50)

    # Train baseline for normal workstation (mean ~100 pps, std ~ 5)
    for pps in [95.0, 105.0, 100.0, 98.0, 102.0]:
        baseline.update("10.0.0.15_pps", pps)

    # Benign packet rate: deviation should be low (< 2.0 sigma)
    dev_normal = baseline.deviation("10.0.0.15_pps", 104.0)
    assert dev_normal < 2.0

    # Anomalous packet flood: deviation should be massive (> 50.0 sigma)
    dev_attack = baseline.deviation("10.0.0.15_pps", 4500.0)
    assert dev_attack > 50.0


def test_fused_score_weighting():
    # Detector dominant threat
    score1 = calculate_fused_score(
        detector_score=0.90,
        ml_score=0.80,
        baseline_score=1.0,
    )
    # 0.60 * 0.9 + 0.25 * 0.8 + 0.15 * 1.0 = 0.54 + 0.20 + 0.15 = 0.89
    assert score1 == 0.89

    # Benign flow
    score2 = calculate_fused_score(
        detector_score=0.0,
        ml_score=0.0,
        baseline_score=0.0,
    )
    assert score2 == 0.0


def test_attack_chain_patterns():
    # Full 3-stage chain
    res1 = detect_attack_chain(["RECON", "C2_BEACON", "EXFIL"])
    assert res1["assessment"] == "LIKELY_COMPROMISED_HOST"
    assert "RECON" in res1["attack_chain"]
    assert "C2_BEACON" in res1["attack_chain"]
    assert "EXFIL" in res1["attack_chain"]

    # 2-stage chain
    res2 = detect_attack_chain(["DGA", "C2_BEACON"])
    assert res2["assessment"] == "LIKELY_COMPROMISED_HOST"

    # Single isolated threat: no multi-stage chain
    res3 = detect_attack_chain(["DDOS"])
    assert res3["assessment"] is None
    assert res3["attack_chain"] == []


def test_temporal_sliding_window():
    now = datetime.utcnow()

    # Events within 5-minute sliding window (10:00 -> 10:03 -> 10:04)
    correlated_events = [
        {"threat_class": "RECON", "timestamp": now},
        {"threat_class": "C2_BEACON", "timestamp": now + timedelta(minutes=3)},
        {"threat_class": "EXFIL", "timestamp": now + timedelta(minutes=4)},
    ]
    res_corr = detect_temporal_attack_chain(correlated_events, window_seconds=300)
    assert res_corr["assessment"] == "LIKELY_COMPROMISED_HOST"

    # Disconnected events (24 hours apart): should NOT correlate into a chain
    disconnected_events = [
        {"threat_class": "RECON", "timestamp": now - timedelta(days=1)},
        {"threat_class": "EXFIL", "timestamp": now},
    ]
    res_disc = detect_temporal_attack_chain(disconnected_events, window_seconds=300)
    assert res_disc["assessment"] is None
    assert "exceeds" in res_disc.get("reason", "")


def test_ml_models_prediction():
    models = MLModels()
    res = models.predict({
        "pps": 4500,
        "bps": 20_000_000,
        "unique_dst_ports": 3,
        "periodicity_score": 0.2,
    })

    assert "predicted_class" in res
    assert "classification_confidence" in res
    assert "is_anomaly" in res
    assert "anomaly_score" in res
    assert isinstance(res["classification_confidence"], float)


def test_end_to_end_fusion_flow():
    features = {
        "pps": 5000,
        "bps": 25_000_000,
        "packets": 10000,
        "bytes": 50_000_000,
        "unique_dst_ports": 1,
        "unique_dst_hosts": 1,
    }

    fusion_result = fuse_flow_threat(
        features=features,
        detector_score=0.85,
        baseline_deviation=3.5,
    )

    assert "fused_score" in fusion_result
    assert fusion_result["fused_score"] > 0.60
    assert "assessment" in fusion_result
    assert fusion_result["detector_score"] == 0.85
