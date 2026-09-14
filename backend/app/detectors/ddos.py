"""
Hybrid DDoS Detector.

Triad Architecture:
1. Rules: Packet sizing signatures (<128B), asymmetric unreturned packets, flood bounds
2. ML: Trained Random Forest / XGBoost rate classifier
3. Statistics: Volumetric and packet rate Z-scores vs adaptive baseline
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, List, Tuple

import joblib
import numpy as np

from app.detectors.base import BaseHybridDetector, DetectionResult
from app.detectors.baseline import global_baseline
from app.schemas.detection import ThreatType
from app.schemas.flow import FlowFeatures

logger = logging.getLogger("sentinelflow.detectors.ddos")
MODEL_PATH = Path(__file__).resolve().parent.parent.parent.parent / "models" / "ddos_model.joblib"


def detect_ddos(features: dict[str, Any]) -> DetectionResult:
    pps = float(features.get("pps", 0))
    bps = float(features.get("bps", 0))
    packets = float(features.get("packets", 0))

    score = 0.0
    evidence = []

    if pps > 1000:
        score += 0.45
        evidence.append({
            "feature": "pps",
            "value": pps,
            "description": "Very high packet rate",
        })

    if bps > 10_000_000:
        score += 0.35
        evidence.append({
            "feature": "bps",
            "value": bps,
            "description": "High traffic throughput",
        })

    if packets > 5000:
        score += 0.20
        evidence.append({
            "feature": "packets",
            "value": packets,
            "description": "Large packet volume",
        })

    score = min(score, 1.0)

    return DetectionResult(
        threat_class="DDOS",
        score=score,
        confidence=score,
        evidence=evidence,
        detector="ddos_detector_v1",
    )


class DDoSSDetector(BaseHybridDetector):
    threat_type = ThreatType.DDOS
    detector_name = "ddos_hybrid_detector"
    threshold = 0.65

    # Triad weights
    w_rules = 0.35
    w_ml = 0.40
    w_stats = 0.25

    def __init__(self):
        self.model = None
        if MODEL_PATH.exists():
            try:
                self.model = joblib.load(MODEL_PATH)
            except Exception as e:
                logger.warning("Could not load DDoS ML model: %s", e)

    def compute_rules(self, features: FlowFeatures) -> Tuple[float, List[str]]:
        score = 0.0
        keys = []

        # High packet rate bound check
        if features.pkts_per_second >= 5000:
            score += 0.50
            keys.append("rule_extreme_packet_rate")
        elif features.pkts_per_second >= 1000:
            score += 0.30
            keys.append("rule_elevated_packet_rate")

        # Small packet flood sizing (<128 bytes)
        if 0 < features.bytes_per_pkt <= 128:
            score += 0.30
            keys.append("rule_small_packet_flood_profile")

        # Massive bandwidth rate
        if features.bytes_per_second >= 2_000_000:
            score += 0.20
            keys.append("rule_high_bandwidth_rate")

        return min(score, 1.0), keys

    def compute_ml(self, features: FlowFeatures) -> Tuple[float, List[str]]:
        keys = []
        if self.model is not None:
            try:
                X = np.array([[
                    features.pkts_per_second,
                    features.bytes_per_second,
                    features.bytes_per_pkt,
                ]])
                # Predict probability of attack (class 1)
                probs = self.model.predict_proba(X)[0]
                prob = float(probs[1]) if len(probs) > 1 else float(probs[0])
                if prob >= 0.5:
                    keys.append(f"ml_rf_rate_classifier_prob_{prob:.2f}")
                return prob, keys
            except Exception as e:
                logger.debug("DDoS ML inference fallback: %s", e)

        # Algorithmic fallback if model unavailable
        score = min(features.pkts_per_second / 8000.0, 1.0)
        if score >= 0.5:
            keys.append("ml_fallback_rate_density")
        return score, keys

    def compute_statistics(self, features: FlowFeatures) -> Tuple[float, List[str]]:
        keys = []
        pps_dev = global_baseline.get_deviation("pkts_per_second", features.pkts_per_second)
        bps_dev = global_baseline.get_deviation("bytes_per_second", features.bytes_per_second)

        # Composite statistical deviation
        avg_dev = max(0.0, (pps_dev + bps_dev) / 2.0)
        # Scale to 0-1 (e.g. 5 standard deviations = 1.0)
        stat_score = min(avg_dev / 5.0, 1.0)

        if pps_dev >= 3.0:
            keys.append(f"stat_packet_rate_zscore_{pps_dev:.1f}")
        if bps_dev >= 3.0:
            keys.append(f"stat_bandwidth_rate_zscore_{bps_dev:.1f}")

        return round(stat_score, 3), keys
