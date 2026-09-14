"""
Hybrid Data Exfiltration Detector.

Triad Architecture:
1. Rules: Massive outbound transfer asymmetry (>85% upload), packet flood exemption
2. ML: Flow Anomaly Isolation Forest scoring on sustained throughput
3. Statistics: Adaptive baseline deviation on bytes-per-second and session duration
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import List, Tuple

import joblib
import numpy as np

from app.detectors.base import BaseHybridDetector
from app.detectors.baseline import global_baseline
from app.schemas.detection import ThreatType
from app.schemas.flow import FlowFeatures

logger = logging.getLogger("sentinelflow.detectors.exfil")
MODEL_PATH = Path(__file__).resolve().parent.parent.parent.parent / "models" / "flow_anomaly.joblib"


class ExfiltrationDetector(BaseHybridDetector):
    threat_type = ThreatType.EXFIL
    detector_name = "exfiltration_hybrid_detector"
    threshold = 0.65

    # Triad weights
    w_rules = 0.35
    w_ml = 0.35
    w_stats = 0.30

    def __init__(self):
        self.model = None
        if MODEL_PATH.exists():
            try:
                self.model = joblib.load(MODEL_PATH)
            except Exception as e:
                logger.warning("Could not load Exfiltration ML model: %s", e)

    def compute_rules(self, features: FlowFeatures) -> Tuple[float, List[str]]:
        # Exemption for flood attacks (tiny packets at extreme rates are DDoS, not exfil)
        if features.pkts_per_second > 2000 and features.bytes_per_pkt < 150:
            return 0.0, []

        score = 0.0
        keys = []

        # Outbound transfer asymmetry
        if features.upload_ratio >= 0.90:
            score += 0.55
            keys.append("rule_massive_outbound_data_asymmetry")
        elif features.upload_ratio >= 0.75:
            score += 0.30
            keys.append("rule_elevated_upload_ratio")

        # Large byte rate
        if features.bytes_per_second >= 500_000:
            score += 0.40
            keys.append("rule_high_exfil_throughput")

        # Sustained duration
        if features.duration_seconds >= 60.0:
            score += 0.20
            keys.append("rule_sustained_outbound_stream")

        return min(score, 1.0), keys

    def compute_ml(self, features: FlowFeatures) -> Tuple[float, List[str]]:
        if features.pkts_per_second > 2000 and features.bytes_per_pkt < 150:
            return 0.0, []

        keys = []
        if self.model is not None:
            try:
                X = np.array([[
                    features.bytes_per_second,
                    features.pkts_per_second,
                    features.duration_seconds,
                    features.upload_ratio,
                ]])
                raw_score = float(self.model.decision_function(X)[0])
                anomaly_score = max(0.0, min(1.0, 0.5 - raw_score))
                if anomaly_score >= 0.5 and features.upload_ratio > 0.7:
                    keys.append(f"ml_throughput_anomaly_{anomaly_score:.2f}")
                return anomaly_score, keys
            except Exception as e:
                logger.debug("Exfil ML inference fallback: %s", e)

        score = 0.7 if features.upload_ratio >= 0.9 and features.bytes_per_second >= 400_000 else 0.0
        return score, keys

    def compute_statistics(self, features: FlowFeatures) -> Tuple[float, List[str]]:
        if features.pkts_per_second > 2000 and features.bytes_per_pkt < 150:
            return 0.0, []

        keys = []
        bps_dev = global_baseline.get_deviation("bytes_per_second", features.bytes_per_second)
        stat_score = min(max(0.0, bps_dev) / 4.0, 1.0)

        if bps_dev >= 3.0:
            keys.append(f"stat_outbound_bandwidth_zscore_{bps_dev:.1f}")

        return round(stat_score, 3), keys
