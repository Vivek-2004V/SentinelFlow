"""
Hybrid Command & Control (C2) Beacon Detector.

Triad Architecture:
1. Rules: Heartbeat payload size (<300B), non-standard ports, symmetric data exchange
2. ML: Flow Anomaly Isolation Forest scoring
3. Statistics: Autocorrelation timing periodicity score (0-1) and jitter analysis
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import List, Tuple

import joblib
import numpy as np

from app.detectors.base import BaseHybridDetector
from app.schemas.detection import ThreatType
from app.schemas.flow import FlowFeatures

logger = logging.getLogger("sentinelflow.detectors.c2")
MODEL_PATH = Path(__file__).resolve().parent.parent.parent.parent / "models" / "flow_anomaly.joblib"


class C2BeaconDetector(BaseHybridDetector):
    threat_type = ThreatType.C2_BEACON
    detector_name = "c2_hybrid_detector"
    threshold = 0.60

    # Triad weights
    w_rules = 0.30
    w_ml = 0.35
    w_stats = 0.35

    def __init__(self):
        self.model = None
        if MODEL_PATH.exists():
            try:
                self.model = joblib.load(MODEL_PATH)
            except Exception as e:
                logger.warning("Could not load Flow Anomaly ML model: %s", e)

    def compute_rules(self, features: FlowFeatures) -> Tuple[float, List[str]]:
        score = 0.0
        keys = []

        # Compact heartbeat payload (<300 bytes)
        if 0 < features.bytes_per_pkt <= 300:
            score += 0.35
            keys.append("rule_compact_heartbeat_payload")

        # Symmetric exchange ratio (0.35 - 0.65)
        if 0.35 <= features.upload_ratio <= 0.65:
            score += 0.30
            keys.append("rule_symmetric_exchange_ratio")

        # Beaconing to non-standard ports
        if features.dst_port not in (80, 443, 53) and features.dst_port > 1024:
            score += 0.35
            keys.append("rule_unusual_port_beaconing")

        return min(score, 1.0), keys

    def compute_ml(self, features: FlowFeatures) -> Tuple[float, List[str]]:
        keys = []
        if self.model is not None:
            try:
                X = np.array([[
                    features.bytes_per_second,
                    features.pkts_per_second,
                    features.duration_seconds,
                    features.upload_ratio,
                ]])
                # Isolation Forest decision_function (lower is more anomalous)
                raw_score = float(self.model.decision_function(X)[0])
                # Map typical decision score [-0.5, 0.5] to anomaly confidence [0.0, 1.0]
                anomaly_score = max(0.0, min(1.0, 0.5 - raw_score))
                if anomaly_score >= 0.5:
                    keys.append(f"ml_isolation_forest_anomaly_{anomaly_score:.2f}")
                return anomaly_score, keys
            except Exception as e:
                logger.debug("C2 ML inference fallback: %s", e)

        # Fallback anomaly heuristic
        score = 0.4 if (0 < features.bytes_per_pkt < 200 and features.duration_seconds < 0.2) else 0.0
        return score, keys

    def compute_statistics(self, features: FlowFeatures) -> Tuple[float, List[str]]:
        keys = []
        # Periodicity score (0.0 = random, 1.0 = highly regular beacon)
        periodicity = features.periodicity_score

        if periodicity >= 0.85:
            keys.append(f"stat_high_timing_periodicity_{periodicity:.2f}")
        elif periodicity >= 0.65:
            keys.append(f"stat_moderate_periodicity_{periodicity:.2f}")

        return periodicity, keys
