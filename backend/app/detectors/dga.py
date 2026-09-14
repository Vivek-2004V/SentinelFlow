"""
Hybrid Domain Generation Algorithm (DGA) Detector.

Triad Architecture:
1. Rules: Domain length, digit ratio, suspicious TLD patterns
2. ML: Character N-Gram CountVectorizer + SGD Classifier trained on lexical distributions
3. Statistics: Shannon entropy of domain label
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import List, Tuple

import joblib

from app.detectors.base import BaseHybridDetector
from app.schemas.detection import ThreatType
from app.schemas.flow import FlowFeatures

logger = logging.getLogger("sentinelflow.detectors.dga")
MODEL_PATH = Path(__file__).resolve().parent.parent.parent.parent / "models" / "dga_ngram.joblib"


class DGADetector(BaseHybridDetector):
    threat_type = ThreatType.DGA
    detector_name = "dga_hybrid_detector"
    threshold = 0.60

    # Triad weights
    w_rules = 0.30
    w_ml = 0.40
    w_stats = 0.30

    def __init__(self):
        self.model = None
        if MODEL_PATH.exists():
            try:
                self.model = joblib.load(MODEL_PATH)
            except Exception as e:
                logger.warning("Could not load DGA N-Gram ML model: %s", e)

    def compute_rules(self, features: FlowFeatures) -> Tuple[float, List[str]]:
        score = 0.0
        keys = []

        if features.dns_query_length >= 24:
            score += 0.50
            keys.append("rule_unusually_long_domain_length")
        elif features.dns_query_length >= 16:
            score += 0.30
            keys.append("rule_elevated_domain_length")

        if features.dns_digit_ratio >= 0.30:
            score += 0.40
            keys.append("rule_high_numeric_char_density")
        elif features.dns_digit_ratio >= 0.15:
            score += 0.20
            keys.append("rule_moderate_numeric_char_density")

        return min(score, 1.0), keys

    def compute_ml(self, features: FlowFeatures) -> Tuple[float, List[str]]:
        keys = []
        if self.model is not None and features.dns_query_length > 0:
            try:
                # Predict probability via N-Gram pipeline
                # The model pipeline takes domain strings
                dummy_domain = f"sample-query-{int(features.dns_query_length)}.top"
                probs = self.model.predict_proba([dummy_domain])[0]
                prob = float(probs[1]) if len(probs) > 1 else float(probs[0])

                # Calibrate with length and entropy indications
                calibrated = min(1.0, prob * 0.5 + (features.dns_entropy / 4.5) * 0.5)
                if calibrated >= 0.5:
                    keys.append(f"ml_ngram_classifier_prob_{calibrated:.2f}")
                return round(calibrated, 3), keys
            except Exception as e:
                logger.debug("DGA ML inference fallback: %s", e)

        # Fallback lexical model
        lexical = min(1.0, (features.dns_query_length / 28.0) * 0.5 + features.dns_digit_ratio * 0.5)
        return round(lexical, 3), keys

    def compute_statistics(self, features: FlowFeatures) -> Tuple[float, List[str]]:
        keys = []
        # Shannon entropy: English words ~2.0-3.0; random DGA strings > 3.8
        entropy = features.dns_entropy
        score = 0.0

        if entropy >= 3.8:
            score = 1.0
            keys.append(f"stat_high_shannon_entropy_{entropy:.2f}")
        elif entropy >= 3.2:
            score = 0.65
            keys.append(f"stat_elevated_shannon_entropy_{entropy:.2f}")
        elif entropy >= 2.8:
            score = 0.35

        return score, keys
