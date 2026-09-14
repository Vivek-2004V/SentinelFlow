"""
Base Hybrid Detector.

Implements the Triad Architecture:
                FEATURES
                   │
        ┌──────────┼──────────┐
        ↓          ↓          ↓
      RULES        ML     STATISTICS
        │          │          │
        └──────────┼──────────┘
                   ↓
              Threat Score
"""
from __future__ import annotations

from typing import List, Tuple

from app.schemas.detection import DetectionResult, ThreatType
from app.schemas.flow import FlowFeatures


class BaseHybridDetector:
    threat_type: ThreatType = ThreatType.UNKNOWN
    detector_name: str = "base_detector"
    threshold: float = 0.60

    # Default component weights (sum to 1.0)
    w_rules: float = 0.35
    w_ml: float = 0.40
    w_stats: float = 0.25

    def compute_rules(self, features: FlowFeatures) -> Tuple[float, List[str]]:
        """
        Deterministic heuristics, port signatures, and hard boundary checks.
        Returns: (score between 0.0 and 1.0, list of evidence keys)
        """
        return 0.0, []

    def compute_ml(self, features: FlowFeatures) -> Tuple[float, List[str]]:
        """
        Inference from trained models (XGBoost, Random Forest, N-gram classifier, Isolation Forest).
        Returns: (score between 0.0 and 1.0, list of evidence keys)
        """
        return 0.0, []

    def compute_statistics(self, features: FlowFeatures) -> Tuple[float, List[str]]:
        """
        Deviations from adaptive baselines, z-scores, entropy, distributions.
        Returns: (score between 0.0 and 1.0, list of evidence keys)
        """
        return 0.0, []

    def detect(self, features: FlowFeatures) -> DetectionResult:
        """
        Evaluates the Hybrid Triad and computes the final combined threat score.
        """
        r_score, r_keys = self.compute_rules(features)
        m_score, m_keys = self.compute_ml(features)
        s_score, s_keys = self.compute_statistics(features)

        # Normalize bounded [0.0, 1.0]
        r_score = max(0.0, min(1.0, r_score))
        m_score = max(0.0, min(1.0, m_score))
        s_score = max(0.0, min(1.0, s_score))

        # Weighted combined score
        combined = (self.w_rules * r_score) + (self.w_ml * m_score) + (self.w_stats * s_score)
        combined_score = round(min(combined, 1.0), 3)

        triggered = combined_score >= self.threshold

        # Deduplicate and combine evidence keys
        all_keys = list(dict.fromkeys(r_keys + m_keys + s_keys))

        raw_features = {
            "rule_score": round(r_score, 3),
            "ml_score": round(m_score, 3),
            "stat_score": round(s_score, 3),
            "combined_score": combined_score,
            "weights": {
                "rules": self.w_rules,
                "ml": self.w_ml,
                "statistics": self.w_stats,
            },
        }

        return DetectionResult(
            threat_type=self.threat_type,
            score=combined_score,
            triggered=triggered,
            threshold=self.threshold,
            detector_name=self.detector_name,
            evidence_keys=all_keys,
            raw_features=raw_features,
        )
