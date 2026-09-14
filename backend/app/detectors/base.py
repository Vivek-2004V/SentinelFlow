"""
Base Detector and Canonical Result Schema.

Standardizes detector output across the hybrid triad:
- Rules (signatures, deterministic limits)
- ML (XGBoost, Random Forest, Isolation Forest)
- Statistics (z-scores, entropy, fan-out)
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, List, Tuple

from app.schemas.detection import DetectionResult as SchemaDetectionResult
from app.schemas.detection import ThreatType
from app.schemas.flow import FlowFeatures


@dataclass
class DetectionResult:
    threat_class: str
    score: float
    confidence: float
    evidence: list[dict[str, Any]]
    detector: str


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
        Model inference: XGBoost / Random Forest classifier.
        Falls back to heuristic proxy if models/ is empty or unloaded.
        Returns: (probability between 0.0 and 1.0, list of evidence keys)
        """
        return 0.0, []

    def compute_statistics(self, features: FlowFeatures) -> Tuple[float, List[str]]:
        """
        Baseline statistical deviation: z-scores, fan-out, entropy.
        Returns: (anomaly score between 0.0 and 1.0, list of evidence keys)
        """
        return 0.0, []

    def evaluate(self, features: FlowFeatures) -> SchemaDetectionResult:
        """
        Runs all three engines, applies component weights, and returns a unified DetectionResult.
        """
        r_score, r_keys = self.compute_rules(features)
        m_score, m_keys = self.compute_ml(features)
        s_score, s_keys = self.compute_statistics(features)

        # Weighted combination
        combined_score = round(
            self.w_rules * r_score + self.w_ml * m_score + self.w_stats * s_score,
            4,
        )
        combined_score = max(0.0, min(1.0, combined_score))
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

        return SchemaDetectionResult(
            threat_type=self.threat_type,
            score=combined_score,
            triggered=triggered,
            threshold=self.threshold,
            detector_name=self.detector_name,
            evidence_keys=all_keys,
            raw_features=raw_features,
        )

    def detect(self, features: FlowFeatures) -> SchemaDetectionResult:
        """
        Evaluates the Hybrid Triad and computes the final combined threat score.
        """
        return self.evaluate(features)
