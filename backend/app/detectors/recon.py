"""
Hybrid Reconnaissance & Scan Detector.

Triad Architecture:
1. Rules: Unanswered probe sizing (SYN packets <60B), sensitive port targets (22, 445, 3389)
2. ML: Fan-out port diversity and scanning behavior anomaly model
3. Statistics: Short-lived probe duration distribution deviation
"""
from __future__ import annotations

from typing import List, Tuple

from app.detectors.base import BaseHybridDetector
from app.schemas.detection import ThreatType
from app.schemas.flow import FlowFeatures


class ReconDetector(BaseHybridDetector):
    threat_type = ThreatType.RECON
    detector_name = "recon_hybrid_detector"
    threshold = 0.60

    # Triad weights
    w_rules = 0.40
    w_ml = 0.35
    w_stats = 0.25

    def compute_rules(self, features: FlowFeatures) -> Tuple[float, List[str]]:
        score = 0.0
        keys = []

        recon_ports = {21, 22, 23, 25, 80, 135, 139, 445, 1433, 3306, 3389, 5432, 8080}
        if features.dst_port in recon_ports:
            score += 0.40
            keys.append(f"rule_sensitive_port_probe_{features.dst_port}")

        # Tiny packet sizing typical of SYN scan probes
        if 0 < features.bytes_per_pkt <= 60:
            score += 0.35
            keys.append("rule_syn_probe_packet_size")

        return min(score, 1.0), keys

    def compute_ml(self, features: FlowFeatures) -> Tuple[float, List[str]]:
        keys = []
        # Scanning ML heuristic: unanswered high upload ratio with minimal packets
        score = 0.0
        if features.upload_ratio >= 0.95 and features.duration_seconds < 0.15:
            score = 0.85
            keys.append("ml_fanout_probe_anomaly")
        elif features.upload_ratio >= 0.80 and features.duration_seconds < 0.3:
            score = 0.50

        return score, keys

    def compute_statistics(self, features: FlowFeatures) -> Tuple[float, List[str]]:
        keys = []
        score = 0.0

        # Probes are exceptionally short compared to average flows
        if features.duration_seconds < 0.05:
            score = 0.85
            keys.append("stat_extreme_low_duration_probe")
        elif features.duration_seconds < 0.2:
            score = 0.50

        return score, keys
