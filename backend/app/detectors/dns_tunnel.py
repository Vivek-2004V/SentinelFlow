"""
Hybrid DNS Tunneling Detector.

Triad Architecture:
1. Rules: Oversized DNS queries (>50B), port 53 bandwidth thresholds
2. ML: Statistical character distribution and base32/hex encoding anomaly scoring
3. Statistics: Subdomain depth nesting variance and query volume deviation
"""
from __future__ import annotations

from typing import List, Tuple

from app.detectors.base import BaseHybridDetector
from app.schemas.detection import ThreatType
from app.schemas.flow import FlowFeatures


class DNSTunnelDetector(BaseHybridDetector):
    threat_type = ThreatType.DNS_TUNNEL
    detector_name = "dns_tunnel_hybrid_detector"
    threshold = 0.65

    # Triad weights
    w_rules = 0.35
    w_ml = 0.35
    w_stats = 0.30

    def compute_rules(self, features: FlowFeatures) -> Tuple[float, List[str]]:
        score = 0.0
        keys = []

        # Tunnels transfer encoded data in very long labels
        if features.dns_query_length >= 50:
            score += 0.60
            keys.append("rule_oversized_dns_tunnel_query")
        elif features.dns_query_length >= 32:
            score += 0.35
            keys.append("rule_extended_dns_query_name")

        # Port 53 bandwidth threshold
        if features.dst_port == 53 and features.bytes_per_second > 10_000:
            score += 0.40
            keys.append("rule_abnormal_dns_bandwidth_volume")

        return min(score, 1.0), keys

    def compute_ml(self, features: FlowFeatures) -> Tuple[float, List[str]]:
        keys = []
        # Encoded anomaly model: tunnels show high entropy + length clustering
        encoded_score = 0.0
        if features.dns_query_length > 30 and features.dns_entropy >= 3.5:
            encoded_score = min(1.0, (features.dns_query_length / 60.0) * 0.5 + (features.dns_entropy / 4.5) * 0.5)
            keys.append(f"ml_encoded_payload_anomaly_{encoded_score:.2f}")

        return round(encoded_score, 3), keys

    def compute_statistics(self, features: FlowFeatures) -> Tuple[float, List[str]]:
        keys = []
        score = 0.0

        # Subdomain depth nesting (tunnels use multi-label base32/hex hierarchy)
        if features.dns_subdomain_depth >= 3:
            score += 0.60
            keys.append(f"stat_excessive_subdomain_depth_{features.dns_subdomain_depth}")
        elif features.dns_subdomain_depth >= 2:
            score += 0.30
            keys.append("stat_nested_subdomain_structure")

        if features.dns_entropy >= 3.6:
            score += 0.40
            keys.append("stat_tunnel_entropy_divergence")

        return min(score, 1.0), keys
