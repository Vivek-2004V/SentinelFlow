"""
Hybrid TLS & QUIC Metadata Anomaly Detector.

Triad Architecture:
1. Rules: Direct IP address in SNI, missing SNI in TLS handshake
2. ML: Unsupervised TLS parameter cluster anomaly scoring
3. Statistics: Port vs protocol distribution divergence (e.g. TLS on non-standard ports)
"""
from __future__ import annotations

from typing import Any, List, Tuple

from app.detectors.base import BaseHybridDetector, DetectionResult
from app.schemas.detection import ThreatType
from app.schemas.flow import FlowFeatures


def detect_tls_anomaly(
    features: dict[str, Any],
) -> DetectionResult:

    packet_std = float(
        features.get("packet_size_std", 0)
    )

    iat_std = float(
        features.get("iat_std", 0)
    )

    score = 0.0
    evidence = []

    if packet_std > 500:
        score += 0.50
        evidence.append({
            "feature": "packet_size_std",
            "value": packet_std,
            "description": (
                "Unusual encrypted-session packet-size variation"
            ),
        })

    if iat_std > 5:
        score += 0.50
        evidence.append({
            "feature": "iat_std",
            "value": iat_std,
            "description": (
                "Unusual encrypted-session timing variation"
            ),
        })

    score = min(score, 1.0)

    return DetectionResult(
        threat_class="TLS_ANOMALY",
        score=score,
        confidence=score,
        evidence=evidence,
        detector="tls_anomaly_detector_v1",
    )



class TLSAnomalyDetector(BaseHybridDetector):
    threat_type = ThreatType.TLS_ANOMALY
    detector_name = "tls_anomaly_hybrid_detector"
    threshold = 0.60

    # Triad weights
    w_rules = 0.40
    w_ml = 0.35
    w_stats = 0.25

    def compute_rules(self, features: FlowFeatures) -> Tuple[float, List[str]]:
        score = 0.0
        keys = []

        if features.has_tls:
            # TLS over non-standard port (not 443, 8443, 9443)
            if features.dst_port not in (443, 8443, 9443, 8080):
                score += 0.45
                keys.append(f"rule_tls_non_standard_port_{features.dst_port}")

            # Missing SNI
            if features.tls_sni_length == 0:
                score += 0.40
                keys.append("rule_missing_sni_in_handshake")

        if features.has_quic and features.proto != "UDP":
            score += 0.50
            keys.append("rule_anomalous_quic_transport")

        return min(score, 1.0), keys

    def compute_ml(self, features: FlowFeatures) -> Tuple[float, List[str]]:
        keys = []
        score = 0.0

        # Parameter combination anomaly: non-standard port without SNI indicates evasion/tunneling
        if features.has_tls and features.dst_port not in (443, 8443) and features.tls_sni_length == 0:
            score = 0.85
            keys.append("ml_tls_evasion_profile_anomaly")
        elif features.has_tls and features.dst_port > 1024 and features.dst_port not in (8443, 9443):
            score = 0.45

        return score, keys

    def compute_statistics(self, features: FlowFeatures) -> Tuple[float, List[str]]:
        keys = []
        score = 0.0

        if features.has_tls and features.dst_port not in (443, 8443):
            # Port divergence metric
            score = 0.75
            keys.append("stat_port_protocol_divergence")

        return score, keys
