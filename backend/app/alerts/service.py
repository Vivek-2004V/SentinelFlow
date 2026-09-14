from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from app.chains.attack_chain import detect_attack_chain
from app.detectors.base import DetectionResult
from app.evidence.engine import (
    build_evidence,
    calculate_severity,
)
from app.schemas.alert import ThreatAlert

LIFECYCLE_ORDER = {
    "RECON": 1,
    "DGA": 2,
    "DNS_TUNNEL": 3,
    "C2": 4,
    "C2_BEACON": 4,
    "EXFIL": 5,
    "DDOS": 6,
    "TLS_ANOMALY": 7,
}


def build_alert(
    flow: dict[str, Any],
    results: list[DetectionResult],
) -> ThreatAlert | None:

    if not results:
        return None

    strongest = max(
        results,
        key=lambda result: result.score,
    )

    if strongest.score < 0.50:
        return None

    threat_classes = sorted(
        [
            result.threat_class
            for result in results
            if result.score >= 0.50
        ],
        key=lambda tc: LIFECYCLE_ORDER.get(tc, 99),
    )

    chain = detect_attack_chain(threat_classes)

    if chain:
        threat_class = chain.name
        confidence = min(
            1.0,
            max(result.score for result in results) + 0.05,
        )
        severity = chain.severity
        attack_chain = list(chain.sequence)
    else:
        threat_class = strongest.threat_class
        confidence = strongest.confidence
        severity = calculate_severity(
            confidence,
            threat_class,
        )
        attack_chain = []

    return ThreatAlert(
        timestamp=datetime.now(timezone.utc),
        flow_id=str(flow.get("flow_id", "unknown")),
        src_ip=str(flow.get("src_ip", "unknown")),
        dst_ip=str(flow.get("dst_ip", "unknown")),
        src_port=flow.get("src_port"),
        dst_port=flow.get("dst_port"),
        protocol=str(flow.get("protocol", "UNKNOWN")),
        threat_class=threat_class,
        severity=severity,
        confidence=confidence,
        evidence=build_evidence(results),
        attack_chain=attack_chain,
        detector=strongest.detector,
        action="ALERT_ONLY",
    )
