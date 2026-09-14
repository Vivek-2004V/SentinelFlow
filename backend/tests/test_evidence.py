"""
Test Suite: Evidence Generation Engine (Step 10.6)
Verifies explainable evidence building:
- Threat class, severity, confidence, source, destination
- Extracted features, values, and contextual explanations
- Deterministic severity matrix calculation
"""
from app.detectors.base import DetectionResult
from app.evidence.engine import build_evidence, calculate_severity


def test_build_evidence_structure():
    """Verify evidence objects contain feature, value, and clear description."""
    detection_results = [
        DetectionResult(
            threat_class="C2_BEACON",
            score=0.96,
            confidence=0.95,
            detector="c2_detector",
            evidence=[
                {
                    "feature": "periodicity_score",
                    "value": 0.96,
                    "description": "Highly regular communication interval (periodicity auto-correlation >= 0.90)",
                },
                {
                    "feature": "mean_iat",
                    "value": 30.0,
                    "description": "Mean inter-arrival time matches known C2 beacon cadence",
                },
            ],
        ),
        DetectionResult(
            threat_class="DGA",
            score=0.88,
            confidence=0.90,
            detector="dga_detector",
            evidence=[
                {
                    "feature": "dns_entropy",
                    "value": 4.52,
                    "description": "Shannon DNS query entropy exceeds algorithmic randomness threshold",
                }
            ],
        ),
    ]

    evidence_list = build_evidence(detection_results)
    assert len(evidence_list) == 3

    features = [e.feature for e in evidence_list]
    assert "periodicity_score" in features
    assert "mean_iat" in features
    assert "dns_entropy" in features

    for ev in evidence_list:
        assert ev.feature != ""
        assert ev.value is not None
        assert ev.description != ""
        assert ":" in ev.description  # Formatted as "{threat_class}: {description}"


def test_calculate_severity_matrix():
    """Verify severity tiers across confidence and threat classification."""
    # Compromised Host
    assert calculate_severity(0.95, "LIKELY_COMPROMISED_HOST") == "CRITICAL"
    assert calculate_severity(0.80, "LIKELY_COMPROMISED_HOST") == "HIGH"

    # Standard threats
    assert calculate_severity(0.92, "C2_BEACON") == "HIGH"
    assert calculate_severity(0.75, "DDOS") == "MEDIUM"
    assert calculate_severity(0.50, "RECON") == "LOW"
