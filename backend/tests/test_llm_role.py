"""
Tests for LLM Role Boundary Invariants.

Verifies:
1. LLM != Security Authority: LLM explanation CANNOT mutate alert classification or response_path.
2. Mandatory Security Disclaimer is always present.
3. API endpoint /api/v1/alerts/{alert_id}/explanation functions correctly.
"""
from fastapi.testclient import TestClient

from app.db.database import db
from app.main import app
from app.schemas.alert import EvidenceItem, SeverityLevel, StandardAlert
from app.services.llm_explainer import generate_alert_explanation

client = TestClient(app)


def test_llm_cannot_mutate_alert():
    alert = StandardAlert(
        flow_id="F-10021",
        src_ip="192.168.1.50",
        dst_ip="203.0.113.10",
        threat_class="C2_BEACON",
        severity=SeverityLevel.HIGH,
        confidence=0.88,
        attack_chain=["C2_BEACON"],
        evidence=[
            EvidenceItem(
                feature="periodicity",
                value=0.92,
                reason="High periodicity beacon (score=0.92)",
            )
        ],
        action="ALERT_ONLY",
    )

    # Generate explanation
    explanation = generate_alert_explanation(alert)

    # Invariants: Alert attributes remain strictly identical
    assert alert.threat_class == "C2_BEACON"
    assert alert.severity == SeverityLevel.HIGH
    assert alert.confidence == 0.88
    assert alert.action == "ALERT_ONLY"

    # Explanation fields
    assert explanation.alert_id == alert.flow_id
    assert explanation.threat_type == "C2_BEACON"
    assert len(explanation.executive_summary) > 0
    assert len(explanation.mitre_tactics) > 0
    assert len(explanation.triage_recommendations) > 0

    # Mandatory security disclaimer
    assert "Advisory Only" in explanation.authority_disclaimer
    assert "zero decision" in explanation.authority_disclaimer


def test_llm_explanation_api_endpoint():
    db.clear_alerts()

    alert = StandardAlert(
        flow_id="F-10099",
        src_ip="198.51.100.99",
        dst_ip="10.0.0.1",
        threat_class="DDOS",
        severity=SeverityLevel.CRITICAL,
        confidence=0.95,
        attack_chain=["DDOS"],
        evidence=[
            EvidenceItem(feature="pkts_per_second", value=15000, reason="Extreme packet rate"),
            EvidenceItem(feature="bytes_per_second", value=2500000, reason="High bandwidth rate"),
        ],
        action="ALERT_ONLY",
    )
    db.save_alert(alert)

    # Request explanation from endpoint
    resp = client.get(f"/api/v1/alerts/{alert.flow_id}/explanation")
    assert resp.status_code == 200
    data = resp.json()

    assert data["alert_id"] == alert.alert_id
    assert data["threat_type"] == "DDOS"
    assert "T1498" in str(data["mitre_tactics"])
    assert len(data["triage_recommendations"]) >= 3
    assert "authority_disclaimer" in data

    # 404 test for non-existent alert
    not_found = client.get("/api/v1/alerts/non-existent-uuid/explanation")
    assert not_found.status_code == 404


def test_sanitize_active_mitigation():
    from app.services.llm_explainer import _sanitize_active_mitigation

    sample_bad_text = "The firewall blocked the attacker and the connection terminated while quarantined endpoint was isolated."
    sanitized = _sanitize_active_mitigation(sample_bad_text)
    assert "firewall blocked" not in sanitized
    assert "connection terminated" not in sanitized
    assert "quarantined endpoint" not in sanitized
    assert "passively alerted on" in sanitized


def test_llm_fallback_on_unreachable_provider():
    from app.core.config import settings
    
    # Save original settings
    orig_provider = settings.llm_provider
    orig_url = settings.ollama_url

    try:
        # Point to unreachable port with fast timeout
        settings.llm_provider = "ollama"
        settings.ollama_url = "http://127.0.0.1:59999"
        settings.llm_timeout_seconds = 0.5

        alert = StandardAlert(
            flow_id="F-FALLBACK-01",
            src_ip="192.168.1.100",
            dst_ip="10.0.0.5",
            threat_class="DGA",
            severity=SeverityLevel.HIGH,
            confidence=0.85,
            attack_chain=["DGA"],
            evidence=[
                EvidenceItem(feature="domain_entropy", value=4.12, reason="High Shannon entropy")
            ],
            action="ALERT_ONLY",
        )

        explanation = generate_alert_explanation(alert)
        assert explanation is not None
        assert explanation.alert_id == alert.flow_id
        assert explanation.threat_type == "DGA"
        assert "DGA" in explanation.executive_summary
        assert "T1568" in str(explanation.mitre_tactics)
    finally:
        settings.llm_provider = orig_provider
        settings.ollama_url = orig_url

