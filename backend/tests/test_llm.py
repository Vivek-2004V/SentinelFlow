from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.core.config import settings
from app.main import app
from app.schemas.alert import EvidenceItem, SeverityLevel, StandardAlert
from app.services.llm.fallback import FallbackProvider
from app.services.llm.service import LLMService, llm_service
from evaluation.llm_check import validate_llm_explanation

client = TestClient(app)


@pytest.mark.anyio
async def test_fallback_provider_output():
    provider = FallbackProvider()
    alert_dict = {
        "threat_class": "C2_BEACON",
        "severity": "HIGH",
        "evidence": [
            {"description": "Highly regular heartbeat interval (periodicity=0.96)"}
        ],
    }
    explanation = await provider.explain(alert_dict)
    assert "C2_BEACON" in explanation
    assert "HIGH" in explanation
    assert "periodicity=0.96" in explanation
    assert "ALERT_ONLY" in explanation


@pytest.mark.anyio
async def test_llm_service_fallback_mode():
    orig_provider = settings.llm_provider
    try:
        settings.llm_provider = "fallback"
        service = LLMService()

        alert_dict = {
            "threat_class": "DNS_TUNNEL",
            "severity": "CRITICAL",
            "confidence": 0.95,
            "evidence": [{"description": "Anomalous DNS query volume"}],
        }

        result = await service.explain(alert_dict)
        assert result["provider"] == "fallback"
        assert result["model"] is None
        assert result["status"] == "fallback"
        assert "DNS_TUNNEL" in result["explanation"]
        assert "ALERT_ONLY" in result["explanation"]
    finally:
        settings.llm_provider = orig_provider


@pytest.mark.anyio
async def test_llm_service_ollama_fallback_when_offline():
    orig_provider = settings.llm_provider
    orig_url = settings.ollama_base_url
    orig_timeout = settings.llm_timeout_seconds

    try:
        settings.llm_provider = "ollama"
        settings.ollama_base_url = "http://127.0.0.1:59998"
        settings.llm_timeout_seconds = 0.5
        service = LLMService()

        alert_dict = {
            "threat_class": "DDOS",
            "severity": "CRITICAL",
            "confidence": 0.99,
            "evidence": [{"description": "Extreme volumetric flood"}],
        }

        result = await service.explain(alert_dict)
        assert result["status"] == "fallback"
        assert result["provider"] == "fallback"
        assert "DDOS" in result["explanation"]
    finally:
        settings.llm_provider = orig_provider
        settings.ollama_base_url = orig_url
        settings.llm_timeout_seconds = orig_timeout


@pytest.mark.anyio
async def test_alert_immutability():
    alert = StandardAlert(
        flow_id="F-IMMUTABLE-01",
        src_ip="192.168.1.10",
        dst_ip="203.0.113.5",
        threat_class="EXFIL",
        severity=SeverityLevel.HIGH,
        confidence=0.89,
        evidence=[EvidenceItem(feature="bytes_sent", value=85000000, description="Massive upload")],
        action="ALERT_ONLY",
    )
    alert_copy = alert.model_dump()

    await llm_service.explain(alert_copy)

    # Invariants: Original fields remain unaltered
    assert alert.threat_class == "EXFIL"
    assert alert.severity == SeverityLevel.HIGH
    assert alert.confidence == 0.89
    assert alert.action == "ALERT_ONLY"
    assert alert_copy["action"] == "ALERT_ONLY"


def test_validate_llm_explanation_safety():
    unsafe_text = "The firewall blocked the attacker after payload decrypted and connection terminated."
    violations = validate_llm_explanation(unsafe_text)
    assert len(violations) >= 3
    assert "firewall blocked" in violations
    assert "payload decrypted" in violations
    assert "connection terminated" in violations

    safe_text = "SentinelFlow detected C2_BEACON activity with HIGH severity. The system operates in ALERT_ONLY mode."
    clean_violations = validate_llm_explanation(safe_text)
    assert len(clean_violations) == 0


def test_simulate_endpoint_includes_llm_field():
    response = client.post(
        "/api/v1/simulate",
        json={"attack_type": "C2_BEACON", "mode": "single"},
    )
    assert response.status_code == 200
    data = response.json()

    assert "alert" in data
    assert "llm" in data
    assert data["llm"] is not None
    assert "provider" in data["llm"]
    assert "status" in data["llm"]
    assert "explanation" in data["llm"]
    assert data["alert"]["action"] == "ALERT_ONLY"
