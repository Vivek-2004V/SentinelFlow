"""
Unit tests for Attack Simulation Lab endpoint (POST /api/v1/simulate).
"""
from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_simulate_single_attack():
    payload = {
        "attack_type": "DDOS",
        "mode": "single",
        "src_ip": "10.0.1.99",
        "dst_ip": "10.0.1.1",
    }
    response = client.post("/api/v1/simulate", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["simulated"] is True
    assert data["attack_type"] == "DDOS"
    assert data["flows_sent"] >= 1
    assert data["alerts_generated"] >= 1
    assert len(data["alerts"]) >= 1
    assert "ai_analysis" in data
    assert data["ai_analysis"]["ml_score"] >= 0.0


def test_simulate_attack_chain():
    payload = {
        "attack_type": "RECON",
        "mode": "chain",
        "src_ip": "192.168.10.88",
        "dst_ip": "10.0.0.1",
    }
    response = client.post("/api/v1/simulate", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["simulated"] is True
    assert data["mode"] == "chain"
    assert data["flows_sent"] >= 3
    assert data["alerts_generated"] >= 1
