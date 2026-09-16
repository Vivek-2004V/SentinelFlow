"""
Automated tests for Attack Simulation Lab endpoint (POST /api/v1/simulate).
Verifies all 6 threat vectors and multi-stage attack chain simulation,
enforcing that action is strictly 'ALERT_ONLY'.
"""
from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_simulate_ddos():
    response = client.post(
        "/api/v1/simulate",
        json={
            "attack_type": "DDOS",
            "mode": "single",
            "src_ip": "10.0.2.1",
        },
    )
    assert response.status_code == 200
    data = response.json()
    assert "alert" in data and data["alert"] is not None
    assert data["alert"]["action"] == "ALERT_ONLY"
    assert data["alert"]["threat_class"] == "DDOS"


def test_simulate_c2():
    response = client.post(
        "/api/v1/simulate",
        json={
            "attack_type": "C2_BEACON",
            "mode": "single",
            "src_ip": "10.0.2.2",
        },
    )
    assert response.status_code == 200
    data = response.json()
    assert "alert" in data and data["alert"] is not None
    assert data["alert"]["action"] == "ALERT_ONLY"
    assert data["alert"]["threat_class"] in ["C2_BEACON", "LIKELY_COMPROMISED_HOST"]


def test_simulate_dga():
    response = client.post(
        "/api/v1/simulate",
        json={
            "attack_type": "DGA",
            "mode": "single",
            "src_ip": "10.0.2.3",
        },
    )
    assert response.status_code == 200
    data = response.json()
    assert "alert" in data and data["alert"] is not None
    assert data["alert"]["action"] == "ALERT_ONLY"
    assert data["alert"]["threat_class"] in ["DGA", "LIKELY_COMPROMISED_HOST"]


def test_simulate_dns_tunnel():
    response = client.post(
        "/api/v1/simulate",
        json={
            "attack_type": "DNS_TUNNEL",
            "mode": "single",
            "src_ip": "10.0.2.4",
        },
    )
    assert response.status_code == 200
    data = response.json()
    assert "alert" in data and data["alert"] is not None
    assert data["alert"]["action"] == "ALERT_ONLY"


def test_simulate_recon():
    response = client.post(
        "/api/v1/simulate",
        json={
            "attack_type": "RECON",
            "mode": "single",
            "src_ip": "10.0.2.5",
        },
    )
    assert response.status_code == 200
    data = response.json()
    assert "alert" in data and data["alert"] is not None
    assert data["alert"]["action"] == "ALERT_ONLY"
    assert data["alert"]["threat_class"] in ["RECON", "LIKELY_COMPROMISED_HOST"]


def test_simulate_exfil():
    response = client.post(
        "/api/v1/simulate",
        json={
            "attack_type": "EXFIL",
            "mode": "single",
            "src_ip": "10.0.2.6",
        },
    )
    assert response.status_code == 200
    data = response.json()
    assert "alert" in data and data["alert"] is not None
    assert data["alert"]["action"] == "ALERT_ONLY"
    assert data["alert"]["threat_class"] in ["EXFIL", "LIKELY_COMPROMISED_HOST"]


def test_simulate_full_chain():
    response = client.post(
        "/api/v1/simulate",
        json={
            "attack_type": "RECON",
            "mode": "chain",
            "src_ip": "10.0.2.7",
        },
    )
    assert response.status_code == 200
    data = response.json()
    assert "alerts" in data
    assert len(data["alerts"]) >= 2
    for alert in data["alerts"]:
        assert alert["action"] == "ALERT_ONLY"
