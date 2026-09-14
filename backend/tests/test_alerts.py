from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_alert_endpoint_exists():
    response = client.post(
        "/api/v1/alerts/analyze",
        json={
            "flow_id": "test-001",
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.2",
            "protocol": "TCP",
            "duration": 10,
            "packets": 100,
            "bytes": 10000,
            "timestamps": [0, 10, 20],
            "destination_ports": [],
            "destination_hosts": [],
            "outbound_bytes": 1000,
            "inbound_bytes": 1000,
        },
    )

    assert response.status_code in (200, 204)


def test_alert_is_alert_only():
    response = client.post(
        "/api/v1/alerts/analyze",
        json={
            "flow_id": "test-002",
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.2",
            "protocol": "TCP",
            "duration": 10,
            "packets": 100,
            "bytes": 10000,
            "timestamps": [0, 10, 20],
            "destination_ports": [],
            "destination_hosts": [],
            "outbound_bytes": 1000,
            "inbound_bytes": 1000,
        },
    )

    if response.status_code == 200:
        assert response.json()["action"] == "ALERT_ONLY"


def test_threat_flow_produces_alert_only_action():
    """Explicitly tests a threat flow producing 200 OK and asserts action='ALERT_ONLY'."""
    response = client.post(
        "/api/v1/alerts/analyze",
        json={
            "flow_id": "test-ddos-001",
            "src_ip": "192.168.1.100",
            "dst_ip": "10.0.0.1",
            "protocol": "TCP",
            "duration": 1.0,
            "packets": 50000,
            "bytes": 40000000,
        },
    )
    assert response.status_code == 200
    data = response.json()
    assert data["action"] == "ALERT_ONLY"
    assert data["threat_class"] == "DDOS"
    assert data["confidence"] >= 0.90
    assert len(data["evidence"]) > 0
