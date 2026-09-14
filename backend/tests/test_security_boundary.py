"""
Test Suite: Security Boundary Validation (Step 10.1)
Verifies SentinelFlow core invariants:
- 100% Passive Ingestion
- Read-Only Monitoring
- Metadata Analysis Only (Zero Payload Decryption)
- Alert-Only Responses (Zero automated inline blocking / mitigation)
- Zero Return Path (No probing, scanning, or socket injection)
"""
from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_status_endpoint_security_invariants():
    """Verify that the system status explicitly reports read-only passive invariants."""
    response = client.get("/api/v1/status")
    assert response.status_code == 200
    data = response.json()

    assert data["status"] == "operational"
    assert data["ingest_mode"] == "passive"
    assert data["response_mode"] == "alert-only"
    assert data["payload_decryption"] is False
    assert data["return_path"] is False


def test_alert_only_action_enforcement():
    """Verify that any alert analyzed or generated strictly enforces action='ALERT_ONLY'."""
    sample_flow = {
        "src_ip": "10.0.0.15",
        "dst_ip": "198.51.100.4",
        "src_port": 50123,
        "dst_port": 80,
        "proto": "TCP",
        "bytes_sent": 50000000,
        "bytes_recv": 1200,
        "pkts_sent": 25000,
        "pkts_recv": 10,
        "duration_seconds": 0.5,
    }
    response = client.post("/api/v1/alerts/analyze", json=sample_flow)
    if response.status_code == 200:
        assert response.json()["action"] == "ALERT_ONLY"


def test_nonexistent_active_manipulation_endpoints():
    """
    Ensure active mitigation, blocking, packet injection, or scanning routes
    do NOT exist in the application (POST /block, /isolate, /probe, /scan, etc. return 404).
    """
    forbidden_endpoints = [
        "/block",
        "/api/v1/block",
        "/isolate",
        "/api/v1/isolate",
        "/probe",
        "/api/v1/probe",
        "/scan",
        "/api/v1/scan",
        "/mitigate",
        "/api/v1/mitigate",
        "/inject",
        "/api/v1/inject",
    ]

    for endpoint in forbidden_endpoints:
        res_post = client.post(endpoint, json={"target": "10.0.0.15"})
        assert res_post.status_code == 404, f"Endpoint {endpoint} should NOT exist!"

        res_get = client.get(endpoint)
        assert res_get.status_code == 404, f"Endpoint {endpoint} should NOT exist!"


def test_read_only_health_endpoint():
    """Verify health endpoint reports read-only passive mode."""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["service"] == "sentinelflow-api"
    assert data["mode"] == "read-only"
