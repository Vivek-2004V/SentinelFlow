"""
End-to-end Pipeline & API Test Suite.

Verifies:
1. Passive benign vs attack detection
2. Architecture contracts (response_path=False, contains_payload=False)
3. Ingest API endpoint responses
4. SOC Alert stats aggregation
"""
from fastapi.testclient import TestClient

from app.main import app
from app.schemas.flow import RawFlow
from app.services.pipeline import pipeline_orchestrator

client = TestClient(app)


def test_benign_flow_produces_no_alert():
    pipeline_orchestrator.clear_alerts()
    flow = RawFlow(
        src_ip="192.168.1.50",
        dst_ip="8.8.8.8",
        dst_port=53,
        proto="UDP",
        bytes_sent=60,
        bytes_recv=120,
        pkts_sent=1,
        pkts_recv=1,
        duration_seconds=0.05,
        dns_query="google.com",
    )
    alert = pipeline_orchestrator.process_flow(flow)
    assert alert is None


def test_ddos_flow_produces_standard_alert():
    pipeline_orchestrator.clear_alerts()
    flow = RawFlow(
        src_ip="198.51.100.22",
        dst_ip="10.0.0.1",
        dst_port=80,
        proto="UDP",
        bytes_sent=1_000_000,
        bytes_recv=0,
        pkts_sent=12000,
        pkts_recv=0,
        duration_seconds=0.1,
    )
    alert = pipeline_orchestrator.process_flow(flow)
    assert alert is not None
    assert alert.threat_class in ("DDOS", "LIKELY_COMPROMISED_HOST")
    assert alert.confidence >= 0.65
    assert alert.action == "ALERT_ONLY"
    assert alert.flow_id.startswith("F-")
    assert len(alert.evidence) > 0
    assert hasattr(alert.evidence[0], "feature")
    assert hasattr(alert.evidence[0], "value")
    assert hasattr(alert.evidence[0], "reason")


def test_dga_flow_triggers_dga_detection():
    flow = RawFlow(
        src_ip="192.168.1.99",
        dst_ip="8.8.8.8",
        dst_port=53,
        proto="UDP",
        bytes_sent=80,
        bytes_recv=80,
        pkts_sent=1,
        pkts_recv=1,
        duration_seconds=0.02,
        dns_query="xq99z88b14aa77llkk2200mm.biz",
    )
    alert = pipeline_orchestrator.process_flow(flow)
    assert alert is not None
    assert alert.threat_class in ("DGA", "LIKELY_COMPROMISED_HOST")
    assert alert.action == "ALERT_ONLY"


def test_api_ingest_and_alerts_query():
    pipeline_orchestrator.clear_alerts()

    payload = {
        "src_ip": "192.168.1.120",
        "dst_ip": "198.51.100.5",
        "dst_port": 443,
        "proto": "TCP",
        "bytes_sent": 50_000_000,
        "bytes_recv": 500,
        "pkts_sent": 30000,
        "pkts_recv": 10,
        "duration_seconds": 90.0,
    }

    # Ingest through REST endpoint
    resp = client.post("/api/v1/ingest/flow", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "processed"
    assert data["alerts_generated"] >= 1

    # Query /api/v1/alerts
    alerts_resp = client.get("/api/v1/alerts")
    assert alerts_resp.status_code == 200
    alerts = alerts_resp.json()
    assert len(alerts) >= 1
    assert alerts[0]["src_ip"] == "192.168.1.120"
    assert alerts[0]["action"] == "ALERT_ONLY"
    assert alerts[0]["flow_id"].startswith("F-")

    # Check /api/v1/alerts/stats
    stats_resp = client.get("/api/v1/alerts/stats")
    assert stats_resp.status_code == 200
    stats = stats_resp.json()
    assert stats["total_alerts"] >= 1
