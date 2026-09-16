from __future__ import annotations

import tempfile

from fastapi.testclient import TestClient
from scapy.all import IP, TCP, UDP, wrpcap

from app.main import app

client = TestClient(app)


def _build_synthetic_pcap_bytes() -> bytes:
    """Generates a small in-memory PCAP containing valid IP packets."""
    packets = []
    # 1. Benign TCP handshake and request
    for i in range(5):
        pkt = IP(src="192.168.1.50", dst="142.250.190.206") / TCP(sport=50000 + i, dport=443, flags="PA") / (b"X" * 120)
        packets.append(pkt)

    # 2. Volumetric UDP flood (DDoS pattern)
    for _ in range(30):
        pkt = IP(src="10.0.99.10", dst="203.0.113.88") / UDP(sport=40000, dport=80) / (b"FLOOD" * 10)
        packets.append(pkt)

    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=True) as tmp:
        wrpcap(tmp.name, packets)
        tmp.seek(0)
        return tmp.read()


def test_invalid_pcap_extension():
    response = client.post(
        "/api/v1/pcap/analyze",
        files={"file": ("test.txt", b"plain text is not a pcap", "text/plain")},
    )
    assert response.status_code == 400
    assert "Unsupported file extension" in response.json()["detail"]


def test_empty_pcap_file():
    response = client.post(
        "/api/v1/pcap/analyze",
        files={"file": ("empty.pcap", b"", "application/vnd.tcpdump.pcap")},
    )
    assert response.status_code == 400
    assert "empty" in response.json()["detail"].lower()


def test_valid_pcap_upload_and_analysis():
    pcap_bytes = _build_synthetic_pcap_bytes()

    response = client.post(
        "/api/v1/pcap/analyze",
        files={"file": ("synthetic_capture.pcap", pcap_bytes, "application/vnd.tcpdump.pcap")},
    )

    assert response.status_code == 200
    data = response.json()

    assert data["filename"] == "synthetic_capture.pcap"
    assert data["mode"] == "PASSIVE"
    assert data["packets_analyzed"] >= 35
    assert data["flows_reconstructed"] >= 2
    assert "alerts" in data
    assert "security" in data
    assert data["security"]["passive_capture"] is True
    assert data["security"]["read_only"] is True
    assert data["security"]["action"] == "ALERT_ONLY"

    for alert in data["alerts"]:
        assert alert["action"] == "ALERT_ONLY"
