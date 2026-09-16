from __future__ import annotations

from fastapi.testclient import TestClient

from app.core.config import settings
from app.main import app

client = TestClient(app)


def test_cors_options_headers():
    """Verify CORS preflight headers and origin whitelisting."""
    response = client.options(
        "/health",
        headers={
            "Origin": "http://localhost:3000",
            "Access-Control-Request-Method": "GET",
        },
    )
    assert response.status_code == 200
    assert response.headers.get("access-control-allow-origin") == "http://localhost:3000"


def test_auth_invalid_api_key():
    """Verify 401 Unauthorized when an invalid API key is provided."""
    response = client.post(
        "/api/v1/pcap/analyze",
        headers={"X-API-Key": "completely-invalid-key-xyz"},
        files={"file": ("test.pcap", b"\xa1\xb2\xc3\xd4" + b"\x00" * 40, "application/vnd.tcpdump.pcap")},
    )
    assert response.status_code == 401
    assert "Invalid API Key" in response.json()["detail"]


def test_auth_valid_api_key():
    """Verify successful authentication with valid API Key header."""
    response = client.post(
        "/api/v1/pcap/analyze",
        headers={"X-API-Key": settings.api_key},
        files={"file": ("test.pcap", b"\xa1\xb2\xc3\xd4" + b"\x00" * 40, "application/vnd.tcpdump.pcap")},
    )
    # The file is accepted past authentication (may succeed or parse 0 packets)
    assert response.status_code in (200, 400)
    assert response.status_code != 401


def test_auth_valid_bearer_token():
    """Verify authentication with Authorization: Bearer <token> format."""
    response = client.post(
        "/api/v1/pcap/analyze",
        headers={"Authorization": f"Bearer {settings.api_key}"},
        files={"file": ("test.pcap", b"\xa1\xb2\xc3\xd4" + b"\x00" * 40, "application/vnd.tcpdump.pcap")},
    )
    assert response.status_code != 401


def test_enforced_auth_rejection(monkeypatch):
    """Verify that when enforce_api_key is enabled, unauthenticated calls are rejected with 401."""
    monkeypatch.setattr(settings, "enforce_api_key", True)

    response = client.post(
        "/api/v1/pcap/analyze",
        files={"file": ("test.pcap", b"\xa1\xb2\xc3\xd4" + b"\x00" * 40, "application/vnd.tcpdump.pcap")},
    )
    assert response.status_code == 401
    assert "Authentication required" in response.json()["detail"]
