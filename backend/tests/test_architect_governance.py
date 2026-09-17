"""
Tests for Backend Architect Governance & Reliability Standards.

Validates:
- Request Tracing (X-Request-ID, X-Response-Time-Ms)
- Defense-in-depth security response headers
- Liveness (/health/live) and Readiness (/health/ready) probes
- Standardized error response envelope with request_id correlation
"""
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_request_tracing_generated():
    """Verify X-Request-ID and X-Response-Time-Ms are injected if not provided."""
    response = client.get("/health")
    assert response.status_code == 200
    assert "x-request-id" in response.headers
    assert "x-response-time-ms" in response.headers
    assert float(response.headers["x-response-time-ms"]) >= 0.0


def test_request_tracing_propagated():
    """Verify custom X-Request-ID from client is preserved in response headers."""
    custom_id = "test-correlation-trace-uuid-1234"
    response = client.get("/health", headers={"X-Request-ID": custom_id})
    assert response.status_code == 200
    assert response.headers["x-request-id"] == custom_id


def test_security_headers_present():
    """Verify defense-in-depth security response headers on all endpoints."""
    response = client.get("/health")
    assert response.headers.get("x-content-type-options") == "nosniff"
    assert response.headers.get("x-frame-options") == "DENY"
    assert "mode=block" in response.headers.get("x-xss-protection", "")
    assert response.headers.get("referrer-policy") == "strict-origin-when-cross-origin"
    assert "accelerometer=()" in response.headers.get("permissions-policy", "")


def test_health_liveness():
    """Verify K8s liveness probe returns 200 and status live."""
    response = client.get("/health/live")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "live"


def test_health_readiness():
    """Verify deep readiness probe reports subsystem readiness."""
    response = client.get("/health/ready")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ready"
    assert "subsystems" in data
    assert data["subsystems"]["read_only_invariant"] == "enforced"
    assert data["subsystems"]["return_path"] == "disabled"
    assert "resources" in data
    assert "memory_usage_mb" in data["resources"]


def test_standardized_error_envelope_404():
    """Verify 404 responses conform to the standardized error envelope."""
    custom_id = "trace-err-404-check"
    response = client.get("/non-existent-endpoint", headers={"X-Request-ID": custom_id})
    assert response.status_code == 404
    data = response.json()
    assert "detail" in data
    assert "error" in data
    assert data["error"]["code"] == "NOT_FOUND"
    assert data["error"]["request_id"] == custom_id
    assert "timestamp" in data["error"]
