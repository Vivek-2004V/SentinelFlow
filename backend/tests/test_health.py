from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_health():
    response = client.get("/health")

    assert response.status_code == 200

    data = response.json()

    assert data["status"] == "ok"
    assert data["mode"] == "read-only"


def test_security_boundary():
    response = client.get("/api/v1/status")

    assert response.status_code == 200

    data = response.json()

    assert data["ingest_mode"] == "passive"
    assert data["response_mode"] == "alert-only"
    assert data["payload_decryption"] is False
    assert data["return_path"] is False
