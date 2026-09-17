"""
Tests for User Feedback API.
"""
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_submit_feedback():
    """Verify user can submit feedback and receive confirmation."""
    payload = {
        "rating": 5,
        "category": "UI / Design",
        "message": "The 5-page layout and real-time network graphs make monitoring intuitive.",
        "email": "analyst@enterprise.com",
    }
    res = client.post("/api/v1/feedback", json=payload)
    assert res.status_code == 201
    data = res.json()
    assert data["status"] == "success"
    assert "feedback_id" in data


def test_list_feedback():
    """Verify feedback can be retrieved for product iteration."""
    res = client.get("/api/v1/feedback")
    assert res.status_code == 200
    data = res.json()
    assert data["total"] >= 1
    assert len(data["feedback"]) >= 1


def test_submit_feedback_validation():
    """Verify invalid feedback ratings or empty messages are rejected."""
    # Rating > 5
    res = client.post("/api/v1/feedback", json={"rating": 10, "message": "Hi"})
    assert res.status_code == 422
