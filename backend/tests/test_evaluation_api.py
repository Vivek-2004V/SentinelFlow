"""
Unit tests for AI Quality Gate Evaluation API endpoints.
"""
import pytest
from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_get_evaluation_status():
    response = client.get("/api/v1/evaluation/status")
    assert response.status_code == 200
    data = response.json()
    assert "status" in data
    assert "gates" in data
    assert data["gates"]["preflight"] in ["PASS", "FAIL"]
    assert data["gates"]["smoke"] in ["PASS", "FAIL"]
    assert data["gates"]["signal"] in ["PASS", "FAIL"]
    assert data["gates"]["controlled"] in ["PASS", "FAIL"]
    assert "models" in data
    assert "dataset" in data
    assert "release_ready" in data


def test_post_run_evaluation():
    response = client.post("/api/v1/evaluation/run")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] in ["PASS", "FAIL"]
    assert data["gates"]["preflight"] == "PASS"
    assert data["gates"]["smoke"] == "PASS"
    assert data["gates"]["signal"] == "PASS"
    assert data["gates"]["controlled"] == "PASS"
    assert data["release_ready"] is True
    assert data["release_status"] == "READY"
