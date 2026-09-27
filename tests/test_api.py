"""
Integration Tests for FastAPI Endpoints
"""

import sys
import os
import pytest
from fastapi.testclient import TestClient

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from backend.app import app

client = TestClient(app)


def test_health_endpoint():
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert "service" in data
    assert "model_loaded" in data


def test_analyze_valid_url():
    payload = {"url": "https://www.github.com/features/security"}
    response = client.post("/api/analyze", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["url"].startswith("https://")
    assert "verdict" in data
    assert "risk_score" in data
    assert "confidence" in data
    assert isinstance(data["indicators"], list)


def test_analyze_ip_url():
    payload = {"url": "http://192.168.1.1/admin/login"}
    response = client.post("/api/analyze", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["verdict"] in ["SUSPICIOUS", "HIGH RISK"]


def test_analyze_malformed_url():
    payload = {"url": "not_a_valid_url_string!!!"}
    response = client.post("/api/analyze", json=payload)
    assert response.status_code in [400, 422]


def test_analyze_empty_input():
    payload = {"url": ""}
    response = client.post("/api/analyze", json=payload)
    assert response.status_code == 422


def test_get_history():
    response = client.get("/api/history?limit=5")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)


def test_get_stats():
    response = client.get("/api/stats")
    assert response.status_code == 200
    data = response.json()
    assert "total_analyzed" in data
    assert "breakdown" in data
