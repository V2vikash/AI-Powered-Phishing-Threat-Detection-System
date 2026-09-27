"""
Unit Tests for URL Analyzer & Threat Engine Services
"""

import sys
import os
import pytest

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from backend.services.url_analyzer import analyze_url


def test_analyze_safe_url():
    url = "https://www.wikipedia.org/wiki/Computer_security"
    res = analyze_url(url)

    assert "verdict" in res
    assert res["verdict"] in ["SAFE", "SUSPICIOUS"]
    assert 0 <= res["risk_score"] <= 100
    assert 0.0 <= res["confidence"] <= 1.0
    assert "explanation" in res
    assert "recommendation" in res


def test_analyze_phishing_url():
    url = "http://185.220.101.5/login-paypal-verify/account.php"
    res = analyze_url(url)

    assert res["verdict"] in ["SUSPICIOUS", "HIGH RISK"]
    assert res["risk_score"] >= 35
    assert len(res["indicators"]) >= 2
    # Verify indicator fields
    for ind in res["indicators"]:
        assert "id" in ind
        assert "severity" in ind
        assert "category" in ind
        assert "message" in ind


def test_analyze_shortened_url():
    url = "http://bit.ly/3xYz123"
    res = analyze_url(url)

    indicator_ids = [i["id"] for i in res["indicators"]]
    assert "URL_SHORTENER_DETECTED" in indicator_ids
