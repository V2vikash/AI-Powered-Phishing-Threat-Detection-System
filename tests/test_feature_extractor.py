"""
Unit Tests for URL Feature Extractor
"""

import sys
import os
import pytest

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from backend.services.feature_extractor import (
    extract_features,
    extract_feature_vector,
    is_valid_ip,
    calculate_entropy,
    normalize_url,
    FEATURE_KEYS
)


def test_normalize_url():
    assert normalize_url("google.com") == "http://google.com"
    assert normalize_url("https://example.org") == "https://example.org"
    assert normalize_url("   http://test.com  ") == "http://test.com"


def test_is_valid_ip():
    assert is_valid_ip("192.168.1.1") is True
    assert is_valid_ip("185.220.101.5") is True
    assert is_valid_ip("256.1.1.1") is False
    assert is_valid_ip("google.com") is False
    assert is_valid_ip("2001:0db8:85a3:0000:0000:8a2e:0370:7334") is True


def test_entropy_calculation():
    assert calculate_entropy("") == 0.0
    assert calculate_entropy("aaaaa") == 0.0  # zero randomness
    assert calculate_entropy("abcdef") > 2.0


def test_extract_features_legitimate():
    url = "https://www.wikipedia.org/wiki/Main_Page"
    feats = extract_features(url)

    assert feats["has_https"] == 1
    assert feats["is_ip_address"] == 0
    assert feats["num_subdomains"] == 1  # www
    assert feats["suspicious_keyword_count"] == 0
    assert feats["is_url_shortened"] == 0
    assert feats["url_length"] > 20


def test_extract_features_ip_based():
    url = "http://192.168.1.100/login.php"
    feats = extract_features(url)

    assert feats["is_ip_address"] == 1
    assert feats["has_https"] == 0
    assert feats["suspicious_keyword_count"] >= 1  # login


def test_extract_features_suspicious_patterns():
    url = "http://paypal.com.verify-billing.account-update.xyz/login/confirm?token=123%20"
    feats = extract_features(url)

    assert feats["tld_in_subdomain"] == 1
    assert feats["suspicious_keyword_count"] >= 3  # verify, account, update, login
    assert feats["num_percent"] > 0
    assert feats["num_subdomains"] >= 2


def test_extract_feature_vector():
    url = "https://example.com"
    vec = extract_feature_vector(url)

    assert len(vec) == len(FEATURE_KEYS)
    assert isinstance(vec[0], float)
