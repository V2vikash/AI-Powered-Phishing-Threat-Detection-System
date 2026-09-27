"""
URL Analyzer Service Integration

Coordinates URL feature extraction, model inference, and threat evaluation.
"""

import os
import sys
import joblib
import numpy as np
from typing import Dict, Any

# Ensure root directory is on sys.path
ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from backend.services.feature_extractor import (
    extract_features,
    extract_feature_vector,
    normalize_url
)
from backend.services.threat_engine import evaluate_threats

MODEL_PATH = os.path.join(os.path.dirname(__file__), "..", "models", "phishing_model.pkl")

# Cached model artifact instance
_MODEL_ARTIFACT = None


def load_model_artifact():
    """Loads and caches the trained ML model artifact."""
    global _MODEL_ARTIFACT
    if _MODEL_ARTIFACT is not None:
        return _MODEL_ARTIFACT

    if os.path.exists(MODEL_PATH):
        try:
            _MODEL_ARTIFACT = joblib.load(MODEL_PATH)
            print(f"[URL Analyzer] Loaded trained model from {MODEL_PATH}")
            return _MODEL_ARTIFACT
        except Exception as e:
            print(f"[URL Analyzer] Error loading model artifact: {e}")
            return None
    else:
        print(f"[URL Analyzer] Model artifact not found at {MODEL_PATH}. Using heuristic fallback.")
        return None


def analyze_url(url: str) -> Dict[str, Any]:
    """
    Primary interface for analyzing a target URL.
    Returns comprehensive threat assessment dict.
    """
    if not url or not isinstance(url, str):
        raise ValueError("Invalid URL input provided.")

    norm_url = normalize_url(url)
    features_dict = extract_features(norm_url)
    feature_vector = extract_feature_vector(norm_url)

    # ML Model Inference
    artifact = load_model_artifact()
    ml_probability = 0.0

    if artifact and "model" in artifact:
        try:
            model = artifact["model"]
            X_vec = np.array([feature_vector], dtype=np.float64)
            # predict_proba returns [prob_legit, prob_phishing]
            probs = model.predict_proba(X_vec)[0]
            ml_probability = float(probs[1])
        except Exception as e:
            print(f"[URL Analyzer] ML inference failed: {e}. Falling back to rule probability.")
            ml_probability = _fallback_heuristic_probability(features_dict)
    else:
        ml_probability = _fallback_heuristic_probability(features_dict)

    # Threat Engine Scoring
    result = evaluate_threats(norm_url, features_dict, ml_probability)
    return result


def _fallback_heuristic_probability(features: Dict[str, Any]) -> float:
    """Calculates a fallback probability when ML model file is absent."""
    score = 0.0
    if features.get("is_ip_address", 0) == 1:
        score += 0.4
    if features.get("tld_in_subdomain", 0) == 1:
        score += 0.4
    if features.get("suspicious_keyword_count", 0) > 0:
        score += 0.3
    if features.get("is_url_shortened", 0) == 1:
        score += 0.3
    if features.get("num_at", 0) > 0:
        score += 0.4
    return min(0.99, score)
