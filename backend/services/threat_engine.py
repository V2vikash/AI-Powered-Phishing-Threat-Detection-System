"""
Threat Scoring & Decision Engine

Combines machine learning prediction probability with rule-based heuristic checks
to calculate a transparent risk score (0-100), verdict, confidence rating,
detected threat indicators, explanation, and security recommendations.
"""

from typing import Dict, Any, List


def evaluate_threats(
    url: str,
    features: Dict[str, Any],
    ml_phishing_probability: float
) -> Dict[str, Any]:
    """
    Evaluates risk score and outputs a comprehensive threat report.
    
    ML probability contributes up to 50 points.
    Heuristic rule indicators contribute up to 50 points.
    Combined score is clamped between 0 and 100.
    """
    indicators: List[Dict[str, Any]] = []
    rule_penalty = 0

    # 1. IP Address Hostname Rule
    if features.get("is_ip_address", 0) == 1:
        rule_penalty += 25
        indicators.append({
            "id": "IP_HOST_ADDRESS",
            "severity": "CRITICAL",
            "category": "Network",
            "message": "URL uses a direct IP address instead of a registered domain name, common in phishing and C2 infrastructure.",
            "penalty": 25
        })

    # 2. HTTPS Absence Rule
    if features.get("has_https", 0) == 0:
        rule_penalty += 15
        indicators.append({
            "id": "UNENCRYPTED_HTTP",
            "severity": "MEDIUM",
            "category": "Transport Security",
            "message": "URL uses unencrypted HTTP protocol instead of HTTPS.",
            "penalty": 15
        })

    # 3. Suspicious Keywords Rule
    matched_kws = features.get("_matched_keywords", [])
    if matched_kws:
        kw_penalty = min(25, len(matched_kws) * 10)
        rule_penalty += kw_penalty
        indicators.append({
            "id": "SUSPICIOUS_KEYWORDS",
            "severity": "HIGH" if len(matched_kws) > 1 else "MEDIUM",
            "category": "Lexical Analysis",
            "message": f"Contains sensitive targeted keywords: {', '.join(matched_kws[:4])}.",
            "penalty": kw_penalty
        })

    # 4. URL Shortener Service
    if features.get("is_url_shortened", 0) == 1:
        rule_penalty += 20
        indicators.append({
            "id": "URL_SHORTENER_DETECTED",
            "severity": "HIGH",
            "category": "Obfuscation",
            "message": "Uses a URL shortening service which masks the actual destination domain.",
            "penalty": 20
        })

    # 5. TLD / Brand Spoofing in Subdomain
    if features.get("tld_in_subdomain", 0) == 1:
        rule_penalty += 25
        indicators.append({
            "id": "SUBDOMAIN_BRAND_SPOOFING",
            "severity": "CRITICAL",
            "category": "Domain Analysis",
            "message": "Appears to embed a top-level domain or brand name inside a subdomain structure.",
            "penalty": 25
        })

    # 6. Excessive Subdomains
    num_subs = features.get("num_subdomains", 0)
    if num_subs >= 3:
        rule_penalty += 15
        indicators.append({
            "id": "EXCESSIVE_SUBDOMAINS",
            "severity": "MEDIUM",
            "category": "Domain Analysis",
            "message": f"Host contains {num_subs} subdomains, suggesting deep nesting or domain camouflage.",
            "penalty": 15
        })

    # 7. User Info Spoofing (@ symbol in URL)
    if features.get("num_at", 0) > 0:
        rule_penalty += 25
        indicators.append({
            "id": "USERINFO_SPOOFING_AT_SYMBOL",
            "severity": "CRITICAL",
            "category": "Lexical Analysis",
            "message": "Contains '@' symbol, which causes browsers to ignore preceding credentials and load the host after '@'.",
            "penalty": 25
        })

    # 8. High Lexical Entropy (Obfuscation)
    url_entropy = features.get("url_entropy", 0.0)
    if url_entropy > 4.6:
        rule_penalty += 10
        indicators.append({
            "id": "HIGH_ENTROPY_STRING",
            "severity": "LOW",
            "category": "Obfuscation",
            "message": f"High character entropy ({url_entropy}), indicating potential randomness or encoded parameters.",
            "penalty": 10
        })

    # 9. Abnormal Length
    url_len = features.get("url_length", 0)
    if url_len > 75:
        rule_penalty += 10
        indicators.append({
            "id": "EXCESSIVE_URL_LENGTH",
            "severity": "LOW",
            "category": "Lexical Analysis",
            "message": f"URL length is unusually long ({url_len} characters).",
            "penalty": 10
        })

    # Calculate Raw Score (ML model 50% + Heuristics 50%)
    ml_score = ml_phishing_probability * 50.0
    heur_score = min(50.0, rule_penalty)
    raw_risk = ml_score + heur_score
    risk_score = int(round(min(100.0, max(0.0, raw_risk))))

    # Verdict Determination
    if risk_score >= 70:
        verdict = "HIGH RISK"
    elif risk_score >= 31:
        verdict = "SUSPICIOUS"
    else:
        verdict = "SAFE"

    # Confidence calculation based on ML probability & rule consensus
    ml_confidence = max(ml_phishing_probability, 1.0 - ml_phishing_probability)
    rule_consensus = (rule_penalty > 0 and ml_phishing_probability > 0.5) or (rule_penalty == 0 and ml_phishing_probability <= 0.5)
    confidence = round(float(ml_confidence * (0.95 if rule_consensus else 0.82)), 2)

    # Explanation Generation
    if verdict == "HIGH RISK":
        explanation = (
            f"The analyzed URL presents multiple severe threat indicators. "
            f"The machine learning classifier assigned a {int(ml_phishing_probability * 100)}% probability of phishing, "
            f"supported by {len(indicators)} heuristic risk rule matches."
        )
        recommendation = (
            "DO NOT click this link or enter any credentials, personal information, or financial details. "
            "If received via email or SMS, report it to your security administrator immediately."
        )
    elif verdict == "SUSPICIOUS":
        explanation = (
            f"The URL exhibits suspicious structural or lexical anomalies. "
            f"While not definitively confirmed as malicious, it triggered {len(indicators)} warning indicator(s) "
            f"with an ML threat probability of {int(ml_phishing_probability * 100)}%."
        )
        recommendation = (
            "Exercise extreme caution. Verify the legitimate domain name independently before interacting with this site. "
            "Check for SSL certificate validity and avoid submitting sensitive information."
        )
    else:
        explanation = (
            f"The URL displays normal structural metrics and low threat indicators. "
            f"The ML model assigned a low phishing probability of {int(ml_phishing_probability * 100)}%."
        )
        recommendation = (
            "The URL appears low risk based on static analysis. Performance on the development dataset does not guarantee real-world phishing detection accuracy. "
            "Always verify site authenticity independently."
        )

    return {
        "url": url,
        "verdict": verdict,
        "risk_score": risk_score,
        "confidence": confidence,
        "ml_probability": round(float(ml_phishing_probability), 4),
        "indicators": indicators,
        "explanation": explanation,
        "recommendation": recommendation,
        "features": {k: v for k, v in features.items() if not k.startswith("_")}
    }
