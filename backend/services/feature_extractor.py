"""
URL Feature Extractor Module

Extracts defensive structural, lexical, and statistical features from a URL
for threat classification and heuristic analysis.
"""

import re
import math
from typing import Dict, Any, List
from urllib.parse import urlparse

# List of common suspicious keywords used in phishing attacks
SUSPICIOUS_KEYWORDS = [
    "login", "verify", "account", "update", "banking", "secure", "signin",
    "security", "support", "service", "paypal", "apple", "microsoft", "google",
    "amazon", "netflix", "bank", "wallet", "crypto", "auth", "credential",
    "confirm", "validate", "payment", "unusual", "activity", "recover",
    "free", "bonus", "reward", "gift", "claim", "urgent", "notice"
]

# Common URL shortening domains
SHORTENING_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "goo.gl", "ow.ly",
    "buff.ly", "cutt.ly", "rb.gy", "shorturl.at", "tiny.cc"
}

# Common Top Level Domains for subdomain abuse checking
COMMON_TLDS = {".com", ".net", ".org", ".gov", ".edu", ".io", ".co", ".info", ".biz"}


def calculate_entropy(text: str) -> float:
    """Calculates Shannon Entropy of a string to detect randomness or obfuscation."""
    if not text:
        return 0.0
    entropy = 0.0
    length = len(text)
    char_counts: Dict[str, int] = {}
    for char in text:
        char_counts[char] = char_counts.get(char, 0) + 1
    for count in char_counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 4)


def is_valid_ip(hostname: str) -> bool:
    """Checks if a hostname is an IPv4 or IPv6 address."""
    if not hostname:
        return False
    # IPv4 check
    ipv4_pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
    if re.match(ipv4_pattern, hostname):
        parts = hostname.split(".")
        return all(0 <= int(p) <= 255 for p in parts)
    # IPv6 check
    if ":" in hostname:
        return True
    return False


def normalize_url(url: str) -> str:
    """Normalizes a URL string for consistent analysis."""
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return url


def extract_features(url: str) -> Dict[str, Any]:
    """
    Extracts numerical and categorical features from a target URL.
    Returns a dictionary of named features.
    """
    cleaned_url = url.strip()
    norm_url = normalize_url(cleaned_url)
    parsed = urlparse(norm_url)
    
    hostname = parsed.hostname or ""
    path = parsed.path or ""
    query = parsed.query or ""
    scheme = parsed.scheme or ""

    # Lexical Length Features
    url_len = len(cleaned_url)
    hostname_len = len(hostname)
    path_len = len(path)
    query_len = len(query)

    # Character Counts
    num_dots = cleaned_url.count(".")
    num_hyphens = cleaned_url.count("-")
    num_at = cleaned_url.count("@")
    num_question = cleaned_url.count("?")
    num_equals = cleaned_url.count("=")
    num_ampersand = cleaned_url.count("&")
    num_percent = cleaned_url.count("%")
    num_slashes = cleaned_url.count("/")
    num_numeric = sum(c.isdigit() for c in cleaned_url)

    # Special characters: @, ?, =, %, _, ~, !, $, &, *, +, #
    special_chars_pattern = r"[@?=%_~!$&*+#]"
    num_special_chars = len(re.findall(special_chars_pattern, cleaned_url))

    # Subdomain Counting
    # If hostname is not an IP, subdomains = dot count in hostname minus 1 (or 0 if single domain)
    if is_valid_ip(hostname):
        num_subdomains = 0
    else:
        domain_parts = [p for p in hostname.split(".") if p]
        num_subdomains = max(0, len(domain_parts) - 2) if len(domain_parts) >= 2 else 0

    # IP Address Presence
    ip_present = 1 if is_valid_ip(hostname) else 0

    # HTTPS usage
    has_https = 1 if scheme.lower() == "https" else 0

    # Suspicious keywords matching
    url_lower = cleaned_url.lower()
    matched_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in url_lower]
    suspicious_keyword_count = len(matched_keywords)

    # URL Shortener Detection
    is_shortened = 1 if hostname.lower() in SHORTENING_DOMAINS else 0

    # Path & Query Structure Anomalies
    has_double_slash_path = 1 if "//" in path else 0
    
    # Check if a TLD appears in subdomain (e.g., paypal.com.attacker.com)
    tld_in_subdomain = 0
    if num_subdomains > 0 and not ip_present:
        parts = hostname.lower().split(".")
        subdomain_part = ".".join(parts[:-2])
        for tld in COMMON_TLDS:
            if tld.lstrip(".") in subdomain_part:
                tld_in_subdomain = 1
                break

    # Shannon Entropy of URL and Hostname
    url_entropy = calculate_entropy(cleaned_url)
    hostname_entropy = calculate_entropy(hostname)

    # Abnormal Path / Query Structure flag
    abnormal_structure = 1 if (has_double_slash_path or num_percent > 3 or query_len > 100 or num_at > 0) else 0

    features = {
        "url_length": url_len,
        "hostname_length": hostname_len,
        "path_length": path_len,
        "query_length": query_len,
        "num_subdomains": num_subdomains,
        "num_dots": num_dots,
        "num_hyphens": num_hyphens,
        "num_at": num_at,
        "num_question": num_question,
        "num_equals": num_equals,
        "num_ampersand": num_ampersand,
        "num_percent": num_percent,
        "num_slashes": num_slashes,
        "num_numeric": num_numeric,
        "num_special_chars": num_special_chars,
        "is_ip_address": ip_present,
        "has_https": has_https,
        "suspicious_keyword_count": suspicious_keyword_count,
        "is_url_shortened": is_shortened,
        "has_double_slash_path": has_double_slash_path,
        "tld_in_subdomain": tld_in_subdomain,
        "url_entropy": url_entropy,
        "hostname_entropy": hostname_entropy,
        "abnormal_structure": abnormal_structure,
        # Helper metadata (not used as numeric feature vector)
        "_matched_keywords": matched_keywords,
        "_hostname": hostname,
        "_scheme": scheme,
        "_path": path
    }

    return features


FEATURE_KEYS = [
    "url_length",
    "hostname_length",
    "path_length",
    "query_length",
    "num_subdomains",
    "num_dots",
    "num_hyphens",
    "num_at",
    "num_question",
    "num_equals",
    "num_ampersand",
    "num_percent",
    "num_slashes",
    "num_numeric",
    "num_special_chars",
    "is_ip_address",
    "has_https",
    "suspicious_keyword_count",
    "is_url_shortened",
    "has_double_slash_path",
    "tld_in_subdomain",
    "url_entropy",
    "hostname_entropy",
    "abnormal_structure"
]


def extract_feature_vector(url: str) -> List[float]:
    """Returns an ordered numerical list of features suitable for scikit-learn model."""
    feats = extract_features(url)
    return [float(feats[k]) for k in FEATURE_KEYS]
