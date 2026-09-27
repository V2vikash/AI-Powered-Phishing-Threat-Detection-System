"""
Synthetic and Curated URL Dataset Generator

Creates a balanced CSV dataset of legitimate and phishing URLs with realistic 
lexical, structural, and domain patterns for training and evaluation.
"""

import os
import random
import pandas as pd

# Seeds for reproducibility
random.seed(42)

# Safe Legitimate Domain & Path Building Blocks
LEGITIMATE_DOMAINS = [
    "google.com", "github.com", "wikipedia.org", "microsoft.com", "apple.com",
    "amazon.com", "stackoverflow.com", "python.org", "mozilla.org", "cloudflare.com",
    "nytimes.com", "bbc.com", "cnn.com", "linkedin.com", "twitter.com",
    "reddit.com", "spotify.com", "netflix.com", "adobe.com", "dropbox.com",
    "salesforce.com", "slack.com", "zoom.us", "github.io", "medium.com",
    "gitlab.com", "oracle.com", "ibm.com", "intel.com", "cisco.com",
    "mit.edu", "stanford.edu", "harvard.edu", "gov.uk", "whitehouse.gov",
    "usps.com", "fedex.com", "paypal.com", "chase.com", "bankofamerica.com"
]

LEGITIMATE_SUBDOMAINS = [
    "www", "docs", "developer", "blog", "news", "mail", "api", "support",
    "account", "app", "store", "download", "community", "status", "dashboard"
]

LEGITIMATE_PATHS = [
    "", "/index.html", "/about-us", "/products/software/v2", "/docs/getting-started",
    "/user/profile/settings", "/articles/2026/cybersecurity-overview",
    "/downloads/latest-release.zip", "/api/v1/health", "/help/faq",
    "/search?q=python+programming", "/category/technology/networking"
]

# Phishing Pattern Components
TARGET_BRANDS = [
    "paypal", "appleid", "login-microsoft", "google-security", "chase-bank",
    "bankofamerica-verify", "netflix-billing", "amazon-update", "wellsfargo-auth",
    "metamask-wallet", "binance-claim", "coinbase-login", "facebook-support",
    "instagram-verify", "dropbox-share", "docusign-confirm", "office365-login"
]

SUSPICIOUS_TLDS = [
    ".xyz", ".top", ".top-domain.info", ".online", ".site", ".club", ".work",
    ".click", ".live", ".link", ".buzz", ".support-security.com", ".auth-update.net"
]

SUSPICIOUS_KEYWORDS_LIST = [
    "login", "verify", "account", "update", "secure", "signin", "banking",
    "confirm", "validate", "payment", "unusual-activity", "recover-access",
    "free-bonus", "claim-reward", "urgent-notice", "auth-portal"
]

SHORTENER_DOMAINS = ["bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly"]

FAKE_IPS = [
    "192.168.1.105", "185.220.101.5", "45.142.120.10", "198.51.100.42",
    "103.253.145.89", "91.240.118.172", "194.26.29.114", "172.67.182.20"
]


def generate_legitimate_url() -> str:
    domain = random.choice(LEGITIMATE_DOMAINS)
    use_sub = random.random() < 0.6
    sub = random.choice(LEGITIMATE_SUBDOMAINS) + "." if use_sub else ""
    path = random.choice(LEGITIMATE_PATHS)
    use_https = random.random() < 0.92  # Most legitimate sites use HTTPS
    scheme = "https://" if use_https else "http://"
    return f"{scheme}{sub}{domain}{path}"


def generate_phishing_url() -> str:
    pattern_type = random.choice([
        "typosquat", "ip_address", "long_subdomains", "suspicious_keywords",
        "url_shortener", "encoded_at_symbol", "tld_abuse", "double_slash"
    ])

    use_https = random.random() < 0.35  # Phishing URLs often use http or free HTTP certs

    if pattern_type == "ip_address":
        ip = random.choice(FAKE_IPS)
        kw = random.choice(SUSPICIOUS_KEYWORDS_LIST)
        return f"http://{ip}/{kw}/index.php?user_id={random.randint(10000, 99999)}"

    elif pattern_type == "typosquat":
        brand = random.choice(TARGET_BRANDS)
        tld = random.choice(SUSPICIOUS_TLDS)
        kw = random.choice(SUSPICIOUS_KEYWORDS_LIST)
        return f"http://{brand}-{kw}{tld}/signin.html"

    elif pattern_type == "long_subdomains":
        brand = random.choice(TARGET_BRANDS)
        sub1 = random.choice(SUSPICIOUS_KEYWORDS_LIST)
        sub2 = random.choice(["service", "portal", "security-check", "user-auth"])
        sub3 = random.choice(["verify", "account-update", "login"])
        domain = random.choice(["attacker-host.com", "free-web-server.net", "cheap-host.xyz"])
        scheme = "https://" if use_https else "http://"
        return f"{scheme}{brand}.{sub1}.{sub2}.{sub3}.{domain}/verify?id={random.randint(1000, 9999)}"

    elif pattern_type == "encoded_at_symbol":
        target = random.choice(LEGITIMATE_DOMAINS)
        malicious = random.choice(["malicious-phish.com", "credential-harvest.top"])
        return f"http://{target}@{malicious}/login/confirm"

    elif pattern_type == "url_shortener":
        shortener = random.choice(SHORTENER_DOMAINS)
        code = "".join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=7))
        return f"http://{shortener}/{code}"

    elif pattern_type == "tld_abuse":
        brand = random.choice(TARGET_BRANDS)
        return f"http://www.paypal.com.verify-billing-update{random.choice(SUSPICIOUS_TLDS)}/account"

    elif pattern_type == "double_slash":
        domain = random.choice(["secure-login-update.online", "auth-portal-check.site"])
        return f"http://{domain}//user//login//index.php?token=%20%3D%26"

    else:  # suspicious_keywords
        domain = f"{random.choice(TARGET_BRANDS)}-{random.choice(SUSPICIOUS_KEYWORDS_LIST)}.info"
        path = f"/{random.choice(SUSPICIOUS_KEYWORDS_LIST)}?ref=email_urgent_verify&session={random.randint(100000, 999999)}"
        scheme = "https://" if use_https else "http://"
        return f"{scheme}{domain}{path}"


def create_dataset(output_path: str, count_per_class: int = 1500) -> pd.DataFrame:
    """Generates balanced dataset and saves to CSV."""
    urls = []
    labels = []

    # Legitimate URLs (label = 0)
    for _ in range(count_per_class):
        urls.append(generate_legitimate_url())
        labels.append(0)

    # Phishing URLs (label = 1)
    for _ in range(count_per_class):
        urls.append(generate_phishing_url())
        labels.append(1)

    df = pd.DataFrame({"url": urls, "label": labels})
    # Shuffle dataset
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)
    
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    df.to_csv(output_path, index=False)
    print(f"[Dataset Generator] Successfully saved {len(df)} URLs to {output_path}")
    return df


if __name__ == "__main__":
    current_dir = os.path.dirname(os.path.abspath(__file__))
    out_file = os.path.join(current_dir, "phishing_dataset.csv")
    create_dataset(out_file, count_per_class=1500)
