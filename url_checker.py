"""
url_checker.py
--------------
Extracts URLs from email body and checks them for phishing indicators.
Things I look for: IP-based URLs, URL shorteners, misleading domains,
homograph attacks, suspicious TLDs, and mismatched hyperlinks.

Author: Mohammed Sayeed
"""

import re
from urllib.parse import urlparse


# URL shorteners commonly used to hide phishing URLs
URL_SHORTENERS = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "is.gd", "buff.ly", "adf.ly", "shorte.st", "bc.vc",
    "rebrand.ly", "cutt.ly", "shorturl.at", "tiny.cc"
]

# TLDs that are heavily abused in phishing campaigns
SUSPICIOUS_TLDS = [
    ".xyz", ".tk", ".ml", ".ga", ".cf", ".gq", ".top",
    ".club", ".online", ".site", ".icu", ".pw", ".cc",
    ".buzz", ".fun", ".space", ".live", ".work", ".rest"
]

# Brands that phishers commonly clone
COMMONLY_SPOOFED_BRANDS = [
    "paypal", "amazon", "microsoft", "google", "apple",
    "netflix", "linkedin", "facebook", "instagram", "whatsapp",
    "bankofamerica", "chase", "wellsfargo", "citibank",
    "sbi", "hdfc", "icici", "axis", "flipkart", "paytm"
]

# Legit domains for those brands — if URL contains brand name but NOT this domain, suspicious
BRAND_DOMAINS = {
    "paypal": "paypal.com",
    "amazon": "amazon.com",
    "microsoft": "microsoft.com",
    "google": "google.com",
    "apple": "apple.com",
    "netflix": "netflix.com",
    "linkedin": "linkedin.com",
    "facebook": "facebook.com",
    "instagram": "instagram.com",
    "sbi": "sbi.co.in",
    "hdfc": "hdfcbank.com",
    "icici": "icicibank.com",
    "flipkart": "flipkart.com",
    "paytm": "paytm.com"
}


def extract_urls(text):
    """
    Extract all URLs from email body text using regex.
    Handles both http:// and https:// links.
    """
    url_pattern = re.compile(
        r'https?://[^\s<>"\')\]]+',
        re.IGNORECASE
    )
    urls = url_pattern.findall(text)

    # also look for URLs without http (e.g. www.evil.com)
    www_pattern = re.compile(r'www\.[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}[^\s<>"\')\]]*')
    www_urls = www_pattern.findall(text)

    all_urls = list(set(urls + ["http://" + u for u in www_urls]))
    return all_urls


def is_ip_url(url):
    """
    Check if URL uses an IP address instead of a domain name.
    Legit websites almost never do this — it's a phishing red flag.
    e.g. http://192.168.1.1/paypal/login.html
    """
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname or ""
        ip_pattern = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
        return bool(ip_pattern.match(hostname))
    except Exception:
        return False


def is_url_shortener(url):
    """Check if URL uses a known URL shortening service."""
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname or ""
        return any(shortener in hostname for shortener in URL_SHORTENERS)
    except Exception:
        return False


def has_suspicious_tld(url):
    """Check if URL uses a TLD commonly associated with phishing."""
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname or ""
        return any(hostname.endswith(tld) for tld in SUSPICIOUS_TLDS)
    except Exception:
        return False


def check_brand_spoofing(url):
    """
    Check if URL contains a brand name but points to a different domain.
    e.g. paypal-security-update.xyz or login-amazon.tk
    This is homograph/typosquatting detection (basic version).
    """
    url_lower = url.lower()
    try:
        parsed = urlparse(url)
        hostname = (parsed.hostname or "").lower()
    except Exception:
        hostname = ""

    for brand, legit_domain in BRAND_DOMAINS.items():
        if brand in url_lower and legit_domain not in hostname:
            # brand name appears in URL but actual domain isn't the legit one
            return True, brand, hostname

    return False, "", hostname


def has_excessive_subdomains(url):
    """
    Phishing URLs often use many subdomains to confuse victims.
    e.g. secure.paypal.com.update.account.evil.com
    Anything more than 3 subdomains is suspicious.
    """
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname or ""
        parts = hostname.split(".")
        return len(parts) > 4
    except Exception:
        return False


def check_url(url):
    """
    Run all checks on a single URL and return a dict of findings.
    """
    findings = {
        "url": url,
        "is_suspicious": False,
        "reasons": []
    }

    if is_ip_url(url):
        findings["is_suspicious"] = True
        findings["reasons"].append("Uses IP address instead of domain name")

    if is_url_shortener(url):
        findings["is_suspicious"] = True
        findings["reasons"].append("URL shortener detected — hides real destination")

    if has_suspicious_tld(url):
        findings["is_suspicious"] = True
        findings["reasons"].append("Suspicious TLD associated with phishing campaigns")

    brand_spoof, brand, hostname = check_brand_spoofing(url)
    if brand_spoof:
        findings["is_suspicious"] = True
        findings["reasons"].append(f"Brand spoofing: '{brand}' in URL but domain is '{hostname}'")

    if has_excessive_subdomains(url):
        findings["is_suspicious"] = True
        findings["reasons"].append("Excessive subdomains — possible subdomain spoofing")

    return findings


def extract_and_check_urls(body_text):
    """
    Main function — extract all URLs from email body and check each one.
    Returns summary dict for use in the main scoring system.
    """
    if not body_text:
        return {
            "all_urls": [],
            "suspicious": [],
            "has_url_shortener": False,
            "has_ip_url": False,
            "url_details": []
        }

    all_urls = extract_urls(body_text)
    url_details = []
    suspicious_urls = []

    for url in all_urls:
        result = check_url(url)
        url_details.append(result)
        if result["is_suspicious"]:
            suspicious_urls.append(url)

    return {
        "all_urls": all_urls,
        "suspicious": suspicious_urls,
        "has_url_shortener": any(is_url_shortener(u) for u in all_urls),
        "has_ip_url": any(is_ip_url(u) for u in all_urls),
        "url_details": url_details,
        "total_urls": len(all_urls)
    }
