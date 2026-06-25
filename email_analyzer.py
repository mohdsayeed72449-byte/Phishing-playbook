"""
email_analyzer.py
-----------------
Handles parsing email files and analysing headers for phishing indicators.
The main things I check: Reply-To mismatch, SPF/DKIM/DMARC failures,
display name spoofing (e.g. "PayPal <attacker@evil.com>").

Author: Mohammed Sayeed
"""

import re
import email
from email import policy
from email.parser import BytesParser, Parser


# Domains that are commonly spoofed in phishing attacks
COMMONLY_SPOOFED_DOMAINS = [
    "paypal.com", "amazon.com", "microsoft.com", "google.com",
    "apple.com", "netflix.com", "linkedin.com", "facebook.com",
    "instagram.com", "bankofamerica.com", "chase.com", "wells fargo.com",
    "irs.gov", "fedex.com", "dhl.com", "ups.com", "sbi.co.in",
    "hdfcbank.com", "icicibank.com", "axisbank.com"
]

# Free email providers — legit companies usually don't use these
FREE_EMAIL_PROVIDERS = [
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com",
    "protonmail.com", "yandex.com", "mail.ru", "aol.com",
    "zoho.com", "guerrillamail.com", "tempmail.com"
]


def parse_email_file(filepath):
    """
    Parse an .eml or .txt email file and extract all the important fields.
    Returns a dict with from, to, subject, body, headers, attachments.
    """
    try:
        # try reading as bytes first (proper .eml files)
        with open(filepath, "rb") as f:
            msg = BytesParser(policy=policy.default).parse(f)
    except Exception:
        # fallback to text mode
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            msg = Parser(policy=policy.default).parsestr(content)
        except Exception as e:
            print(f"[!] Failed to parse email: {e}")
            return None

    # extract body
    body = ""
    attachments = []

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get("Content-Disposition", ""))

            if "attachment" in content_disposition:
                filename = part.get_filename()
                if filename:
                    attachments.append(filename)
            elif content_type == "text/plain":
                try:
                    body += part.get_content()
                except Exception:
                    pass
            elif content_type == "text/html" and not body:
                try:
                    body += part.get_content()
                except Exception:
                    pass
    else:
        try:
            body = msg.get_content()
        except Exception:
            body = str(msg.get_payload())

    return {
        "from": str(msg.get("From", "")),
        "to": str(msg.get("To", "")),
        "subject": str(msg.get("Subject", "")),
        "date": str(msg.get("Date", "")),
        "reply_to": str(msg.get("Reply-To", "")),
        "return_path": str(msg.get("Return-Path", "")),
        "received_spf": str(msg.get("Received-SPF", "")),
        "dkim_signature": str(msg.get("DKIM-Signature", "")),
        "authentication_results": str(msg.get("Authentication-Results", "")),
        "x_originating_ip": str(msg.get("X-Originating-IP", "")),
        "message_id": str(msg.get("Message-ID", "")),
        "body": body,
        "attachments": attachments,
        "raw_headers": dict(msg.items())
    }


def extract_email_address(field):
    """Pull just the email address from a field like 'PayPal <security@paypal.com>'"""
    match = re.search(r'<([^>]+)>', field)
    if match:
        return match.group(1).strip().lower()
    return field.strip().lower()


def extract_display_name(field):
    """Pull the display name from 'PayPal <security@evil.com>'"""
    match = re.match(r'^"?([^"<]+)"?\s*<', field)
    if match:
        return match.group(1).strip()
    return ""


def get_domain(email_addr):
    """Get domain from email address."""
    if "@" in email_addr:
        return email_addr.split("@")[-1].lower()
    return ""


def check_spf_dkim_dmarc(email_data):
    """
    Parse the Authentication-Results header to check SPF, DKIM, DMARC.
    In a real SOC environment this would be queried live from DNS,
    but we can extract the results that the email server already recorded.
    """
    auth_results = email_data.get("authentication_results", "").lower()
    received_spf = email_data.get("received_spf", "").lower()

    # SPF check
    spf_fail = False
    if "spf=fail" in auth_results or "spf=fail" in received_spf:
        spf_fail = True
    elif "spf=softfail" in auth_results or "softfail" in received_spf:
        spf_fail = True

    # DKIM check
    dkim_fail = False
    dkim_sig = email_data.get("dkim_signature", "")
    if "dkim=fail" in auth_results:
        dkim_fail = True
    elif not dkim_sig or dkim_sig == "None":
        # no DKIM signature at all is suspicious
        dkim_fail = True

    # DMARC check
    dmarc_fail = False
    if "dmarc=fail" in auth_results:
        dmarc_fail = True

    return spf_fail, dkim_fail, dmarc_fail


def check_display_name_spoofing(from_field):
    """
    Check if display name looks like a legit brand but the actual
    email domain doesn't match. e.g. "PayPal <security@random123.com>"
    This is one of the most common phishing tricks.
    """
    display_name = extract_display_name(from_field).lower()
    email_addr = extract_email_address(from_field)
    domain = get_domain(email_addr)

    for legit_domain in COMMONLY_SPOOFED_DOMAINS:
        brand = legit_domain.split(".")[0]  # e.g. "paypal" from "paypal.com"
        if brand in display_name and legit_domain not in domain:
            return True, display_name, domain

    return False, display_name, domain


def analyze_headers(email_data):
    """
    Main header analysis function. Returns a dict of all findings.
    """
    from_field = email_data.get("from", "")
    reply_to = email_data.get("reply_to", "")
    return_path = email_data.get("return_path", "")

    from_email = extract_email_address(from_field)
    from_domain = get_domain(from_email)

    # Check 1: Reply-To mismatch
    reply_to_mismatch = False
    reply_to_domain = ""
    if reply_to and reply_to != "None":
        reply_to_email = extract_email_address(reply_to)
        reply_to_domain = get_domain(reply_to_email)
        if reply_to_domain and reply_to_domain != from_domain:
            reply_to_mismatch = True

    # Check 2: Display name spoofing
    display_spoof, display_name, _ = check_display_name_spoofing(from_field)

    # Check 3: From domain is a free email provider (suspicious for "official" emails)
    from_free_provider = from_domain in FREE_EMAIL_PROVIDERS

    # Check 4: SPF / DKIM / DMARC
    spf_fail, dkim_fail, dmarc_fail = check_spf_dkim_dmarc(email_data)

    # Check 5: Return-Path doesn't match From domain
    return_path_mismatch = False
    if return_path and return_path != "None":
        rp_email = extract_email_address(return_path)
        rp_domain = get_domain(rp_email)
        if rp_domain and rp_domain != from_domain:
            return_path_mismatch = True

    # Check 6: Missing Message-ID (legit emails always have one)
    missing_message_id = not email_data.get("message_id") or email_data.get("message_id") == "None"

    findings = {
        "from_email": from_email,
        "from_domain": from_domain,
        "reply_to_mismatch": reply_to_mismatch,
        "reply_to_domain": reply_to_domain,
        "from_display_mismatch": display_spoof,
        "display_name": display_name,
        "from_free_provider": from_free_provider,
        "spf_fail": spf_fail,
        "dkim_fail": dkim_fail,
        "dmarc_fail": dmarc_fail,
        "return_path_mismatch": return_path_mismatch,
        "missing_message_id": missing_message_id,
        "x_originating_ip": email_data.get("x_originating_ip", "")
    }

    return findings
