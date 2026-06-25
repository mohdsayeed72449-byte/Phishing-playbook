#!/usr/bin/env python3
"""
Phishing Detection Tool
-----------------------
Author  : Mohammed Sayeed
Date    : June 2026
Purpose : Analyse suspicious emails and score them for phishing indicators.
          Built for my SOC analyst portfolio — covers email header analysis,
          URL inspection, and keyword detection with a risk scoring system.

Usage:
    python phishing_detector.py --file samples/phishing_sample.eml
    python phishing_detector.py --file samples/legit_sample.eml --report
"""

import argparse
import os
import sys
from datetime import datetime

from email_analyzer import analyze_headers, parse_email_file
from url_checker import extract_and_check_urls
from report_generator import generate_report, print_summary

BANNER = """
╔══════════════════════════════════════════════════════════════╗
║           PHISHING EMAIL DETECTION TOOL  v1.0               ║
║           Author : Mohammed Sayeed  |  CEH Certified        ║
║           Tools  : Python  |  Email Analysis  |  Heuristics ║
╚══════════════════════════════════════════════════════════════╝
"""

# Phishing keywords I keep seeing in actual phishing emails (from CEH study + BOTS v3)
PHISHING_KEYWORDS_SUBJECT = [
    "urgent", "verify your account", "suspended", "unusual activity",
    "confirm your identity", "action required", "account locked",
    "limited time", "winner", "congratulations", "prize",
    "update your payment", "click here immediately", "invoice attached",
    "your password has expired", "security alert"
]

PHISHING_KEYWORDS_BODY = [
    "click here", "verify now", "log in immediately", "confirm your details",
    "your account will be closed", "we detected suspicious",
    "enter your credentials", "reset your password now",
    "provide your social security", "wire transfer", "gift card",
    "western union", "bitcoin", "kindly", "dear customer",
    "do not ignore this", "failure to verify"
]

SUSPICIOUS_ATTACHMENT_TYPES = [
    ".exe", ".vbs", ".js", ".bat", ".cmd", ".ps1",
    ".scr", ".hta", ".macro", ".jar", ".msi"
]


def calculate_risk_score(findings):
    """
    Score the email from 0 to 100 based on how many red flags we found.
    I designed this scoring based on what I learned from CEH and phishing labs.
    """
    score = 0

    # Header issues are the biggest red flags
    if findings["header"]["reply_to_mismatch"]:
        score += 25  # reply-to != from is almost always phishing
    if findings["header"]["from_display_mismatch"]:
        score += 20
    if findings["header"]["spf_fail"]:
        score += 15
    if findings["header"]["dkim_fail"]:
        score += 10
    if findings["header"]["dmarc_fail"]:
        score += 10

    # URL red flags
    url_score = min(len(findings["urls"]["suspicious"]) * 15, 30)
    score += url_score
    if findings["urls"]["has_url_shortener"]:
        score += 15
    if findings["urls"]["has_ip_url"]:
        score += 20  # IP-based URLs are almost never legit

    # Keyword hits
    subject_hits = len(findings["keywords"]["subject_hits"])
    body_hits = len(findings["keywords"]["body_hits"])
    score += min(subject_hits * 10, 20)
    score += min(body_hits * 5, 15)

    # Suspicious attachments
    if findings["attachments"]["suspicious_found"]:
        score += 25

    # cap at 100
    return min(score, 100)


def get_risk_label(score):
    if score <= 30:
        return "LOW", "Likely legitimate — still review manually"
    elif score <= 60:
        return "MEDIUM", "Suspicious — escalate for manual review"
    else:
        return "HIGH", "Likely phishing — do not interact, escalate immediately"


def scan_keywords(subject, body):
    """Check subject and body for known phishing keywords."""
    subject_lower = subject.lower()
    body_lower = body.lower()

    subject_hits = [kw for kw in PHISHING_KEYWORDS_SUBJECT if kw in subject_lower]
    body_hits = [kw for kw in PHISHING_KEYWORDS_BODY if kw in body_lower]

    return {
        "subject_hits": subject_hits,
        "body_hits": body_hits
    }


def check_attachments(email_data):
    """Check for dangerous attachment types."""
    attachments = email_data.get("attachments", [])
    suspicious = [a for a in attachments if any(a.lower().endswith(ext) for ext in SUSPICIOUS_ATTACHMENT_TYPES)]
    return {
        "all_attachments": attachments,
        "suspicious_found": len(suspicious) > 0,
        "suspicious_list": suspicious
    }


def run_analysis(filepath, save_report=False):
    print(BANNER)
    print(f"[*] Scanning: {filepath}")
    print(f"[*] Time    : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("-" * 60)

    # Step 1 — parse the email file
    email_data = parse_email_file(filepath)
    if not email_data:
        print("[!] ERROR: Could not parse email file. Check the file format.")
        sys.exit(1)

    print(f"[*] From    : {email_data.get('from', 'N/A')}")
    print(f"[*] To      : {email_data.get('to', 'N/A')}")
    print(f"[*] Subject : {email_data.get('subject', 'N/A')}")
    print(f"[*] Date    : {email_data.get('date', 'N/A')}")
    print("-" * 60)

    # Step 2 — analyse headers
    print("[*] Analysing headers...")
    header_findings = analyze_headers(email_data)

    # Step 3 — extract and check URLs
    print("[*] Checking URLs in email body...")
    body = email_data.get("body", "")
    url_findings = extract_and_check_urls(body)

    # Step 4 — keyword scan
    print("[*] Scanning for phishing keywords...")
    keyword_findings = scan_keywords(email_data.get("subject", ""), body)

    # Step 5 — attachment check
    print("[*] Checking attachments...")
    attachment_findings = check_attachments(email_data)

    # Build findings dict
    findings = {
        "file": filepath,
        "email": email_data,
        "header": header_findings,
        "urls": url_findings,
        "keywords": keyword_findings,
        "attachments": attachment_findings,
        "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }

    # Step 6 — score it
    score = calculate_risk_score(findings)
    risk_label, risk_message = get_risk_label(score)
    findings["score"] = score
    findings["risk_label"] = risk_label
    findings["risk_message"] = risk_message

    # Step 7 — print summary
    print_summary(findings)

    # Step 8 — save report if flag set
    if save_report:
        report_path = generate_report(findings)
        print(f"\n[+] Report saved: {report_path}")

    return findings


def main():
    parser = argparse.ArgumentParser(
        description="Phishing Email Detection Tool — Mohammed Sayeed"
    )
    parser.add_argument(
        "--file", "-f",
        required=True,
        help="Path to the email file (.eml or .txt)"
    )
    parser.add_argument(
        "--report", "-r",
        action="store_true",
        help="Save a detailed report to /reports/ folder"
    )

    args = parser.parse_args()

    if not os.path.exists(args.file):
        print(f"[!] File not found: {args.file}")
        sys.exit(1)

    run_analysis(args.file, save_report=args.report)


if __name__ == "__main__":
    main()
