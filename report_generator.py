"""
report_generator.py
--------------------
Handles printing the analysis summary to terminal and saving
a detailed report to the /reports/ folder.

Author: Mohammed Sayeed
"""

import os
from datetime import datetime


def get_risk_colour(risk_label):
    """Terminal colour codes for risk level output."""
    colours = {
        "HIGH":   "\033[91m",   # red
        "MEDIUM": "\033[93m",   # yellow
        "LOW":    "\033[92m",   # green
    }
    reset = "\033[0m"
    colour = colours.get(risk_label, "")
    return colour, reset


def tick(condition):
    """Return FOUND or CLEAN based on condition."""
    return "[FOUND]" if condition else "[CLEAN]"


def print_summary(findings):
    """Print a structured summary to the terminal."""
    score = findings["score"]
    risk_label = findings["risk_label"]
    risk_message = findings["risk_message"]
    header = findings["header"]
    urls = findings["urls"]
    keywords = findings["keywords"]
    attachments = findings["attachments"]

    colour, reset = get_risk_colour(risk_label)

    print("\n" + "=" * 60)
    print("  ANALYSIS RESULTS")
    print("=" * 60)

    print(f"\n  RISK SCORE : {colour}{score}/100{reset}")
    print(f"  RISK LEVEL : {colour}{risk_label}{reset}")
    print(f"  ASSESSMENT : {risk_message}")

    print("\n--- HEADER ANALYSIS ---")
    print(f"  {tick(header['reply_to_mismatch'])}  Reply-To mismatch with From domain")
    print(f"  {tick(header['from_display_mismatch'])}  Display name spoofing detected")
    print(f"  {tick(header['spf_fail'])}  SPF check failed")
    print(f"  {tick(header['dkim_fail'])}  DKIM signature missing or failed")
    print(f"  {tick(header['dmarc_fail'])}  DMARC check failed")
    print(f"  {tick(header['return_path_mismatch'])}  Return-Path domain mismatch")
    print(f"  {tick(header['from_free_provider'])}  Sender using free email provider")

    if header['reply_to_domain']:
        print(f"  [i]  Reply-To domain: {header['reply_to_domain']}")
    if header['x_originating_ip']:
        print(f"  [i]  Originating IP: {header['x_originating_ip']}")

    print("\n--- URL ANALYSIS ---")
    print(f"  [i]  Total URLs found : {urls['total_urls']}")
    print(f"  {tick(len(urls['suspicious']) > 0)}  Suspicious URLs  : {len(urls['suspicious'])}")
    print(f"  {tick(urls['has_ip_url'])}  IP-based URLs detected")
    print(f"  {tick(urls['has_url_shortener'])}  URL shorteners detected")

    if urls["url_details"]:
        print("\n  URL Details:")
        for detail in urls["url_details"]:
            status = "  [!]" if detail["is_suspicious"] else "  [ok]"
            print(f"  {status}  {detail['url'][:70]}")
            for reason in detail["reasons"]:
                print(f"         -> {reason}")

    print("\n--- KEYWORD ANALYSIS ---")
    print(f"  {tick(len(keywords['subject_hits']) > 0)}  Subject keywords : {keywords['subject_hits'] or 'None'}")
    print(f"  {tick(len(keywords['body_hits']) > 0)}  Body keywords    : {keywords['body_hits'][:5] or 'None'}")

    print("\n--- ATTACHMENTS ---")
    if attachments["all_attachments"]:
        print(f"  [i]  Attachments found: {attachments['all_attachments']}")
        if attachments["suspicious_found"]:
            print(f"  [FOUND]  Dangerous attachment types: {attachments['suspicious_list']}")
        else:
            print(f"  [CLEAN]  No dangerous attachment types")
    else:
        print("  [i]  No attachments found")

    print("\n" + "=" * 60)
    if risk_label == "HIGH":
        print("  ACTION: Do NOT click any links or open attachments.")
        print("          Escalate to L2/security team immediately.")
        print("          Block sender domain and report to email admin.")
    elif risk_label == "MEDIUM":
        print("  ACTION: Do not interact with email.")
        print("          Manually review and escalate if confirmed suspicious.")
    else:
        print("  ACTION: Low risk — continue monitoring.")
    print("=" * 60 + "\n")


def generate_report(findings):
    """Save a full text report to the reports/ folder."""
    os.makedirs("reports", exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"reports/phishing_report_{timestamp}.txt"

    email_info = findings.get("email", {})
    header = findings["header"]
    urls = findings["urls"]
    keywords = findings["keywords"]
    attachments = findings["attachments"]

    lines = []
    lines.append("=" * 65)
    lines.append("  PHISHING EMAIL ANALYSIS REPORT")
    lines.append(f"  Generated : {findings['scan_time']}")
    lines.append(f"  Tool      : Phishing Detection Tool v1.0 — Mohammed Sayeed")
    lines.append("=" * 65)

    lines.append("\n[EMAIL DETAILS]")
    lines.append(f"  File    : {findings['file']}")
    lines.append(f"  From    : {email_info.get('from', 'N/A')}")
    lines.append(f"  To      : {email_info.get('to', 'N/A')}")
    lines.append(f"  Subject : {email_info.get('subject', 'N/A')}")
    lines.append(f"  Date    : {email_info.get('date', 'N/A')}")

    lines.append("\n[RISK ASSESSMENT]")
    lines.append(f"  Score : {findings['score']}/100")
    lines.append(f"  Level : {findings['risk_label']}")
    lines.append(f"  Note  : {findings['risk_message']}")

    lines.append("\n[HEADER FINDINGS]")
    lines.append(f"  Reply-To mismatch    : {header['reply_to_mismatch']}")
    lines.append(f"  Display name spoof   : {header['from_display_mismatch']}")
    lines.append(f"  SPF failed           : {header['spf_fail']}")
    lines.append(f"  DKIM failed/missing  : {header['dkim_fail']}")
    lines.append(f"  DMARC failed         : {header['dmarc_fail']}")
    lines.append(f"  Return-Path mismatch : {header['return_path_mismatch']}")
    lines.append(f"  Sender IP            : {header['x_originating_ip']}")

    lines.append("\n[URL FINDINGS]")
    lines.append(f"  Total URLs      : {urls['total_urls']}")
    lines.append(f"  Suspicious URLs : {len(urls['suspicious'])}")
    for detail in urls["url_details"]:
        lines.append(f"  URL : {detail['url']}")
        lines.append(f"  Status : {'SUSPICIOUS' if detail['is_suspicious'] else 'CLEAN'}")
        for reason in detail["reasons"]:
            lines.append(f"    Reason: {reason}")

    lines.append("\n[KEYWORD FINDINGS]")
    lines.append(f"  Subject hits : {keywords['subject_hits']}")
    lines.append(f"  Body hits    : {keywords['body_hits']}")

    lines.append("\n[ATTACHMENTS]")
    lines.append(f"  All attachments      : {attachments['all_attachments']}")
    lines.append(f"  Dangerous found      : {attachments['suspicious_found']}")
    if attachments["suspicious_list"]:
        lines.append(f"  Dangerous files      : {attachments['suspicious_list']}")

    lines.append("\n[RECOMMENDED ACTIONS]")
    if findings["risk_label"] == "HIGH":
        lines.append("  1. Do NOT click any links or open attachments")
        lines.append("  2. Escalate to L2/security team immediately")
        lines.append("  3. Block sender domain at email gateway")
        lines.append("  4. Check if other users received the same email")
        lines.append("  5. Add IOCs (sender IP, URLs, domain) to Splunk watchlist")
    elif findings["risk_label"] == "MEDIUM":
        lines.append("  1. Do not interact with email")
        lines.append("  2. Manually verify with the supposed sender via phone")
        lines.append("  3. Escalate if any part of email confirmed suspicious")
    else:
        lines.append("  1. Low risk — continue normal monitoring")
        lines.append("  2. Keep an eye out for similar patterns")

    lines.append("\n" + "=" * 65)

    with open(filename, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    return filename
