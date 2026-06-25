# 🎣 Phishing Attack Simulation & Detection Tool

![Python](https://img.shields.io/badge/Python-3.7+-3776AB?style=flat&logo=python&logoColor=white)
![CEH](https://img.shields.io/badge/Certified-CEH-darkgreen?style=flat)
![Security](https://img.shields.io/badge/Domain-Email%20Security-red?style=flat)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=flat)

> A Python-based phishing email detection tool that analyses email files for phishing indicators — header anomalies, suspicious URLs, keyword patterns, and dangerous attachments — and outputs a risk score with recommended SOC response actions.

Built as part of my cybersecurity portfolio while preparing for SOC Analyst L1 roles.

---

## What It Does

The tool analyses a `.eml` or `.txt` email file and checks for:

| Check | What It Looks For |
|---|---|
| **Header Analysis** | Reply-To mismatch, SPF/DKIM/DMARC failures, display name spoofing, Return-Path mismatch |
| **URL Analysis** | IP-based URLs, URL shorteners, suspicious TLDs, brand spoofing (e.g. paypal in URL but wrong domain) |
| **Keyword Detection** | Known phishing phrases in subject and body |
| **Attachment Check** | Dangerous file types (.exe, .vbs, .js, .ps1, .hta etc.) |
| **Risk Scoring** | 0–100 score with LOW / MEDIUM / HIGH classification |

---

## Project Structure

```
phishing-simulation-detection/
│
├── phishing_detector.py      # Main script — run this
├── email_analyzer.py         # Header parsing and analysis
├── url_checker.py            # URL extraction and inspection
├── report_generator.py       # Terminal output + report saving
├── requirements.txt
│
├── samples/
│   ├── phishing_sample.eml   # Simulated phishing email (test here)
│   └── legit_sample.eml      # Legitimate email for comparison
│
└── reports/                  # Auto-generated reports saved here
```

---

## How to Run

**Requirements:** Python 3.7+ (no external packages needed — all built-in modules)

```bash
# Clone the repo
git clone https://github.com/yourusername/phishing-simulation-detection
cd phishing-simulation-detection

# Scan the sample phishing email
python phishing_detector.py --file samples/phishing_sample.eml

# Scan and save a report
python phishing_detector.py --file samples/phishing_sample.eml --report

# Scan a legit email to see the difference
python phishing_detector.py --file samples/legit_sample.eml

# Scan your own email (export as .eml from your email client)
python phishing_detector.py --file /path/to/your/email.eml --report
```

---

## Sample Output

```
╔══════════════════════════════════════════════════════════════╗
║           PHISHING EMAIL DETECTION TOOL  v1.0               ║
║           Author : Mohammed Sayeed  |  CEH Certified        ║
║           Tools  : Python  |  Email Analysis  |  Heuristics ║
╚══════════════════════════════════════════════════════════════╝

[*] Scanning: samples/phishing_sample.eml
[*] Time    : 2026-06-12 14:30:00
------------------------------------------------------------
[*] From    : "PayPal Security" <security-alert@paypa1-support.xyz>
[*] Subject : URGENT: Your PayPal account has been suspended
------------------------------------------------------------
[*] Analysing headers...
[*] Checking URLs in email body...
[*] Scanning for phishing keywords...

============================================================
  ANALYSIS RESULTS
============================================================

  RISK SCORE : 95/100
  RISK LEVEL : HIGH
  ASSESSMENT : Likely phishing — do not interact, escalate immediately

--- HEADER ANALYSIS ---
  [FOUND]  Reply-To mismatch with From domain
  [FOUND]  Display name spoofing detected
  [FOUND]  SPF check failed
  [FOUND]  DKIM signature missing or failed
  [FOUND]  DMARC check failed
  [FOUND]  Return-Path domain mismatch
  [FOUND]  Sender using free email provider
  [i]  Reply-To domain: attacker-collect.tk
  [i]  Originating IP: 185.234.22.11

--- URL ANALYSIS ---
  [i]  Total URLs found : 3
  [FOUND]  Suspicious URLs  : 3
  [FOUND]  IP-based URLs detected
  [FOUND]  URL shorteners detected

  URL Details:
  [!]  http://185.234.22.11/paypal/secure-login/verify.php
         -> Uses IP address instead of domain name
         -> Brand spoofing: 'paypal' in URL but domain is '185.234.22.11'
  [!]  https://paypal-account-verify.xyz/login?ref=urgent
         -> Suspicious TLD associated with phishing campaigns
         -> Brand spoofing: 'paypal' in URL but domain is 'paypal-account-verify.xyz'
  [!]  http://bit.ly/remove-me-paypal
         -> URL shortener detected — hides real destination

--- KEYWORD ANALYSIS ---
  [FOUND]  Subject keywords : ['urgent', 'action required']
  [FOUND]  Body keywords    : ['click here', 'verify now', 'do not ignore this', 'kindly']

============================================================
  ACTION: Do NOT click any links or open attachments.
          Escalate to L2/security team immediately.
          Block sender domain and report to email admin.
============================================================
```

---

## Risk Scoring System

| Score | Level | SOC Action |
|---|---|---|
| 0–30 | 🟢 LOW | Likely legit — monitor |
| 31–60 | 🟡 MEDIUM | Suspicious — escalate for manual review |
| 61–100 | 🔴 HIGH | Likely phishing — contain and escalate immediately |

**Score breakdown:**

| Indicator | Points |
|---|---|
| Reply-To domain mismatch | +25 |
| IP-based URL in email | +20 |
| Display name spoofing | +20 |
| Suspicious attachment type | +25 |
| SPF failed | +15 |
| URL shortener found | +15 |
| Suspicious URL (per URL, max 30) | +15 |
| DKIM missing/failed | +10 |
| DMARC failed | +10 |

---

## How I Built This

I've been studying for my CEH and practising in Splunk (BOTS v3 dataset). While going through phishing email analysis labs I kept having to manually check the same things every time — headers, URLs, keywords. So I wrote this tool to automate that triage process.

The detection logic is based on:
- Email security concepts from CEH (EC-Council) coursework
- NIST SP 800-45 (Email Security Guidelines)
- Common phishing patterns I've seen in SOC labs and BOTS challenges
- SANS phishing analysis methodology

I kept it to built-in Python modules only so there are zero dependencies to install.

---

## What I Learned

- How email headers work (SPF, DKIM, DMARC authentication chain)
- How phishers spoof display names and bypass basic filters
- URL analysis techniques for detecting obfuscated phishing links
- How to structure a Python security tool for SOC use
- Email security workflow that maps to real L1 analyst procedures

---

## Limitations / Future Improvements

- [ ] Add VirusTotal API integration for live URL reputation checks
- [ ] Add support for scanning HTML email bodies (strip tags)
- [ ] Build a simple web interface using Flask
- [ ] Add bulk scanning mode (scan folder of emails)
- [ ] Export reports as PDF

---

## About

**Mohammed Sayeed**  
SOC Analyst | CEH Certified (108/125) | Splunk | CrowdStrike Falcon | Wireshark  
📍 Kalaburagi, Karnataka → Targeting Hyderabad MSSP/SOC roles

---

*For educational and portfolio use only. Do not use against real systems without authorisation.*
