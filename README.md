# WebVulnScanner

A lightweight Web vulnerability scanner written in Python. Detects common security issues including SQL injection, XSS, command injection, information disclosure, and service fingerprinting.

## Features

- **Vulnerability Detection**: SQL injection, XSS (reflected), command injection
- **Information Disclosure**: HTTP security headers check, sensitive file exposure (.git, .env, robots.txt), directory listing
- **Service Fingerprinting**: Server type detection, CMS identification, WAF detection
- **Report Generation**: Auto-generated HTML security report with findings, severity levels, and remediation advice

## Requirements

- Python 3.8+

## Installation

```bash
cd WebVulnScanner
pip install -r requirements.txt
```

## Usage

```bash
# Basic scan
python -m scanner -u http://target-url.com

# Scan with report output
python -m scanner -u http://target-url.com -r report.html

# Scan specific modules only
python -m scanner -u http://target-url.com -m vuln,info
```

## Modules

| Module | Description |
|--------|-------------|
| `info` | Information disclosure & sensitive file detection |
| `vuln` | Web vulnerability detection (SQLi, XSS, Cmdi) |
| `fingerprint` | Service & technology fingerprinting |
| `report` | HTML report generation |

## Disclaimer

This tool is for educational and authorized security testing only. Always obtain proper authorization before scanning any target.
