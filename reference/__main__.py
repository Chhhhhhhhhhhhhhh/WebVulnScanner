"""
WebVulnScanner - Main Entry
Usage: python -m scanner -u <URL> [-r report.html] [-m info,vuln,fingerprint]
"""

import argparse
import os
import sys
import time
import warnings
import requests

warnings.filterwarnings("ignore", message="Unverified HTTPS request")
requests.packages.urllib3.disable_warnings()

from scanner.utils import normalize_url, is_in_scope
from scanner.info_scanner import run_info_scan
from scanner.vuln_scanner import run_vuln_scan
from scanner.report import generate_report

BANNER = """
  +============================================+
  |         WebVulnScanner v1.0                |
  |     Lightweight Web Vulnerability Scanner   |
  |   For authorized security testing only     |
  +============================================+
"""


def parse_args():
    parser = argparse.ArgumentParser(
        description="WebVulnScanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python -m scanner -u http://example.com
  python -m scanner -u http://example.com -r report.html
  python -m scanner -u http://example.com -m info,vuln
        """,
    )
    parser.add_argument("-u", "--url", required=True, help="Target URL")
    parser.add_argument("-r", "--report", default=None, help="Output HTML report path")
    parser.add_argument(
        "-m", "--modules", default="info,fingerprint,vuln",
        help="Scan modules: info, fingerprint, vuln (comma-separated, default: all)",
    )
    return parser.parse_args()


def main():
    print(BANNER)
    args = parse_args()

    target = normalize_url(args.url)
    modules = [m.strip() for m in args.modules.split(",")]

    # Safety check: prevent scanning internal network (SSRF protection)
    if not is_in_scope(target, target):
        print("[!] Error: Target address is not in the allowed scanning scope")
        sys.exit(1)

    print(f"\n[*] Target: {target}")
    print(f"[*] Modules: {', '.join(modules)}")
    print(f"[*] Starting scan...\n")

    session = requests.Session()
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    })

    scan_results = []
    start_time = time.time()

    # Info gathering & fingerprinting
    if "info" in modules or "fingerprint" in modules:
        info_result = run_info_scan(target, session)
        scan_results.append(info_result)
        info_count = len(info_result["findings"])
        print(f"  [+] Info & fingerprint: {info_count} findings\n")

    # Vulnerability scanning
    if "vuln" in modules:
        print("[*] Vulnerability scanning (please wait)...")
        vuln_result = run_vuln_scan(target, session)
        scan_results.append(vuln_result)
        vuln_count = len(vuln_result["findings"])
        print(f"  [+] Vulnerabilities: {vuln_count} findings\n")

    elapsed = time.time() - start_time

    # Summary
    all_findings = []
    for r in scan_results:
        all_findings.extend(r.get("findings", []))

    print("=" * 50)
    print(f"[*] Scan completed in {elapsed:.1f}s")
    print(f"[*] Total findings: {len(all_findings)}")

    if all_findings:
        severity_count = {}
        for f in all_findings:
            sev = f.get("severity", "info")
            severity_count[sev] = severity_count.get(sev, 0) + 1

        sev_labels = {
            "critical": "CRITICAL", "high": "HIGH",
            "medium": "MEDIUM", "low": "LOW", "info": "INFO",
        }
        for sev in ["critical", "high", "medium", "low", "info"]:
            if sev in severity_count:
                print(f"    {sev_labels[sev]}: {severity_count[sev]}")

    print("=" * 50)

    # Generate report
    report_path = args.report
    if report_path or all_findings:
        if not report_path:
            report_path = f"scan_report_{int(time.time())}.html"

        report_file, report_count = generate_report(scan_results, target, report_path)
        abs_path = os.path.abspath(report_file)
        print(f"\n[+] Report saved: {abs_path}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
