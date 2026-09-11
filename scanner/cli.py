"""Command-line interface and console orchestration."""

from __future__ import annotations

import argparse
import json
import os
import sys

from . import __version__
from .httpclient import GuardBlocked
from .models import SEVERITY_ORDER
from .modules import MODULES
from .report import (default_report_paths, render_batch_html, render_batch_json,
                     render_json, write_reports)
from .sarif import render_sarif
from .scanner import BANNER, ScanConfig, Scanner

SEVERITY_LABELS_EN = {
    "critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM",
    "low": "LOW", "info": "INFO",
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="webvulnscanner",
        description="WebVulnScanner - lightweight web vulnerability scanner "
                    "for authorised security testing.",
        epilog=(
            "examples:\n"
            "  python -m scanner -u https://example.com\n"
            "  python -m scanner -u https://example.com -m sqli,xss -t 8\n"
            "  python -m scanner --targets urls.txt --fail-on high --format json\n"
            "  python -m scanner -u http://lab.local --allow-private --json out.json\n"
            "  python -m scanner -u https://example.com --login-url https://example.com/login \\\n"
            "      --auth-user demo --auth-pass demo123\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    targets = parser.add_mutually_exclusive_group(required=True)
    targets.add_argument("-u", "--url", help="target URL (e.g. https://example.com/page?id=1)")
    targets.add_argument("--targets", metavar="FILE",
                         help="batch mode: file with one target URL per line "
                              "(# comments allowed; writes per-target reports + a batch summary)")
    parser.add_argument("-m", "--modules", default=",".join(MODULES),
                        help=f"comma-separated modules (default: all of {','.join(MODULES)})")
    parser.add_argument("-r", "--report", metavar="PATH", default=None,
                        help="HTML report path (single-target mode only; "
                             "default: reports/scan_<host>_<ts>.html)")
    parser.add_argument("--json", metavar="PATH", default=None,
                        help="additional JSON report path (default: written next to the HTML report)")
    parser.add_argument("--no-report", action="store_true", help="do not write any report file")
    parser.add_argument("--no-crawl", action="store_true",
                        help="test only the given URL and its forms (no link discovery)")
    parser.add_argument("--depth", type=int, default=2, help="crawl depth (default: 2)")
    parser.add_argument("--max-pages", type=int, default=30, help="max pages to crawl (default: 30)")
    parser.add_argument("-t", "--threads", type=int, default=4, help="worker threads (default: 4)")
    parser.add_argument("--delay", type=float, default=0.0,
                        help="minimum delay between requests in seconds (default: 0)")
    parser.add_argument("--timeout", type=float, default=10.0, help="per-request timeout (default: 10s)")
    parser.add_argument("--cookie", default=None, help='cookie header, e.g. "session=abc; lang=en"')
    parser.add_argument("--login-url", default=None,
                        help="login page URL for authenticated scanning (auto-fills the "
                             "password form, maintains the session)")
    parser.add_argument("--auth-user", default=None, help="username for --login-url")
    parser.add_argument("--auth-pass", default=None, help="password for --login-url")
    parser.add_argument("--wordlist", default=None,
                        help="extra file-exposure paths to probe (one per line, # comments)")
    parser.add_argument("-A", "--user-agent", default=None, help="custom User-Agent")
    parser.add_argument("--proxy", default=None, help="HTTP(S) proxy URL")
    parser.add_argument("-k", "--insecure", action="store_true", help="skip TLS certificate verification")
    parser.add_argument("--allow-private", action="store_true",
                        help="allow loopback/private targets (for lab environments, e.g. DVWA)")
    parser.add_argument("-v", "--verbose", action="store_true", help="verbose request logging")
    parser.add_argument("--fail-on", choices=["none", "info", "low", "medium", "high", "critical"],
                        default="none",
                        help="exit with code 1 when findings at or above this severity exist "
                             "(CI gate; default: none)")
    parser.add_argument("--format", choices=["text", "json"], default="text",
                        help="console output format; json prints the machine-readable scan "
                             "result to stdout and silences progress output (default: text)")
    parser.add_argument("--time-based", action="store_true",
                        help="also run the opt-in time-based blind injection module (slower: "
                             "winning probes really sleep ~3s, twice, per parameter)")
    parser.add_argument("--sarif", metavar="PATH", default=None,
                        help="additional SARIF 2.1.0 report (single-target mode only)")
    parser.add_argument("--compare", metavar="PREV_JSON", default=None,
                        help="diff against a previous JSON report (single-target mode only); "
                             "with --fail-on, only NEW findings count towards the gate")
    parser.add_argument("--version", action="version", version=f"WebVulnScanner {__version__}")
    return parser


def _print_summary(result) -> None:
    print("=" * 62)
    print(f"[*] Scan finished in {result.duration:.1f}s "
          f"({result.stats.requests} requests, {result.pages_crawled} pages, "
          f"{result.attack_points} parameters tested)")
    if result.stats.blocked:
        print(f"[*] {result.stats.blocked} request(s) blocked by the network guard")
    if result.stats.rate_limited:
        print(f"[*] {result.stats.rate_limited} throttled response(s); adaptive pacing engaged")
    counts = result.severity_counts
    if not counts:
        print("[*] No findings.")
    else:
        print(f"[*] Findings: {len(result.findings)}")
        for sev in sorted(SEVERITY_ORDER, key=lambda s: SEVERITY_ORDER[s], reverse=True):
            if sev in counts:
                print(f"    {SEVERITY_LABELS_EN[sev]:<9} {counts[sev]}")
    print("=" * 62)


def _load_previous(path: str) -> list:
    with open(path, encoding="utf-8") as handle:
        data = json.load(handle)
    previous = data.get("findings", [])
    if not isinstance(previous, list):
        raise ValueError(f"{path}: 'findings' is not a list")
    return previous


def _diff_key(finding: dict) -> tuple:
    return (finding.get("module", ""), finding.get("check_id", ""),
            finding.get("url", "").rstrip("/"), finding.get("param", ""))


def _build_comparison(result, previous_path: str) -> dict:
    previous = _load_previous(previous_path)
    previous_keys = {_diff_key(f) for f in previous}
    current = [f.to_dict() for f in result.sorted_findings()]
    current_keys = {_diff_key(f) for f in current}
    return {
        "previous": previous_path,
        "new": [f for f in current if _diff_key(f) not in previous_keys],
        "fixed": [f for f in previous if _diff_key(f) not in current_keys],
        "unchanged": len(current_keys & previous_keys),
    }


def _print_comparison(comparison: dict, log) -> None:
    log(f"[*] Comparison against {comparison.get('previous', '?')}:")
    log(f"    NEW ({len(comparison['new'])}):")
    for item in comparison["new"][:5]:
        log(f"      + [{item.get('severity')}] {item.get('title')}")
    if len(comparison["new"]) > 5:
        log(f"      ... and {len(comparison['new']) - 5} more")
    log(f"    FIXED ({len(comparison['fixed'])}):")
    for item in comparison["fixed"][:5]:
        log(f"      - [{item.get('severity')}] {item.get('title')}")
    if len(comparison["fixed"]) > 5:
        log(f"      ... and {len(comparison['fixed']) - 5} more")
    log(f"    UNCHANGED: {comparison['unchanged']}")


def _read_targets_file(path: str) -> list:
    urls = []
    seen = set()
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            entry = line.split("#", 1)[0].strip()
            if entry and entry not in seen:
                seen.add(entry)
                urls.append(entry)
    if not urls:
        raise ValueError(f"no target URLs found in {path}")
    return urls


def _threshold_breached(findings, fail_on: str) -> bool:
    threshold = SEVERITY_ORDER[fail_on]
    return any(SEVERITY_ORDER.get(f.severity, 0) >= threshold for f in findings)


def _build_config(args) -> ScanConfig:
    return ScanConfig(
        modules=[m.strip() for m in args.modules.split(",") if m.strip()],
        threads=args.threads,
        delay=args.delay,
        timeout=args.timeout,
        depth=args.depth,
        max_pages=args.max_pages,
        no_crawl=args.no_crawl,
        verify_tls=not args.insecure,
        allow_private=args.allow_private,
        user_agent=args.user_agent,
        proxy=args.proxy,
        cookies=args.cookie,
        verbose=args.verbose,
        time_based=args.time_based,
        login_url=args.login_url,
        auth_user=args.auth_user,
        auth_pass=args.auth_pass,
        wordlist=args.wordlist,
    )


# ---------------------------------------------------------------------------
# single-target flow
# ---------------------------------------------------------------------------
def _run_single(args, log) -> int:
    config = _build_config(args)
    try:
        result = Scanner(config).run(args.url, log=log)
        if args.compare:
            result.comparison = _build_comparison(result, args.compare)
    except GuardBlocked as exc:
        log(f"[!] Target blocked by the network guard: {exc.reason}")
        log("    Re-run with --allow-private only for lab targets you own.")
        return 2
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        log(f"[!] {exc}")
        return 2
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")
        return 130

    machine_mode = args.format == "json"
    if machine_mode:
        print(render_json(result))
    else:
        _print_summary(result)
        if result.comparison:
            _print_comparison(result.comparison, log)

    if not args.no_report:
        html_path = args.report
        json_path = args.json
        if html_path is None:
            html_path, default_json = default_report_paths(result)
            json_path = json_path or default_json
        for path in write_reports(result, html_path, json_path):
            log(f"[+] Report written: {path}")

    if args.sarif:
        directory = os.path.dirname(os.path.abspath(args.sarif))
        if directory:
            os.makedirs(directory, exist_ok=True)
        with open(args.sarif, "w", encoding="utf-8") as handle:
            handle.write(render_sarif(result))
        log(f"[+] SARIF report written: {os.path.abspath(args.sarif)}")

    if args.fail_on != "none":
        gate_findings = result.findings
        if result.comparison:
            new_keys = {_diff_key(f) for f in result.comparison.get("new", [])}
            gate_findings = [f for f in result.findings if _diff_key(f.to_dict()) in new_keys]
        if _threshold_breached(gate_findings, args.fail_on):
            log(f"[!] Fail threshold breached (findings at or above '{args.fail_on}'"
                + (", among NEW findings" if result.comparison else "") + ")")
            return 1
    return 0


# ---------------------------------------------------------------------------
# batch flow
# ---------------------------------------------------------------------------
def _run_batch(args, log) -> int:
    if args.compare or args.sarif or args.report:
        log("[!] --compare, --sarif and --report are single-target options; "
            "batch mode writes its own per-target + summary reports")
        return 2

    try:
        targets = _read_targets_file(args.targets)
    except (OSError, ValueError) as exc:
        log(f"[!] {exc}")
        return 2

    machine_mode = args.format == "json"
    if not machine_mode:
        print(f"[*] Batch scan: {len(targets)} target(s)")

    config = _build_config(args)
    results = []
    failures = 0
    for index, url in enumerate(targets, 1):
        if not machine_mode:
            print(f"\n=== [{index}/{len(targets)}] {url} ===")
        try:
            result = Scanner(config).run(url, log=log)
        except GuardBlocked as exc:
            log(f"[!] {url}: blocked by the network guard ({exc.reason})")
            failures += 1
            continue
        except KeyboardInterrupt:
            print("\n[!] Interrupted by user")
            return 130
        except (ValueError, OSError) as exc:
            log(f"[!] {url}: {exc.__class__.__name__}: {exc}")
            failures += 1
            continue

        results.append(result)
        if not args.no_report:
            html_path, json_path = default_report_paths(result)
            for path in write_reports(result, html_path, json_path):
                log(f"[+] Report written: {path}")
        if not machine_mode:
            counts = result.severity_counts
            chips = " ".join(f"{SEVERITY_LABELS_EN[s]}:{counts[s]}"
                             for s in ("critical", "high", "medium", "low", "info")
                             if counts.get(s))
            print(f"    -> {len(result.findings)} finding(s)"
                  + (f" [{chips}]" if chips else ""))

    if machine_mode:
        print(render_batch_json(results))

    if not args.no_report and results:
        import time as _time

        stamp = _time.strftime("%Y%m%d_%H%M%S", _time.localtime(results[0].started_at))
        stem = os.path.join("reports", f"batch_{stamp}")
        os.makedirs("reports", exist_ok=True)
        with open(f"{stem}.html", "w", encoding="utf-8") as handle:
            handle.write(render_batch_html(results))
        with open(f"{stem}.json", "w", encoding="utf-8") as handle:
            handle.write(render_batch_json(results))
        log(f"[+] Batch summary: {os.path.abspath(stem)}.html / .json")

    if not machine_mode and results:
        total = sum(len(r.findings) for r in results)
        print("=" * 62)
        print(f"[*] Batch finished: {len(results)}/{len(targets)} scanned, "
              f"{total} finding(s)" + (f", {failures} failed/skipped" if failures else ""))
        print("=" * 62)

    if args.fail_on != "none" and any(
        _threshold_breached(r.findings, args.fail_on) for r in results
    ):
        log(f"[!] Fail threshold breached on at least one target "
            f"(findings at or above '{args.fail_on}')")
        return 1
    if failures:
        return 2
    return 0


def main(argv=None) -> int:
    # Best-effort UTF-8 console (Windows defaults to a legacy codepage).
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure:
            try:
                reconfigure(encoding="utf-8")
            except Exception:
                pass

    args = build_parser().parse_args(argv)
    machine_mode = args.format == "json"
    log = (lambda *_a, **_k: None) if machine_mode else print

    if not machine_mode:
        print(BANNER)

    if args.targets:
        return _run_batch(args, log)
    return _run_single(args, log)


if __name__ == "__main__":
    sys.exit(main())
