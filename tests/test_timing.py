"""Time-based blind injection module (opt-in) against the bundled app."""

from __future__ import annotations

from scanner.models import ScanResult
from scanner.scanner import ScanConfig, Scanner


def run_scan(app_url, **overrides) -> ScanResult:
    options = dict(modules=["timing"], threads=4, timeout=10,
                   allow_private=True, max_pages=20, depth=2)
    options.update(overrides)
    return Scanner(ScanConfig(**options)).run(app_url, log=lambda *_: None)


def test_time_based_sqli_and_cmdi(app_url):
    result = run_scan(app_url)
    ids = {(f.check_id, f.param) for f in result.findings}
    # /query sleeps on SQL SLEEP() payloads
    assert ("timing.sqli_sleep", "user") in ids, f"findings: {ids}"
    # /ping sleeps on shell `sleep` payloads (separator required in the app)
    assert ("timing.cmdi_sleep", "host") in ids, f"findings: {ids}"


def test_time_based_no_fp_on_fast_params(app_url):
    result = run_scan(app_url)
    timing = [f for f in result.findings if f.module == "timing"]
    fast_params = {"id", "q", "file", "tpl", "next"}   # params that never sleep
    assert not any(f.param in fast_params for f in timing)


def test_timing_not_in_default_modules():
    from scanner.modules import DEFAULT_MODULES, MODULES

    assert "timing" in MODULES
    assert "timing" not in DEFAULT_MODULES
    assert "domxss" in MODULES
    assert "domxss" not in DEFAULT_MODULES


def test_cli_time_based_flag(app_url, capsys):
    from scanner import cli

    rc = cli.main(["-u", app_url, "--allow-private", "--no-report",
                   "--modules", "timing", "--time-based", "--fail-on", "high",
                   "--format", "json"])
    # timing findings (high) exist → gate must fire even though the flag,
    # not the module list, is what pulls the module in
    assert rc == 1
    assert "timing" in capsys.readouterr().out
