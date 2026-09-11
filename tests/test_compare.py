"""Scan diff (--compare): regression-only gating and comparison content."""

from __future__ import annotations

import json

from scanner import cli
from scanner.models import ScanResult
from scanner.report import render_json
from scanner.scanner import ScanConfig, Scanner


def _scan(app_url, modules) -> ScanResult:
    return Scanner(ScanConfig(modules=modules, threads=4, timeout=5,
                              allow_private=True, max_pages=20, depth=2)
                   ).run(app_url, log=lambda *_: None)


def test_comparison_diff_and_regression_gate(app_url, tmp_path):
    # baseline scan: sqli findings only
    baseline = _scan(app_url, ["sqli"])
    prev_path = tmp_path / "prev.json"
    prev_path.write_text(render_json(baseline), encoding="utf-8")

    # follow-up scan with different modules: xss findings are NEW,
    # sqli findings are "fixed" relative to the baseline
    rc = cli.main(["-u", app_url, "--allow-private", "--no-report",
                   "--modules", "sqli,xss", "--compare", str(prev_path),
                   "--fail-on", "critical", "--format", "json"])
    assert rc == 0  # xss findings are high, not critical → gate not breached

    # a follow-up where a NEW critical finding appears must fail the gate
    rc = cli.main(["-u", app_url, "--allow-private", "--no-report",
                   "--modules", "sqli,cmdi,ssti", "--compare", str(prev_path),
                   "--fail-on", "critical", "--format", "json"])
    assert rc == 1  # cmdi/ssti criticals are new vs the baseline


def test_comparison_sections_in_json_report(app_url, tmp_path):
    baseline = _scan(app_url, ["sqli"])
    prev_path = tmp_path / "prev.json"
    prev_path.write_text(render_json(baseline), encoding="utf-8")

    json_path = tmp_path / "new.json"
    # follow-up without the sqli module: its findings count as "fixed",
    # the xss findings are "new"
    rc = cli.main(["-u", app_url, "--allow-private",
                   "--modules", "xss", "--compare", str(prev_path),
                   "--json", str(json_path)])
    assert rc == 0
    data = json.loads(json_path.read_text(encoding="utf-8"))
    comparison = data["comparison"]
    assert comparison["previous"] == str(prev_path)
    assert any(f["module"] == "xss" for f in comparison["new"])
    assert any(f["module"] == "sqli" for f in comparison["fixed"])
    assert comparison["unchanged"] == 0


def test_compare_missing_file_fails_cleanly(app_url):
    rc = cli.main(["-u", app_url, "--allow-private", "--no-report",
                   "--modules", "headers", "--compare", "does-not-exist.json"])
    assert rc == 2
