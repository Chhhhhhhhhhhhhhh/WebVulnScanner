"""SARIF 2.1.0 output structure and CLI flag."""

from __future__ import annotations

import json

from scanner.models import ScanResult
from scanner.sarif import LEVEL_MAP, render_sarif
from scanner.scanner import ScanConfig, Scanner


def _scan(app_url) -> ScanResult:
    return Scanner(ScanConfig(modules=["headers", "sqli"], threads=4, timeout=5,
                              allow_private=True, max_pages=20, depth=2)
                   ).run(app_url, log=lambda *_: None)


def test_level_mapping():
    assert LEVEL_MAP["critical"] == "error"
    assert LEVEL_MAP["high"] == "error"
    assert LEVEL_MAP["medium"] == "warning"
    assert LEVEL_MAP["low"] == "warning"
    assert LEVEL_MAP["info"] == "note"


def test_sarif_structure(app_url):
    result = _scan(app_url)
    sarif = json.loads(render_sarif(result))
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "WebVulnScanner"
    assert len(run["results"]) == len(result.findings)
    rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
    assert rule_ids == {f.check_id for f in result.findings}
    for entry, finding in zip(run["results"], result.sorted_findings()):
        assert entry["ruleId"] == finding.check_id
        assert entry["level"] == LEVEL_MAP[finding.severity]
        assert entry["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]


def test_sarif_pretty_and_valid_json(app_url):
    result = _scan(app_url)
    text = render_sarif(result)
    assert "\n" in text  # pretty-printed
    json.loads(text)     # must remain valid JSON with any evidence content


def test_cli_sarif_flag(app_url, tmp_path):
    from scanner import cli

    sarif_path = tmp_path / "out.sarif"
    rc = cli.main(["-u", app_url, "--allow-private", "--no-report",
                   "--modules", "headers", "--sarif", str(sarif_path),
                   "--format", "json"])
    assert rc == 0
    data = json.loads(sarif_path.read_text(encoding="utf-8"))
    assert data["version"] == "2.1.0"
    assert data["runs"][0]["results"]
