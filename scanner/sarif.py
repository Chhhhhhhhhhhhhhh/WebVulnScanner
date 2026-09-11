"""SARIF 2.1.0 output for GitHub code scanning / CI integrations.

Maps findings to results; severity → level:

* critical, high   → error
* medium, low      → warning
* info             → note
"""

from __future__ import annotations

import json

from . import __version__
from .models import ScanResult

SARIF_SCHEMA = ("https://raw.githubusercontent.com/oasis-tcs/sarif-spec/"
                "master/Schemata/sarif-schema-2.1.0.json")

LEVEL_MAP = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "warning",
    "info": "note",
}


def render_sarif(result: ScanResult, pretty: bool = True) -> str:
    findings = result.sorted_findings()

    # one rule per distinct check_id, in first-seen order
    rule_ids: list = []
    rule_meta: dict = {}
    for finding in findings:
        if finding.check_id not in rule_ids:
            rule_ids.append(finding.check_id)
            rule_meta[finding.check_id] = finding

    rules = []
    for check_id in rule_ids:
        prototype = rule_meta[check_id]
        rule = {
            "id": check_id,
            "shortDescription": {"text": prototype.title[:120]},
        }
        if prototype.cwe:
            rule["properties"] = {"cwe": prototype.cwe}
        rules.append(rule)

    sarif_results = []
    for finding in findings:
        sarif_results.append({
            "ruleId": finding.check_id,
            "ruleIndex": rule_ids.index(finding.check_id),
            "level": LEVEL_MAP.get(finding.severity, "note"),
            "message": {
                "text": f"{finding.title}"
                        + (f" [{finding.description[:400]}]" if finding.description else ""),
            },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": finding.url or result.target},
                },
            }],
            "properties": {
                "severity": finding.severity,
                "module": finding.module,
                "param": finding.param,
                "cwe": finding.cwe,
            },
        })

    sarif = {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "WebVulnScanner",
                    "version": __version__,
                    "informationUri": "https://github.com/Chhhhhhhhhhhhhhh/WebVulnScanner",
                    "rules": rules,
                },
            },
            "properties": {
                "target": result.target,
                "scan_started_at": result.started_at,
                "requests": result.stats.requests,
            },
            "results": sarif_results,
        }],
    }
    return json.dumps(sarif, ensure_ascii=False, indent=2 if pretty else None)
