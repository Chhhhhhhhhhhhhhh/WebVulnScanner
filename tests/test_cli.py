"""CLI behaviour: --fail-on gate and --format json machine output."""

from __future__ import annotations

import json

from scanner import cli


class TestFailOnGate:
    def test_fail_on_critical_triggered(self, app_url):
        rc = cli.main(["-u", app_url, "--allow-private", "--no-report",
                       "--modules", "cmdi", "--fail-on", "critical"])
        assert rc == 1  # /ping hosts a critical command-injection finding

    def test_fail_on_high_not_triggered_by_lower_severity(self, app_url):
        rc = cli.main(["-u", app_url, "--allow-private", "--no-report",
                       "--modules", "headers", "--fail-on", "high"])
        assert rc == 0  # header findings are medium/low at most

    def test_fail_on_none_by_default(self, app_url):
        rc = cli.main(["-u", app_url, "--allow-private", "--no-report",
                       "--modules", "headers"])
        assert rc == 0


class TestMachineFormat:
    def test_format_json_outputs_result(self, app_url, capsys):
        rc = cli.main(["-u", app_url, "--allow-private", "--no-report",
                       "--modules", "headers", "--format", "json"])
        assert rc == 0
        captured = capsys.readouterr().out
        # the banner/progress must not pollute machine output
        assert "Crawl finished" not in captured
        data = json.loads(captured)
        assert data["meta"]["target"].startswith("http://127.0.0.1")
        assert isinstance(data["findings"], list) and data["findings"]
        assert any(f["check_id"].startswith("headers.missing") for f in data["findings"])
