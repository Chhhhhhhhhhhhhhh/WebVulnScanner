"""End-to-end scan against the bundled vulnerable app."""

from __future__ import annotations

import html
import json

import pytest

from scanner.httpclient import GuardBlocked
from scanner.models import ScanResult
from scanner.report import render_html, write_reports
from scanner.scanner import ScanConfig, Scanner

ALL_MODULES = ["headers", "fingerprint", "sensitive", "sqli", "xss", "cmdi", "lfi",
               "redirect", "cors", "ssti"]


def run_scan(app_url, **overrides) -> ScanResult:
    options = dict(
        modules=ALL_MODULES,
        threads=4,
        timeout=5,
        allow_private=True,
        max_pages=20,
        depth=2,
    )
    options.update(overrides)
    return Scanner(ScanConfig(**options)).run(app_url, log=lambda *_: None)


@pytest.fixture(scope="session")
def full_result(app_url) -> ScanResult:
    """One full scan reused by all detection assertions."""
    return run_scan(app_url)


class TestVulnerabilityDetection:
    def test_error_based_sqli_get(self, full_result):
        ids = {(f.check_id, f.param) for f in full_result.findings}
        assert ("sqli.error_based", "id") in ids, f"findings: {ids}"

    def test_error_based_sqli_post_form(self, full_result):
        ids = {(f.check_id, f.param) for f in full_result.findings}
        assert ("sqli.error_based", "username") in ids, f"findings: {ids}"

    def test_single_use_csrf_form_still_tested(self, full_result):
        # /login consumes its CSRF token on every POST; only the scanner's
        # per-probe token refresh keeps the SQLi probes reaching the app.
        ids = {(f.check_id, f.param) for f in full_result.findings}
        assert ("sqli.error_based", "username") in ids
        expired = [f for f in full_result.findings if "Session expired" in f.evidence]
        assert not expired

    def test_reflected_xss_high(self, full_result):
        xss = [f for f in full_result.findings if f.check_id == "xss.reflected_html"]
        assert any(f.param == "q" for f in xss), \
            f"findings: {[f.title for f in full_result.findings]}"

    def test_command_injection(self, full_result):
        ids = {(f.check_id, f.param) for f in full_result.findings}
        assert ("cmdi.echo_marker", "host") in ids, f"findings: {ids}"

    def test_path_traversal(self, full_result):
        ids = {(f.check_id, f.param) for f in full_result.findings}
        assert ("lfi.traversal", "file") in ids, f"findings: {ids}"

    def test_env_exposure(self, full_result):
        ids = {f.check_id for f in full_result.findings}
        assert "sensitive.env" in ids

    def test_open_redirect(self, full_result):
        ids = {(f.check_id, f.param) for f in full_result.findings}
        assert ("redirect.open", "url") in ids, f"findings: {ids}"

    def test_validated_redirect_not_flagged(self, full_result):
        redirect_hits = [f for f in full_result.findings if f.module == "redirect"]
        assert not any(f.param == "next" for f in redirect_hits)

    def test_cors_reflection_with_credentials(self, full_result):
        cors = [f for f in full_result.findings if f.check_id == "cors.reflect"]
        assert cors and cors[0].severity == "high"

    def test_cors_fixed_origin_not_flagged(self, full_result):
        cors = [f for f in full_result.findings if f.module == "cors"]
        assert not any("api/safe" in (f.evidence or "") for f in cors)

    def test_ssti(self, full_result):
        ids = {(f.check_id, f.param) for f in full_result.findings}
        assert ("ssti.eval", "tpl") in ids, f"findings: {ids}"

    def test_ssti_no_fp_on_plain_reflection(self, full_result):
        # /search reflects raw input but never evaluates templates
        ssti_params = {f.param for f in full_result.findings if f.module == "ssti"}
        assert "q" not in ssti_params

    def test_cwe_and_fix_populated(self, full_result):
        vulns = [f for f in full_result.findings
                 if f.severity in ("critical", "high", "medium")]
        assert vulns
        for finding in vulns:
            assert finding.cwe.startswith("CWE-"), finding.title
            assert finding.fix, finding.title


class TestFalsePositiveControl:
    def test_soft404_does_not_flag_missing_files(self, full_result):
        # backup.sql, phpinfo.php etc. fall through to the soft-404 page
        ids = {f.check_id for f in full_result.findings}
        for banned in ("sensitive.sql_backup", "sensitive.phpinfo",
                       "sensitive.git_head", "sensitive.directory_listing"):
            assert banned not in ids, f"{banned} falsely reported"

    def test_safe_page_not_flagged_for_xss(self, full_result):
        dangerous = [f for f in full_result.findings
                     if f.param == "id" and f.url.endswith("/safe/page")
                     and f.severity in ("high", "medium")]
        assert not dangerous

    def test_robots_txt_not_reported_as_sensitive(self, full_result):
        sensitive_titles = " ".join(
            f.title for f in full_result.findings if f.module == "sensitive"
        ).lower()
        assert "robots" not in sensitive_titles


class TestScanHygiene:
    def test_findings_deduped(self, full_result):
        keys = [f.dedup_key for f in full_result.findings]
        assert len(keys) == len(set(keys))

    def test_headers_module_reports_missing_csp(self, full_result):
        ids = {f.check_id for f in full_result.findings}
        assert "headers.missing.content-security-policy" in ids

    def test_fingerprint_reports_server(self, full_result):
        assert any(f.check_id == "fingerprint.server" for f in full_result.findings)

    def test_stats_populated(self, full_result):
        assert full_result.stats.requests > 10
        assert full_result.pages_crawled >= 3
        assert full_result.attack_points >= 5

    def test_no_crawl_limits_pages(self, app_url):
        result = run_scan(app_url, no_crawl=True)
        assert result.pages_crawled <= 2  # entry + robots

    def test_module_selection(self, app_url):
        result = run_scan(app_url, modules=["headers"])
        assert result.modules_run == ["headers"]
        assert all(f.module == "headers" for f in result.findings)

    def test_unknown_module_rejected(self):
        with pytest.raises(ValueError):
            Scanner(ScanConfig(modules=["nope"])).run("http://example.com")

    def test_private_target_blocked_without_flag(self, app_url):
        with pytest.raises(GuardBlocked):
            run_scan(app_url, allow_private=False)


class TestReportIntegration:
    def test_json_roundtrip(self, full_result, tmp_path):
        html_path = tmp_path / "r.html"
        json_path = tmp_path / "r.json"
        written = write_reports(full_result, str(html_path), str(json_path))
        assert len(written) == 2
        data = json.loads(json_path.read_text(encoding="utf-8"))
        assert data["meta"]["target"].startswith("http://127.0.0.1")
        assert len(data["findings"]) == len(full_result.findings)

    def test_html_escapes_untrusted_content(self, full_result):
        html_text = render_html(full_result)
        assert "WebVulnScanner" in html_text
        # evidence containing payloads must never ship raw script tags
        for finding in full_result.findings:
            if "<script" in finding.evidence or "<img" in finding.evidence:
                assert "<script>alert" not in html_text
                assert html.escape(finding.evidence) in html_text

    def test_html_contains_severity_filter(self, full_result):
        html_text = render_html(full_result)
        assert "filterFindings" in html_text
        assert 'data-sev=' in html_text
