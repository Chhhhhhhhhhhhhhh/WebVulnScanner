"""Wordlist-driven file exposure and crawler discovery (sitemap / JS)."""

from __future__ import annotations

from scanner.models import ScanResult
from scanner.scanner import ScanConfig, Scanner


def _scan(app_url, modules, **overrides) -> ScanResult:
    options = dict(modules=modules, threads=4, timeout=5,
                   allow_private=True, max_pages=30, depth=2)
    options.update(overrides)
    return Scanner(ScanConfig(**options)).run(app_url, log=lambda *_: None)


class TestWordlist:
    def test_wordlist_hits_and_misses(self, app_url, tmp_path):
        wordlist = tmp_path / "words.txt"
        wordlist.write_text(
            "# custom entries\n/custom-secret.txt\nmissing-path-xyz # note: gets a leading slash\n",
            encoding="utf-8",
        )
        result = _scan(app_url, ["sensitive"], wordlist=str(wordlist))
        ids = {f.check_id for f in result.findings}
        assert "sensitive.wordlist_custom_secret_txt" in ids, sorted(ids)
        # the non-existent entry must not be flagged (soft-404 calibration)
        assert not any("missing" in i for i in ids), sorted(ids)

    def test_broken_wordlist_does_not_crash(self, app_url):
        result = _scan(app_url, ["sensitive"], wordlist="no-such-file.txt")
        assert result.modules_run == ["sensitive"]


class TestSitemapDiscovery:
    def test_sitemap_url_becomes_attack_surface(self, app_url):
        result = _scan(app_url, ["xss"])
        # /hidden?id=1 is only reachable via sitemap.xml
        hits = [f for f in result.findings
                if f.url.endswith("/hidden") and f.check_id == "xss.reflected_html"]
        assert hits, f"findings: {[(f.url, f.param) for f in result.findings]}"
        assert hits[0].param == "id"


class TestJsEndpointDiscovery:
    def test_js_referenced_api_becomes_attack_surface(self, app_url):
        result = _scan(app_url, ["xss"])
        # /secretapi?cmd= appears only inside /static/app.js
        hits = [f for f in result.findings
                if f.url.endswith("/secretapi") and f.check_id == "xss.reflected_html"]
        assert hits, f"findings: {[(f.url, f.param) for f in result.findings]}"
        assert hits[0].param == "cmd"
