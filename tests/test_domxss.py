"""DOM XSS module (browser-based, optional playwright dependency).

Skipped automatically when playwright (or its Chromium build) is missing —
the unit part of the probe-URL builder still runs everywhere.
"""

from __future__ import annotations

import pytest

from scanner.modules.domxss import build_probe_url

playwright_sync = pytest.importorskip(
    "playwright.sync_api", reason="playwright not installed (optional 'dom' extra)"
)


def test_build_probe_url_preserves_other_params():
    url = "http://127.0.0.1:1/page?a=1&b=2"
    probe = build_probe_url(url, {"a": "1", "b": "2"}, "b", "wvscanary")
    assert "a=1" in probe
    assert "b=wvscanary" in probe
    assert probe.startswith("http://127.0.0.1:1/page?")


def _chromium_available() -> bool:
    try:
        from playwright.sync_api import sync_playwright

        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True)
            browser.close()
        return True
    except Exception:
        return False


@pytest.mark.skipif(not _chromium_available(), reason="chromium build not installed")
def test_dom_xss_sink_detected(app_url):
    from scanner.models import ScanResult
    from scanner.scanner import ScanConfig, Scanner

    result: ScanResult = Scanner(ScanConfig(
        modules=["domxss"], threads=2, timeout=5,
        allow_private=True, max_pages=25, depth=2,
    )).run(app_url, log=lambda *_: None)

    hits = [f for f in result.findings if f.module == "domxss"]
    assert any(f.param == "name" and f.url.endswith("/dom") for f in hits), \
        f"findings: {[(f.url, f.param) for f in result.findings]}"
    # the textContent counterpart must stay clean
    assert not any(f.url.endswith("/domsafe") for f in hits)
    # innerHTML sink → high severity, evidence mentions the sink
    dom_hit = next(f for f in hits if f.url.endswith("/dom"))
    assert dom_hit.severity == "high"
    assert "innerHTML" in dom_hit.evidence
