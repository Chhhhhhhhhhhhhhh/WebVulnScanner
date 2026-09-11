"""Authenticated scanning: auto login, session cookies, logout avoidance."""

from __future__ import annotations

from scanner.models import ScanResult
from scanner.scanner import ScanConfig, Scanner


def _scan(app_url, **overrides) -> ScanResult:
    options = dict(modules=["xss"], threads=4, timeout=5,
                   allow_private=True, max_pages=25, depth=2)
    options.update(overrides)
    return Scanner(ScanConfig(**options)).run(app_url, log=lambda *_: None)


class TestAuthenticatedScanning:
    def test_unauthenticated_cannot_see_account(self, app_url):
        result = _scan(app_url)
        assert not any(f.url.endswith("/account") for f in result.findings)

    def test_login_unlocks_account_surface(self, app_url):
        result = _scan(
            app_url,
            login_url=f"{app_url}login-page",
            auth_user="demo@example.com",
            auth_pass="secret123",
        )
        hits = [f for f in result.findings
                if f.url.endswith("/account") and f.check_id == "xss.reflected_html"]
        assert hits, f"findings: {[(f.url, f.check_id) for f in result.findings]}"
        assert hits[0].param == "id"

    def test_bad_credentials_fall_back_gracefully(self, app_url):
        # wrong creds → no session cookie → scan continues unauthenticated
        result = _scan(
            app_url,
            login_url=f"{app_url}login-page",
            auth_user="demo@example.com",
            auth_pass="wrong-password",
        )
        assert result.pages_crawled > 0
        assert not any(f.url.endswith("/account") for f in result.findings)


class TestLogoutAvoidance:
    def test_logout_links_never_fetched(self, app_url):
        result = _scan(app_url, login_url=f"{app_url}login-page",
                       auth_user="demo@example.com", auth_pass="secret123")
        # app.js advertises "/logout"; the crawler must refuse it even though
        # it looks like a JS endpoint, or the session would die mid-scan
        assert result.pages_crawled > 0
        # login must have succeeded (session survived the whole scan)
        assert any(f.url.endswith("/account") for f in result.findings)
