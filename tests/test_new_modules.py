"""New v2.4 modules: HTTP methods, Host header injection, NoSQL injection."""

from __future__ import annotations

from scanner.models import ScanResult
from scanner.scanner import ScanConfig, Scanner


def _scan(app_url, modules, **overrides) -> ScanResult:
    options = dict(modules=modules, threads=4, timeout=5,
                   allow_private=True, max_pages=30, depth=2)
    options.update(overrides)
    return Scanner(ScanConfig(**options)).run(app_url, log=lambda *_: None)


class TestMethodsModule:
    def test_trace_enabled(self, app_url):
        result = _scan(app_url, ["methods"])
        ids = {f.check_id for f in result.findings}
        assert "methods.trace" in ids, sorted(ids)

    def test_put_upload_detected_and_cleaned(self, app_url):
        result = _scan(app_url, ["methods"])
        ids = {(f.check_id, f.severity) for f in result.findings}
        assert ("methods.put_upload", "high") in ids, sorted(ids)
        # the probe file must have been deleted again (not publicly readable)
        assert "methods.put_persisted" not in {c for c, _ in ids}


class TestHostHeaderModule:
    def test_host_reflection_detected(self, app_url):
        # /canonical builds its URL from the Host header
        result = _scan(app_url, ["hostheader"])
        hits = [f for f in result.findings if f.check_id == "hostheader.reflect"]
        assert hits, [(f.check_id, f.url) for f in result.findings]
        assert "evil.example" in hits[0].evidence

    def test_host_cwe(self, app_url):
        result = _scan(app_url, ["hostheader"])
        hits = [f for f in result.findings if f.module == "hostheader"]
        assert hits and hits[0].cwe == "CWE-644"


class TestNoSqlModule:
    def test_error_based_nosqli(self, app_url):
        result = _scan(app_url, ["nosqli"])
        ids = {(f.check_id, f.param) for f in result.findings}
        assert ("nosqli.error", "user") in ids, sorted(ids)

    def test_no_fp_on_relational_error_page(self, app_url):
        # /item returns MySQL errors for quotes; NoSQL operators must not match
        result = _scan(app_url, ["nosqli"])
        assert not any(f.param == "id" and f.url.endswith("/item")
                       for f in result.findings)


class TestNewModulesInDefaults:
    def test_registered_and_default(self):
        from scanner.modules import DEFAULT_MODULES, MODULES

        for module_id in ("methods", "hostheader", "nosqli"):
            assert module_id in MODULES
            assert module_id in DEFAULT_MODULES
