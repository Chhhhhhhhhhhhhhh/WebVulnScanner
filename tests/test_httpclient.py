"""Tests for the HTTP client: network guard, redirects, stats, backoff."""

import pytest

from scanner.httpclient import GuardBlocked, HttpClient, ip_block_reason


class TestIpBlockReason:
    @pytest.mark.parametrize("ip", ["127.0.0.1", "::1", "10.0.0.5", "192.168.1.1",
                                    "172.16.0.1", "169.254.1.1", "0.0.0.0", "224.0.0.1"])
    def test_blocked_ranges(self, ip):
        assert ip_block_reason(ip) is not None

    @pytest.mark.parametrize("ip", ["93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946"])
    def test_public_allowed(self, ip):
        assert ip_block_reason(ip) is None


class TestGuard:
    def test_loopback_blocked_without_flag(self):
        client = HttpClient()
        with pytest.raises(GuardBlocked):
            client.guard("http://127.0.0.1/x")

    def test_loopback_allowed_with_flag(self):
        client = HttpClient(allow_private=True)
        client.guard("http://127.0.0.1/x")  # must not raise

    def test_private_blocked_without_flag(self):
        client = HttpClient()
        with pytest.raises(GuardBlocked):
            client.guard("http://10.255.0.1/x")


class TestRequests:
    def test_request_counts_stats(self, app_url):
        client = HttpClient(allow_private=True, timeout=5)
        resp = client.request("GET", app_url)
        assert resp is not None and resp.status_code == 200
        assert client.stats.requests == 1

    def test_guard_blocks_request_to_loopback(self):
        client = HttpClient()  # no allow_private
        assert client.request("GET", "http://127.0.0.1:1/") is None
        assert client.stats.blocked >= 1

    def test_manual_redirect_follows(self, app_url):
        client = HttpClient(allow_private=True, timeout=5)
        page = client.get_page(app_url)
        assert page is not None and page.status == 200

    def test_get_page_caps_body(self, app_url):
        client = HttpClient(allow_private=True, timeout=5)
        page = client.get_page(app_url, cap=64)
        assert page is not None and len(page.body) <= 64 + 8192  # cap + final chunk

    def test_unknown_host_returns_none(self):
        client = HttpClient(timeout=3)
        assert client.request("GET", "http://nonexistent-wvs-test-host.invalid/") is None
        # DNS failure surfaces through the guard as a blocked request
        assert client.stats.blocked >= 1


class TestAdaptiveBackoff:
    def test_get_backs_off_and_returns_429(self, app_url):
        client = HttpClient(allow_private=True, timeout=5)
        resp = client.request("GET", app_url + "ratelimit")
        assert resp is not None and resp.status_code == 429
        # MAX_BACKOFF_RETRIES adaptive retries before giving up
        assert client.stats.rate_limited >= 2
        assert client.adaptive_delay > 0

    def test_post_is_not_retried_on_429(self, app_url):
        client = HttpClient(allow_private=True, timeout=5)
        resp = client.request("POST", app_url + "ratelimit", data={"x": "1"})
        assert resp is not None and resp.status_code == 429
        assert client.stats.rate_limited == 0


class TestRateLimit:
    def test_delay_spacing(self, app_url):
        import time

        client = HttpClient(allow_private=True, timeout=5, delay=0.2)
        start = time.monotonic()
        client.request("GET", app_url)
        client.request("GET", app_url)
        elapsed = time.monotonic() - start
        assert elapsed >= 0.2
