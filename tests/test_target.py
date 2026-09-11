"""Unit tests for URL/target handling (regression: query strings must survive)."""

import pytest

from scanner.target import host_of, normalize_url, same_host


class TestNormalizeUrl:
    def test_adds_scheme_and_path(self):
        assert normalize_url("example.com") == "http://example.com/"

    def test_keeps_https(self):
        assert normalize_url("https://example.com") == "https://example.com/"

    def test_query_string_is_preserved_untouched(self):
        # v1 appended "/" and corrupted this exact class of URL
        assert normalize_url("http://a.com/page.php?id=1") == "http://a.com/page.php?id=1"
        assert normalize_url("http://a.com/page.php?id=1").endswith("id=1")

    def test_existing_path_not_modified(self):
        assert normalize_url("http://a.com/sub/page") == "http://a.com/sub/page"

    def test_rejects_non_http_scheme(self):
        with pytest.raises(ValueError):
            normalize_url("ftp://example.com/file")

    def test_rejects_empty(self):
        with pytest.raises(ValueError):
            normalize_url("   ")

    def test_rejects_missing_host(self):
        with pytest.raises(ValueError):
            normalize_url("http:///path")

    def test_uppercase_scheme_normalised(self):
        assert normalize_url("HTTP://example.com/") == "http://example.com/"


class TestHostHelpers:
    def test_host_of_strips_port(self):
        assert host_of("http://example.com:8080/x") == "example.com"

    def test_same_host_default_ports(self):
        assert same_host("http://a.com/x", "http://a.com:80/y")
        assert not same_host("http://a.com", "https://a.com")

    def test_same_host_different_host(self):
        assert not same_host("http://a.com", "http://b.com")
