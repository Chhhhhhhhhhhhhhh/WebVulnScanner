"""Target URL normalisation and host helpers.

The v1 normaliser appended "/" to any URL not ending in "/", which corrupted
targets with a query string (``http://a.com/page.php?id=1`` became
``http://a.com/page.php?id=1/``). This module never rewrites the query.
"""

from __future__ import annotations

from urllib.parse import urlsplit, urlunsplit

DEFAULT_PORTS = {"http": 80, "https": 443}


def normalize_url(raw: str) -> str:
    """Return a usable absolute URL: trimmed, with scheme and path defaults.

    The query string, fragment-free path and explicit ports are preserved
    exactly as given.
    """
    url = (raw or "").strip()
    if not url:
        raise ValueError("empty URL")
    parts = urlsplit(url)
    if parts.scheme and parts.scheme.lower() not in ("http", "https"):
        raise ValueError(f"unsupported scheme: {parts.scheme!r}")
    if not parts.scheme:
        url = "http://" + url
        parts = urlsplit(url)
    if not parts.netloc:
        raise ValueError(f"URL has no host: {raw!r}")
    path = parts.path or "/"
    return urlunsplit((parts.scheme.lower(), parts.netloc, path, parts.query, ""))


def host_of(url: str) -> str:
    """Return the hostname (lowercased, without port)."""
    return (urlsplit(url).hostname or "").lower()


def origin_key(url: str) -> tuple:
    """Compare hosts across default ports: (scheme, host, effective_port)."""
    parts = urlsplit(url)
    try:
        port = parts.port or DEFAULT_PORTS[parts.scheme.lower()]
    except (KeyError, ValueError):
        port = 0
    return (parts.scheme.lower(), (parts.hostname or "").lower(), port)


def same_host(a: str, b: str) -> bool:
    """True when both URLs point at the same scheme/host/port."""
    return origin_key(a) == origin_key(b)
