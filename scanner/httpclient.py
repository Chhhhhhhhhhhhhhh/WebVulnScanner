"""Thread-safe HTTP client for the scanner.

Design notes:

* One ``requests.Session`` per thread (Session is not documented as
  thread-safe); cookies persist per worker thread. Cookies captured at
  construction (or via ``update_shared_cookies`` after login) are applied
  to every session as it is created.
* Redirects are followed manually so that **every hop** passes the
  network guard.  This closes the classic SSRF bypass where
  ``http://public.example/redirect`` forwards to ``http://127.0.0.1/``.
* The guard resolves DNS and blocks loopback / private / link-local /
  reserved / multicast targets unless ``allow_private`` is set (intended
  for lab targets such as a local DVWA instance).
* All requests go through a global rate limiter (``delay``) and are
  counted in ``stats``. 429/503 responses trigger adaptive backoff.
* ``get_page`` reads at most ``cap`` bytes so a huge "backup.sql" cannot
  drag the scanner into memory exhaustion.
"""

from __future__ import annotations

import ipaddress
import socket
import threading
import time
from dataclasses import dataclass

import requests

from .models import RequestStats

DEFAULT_USER_AGENT = "Mozilla/5.0 (compatible; WebVulnScanner/2.0; +authorized-testing)"

# Adaptive backoff: when the target answers 429/503 we honour Retry-After
# (capped), slow the global pace, and retry idempotent requests a couple of
# times before giving up and handing the throttled response to the caller.
THROTTLE_STATUSES = (429, 503)
MAX_BACKOFF_RETRIES = 2
MAX_BACKOFF_SLEEP = 30.0
ADAPTIVE_DELAY_CEILING = 5.0


class GuardBlocked(Exception):
    """Raised when a URL resolves to a blocked address."""

    def __init__(self, url: str, host: str, reason: str):
        super().__init__(f"{host}: {reason}")
        self.url = url
        self.host = host
        self.reason = reason


def ip_block_reason(ip_text: str) -> str | None:
    """Return a reason string when the IP must not be scanned, else None."""
    try:
        ip = ipaddress.ip_address(ip_text)
    except ValueError:
        return "invalid address"
    if ip.is_loopback:
        return "loopback address"
    if ip.is_private:
        return "private address"
    if ip.is_link_local:
        return "link-local address"
    if ip.is_reserved:
        return "reserved address"
    if ip.is_multicast:
        return "multicast address"
    if ip.is_unspecified:
        return "unspecified address"
    return None


@dataclass
class PageResponse:
    """Capped response payload used across crawler and modules."""

    url: str                 # final URL after redirects
    status: int
    headers: dict
    body: bytes
    set_cookies: list


class HttpClient:
    def __init__(
        self,
        *,
        timeout: float = 10.0,
        delay: float = 0.0,
        verify_tls: bool = True,
        user_agent: str | None = None,
        proxy: str | None = None,
        cookies: dict | None = None,
        allow_private: bool = False,
        follow_redirects: bool = True,
        max_redirects: int = 5,
        verbose: bool = False,
    ):
        self.timeout = timeout
        self.delay = max(float(delay), 0.0)
        self.adaptive_delay = self.delay   # grows when the target throttles us
        self.verify_tls = verify_tls
        self.user_agent = user_agent or DEFAULT_USER_AGENT
        self.proxy = proxy
        self.cookies = cookies or {}
        self.allow_private = allow_private
        self.follow_redirects = follow_redirects
        self.max_redirects = max_redirects
        self.verbose = verbose

        if not verify_tls:
            try:
                import urllib3

                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            except Exception:  # pragma: no cover - defensive
                pass

        self.stats = RequestStats()
        self._local = threading.local()
        self._rl_lock = threading.Lock()
        self._last_sent = 0.0
        self._resolve_lock = threading.Lock()
        self._resolve_cache: dict[str, tuple[bool, str | None]] = {}
        self._warned_hosts: set[str] = set()
        self._warn_lock = threading.Lock()

    # ------------------------------------------------------------------
    # sessions
    # ------------------------------------------------------------------
    def update_shared_cookies(self, cookies: dict) -> None:
        """Merge cookies into the shared baseline and rebuild sessions.

        Call before any worker threads exist (e.g. right after login):
        thread-local sessions are created lazily, so sessions spun up
        afterwards inherit the updated cookie jar automatically."""
        self.cookies.update(cookies)
        self._local = threading.local()   # drop already-built sessions

    def _session(self) -> requests.Session:
        session = getattr(self._local, "session", None)
        if session is None:
            session = requests.Session()
            session.headers.update({
                "User-Agent": self.user_agent,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en",
            })
            session.verify = self.verify_tls
            if self.proxy:
                session.proxies = {"http": self.proxy, "https": self.proxy}
            if self.cookies:
                session.cookies.update(self.cookies)
            self._local.session = session
        return session

    # ------------------------------------------------------------------
    # network guard
    # ------------------------------------------------------------------
    def guard(self, url: str) -> None:
        """Raise GuardBlocked when ``url`` points at a blocked destination."""
        from urllib.parse import urlsplit

        parts = urlsplit(url)
        if parts.scheme.lower() not in ("http", "https"):
            raise GuardBlocked(url, parts.netloc, f"unsupported scheme {parts.scheme!r}")
        host = (parts.hostname or "").lower()
        if not host:
            raise GuardBlocked(url, url, "URL has no host")

        cached = self._resolve_cache.get(host)
        if cached is None:
            try:
                infos = socket.getaddrinfo(host, None)
            except OSError as exc:
                cached = (False, f"DNS resolution failed ({exc.__class__.__name__})")
            else:
                reason = None
                for info in infos:
                    addr = str(info[4][0])
                    r = ip_block_reason(addr)
                    if r and not self.allow_private:
                        reason = f"{r} ({addr})"
                        break
                cached = (reason is None, reason)
            with self._resolve_lock:
                self._resolve_cache.setdefault(host, cached)
        ok, reason = self._resolve_cache[host]
        if not ok:
            raise GuardBlocked(url, host, reason or "blocked")

    def _warn_blocked_once(self, exc: GuardBlocked) -> None:
        with self._warn_lock:
            if exc.host in self._warned_hosts:
                return
            self._warned_hosts.add(exc.host)
        self._log(f"[guard] blocked {exc.host}: {exc.reason}")

    # ------------------------------------------------------------------
    # rate limiting / logging
    # ------------------------------------------------------------------
    def _throttle(self) -> None:
        if self.adaptive_delay <= 0:
            return
        with self._rl_lock:
            wait = self.adaptive_delay - (time.monotonic() - self._last_sent)
            if wait > 0:
                time.sleep(wait)
            self._last_sent = time.monotonic()

    def _retry_after_seconds(self, resp) -> float:
        value = (resp.headers.get("Retry-After") or "").strip()
        if value:
            try:
                return max(float(value), 0.0)
            except ValueError:
                try:  # HTTP-date form
                    from datetime import datetime, timezone
                    from email.utils import parsedate_to_datetime

                    when = parsedate_to_datetime(value)
                    if when.tzinfo is None:
                        when = when.replace(tzinfo=timezone.utc)
                    return max((when - datetime.now(timezone.utc)).total_seconds(), 0.0)
                except Exception:
                    pass
        return 1.0  # no header: assume a modest pause

    def _bump_adaptive_delay(self) -> None:
        ceiling = max(ADAPTIVE_DELAY_CEILING, self.delay * 4)
        with self._rl_lock:
            grown = max(self.adaptive_delay * 2, self.adaptive_delay + 0.5)
            self.adaptive_delay = min(grown, ceiling)

    def _log(self, message: str) -> None:
        if self.verbose:
            print(f"    {message}")

    # ------------------------------------------------------------------
    # requests
    # ------------------------------------------------------------------
    def request(
        self,
        method: str,
        url: str,
        *,
        params: dict | None = None,
        data: dict | str | bytes | None = None,
        headers: dict | None = None,
        follow: bool | None = None,
        stream: bool = False,
        retries: int = 0,
    ) -> requests.Response | None:
        """Perform a request, following redirects manually with per-hop guard.

        Returns ``None`` on network errors or guard blocks (so probe code
        stays simple); guards are additionally logged once per host.
        """
        from urllib.parse import urljoin

        method = method.upper()
        follow = self.follow_redirects if follow is None else follow
        retries = max(retries, 0) if method in ("GET", "HEAD") else 0

        current = url
        send_data = data
        attempt = 0
        hops = 0
        backoffs = 0
        while True:
            try:
                self.guard(current)
            except GuardBlocked as exc:
                self.stats.blocked += 1
                self._warn_blocked_once(exc)
                return None

            self._throttle()
            try:
                resp = self._session().request(
                    method, current,
                    params=params if hops == 0 else None,
                    data=send_data,
                    headers=headers,
                    allow_redirects=False,
                    timeout=self.timeout,
                    stream=stream,
                )
            except requests.RequestException as exc:
                self.stats.errors += 1
                if attempt < retries:
                    attempt += 1
                    time.sleep(0.5 * attempt)
                    continue
                self._log(f"[net] {method} {current} failed: {exc.__class__.__name__}")
                return None

            self.stats.requests += 1

            if (
                resp.status_code in THROTTLE_STATUSES
                and method in ("GET", "HEAD")
                and backoffs < MAX_BACKOFF_RETRIES
            ):
                backoffs += 1
                self.stats.rate_limited += 1
                wait = min(self._retry_after_seconds(resp), MAX_BACKOFF_SLEEP)
                self._bump_adaptive_delay()
                self._log(f"[throttle] {resp.status_code} on {current}; "
                          f"backing off {wait:.1f}s (pace now {self.adaptive_delay:.2f}s)")
                time.sleep(wait)
                continue

            if follow and resp.is_redirect:
                location = resp.headers.get("Location", "")
                if not location or hops >= self.max_redirects:
                    return resp
                if stream:
                    try:
                        resp.close()
                    except Exception:  # pragma: no cover
                        pass
                if resp.status_code in (301, 302, 303) and method == "POST":
                    method, send_data, params = "GET", None, None
                current = urljoin(current, location)
                self.stats.redirects += 1
                hops += 1
                continue

            return resp

    def get_page(
        self,
        url: str,
        *,
        cap: int = 1024 * 1024,
        follow: bool | None = None,
    ) -> PageResponse | None:
        """GET a URL and read at most ``cap`` bytes of the body."""
        resp = self.request("GET", url, follow=follow, stream=True)
        if resp is None:
            return None
        chunks: list[bytes] = []
        total = 0
        try:
            for chunk in resp.iter_content(chunk_size=8192):
                if not chunk:
                    continue
                chunks.append(chunk)
                total += len(chunk)
                if total >= cap:
                    break
        except requests.RequestException:
            self.stats.errors += 1
            return None
        finally:
            try:
                resp.close()
            except Exception:  # pragma: no cover
                pass
        try:
            set_cookies = resp.raw.headers.getlist("Set-Cookie")
        except Exception:  # pragma: no cover - header type differs across versions
            set_cookies = []
        return PageResponse(
            url=resp.url or url,
            status=resp.status_code,
            headers=dict(resp.headers),
            body=b"".join(chunks),
            set_cookies=set_cookies,
        )
