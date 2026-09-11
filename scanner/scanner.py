"""Scan orchestrator: wires the HTTP client, crawler and modules together."""

from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

from .crawler import crawl
from .httpclient import GuardBlocked, HttpClient
from .models import CrawlResult, Finding, ScanResult
from .modules import DEFAULT_MODULES, resolve_modules
from .modules.base import ScanContext
from .target import normalize_url

BANNER = r"""
  __      __        .__                                ___________   __
 /  \    /  \ ____ |  |   ____  ______ ___________  /\_   _____/ |__| ____ _____    ____
 \   \/\/   // __ \|  |  /  _ \ \____ \\____ \__  \ \____   __\ |  |/    \\__  \  /    \
  \        /\  ___/|  |_(  <_> )  |_> >  |_> >/ __ \/   |  |   |  |   |  \ / __ \|   |  \
   \__/\  /  \___  >____/\____/|   __/|   __(____  /   |__|   |__|___|  (____  /___|  /
        \/       \/           |__|   |__|       \/                      \/     \/    \/
  v2.3 — authorised security testing only
"""


class ScanConfig:
    def __init__(
        self,
        *,
        modules=None,
        threads: int = 4,
        delay: float = 0.0,
        timeout: float = 10.0,
        depth: int = 2,
        max_pages: int = 30,
        no_crawl: bool = False,
        verify_tls: bool = True,
        allow_private: bool = False,
        user_agent: str | None = None,
        proxy: str | None = None,
        cookies: str | None = None,
        verbose: bool = False,
        time_based: bool = False,
        login_url: str | None = None,
        auth_user: str | None = None,
        auth_pass: str | None = None,
        wordlist: str | None = None,
    ):
        self.modules = list(modules) if modules else None
        self.threads = max(1, int(threads))
        self.delay = max(float(delay), 0.0)
        self.timeout = float(timeout)
        self.depth = max(0, int(depth))
        self.max_pages = max(1, int(max_pages))
        self.no_crawl = bool(no_crawl)
        self.verify_tls = bool(verify_tls)
        self.allow_private = bool(allow_private)
        self.user_agent = user_agent
        self.proxy = proxy
        self.cookies = cookies
        self.verbose = bool(verbose)
        self.time_based = bool(time_based)
        self.login_url = login_url
        self.auth_user = auth_user or ""
        self.auth_pass = auth_pass or ""
        self.wordlist = wordlist


def _parse_cookie_header(cookie_header: str) -> dict:
    cookies = {}
    for part in cookie_header.split(";"):
        if "=" in part:
            name, _, value = part.partition("=")
            cookies[name.strip()] = value.strip()
    return cookies


class Scanner:
    def __init__(self, config: ScanConfig):
        self.config = config

    def run(self, raw_url: str, log=print) -> ScanResult:
        target = normalize_url(raw_url)

        cookie_dict = _parse_cookie_header(self.config.cookies) if self.config.cookies else {}
        client = HttpClient(
            timeout=self.config.timeout,
            delay=self.config.delay,
            verify_tls=self.config.verify_tls,
            allow_private=self.config.allow_private,
            user_agent=self.config.user_agent,
            proxy=self.config.proxy,
            cookies=cookie_dict,
            verbose=self.config.verbose,
        )

        # Fail fast with a clear message when the target itself is blocked.
        try:
            client.guard(target)
        except GuardBlocked as exc:
            raise GuardBlocked(target, exc.host, exc.reason) from None

        result = ScanResult(target=target)
        log(f"[*] Target: {target}")
        if not self.config.allow_private:
            log("[*] Network guard active (private/loopback targets blocked)")

        # authenticated scanning: log in before anything else so every
        # thread-local session inherits the session cookies
        if self.config.login_url:
            from .auth import try_login

            session_cookies = try_login(
                client,
                self.config.login_url,
                self.config.auth_user,
                self.config.auth_pass,
                log=log,
            )
            if session_cookies:
                client.update_shared_cookies(session_cookies)

        started = time.time()
        crawl_result = CrawlResult(entry_url=target)
        crawl_depth = 0 if self.config.no_crawl else self.config.depth
        crawl_max_pages = 1 if self.config.no_crawl else self.config.max_pages
        try:
            crawl_result = crawl(
                client, target,
                max_pages=crawl_max_pages,
                depth=crawl_depth,
                log=log,
            )
        except Exception as exc:  # keep the scan alive; modules handle missing data
            log(f"[!] Crawler crashed: {exc.__class__.__name__}: {exc}")

        requested = self.config.modules or list(DEFAULT_MODULES)
        if self.config.time_based and "timing" not in requested:
            requested.append("timing")
        module_classes = resolve_modules(requested)
        if not module_classes:
            log("[!] No modules selected")

        seen_keys = set()
        findings: list[Finding] = []
        with ThreadPoolExecutor(max_workers=self.config.threads) as executor:
            ctx = ScanContext(
                client=client,
                target=target,
                crawl=crawl_result,
                config={
                    "depth": self.config.depth,
                    "max_pages": self.config.max_pages,
                    "no_crawl": self.config.no_crawl,
                    "wordlist": self.config.wordlist,
                },
                executor=executor,
                log=log,
            )
            ctx.build_attack_points()
            result.attack_points = ctx.attack_point_count

            for module_class in module_classes:
                module = module_class()
                log(f"[*] Module: {module.name}")
                module_started = time.time()
                try:
                    module_findings = module.run(ctx)
                except Exception as exc:
                    log(f"[!] Module '{module.id}' crashed: {exc.__class__.__name__}: {exc}")
                    continue
                elapsed = time.time() - module_started
                log(f"    -> {len(module_findings)} finding(s) in {elapsed:.1f}s")
                result.modules_run.append(module.id)
                for finding in module_findings:
                    if finding.dedup_key in seen_keys:
                        continue
                    seen_keys.add(finding.dedup_key)
                    findings.append(finding)

        result.findings = findings
        result.pages_crawled = len(crawl_result.pages)
        result.stats = client.stats
        result.started_at = started
        result.finished_at = time.time()
        return result
