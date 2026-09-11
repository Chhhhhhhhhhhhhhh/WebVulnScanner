"""Module infrastructure: scan context, attack points and shared helpers."""

from __future__ import annotations

from concurrent.futures import as_completed
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from bs4 import BeautifulSoup

from ..crawler import CrawlResult, extract_forms
from ..httpclient import HttpClient
from ..models import PageData

# Input names that look like anti-CSRF tokens: testing them only wastes
# requests and can invalidate sessions.
CSRF_NAME_HINTS = ("csrf", "token", "xsrf", "authenticity")


@dataclass
class AttackPoint:
    """One testable parameter: a URL query parameter or a form field."""

    url: str              # GET: URL without query string; POST: form action
    method: str           # "GET" | "POST"
    params: dict          # baseline values for every parameter
    param: str            # the parameter under test
    origin: str = ""      # page the surface was found on

    def with_value(self, value: str) -> dict:
        merged = dict(self.params)
        merged[self.param] = value
        return merged

    def full_url(self) -> str:
        """Reconstructed URL with current baseline values (for logging)."""
        if self.method != "GET":
            return self.url
        parts = urlsplit(self.url)
        return urlunsplit(
            (parts.scheme, parts.netloc, parts.path, urlencode(self.params), "")
        )

    @property
    def csrf_fields(self) -> list:
        """Parameter names that look like anti-CSRF tokens."""
        return [n for n in self.params if any(h in n.lower() for h in CSRF_NAME_HINTS)]


@dataclass
class ScanContext:
    client: HttpClient
    target: str
    crawl: CrawlResult
    config: dict = field(default_factory=dict)
    executor: Any = None
    log: Any = print
    attack_point_count: int = 0

    # ------------------------------------------------------------------
    def submit(self, fn, *args, **kwargs):
        return self.executor.submit(fn, *args, **kwargs)

    def gather(self, futures: dict) -> list:
        """Collect findings from {future: attack_point}, logging failures."""
        findings = []
        for future in as_completed(futures):
            point = futures[future]
            try:
                findings.extend(future.result())
            except Exception as exc:  # keep scanning whatever happens
                self.log(f"[!] {point.method} {point.full_url()} "
                         f"test crashed: {exc.__class__.__name__}: {exc}")
        return findings

    # ------------------------------------------------------------------
    def build_attack_points(self) -> list:
        """Combine parameterised URLs and parsed forms into attack points."""
        from ..target import same_host

        points: list[AttackPoint] = []
        seen = set()

        def add(point: AttackPoint) -> None:
            key = (point.method, point.url, point.param)
            if key in seen:
                return
            seen.add(key)
            points.append(point)

        for url in [self.crawl.entry_url] + list(self.crawl.param_urls):
            if not same_host(url, self.target):
                continue
            parts = urlsplit(url)
            if not parts.query:
                continue
            params = dict(parse_qsl(parts.query, keep_blank_values=True))
            base = urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))
            for name in params:
                add(AttackPoint(
                    url=base, method="GET", params=params,
                    param=name, origin=url,
                ))

        for form in self.crawl.forms:
            if not same_host(form.action, self.target):
                continue
            params = {i["name"]: i["value"] for i in form.inputs}
            for inp in form.inputs:
                if inp["type"] == "hidden" and any(
                    hint in inp["name"].lower() for hint in CSRF_NAME_HINTS
                ):
                    continue
                add(AttackPoint(
                    url=form.action, method=form.method.upper(),
                    params=params, param=inp["name"],
                    origin=form.source_url,
                ))

        self.attack_point_count = len(points)
        return points

    # ------------------------------------------------------------------
    def refresh_form_values(self, point: AttackPoint) -> dict | None:
        """Re-fetch the page a POST form came from and return a fresh copy
        of the form's baseline values (CSRF tokens are often single-use, so
        values captured at crawl time go stale during testing)."""
        page = self.client.get_page(point.origin)
        if page is None:
            return None
        # reuse PageData's charset-aware decoding of the raw body
        html = PageData(page.url, page.status, page.headers,
                        page.body, page.set_cookies).text
        try:
            soup = BeautifulSoup(html, "html.parser")
        except Exception:
            return None
        for form in extract_forms(soup, page.url):
            if form.action == point.url and form.method == point.method.lower():
                fresh = {i["name"]: i["value"] for i in form.inputs}
                merged = dict(point.params)
                merged.update({k: v for k, v in fresh.items() if k in merged})
                return merged
        return None

    def send(self, point: AttackPoint, value: str):
        """Submit one probe value for an attack point; response or None.

        POST points carrying CSRF-ish fields get a fresh form fetch per
        probe so single-use tokens stay valid."""
        if point.method == "POST":
            data = point.with_value(value)
            if point.csrf_fields and point.origin:
                fresh = self.refresh_form_values(point)
                if fresh is not None:
                    fresh[point.param] = value
                    data = fresh
            return self.client.request("POST", point.url, data=data)
        return self.client.request("GET", point.url, params=point.with_value(value))


class BaseModule:
    id: str = ""
    name: str = ""

    def run(self, ctx: ScanContext) -> list:
        raise NotImplementedError


class VulnModule(BaseModule):
    """Base class for parameter-oriented vulnerability modules.

    Subclasses implement ``test_point``; probes for a single parameter run
    in order (differential logic depends on it), different parameters are
    tested in parallel through the shared executor.
    """

    def run(self, ctx: ScanContext) -> list:
        points = ctx.build_attack_points()
        if not points:
            ctx.log(f"[*] {self.name}: no parameters found, skipping")
            return []
        ctx.log(f"[*] {self.name}: testing {len(points)} parameter(s)")
        futures = {}
        for point in points:
            futures[ctx.submit(self.test_point, ctx, point)] = point
        return ctx.gather(futures)

    def test_point(self, ctx: ScanContext, point: AttackPoint) -> list:
        raise NotImplementedError


def strip_echo(text: str, payload: str) -> str:
    """Remove occurrences of the payload (raw / HTML-escaped / URL-encoded /
    entity-encoded) from a response body, so a merely echoed parameter cannot
    be mistaken for command output."""
    import html as _html
    from urllib.parse import quote

    variants = {payload, _html.escape(payload, quote=True), quote(payload)}
    cleaned = text
    for variant in variants:
        if variant:
            cleaned = cleaned.replace(variant, "")
    # handle pages that entity-encode the echo (&#96; style)
    entity_free = _html.unescape(cleaned)
    for variant in variants:
        if variant:
            entity_free = entity_free.replace(variant, "")
    return entity_free


def snippet(text: str, needle: str, width: int = 60) -> str:
    """Return a short context excerpt around the first match of needle."""
    idx = text.find(needle)
    if idx < 0:
        return needle
    start = max(idx - width // 2, 0)
    end = min(idx + len(needle) + width, len(text))
    excerpt = text[start:end].replace("\r", " ").replace("\n", " ")
    return f"...{excerpt}..."


def response_text(resp, limit: int = 2 * 1024 * 1024) -> str:
    if resp is None:
        return ""
    try:
        return resp.text[:limit]
    except Exception:
        return ""
