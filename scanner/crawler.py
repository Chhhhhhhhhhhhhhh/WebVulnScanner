"""Same-host BFS crawler.

Discovers in-scope pages (``<a href>``, ``<script src>``), HTML forms,
paths advertised in ``robots.txt`` Disallow entries and ``sitemap.xml``
locations, and API-ish endpoints embedded in JavaScript sources — the
crawler's job is purely to map the attack surface; vulnerability decisions
belong to the modules.

Pages are fetched **layer by layer in parallel** (``threads`` concurrent
fetches within one BFS depth), while parsing stays on the calling thread.
The shared HttpClient's global rate limiter keeps politeness intact.

Safety details:

* links that look like logout endpoints are never followed (they would
  kill an authenticated session mid-scan);
* JS files are fetched under their own budget and never parsed as HTML;
* everything stays within the starting scheme/host/port.
"""

from __future__ import annotations

import re
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlsplit, urlunsplit

from bs4 import BeautifulSoup

from .httpclient import HttpClient
from .models import CrawlResult, FormSpec, PageData
from .target import same_host

# Extensions that never yield parseable content.
SKIP_EXTENSIONS = {
    ".zip", ".gz", ".tgz", ".tar", ".rar", ".7z",
    ".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg", ".ico", ".bmp",
    ".mp3", ".mp4", ".avi", ".mkv", ".wmv", ".flv",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".exe", ".dll", ".bin", ".iso", ".dmg", ".apk",
    ".woff", ".woff2", ".ttf", ".eot", ".css", ".map",
}

JS_EXTENSIONS = {".js", ".mjs", ".jsx", ".ts"}

# Following these would log the scanner out mid-scan.
LOGOUT_RE = re.compile(r"log[-_]?out|log[-_]?off|sign[-_]?out|sign[-_]?off", re.IGNORECASE)

# Quoted paths inside JS sources/inline scripts that look like endpoints.
JS_ENDPOINT_RE = re.compile(
    r"[\"']((?:/[A-Za-z0-9_\-.%]+){1,6}(?:\?[A-Za-z0-9_\-.%=&]{0,80})?)[\"']"
)
ENDPOINT_JUNK_RE = re.compile(
    r"\.(?:png|jpe?g|gif|svg|css|woff2?|ttf|eot|ico|mp[34]|pdf)$", re.IGNORECASE
)

MAX_PARAM_URLS = 60
MAX_FORMS = 40
MAX_ROBOTS_ENTRIES = 15
MAX_SITEMAP_URLS = 25
MAX_JS_FILES = 15
MAX_JS_ENDPOINTS = 25

DEFAULT_MAX_PAGES = 30
DEFAULT_DEPTH = 2


def canonical(url: str) -> str:
    """Drop the fragment; keep path and query untouched."""
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, parts.query, ""))


def _skippable(url: str) -> bool:
    parts = urlsplit(url)
    path = parts.path.lower()
    return any(path.endswith(ext) for ext in SKIP_EXTENSIONS)


def _is_js(url: str, content_type: str = "") -> bool:
    path = urlsplit(url).path.lower()
    return path.endswith(tuple(JS_EXTENSIONS)) or "javascript" in content_type.lower()


def extract_js_endpoints(text: str) -> list:
    """Pull same-site-looking endpoint paths out of JS source text."""
    endpoints = []
    seen = set()
    for match in JS_ENDPOINT_RE.finditer(text):
        candidate = match.group(1)
        if candidate.startswith("//"):        # protocol-relative → off-site
            continue
        if candidate in seen or ENDPOINT_JUNK_RE.search(candidate):
            continue
        seen.add(candidate)
        endpoints.append(candidate)
        if len(endpoints) >= MAX_JS_ENDPOINTS:
            break
    return endpoints


def extract_forms(soup: BeautifulSoup, base_url: str) -> list:
    """Parse ``<form>`` elements into FormSpec objects."""
    forms = []
    for form in soup.find_all("form"):
        raw_action = str(form.get("action") or "").strip()
        action = urljoin(base_url, raw_action) if raw_action else base_url
        method = str(form.get("method") or "get").lower()
        if method not in ("get", "post"):
            method = "post" if method == "dialog" else "get"

        inputs = []
        for tag in form.find_all(["input", "textarea", "select"]):
            name = str(tag.get("name") or "").strip()
            if not name:
                continue
            if tag.name == "textarea":
                inp_type = "textarea"
            elif tag.name == "select":
                inp_type = "select"
            else:
                inp_type = str(tag.get("type") or "text").lower()
            if inp_type in ("submit", "button", "image", "reset", "file"):
                continue
            inputs.append({
                "name": name,
                "type": inp_type,
                "value": str(tag.get("value") or "").strip(),
            })

        if inputs:
            forms.append(FormSpec(
                action=canonical(action),
                method=method,
                inputs=inputs,
                source_url=base_url,
            ))
    return forms


def _parse_robots(text: str) -> list:
    """Return Disallow paths from a robots.txt body."""
    paths = []
    in_agents = False
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        key, _, value = line.partition(":")
        key = key.strip().lower()
        value = value.strip()
        if key == "user-agent":
            in_agents = value == "*"
        elif key == "disallow" and in_agents and value:
            paths.append(value)
    return paths[:MAX_ROBOTS_ENTRIES]


def _parse_sitemap(text: str) -> tuple:
    """Return (page_urls, nested_sitemap_urls) from sitemap XML."""
    page_urls = re.findall(r"<loc>\s*([^<\s]+)\s*</loc>", text)
    if "<sitemapindex" in text:
        return [], page_urls[:5]        # inner <loc> are sitemaps, not pages
    return page_urls[:MAX_SITEMAP_URLS], []


def crawl(
    client: HttpClient,
    start_url: str,
    *,
    max_pages: int = DEFAULT_MAX_PAGES,
    depth: int = DEFAULT_DEPTH,
    threads: int = 4,
    log=print,
) -> CrawlResult:
    """BFS-crawl ``start_url`` within the same scheme/host/port.

    Pages of one BFS layer are fetched concurrently (up to ``threads``);
    layer N+1 is only queued after layer N completes, preserving depth
    semantics and the page budget.
    """
    result = CrawlResult(entry_url=start_url)
    queue: deque = deque()
    form_signatures: set = set()
    js_budget = MAX_JS_FILES

    def enqueue(url: str, at_depth: int, is_js: bool = False) -> None:
        nonlocal js_budget
        url = canonical(url)
        if url in visited or len(visited) >= max_pages * 6:
            return
        if not same_host(url, start_url):
            return
        if LOGOUT_RE.search(urlsplit(url).path):
            return
        if is_js:
            if js_budget <= 0 or not _is_js(url):
                return
            js_budget -= 1
        elif _skippable(url):
            return
        visited.add(url)
        queue.append((url, at_depth))

    visited = {canonical(start_url)}

    def absorb(page_data: PageData, requested_url: str) -> None:
        """Parse one fetched page on the calling thread."""
        if _is_js(page_data.url, page_data.content_type):
            for endpoint in extract_js_endpoints(page_data.text):
                enqueue(urljoin(page_data.url, endpoint), current_depth + 1)
            return
        if not page_data.is_html:
            return
        for candidate in {canonical(page_data.url), canonical(requested_url)}:
            if urlsplit(candidate).query and candidate not in result.param_urls:
                if len(result.param_urls) < MAX_PARAM_URLS:
                    result.param_urls.append(candidate)
        soup = BeautifulSoup(page_data.text, "html.parser")
        for anchor in soup.find_all("a", href=True):
            href = str(anchor["href"]).strip()
            if not href or href.startswith(("#", "javascript:", "mailto:", "tel:", "data:")):
                continue
            link = urljoin(page_data.url, href)
            if link.lower().startswith(("http://", "https://")):
                enqueue(link, current_depth + 1)
        for tag in soup.find_all(["script", "iframe"], src=True):
            src = str(tag["src"] or "").strip()
            if src:
                enqueue(urljoin(page_data.url, src), current_depth + 1, is_js=True)
        for script in soup.find_all("script", src=False):
            if script.string:
                for endpoint in extract_js_endpoints(str(script.string)):
                    enqueue(urljoin(page_data.url, endpoint), current_depth + 1)
        for form in extract_forms(soup, page_data.url):
            if form.signature not in form_signatures and len(result.forms) < MAX_FORMS:
                form_signatures.add(form.signature)
                result.forms.append(form)

    # the entry URL must be queued FIRST so the BFS deque stays
    # depth-ordered: robots/sitemap items enter at depth 1, after it
    current_depth = 0
    queue.append((canonical(start_url), 0))

    # robots.txt as a discovery source (also recorded for the report)
    origin = f"{urlsplit(start_url).scheme}://{urlsplit(start_url).netloc}"
    robots_url = f"{origin}/robots.txt"
    page = client.get_page(robots_url, cap=64 * 1024)
    if page is not None and page.status == 200 and len(page.body) > 0:
        result.robots_found = True
        for path in _parse_robots(page.body.decode("utf-8", errors="replace")):
            if path and not path.endswith(("*", "$")):
                enqueue(urljoin(start_url, path), 1)

    # sitemap.xml (one level of sitemapindex nesting)
    sitemap_url = f"{origin}/sitemap.xml"
    sitemap = client.get_page(sitemap_url, cap=256 * 1024)
    if sitemap is not None and sitemap.status == 200:
        urls, nested = _parse_sitemap(sitemap.body.decode("utf-8", errors="replace"))
        for loc in urls:
            enqueue(urljoin(start_url, loc), 1)
        for loc in nested:
            inner = client.get_page(urljoin(start_url, loc), cap=256 * 1024)
            if inner is None or inner.status != 200:
                continue
            inner_urls, _ = _parse_sitemap(inner.body.decode("utf-8", errors="replace"))
            for inner_loc in inner_urls:
                enqueue(urljoin(start_url, inner_loc), 1)

    # --- BFS, one layer fetched in parallel at a time --------------------
    with ThreadPoolExecutor(max_workers=max(1, threads)) as executor:
        while queue and len(result.pages) < max_pages:
            # collect the whole current layer (BFS queue is depth-ordered)
            budget = max_pages - len(result.pages)
            batch: list = []
            while queue and queue[0][1] == current_depth and len(batch) < budget:
                batch.append(queue.popleft())
            if not batch:
                if current_depth >= depth:
                    break               # nothing left within the depth limit
                current_depth += 1
                continue
            if current_depth > depth:
                break                   # next layer would exceed --depth

            futures = {executor.submit(client.get_page, url): url for url, _ in batch}
            fetched: list = []
            for future in as_completed(futures):
                url = futures[future]
                resp = future.result()
                if resp is None:
                    continue
                fetched.append((url, PageData(
                    url=resp.url, status=resp.status, headers=resp.headers,
                    body=resp.body, set_cookies=resp.set_cookies,
                )))
            # deterministic order within the layer (matching serial crawl)
            order = {url: i for i, (url, _) in enumerate(batch)}
            fetched.sort(key=lambda pair: order.get(pair[0], len(order)))
            for requested_url, page_data in fetched:
                result.pages.append(page_data)
                if result.entry is None and current_depth == 0:
                    result.entry = page_data

            # parse every fetched page: absorbing issues no requests, so the
            # page budget only caps what we fetch, never what we parse
            for requested_url, page_data in fetched:
                absorb(page_data, requested_url)

            current_depth += 1

    log(f"[*] Crawl finished: {len(result.pages)} page(s), "
        f"{len(result.param_urls)} parameterised URL(s), {len(result.forms)} form(s)")
    return result
