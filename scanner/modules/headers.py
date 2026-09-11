"""HTTP security header and cookie-attribute checks.

Checks are aggregated across every crawled page (not just the entry
page): API endpoints and sub-pages frequently ship different header
configurations. Each finding lists where it was observed.

Note: X-XSS-Protection is deprecated and disabled in modern browsers, so
its absence is *not* reported (a common false positive in v1-era scanners).
"""

from __future__ import annotations

from .base import BaseModule, ScanContext
from ..models import Finding

HEADER_CHECKS = [
    # header, severity, why it matters, fix
    ("Content-Security-Policy", "medium",
     "Content-Security-Policy restricts which resources a page may load and is the strongest defence against content injection (XSS).",
     "Add a restrictive Content-Security-Policy header, e.g. \"default-src 'self'\"."),
    ("Strict-Transport-Security", "medium",
     "HSTS forces browsers to use HTTPS for future visits, preventing protocol downgrade and cookie theft over plain HTTP.",
     "Add \"Strict-Transport-Security: max-age=31536000; includeSubDomains\" (HTTPS only)."),
    ("X-Frame-Options", "medium",
     "Prevents the page from being embedded in an iframe on another origin (clickjacking).",
     "Add \"X-Frame-Options: DENY\" or \"SAMEORIGIN\", or a CSP frame-ancestors directive."),
    ("X-Content-Type-Options", "low",
     "Stops browsers from MIME-sniffing a response away from its declared Content-Type.",
     "Add \"X-Content-Type-Options: nosniff\"."),
    ("Referrer-Policy", "low",
     "Controls how much referrer information leaks to third-party sites.",
     "Add \"Referrer-Policy: strict-origin-when-cross-origin\" or \"no-referrer\"."),
    ("Permissions-Policy", "low",
     "Restricts access to powerful browser features (camera, geolocation, microphone...).",
     "Add a Permissions-Policy header allowing only the features the site uses."),
]

SERVER_VERSION_HINTS = ("apache/", "nginx/", "iis/", "tomcat/", "jetty", "php/", "openresty/", "lighttpd/")

MAX_PAGES_SAMPLED = 10


def _cookie_attrs(set_cookie: str) -> tuple:
    """Return (name, has_httponly, has_secure, has_samesite) for one Set-Cookie line."""
    parts = [p.strip() for p in set_cookie.split(";")]
    name = parts[0].split("=", 1)[0] if parts else ""
    lowered = {p.lower() for p in parts[1:]}
    has_httponly = any(p == "httponly" for p in lowered)
    has_secure = any(p == "secure" for p in lowered)
    has_samesite = any(p.startswith("samesite") for p in lowered)
    return name, has_httponly, has_secure, has_samesite


class HeadersModule(BaseModule):
    id = "headers"
    name = "HTTP security headers"

    def run(self, ctx: ScanContext) -> list:
        entry = ctx.crawl.entry
        if entry is None:
            ctx.log(f"[!] {self.name}: entry page was not fetched, skipping")
            return []

        pages = [p for p in ctx.crawl.pages if p.is_html][:MAX_PAGES_SAMPLED]
        if not pages or pages[0].url != entry.url:
            pages = [entry] + [p for p in pages if p.url != entry.url]
        sample_urls = [p.url for p in pages]

        findings: list[Finding] = []
        is_https = entry.url.lower().startswith("https://")
        base_url = entry.url

        def page_evidence(missing_urls: list) -> str:
            shown = ", ".join(missing_urls[:3])
            more = "" if len(missing_urls) <= 3 else f" (+{len(missing_urls) - 3} more)"
            return f"Missing on {len(missing_urls)}/{len(sample_urls)} sampled pages: {shown}{more}"

        for header, severity, description, fix in HEADER_CHECKS:
            if header == "Strict-Transport-Security" and not is_https:
                # HSTS is only meaningful over HTTPS; plain HTTP gets the
                # "HTTPS not enforced" finding below instead.
                continue
            missing_urls = [p.url for p in pages if not p.headers.get(header)]
            if not missing_urls:
                continue
            if header == "X-Frame-Options":
                # XFO missing is acceptable when *every* sampled page
                # carries a CSP frame-ancestors directive.
                if all("frame-ancestors" in (p.headers.get("Content-Security-Policy") or "")
                       for p in pages):
                    continue
            findings.append(Finding(
                module=self.id,
                check_id=f"headers.missing.{header.lower()}",
                severity=severity,
                title=f"Missing security header: {header}",
                description=description,
                fix=fix,
                cwe="CWE-693",
                url=base_url,
                evidence=page_evidence(missing_urls),
            ))

        # HTTPS enforcement (entry-based: scheme + redirect chain)
        if not is_https:
            findings.append(Finding(
                module=self.id,
                check_id="headers.no_https",
                severity="low",
                title="HTTPS not enforced",
                description="The target serves plain HTTP and did not redirect to HTTPS. Credentials and session cookies can be intercepted in transit.",
                fix="Redirect all HTTP traffic to HTTPS and enable HSTS.",
                cwe="CWE-319",
                url=base_url,
                evidence=f"Final response URL after redirects: {entry.url}",
            ))

        # Detailed server version disclosure (any sampled page)
        disclosed: dict = {}
        for page in pages:
            server = page.headers.get("Server", "")
            if server and any(hint in server.lower() for hint in SERVER_VERSION_HINTS):
                disclosed.setdefault(server, page.url)
        if disclosed:
            values = "; ".join(f"{v} (on {u})" for v, u in list(disclosed.items())[:3])
            findings.append(Finding(
                module=self.id,
                check_id="headers.server_version",
                severity="low",
                title="Server version disclosed",
                description="The Server header reveals the server software and version, helping attackers pick matching exploits.",
                fix="Suppress version details (nginx: server_tokens off; Apache: ServerTokens Prod).",
                cwe="CWE-200",
                url=base_url,
                evidence=values,
            ))

        # Cookie flags, aggregated across every sampled page
        no_httponly, no_secure, no_samesite = [], [], []
        seen_cookie_lines = set()
        for page in pages:
            is_page_https = page.url.lower().startswith("https://")
            for line in page.set_cookies:
                if line in seen_cookie_lines or "=" not in line:
                    continue
                seen_cookie_lines.add(line)
                name, has_httponly, has_secure, has_samesite = _cookie_attrs(line)
                if not name:
                    continue
                if not has_httponly:
                    no_httponly.append(name)
                if not has_secure and (is_https or is_page_https):
                    no_secure.append(name)
                if not has_samesite:
                    no_samesite.append(name)

        if no_httponly:
            unique = sorted(set(no_httponly))
            findings.append(Finding(
                module=self.id,
                check_id="headers.cookie_httponly",
                severity="medium",
                title=f"Cookie without HttpOnly ({len(unique)})",
                description="These cookies are readable by JavaScript, so any XSS can steal them: "
                            + ", ".join(unique[:10]),
                fix="Set the HttpOnly attribute on session cookies.",
                cwe="CWE-1004",
                url=base_url,
                evidence="; ".join(unique[:10]),
            ))
        if no_secure:
            unique = sorted(set(no_secure))
            findings.append(Finding(
                module=self.id,
                check_id="headers.cookie_secure",
                severity="medium",
                title=f"Cookie without Secure ({len(unique)})",
                description="These cookies may be transmitted over plain HTTP on an HTTPS site: "
                            + ", ".join(unique[:10]),
                fix="Set the Secure attribute on all cookies.",
                cwe="CWE-614",
                url=base_url,
                evidence="; ".join(unique[:10]),
            ))
        if no_samesite:
            unique = sorted(set(no_samesite))
            findings.append(Finding(
                module=self.id,
                check_id="headers.cookie_samesite",
                severity="low",
                title=f"Cookie without SameSite ({len(unique)})",
                description="Without a SameSite attribute these cookies accompany cross-site requests, enabling CSRF: "
                            + ", ".join(unique[:10]),
                fix="Set SameSite=Lax (or Strict) on cookies.",
                cwe="CWE-352",
                url=base_url,
                evidence="; ".join(unique[:10]),
            ))

        return findings
