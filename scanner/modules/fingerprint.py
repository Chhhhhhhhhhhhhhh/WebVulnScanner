"""Passive technology fingerprinting: server, languages, CMS, WAF/CDN.

Purely informational findings (severity=info) — they feed the report's
context rather than the vulnerability count.
"""

from __future__ import annotations

import re

from .base import BaseModule, ScanContext
from ..models import Finding

CMS_SIGNATURES = {
    "WordPress": [r"wp-content", r"wp-includes", r"/wp-json/"],
    "Drupal": [r"drupal", r"sites/all/themes", r"sites/default/files"],
    "Joomla": [r"/media/jui/", r"joomla"],
    "Laravel": [r"laravel_session", r"xsrf-laravel"],
    "Django": [r"csrfmiddlewaretoken"],
    "Flask": [r"werkzeug"],
    "Spring Boot": [r"x-application-context", r"Whitelabel Error Page"],
    "ASP.NET": [r"__VIEWSTATE", r"asp-net"],
    "React/Next.js": [r"__next", r"_next/static", r"react"],
    "Vue.js": [r"data-v-[0-9a-f]", r"vue", r"nuxt"],
    "jQuery": [r"jquery[.-]"],
    "Bootstrap": [r"bootstrap(\.min)?\.(css|js)"],
}

COOKIE_TECH = {
    "phpsessid": "PHP",
    "jsessionid": "Java",
    "asp.net_sessionid": "ASP.NET",
    "laravel_session": "Laravel",
    "ci_session": "CodeIgniter",
    "rack.session": "Ruby (Rack)",
    "connect.sid": "Node.js (Express)",
    "_session_id": "Rails",
}

WAF_SIGNATURES = {
    "Cloudflare": [r"cf-ray", r"cloudflare", r"__cfduid"],
    "AWS WAF / CloudFront": [r"x-amz-cf-id", r"awswaf", r"cloudfront"],
    "Akamai": [r"akamai", r"x-akamai-transformed"],
    "Alibaba Cloud WAF": [r"aliyun", r"acs-sc"],
    "Tencent Cloud WAF": [r"qwaf", r"waf-tencent"],
    "ModSecurity": [r"mod_security", r"modsecurity"],
    "F5 BIG-IP ASM": [r"ts=[0-9a-f]{20,}", r"bigipserver"],
    "Imperva": [r"incapsula", r"visid_incap"],
    "Sucuri": [r"sucuri", r"cloudproxy"],
}


def _match_any(signatures: dict, haystacks: list) -> list:
    hits = []
    for name, patterns in signatures.items():
        for pattern in patterns:
            if any(re.search(pattern, h, re.IGNORECASE) for h in haystacks if h):
                hits.append(name)
                break
    return hits


class FingerprintModule(BaseModule):
    id = "fingerprint"
    name = "Technology fingerprint"

    def run(self, ctx: ScanContext) -> list:
        pages = [p for p in ctx.crawl.pages if p.is_html][:20]
        if not pages:
            pages = [p for p in ctx.crawl.pages if p.status] or []
        entry = ctx.crawl.entry
        if entry is None:
            ctx.log(f"[!] {self.name}: nothing crawled, skipping")
            return []

        headers = entry.headers
        header_blob = "\n".join(f"{k}: {v}" for k, v in headers.items())
        body_blobs = [p.text for p in pages]

        findings: list[Finding] = []
        base_url = entry.url

        server = headers.get("Server", "")
        if server:
            findings.append(Finding(
                module=self.id, check_id="fingerprint.server",
                severity="info", title=f"Web server: {server}",
                description="Server header reported by the target.",
                evidence=f"Server: {server}", url=base_url,
            ))
        powered = headers.get("X-Powered-By", "")
        if powered:
            findings.append(Finding(
                module=self.id, check_id="fingerprint.powered_by",
                severity="info", title=f"Runtime: {powered}",
                description="X-Powered-By header reported by the target.",
                evidence=f"X-Powered-By: {powered}", url=base_url,
            ))

        cms = _match_any(CMS_SIGNATURES, body_blobs + [header_blob])
        if cms:
            findings.append(Finding(
                module=self.id, check_id="fingerprint.cms",
                severity="info",
                title="Detected frameworks / libraries: " + ", ".join(cms),
                description="Signatures matched in crawled HTML and headers.",
                evidence=", ".join(cms), url=base_url,
            ))

        cookie_blob = "\n".join(entry.set_cookies)
        tech = _match_any({k: [re.escape(k)] for k in COOKIE_TECH}, [cookie_blob.lower()])
        tech_names = sorted({COOKIE_TECH[t] for t in tech})
        if tech_names:
            findings.append(Finding(
                module=self.id, check_id="fingerprint.language",
                severity="info",
                title="Backend language (from cookies): " + ", ".join(tech_names),
                description="Session cookie names reveal the server-side stack.",
                evidence=", ".join(tech_names), url=base_url,
            ))

        waf = _match_any(WAF_SIGNATURES, [header_blob] + body_blobs[:3])
        for name in waf:
            findings.append(Finding(
                module=self.id, check_id="fingerprint.waf",
                severity="info", title=f"WAF / CDN detected: {name}",
                description="A web application firewall or CDN is in front of the target; "
                            "active checks may be filtered or rate-limited.",
                evidence=name, url=base_url,
            ))

        if ctx.crawl.robots_found:
            findings.append(Finding(
                module=self.id, check_id="fingerprint.robots",
                severity="info", title="robots.txt is present",
                description="robots.txt was fetched successfully; its Disallow entries were "
                            "used as additional crawl paths.",
                url=base_url,
            ))

        return findings
