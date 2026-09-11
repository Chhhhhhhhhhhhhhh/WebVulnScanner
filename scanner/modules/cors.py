"""CORS misconfiguration detection (CWE-942).

Sends a fictional cross-origin request (``Origin: https://evil.example``,
a reserved documentation TLD) to sampled pages and classifies:

* reflected arbitrary origin + ``Allow-Credentials: true`` → high
  (any website can read authenticated responses);
* reflected arbitrary origin → medium;
* wildcard ``*`` → low (public data, but worth reviewing).
"""

from __future__ import annotations

from .base import BaseModule, ScanContext
from ..models import Finding

PROBE_ORIGIN = "https://evil.example"
MAX_URLS_PROBED = 20


class CorsModule(BaseModule):
    id = "cors"
    name = "CORS policy"

    def run(self, ctx: ScanContext) -> list:
        urls = []
        seen = set()
        candidates = [ctx.crawl.entry_url] + [p.url for p in ctx.crawl.pages]
        for url in candidates:
            if url not in seen:
                seen.add(url)
                urls.append(url)
        urls = urls[:MAX_URLS_PROBED]
        if not urls:
            return []

        reflected, wildcard = [], []
        for url in urls:
            resp = ctx.client.request("GET", url, headers={"Origin": PROBE_ORIGIN},
                                      follow=False)
            if resp is None:
                continue
            allow_origin = resp.headers.get("Access-Control-Allow-Origin", "").strip()
            allow_creds = resp.headers.get("Access-Control-Allow-Credentials", "").strip().lower() == "true"
            if allow_origin == PROBE_ORIGIN:
                reflected.append((url, allow_creds))
            elif allow_origin == "*" and resp.status_code == 200:
                wildcard.append(url)

        findings: list[Finding] = []
        if reflected:
            cred_urls = [u for u, c in reflected if c]
            plain_urls = [u for u, c in reflected if not c]
            shown = ", ".join(u for u, _ in reflected[:4])
            more = "" if len(reflected) <= 4 else f" (+{len(reflected) - 4} more)"
            findings.append(Finding(
                module=self.id,
                check_id="cors.reflect",
                severity="high" if cred_urls else "medium",
                title="CORS reflects arbitrary origins" + (" with credentials" if cred_urls else ""),
                description=("The Access-Control-Allow-Origin header echoes any supplied Origin. "
                             "An attacker page can read these responses cross-origin"
                             + (", including authenticated content, because Allow-Credentials is true"
                                if cred_urls else "")
                             + f". Affected: {shown}{more}"),
                fix="Never reflect the request Origin. Return a fixed allow-list of trusted "
                    "origins, and keep Access-Control-Allow-Credentials off for anything broader.",
                cwe="CWE-942",
                url=ctx.crawl.entry_url,
                evidence=f"Probe Origin {PROBE_ORIGIN} reflected on {len(reflected)} URL(s): "
                         + "; ".join(cred_urls or plain_urls)[:300],
            ))
        if wildcard:
            shown = ", ".join(wildcard[:4])
            more = "" if len(wildcard) <= 4 else f" (+{len(wildcard) - 4} more)"
            findings.append(Finding(
                module=self.id,
                check_id="cors.wildcard",
                severity="low",
                title="Permissive CORS wildcard (*)",
                description=f"These responses are readable from any origin: {shown}{more}. "
                            "Acceptable for public assets; a problem if any of them carry "
                            "user-specific data.",
                fix="Replace the wildcard with an explicit origin allow-list.",
                cwe="CWE-942",
                url=ctx.crawl.entry_url,
                evidence=shown,
            ))
        return findings
