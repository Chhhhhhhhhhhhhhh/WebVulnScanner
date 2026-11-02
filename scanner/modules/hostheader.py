"""Host header injection detection (CWE-644 / CWE-807).

Many apps trust the ``Host`` header when building absolute URLs (password
reset links, canonical tags, OAuth redirects). The module re-requests the
entry page with ``Host: evil.<original-tld-replaced>``-style attacker
value and reports when the value is reflected into the page body or a
``Location`` header — the primitive behind cache poisoning and
account-takeover-via-reset-mail chains.

The probe keeps the original port so the request still reaches the same
listener, and uses the reserved ``evil.example`` documentation domain.
"""

from __future__ import annotations

from urllib.parse import urlsplit

from .base import BaseModule, ScanContext
from ..models import Finding

ATTACK_HOST = "evil.example"


class HostHeaderModule(BaseModule):
    id = "hostheader"
    name = "Host header injection"

    MAX_URLS = 6

    def run(self, ctx: ScanContext) -> list:
        if ctx.crawl.entry is None:
            return []

        # the reflection typically lives on specific routes (canonical tags,
        # reset pages), so probe the entry plus a sample of crawled pages
        candidates = [ctx.crawl.entry_url]
        seen = {ctx.crawl.entry_url}
        for page in ctx.crawl.pages:
            if page.is_html and page.url not in seen:
                seen.add(page.url)
                candidates.append(page.url)
        candidates = candidates[: self.MAX_URLS]

        for base in candidates:
            finding = self._probe(ctx, base)
            if finding is not None:
                return [finding]
        return []

    def _probe(self, ctx: ScanContext, base: str) -> Finding | None:
        parts = urlsplit(base)
        port = parts.port
        spoofed = f"{ATTACK_HOST}:{port}" if port else ATTACK_HOST

        resp = ctx.client.request("GET", base, headers={"Host": spoofed},
                                  follow=False)
        if resp is None:
            return None

        location = resp.headers.get("Location", "")
        body = ""
        try:
            body = resp.text[:65536]
        except Exception:
            pass

        in_location = ATTACK_HOST in location
        in_body = ATTACK_HOST in body

        if not (in_location or in_body):
            return None

        if in_location:
            severity = "high"
            detail = (f"The response redirects to an absolute URL containing the injected "
                      f"host: Location: {location[:160]}")
        else:
            severity = "medium"
            detail = ("The injected host is reflected into the page body (e.g. canonical "
                      "links or generated absolute URLs)")

        return Finding(
            module=self.id,
            check_id="hostheader.reflect",
            severity=severity,
            title=f"Host header injection on {base}",
            description=(f"Sending Host: {spoofed} produced a response that embeds the "
                         f"attacker-controlled host. {detail}. This is the primitive behind "
                         f"password-reset poisoning, cache poisoning and SSO redirect abuse."),
            evidence=(f"Location: {location[:160]}" if in_location
                      else body[max(0, body.find(ATTACK_HOST) - 40):
                                body.find(ATTACK_HOST) + len(ATTACK_HOST) + 40]),
            fix="Never build absolute URLs from the Host header. Derive the origin from a "
                "trusted configuration value, validate Host against an allow-list at the "
                "web server / load balancer, and keep redirect targets relative.",
            cwe="CWE-644",
            url=base,
        )
