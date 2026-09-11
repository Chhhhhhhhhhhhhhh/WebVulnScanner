"""Open redirect detection (CWE-601).

For every parameter the module submits a neutral control value and two
off-host payloads. A finding requires the *payload* run to redirect to a
different host while the *control* run does not — pages that bounce
off-site regardless of the parameter (e.g. fixed SSO redirects) are not
reported.
"""

from __future__ import annotations

from urllib.parse import urljoin

from .base import AttackPoint, ScanContext, VulnModule
from ..models import Finding
from ..target import host_of

CONTROL_VALUE = "/wvs-local-probe"
PAYLOAD_HOST = "example.com"          # IANA-reserved documentation domain
REDIRECT_STATUSES = (301, 302, 303, 307, 308)


class RedirectModule(VulnModule):
    id = "redirect"
    name = "Open redirect"

    PAYLOADS = ("https://example.com/", "//example.com/")

    def _redirect_host(self, point: AttackPoint, resp) -> str:
        location = resp.headers.get("Location", "")
        if not location:
            return ""
        return host_of(urljoin(point.url, location))

    def test_point(self, ctx: ScanContext, point: AttackPoint) -> list:
        control_resp = self._fetch(ctx, point, CONTROL_VALUE)
        if control_resp is None:
            return []
        control_host = self._redirect_host(point, control_resp)
        control_offhost = control_host not in ("", host_of(point.url))

        for payload in self.PAYLOADS:
            resp = self._fetch(ctx, point, payload)
            if resp is None or resp.status_code not in REDIRECT_STATUSES:
                continue
            landing_host = self._redirect_host(point, resp)
            if not landing_host or landing_host == host_of(point.url):
                continue
            if control_offhost and landing_host == control_host:
                continue  # redirects off-site no matter what we send
            if landing_host != PAYLOAD_HOST:
                continue  # not our payload's host → not attacker-controlled
            return [Finding(
                module=self.id,
                check_id="redirect.open",
                severity="high",
                title=f"Open redirect in parameter '{point.param}'",
                description=(f"The {point.method} parameter '{point.param}' is used as a redirect "
                             f"target without host validation: the value {payload!r} produced a "
                             f"{resp.status_code} to {landing_host}. Open redirects power phishing "
                             f"campaigns (trusted-domain links) and SSRF/filter bypass chains."),
                evidence=f"{resp.status_code} Location: {resp.headers.get('Location', '')}",
                fix="Validate redirect targets against an allow-list of hosts, or only allow "
                    "relative paths; never pass user input straight into a Location header.",
                cwe="CWE-601",
                url=point.url,
                param=point.param,
            )]
        return []

    def _fetch(self, ctx: ScanContext, point: AttackPoint, value: str):
        if point.method == "POST":
            return ctx.client.request("POST", point.url, data=point.with_value(value),
                                      follow=False)
        return ctx.client.request("GET", point.url, params=point.with_value(value),
                                  follow=False)
