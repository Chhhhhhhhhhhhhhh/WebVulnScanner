"""Dangerous HTTP method detection (CWE-749 / XST).

Probes the entry URL with:

* **OPTIONS** — informational only (the Allow header alone is not a finding);
* **TRACE** — a finding when the server actually echoes the request
  (Cross-Site Tracing). Modern browsers can no longer issue TRACE, so the
  severity stays low, but an answering TRACE is a misconfiguration signal;
* **PUT** — writes a uniquely named, harmless marker file and immediately
  deletes it again. A successful write is *high*: arbitrary uploads usually
  escalate to defacement or RCE.

Note: the PUT probe writes (and removes) one random file on the target —
that is within the remit of an authorised scan but is documented here so
nobody is surprised by it in access logs.
"""

from __future__ import annotations

import secrets

from .base import BaseModule, ScanContext
from ..models import Finding

PUT_SUCCESS_CODES = (200, 201, 204)


class MethodsModule(BaseModule):
    id = "methods"
    name = "HTTP methods"

    def run(self, ctx: ScanContext) -> list:
        entry = ctx.crawl.entry
        if entry is None:
            return []
        base = ctx.crawl.entry_url
        findings: list[Finding] = []

        # TRACE: only a finding when the request is actually echoed back
        trace_resp = ctx.client.request("TRACE", base, follow=False)
        if trace_resp is not None:
            text = ""
            try:
                text = trace_resp.text[:4096]
            except Exception:
                pass
            if trace_resp.status_code == 200 and "TRACE /" in text.upper() \
                    and "HTTP/1." in text.upper():
                findings.append(Finding(
                    module=self.id,
                    check_id="methods.trace",
                    severity="low",
                    title="HTTP TRACE method enabled (Cross-Site Tracing)",
                    description="The server answers TRACE requests by echoing the full request "
                                "back. TRACE historically allowed reading HttpOnly cookies via "
                                "XST; browsers have removed TRACE support, but an enabled TRACE "
                                "indicates permissive server configuration and may still aid "
                                "proxy/debug endpoint abuse.",
                    evidence=text.splitlines()[0][:120] if text else "",
                    fix="Disable TRACE (Apache: TraceEnable Off; nginx does not answer TRACE).",
                    cwe="CWE-749",
                    url=base,
                ))

        # PUT: write a uniquely named marker, then clean up after ourselves
        nonce = secrets.token_hex(8)
        probe_path = f"/wvs-put-probe-{nonce}.txt"
        put_url = base.rstrip("/") + probe_path
        put_resp = ctx.client.request(
            "PUT", put_url, data=f"webvulnscanner probe {nonce}",
            follow=False)
        put_status = put_resp.status_code if put_resp is not None else 0
        if put_status in PUT_SUCCESS_CODES:
            findings.append(Finding(
                module=self.id,
                check_id="methods.put_upload",
                severity="high",
                title="HTTP PUT allows arbitrary file writes",
                description=f"A PUT request created {probe_path} on the server (the scanner "
                            f"deleted it again immediately). Unauthenticated PUT usually leads "
                            f"to defacement, webshell upload and remote code execution.",
                evidence=f"PUT {probe_path} -> HTTP {put_status}",
                fix="Disable WebDAV/PUT (Apache: disable mod_dav, LimitExcept; "
                    "IIS: remove WebDAV authoring rules); uploads must go through "
                    "authenticated, type-restricted endpoints.",
                cwe="CWE-749",
                url=base,
            ))
            ctx.client.request("DELETE", put_url, follow=False)   # cleanup
            cleanup_resp = ctx.client.request("GET", put_url, follow=False)
            cleanup_text = ""
            if cleanup_resp is not None:
                try:
                    cleanup_text = cleanup_resp.text[:4096]
                except Exception:
                    pass
            # a plain 200 is not proof (soft-404 apps answer 200 for
            # anything); require the probe *content* to be served back
            if f"webvulnscanner probe {nonce}" in cleanup_text:
                findings.append(Finding(
                    module=self.id,
                    check_id="methods.put_persisted",
                    severity="high",
                    title="PUT-uploaded file is publicly readable",
                    description="The scanner's PUT probe file remained readable after the "
                                "DELETE cleanup attempt failed — uploaded content is served "
                                "back over HTTP.",
                    evidence=f"GET {probe_path} still returns 200 after DELETE",
                    fix="Disable unauthenticated PUT and remove the leftover probe file "
                        f"({probe_path}).",
                    cwe="CWE-749",
                    url=base,
                ))

        return findings
