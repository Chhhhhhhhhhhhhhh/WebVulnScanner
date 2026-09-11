"""Reflected XSS detection via canary reflection + character-survival analysis.

Naive scanners search the response for the raw payload (``<script>...``),
which both false-negatives (encoding to ``&lt;``) and false-positives
(payload echoed in an escaped context or in a comment). This module works
in two steps:

1. **Canary** — submit a purely alphanumeric random marker. If it is not
   reflected at all, the parameter is uninteresting and no dangerous
   payload is ever sent.
2. **Probe** — resubmit the canary followed by metacharacters
   ``' " < > ( ) { } $ \\ [ ] ` ``. For every reflected canary occurrence,
   check *which* metacharacters survived encoding/striping *in order*.
   ``<`` and ``>`` surviving → high (HTML context injectable); quotes
   surviving → medium (attribute break-out); nothing surviving → the app
   encodes correctly (info only).
"""

from __future__ import annotations

import secrets

from .base import AttackPoint, ScanContext, VulnModule, response_text, snippet
from ..models import Finding

PROBE_SUFFIX = "'\"<>(){}$\\[]`"


def make_canary() -> str:
    return "wvs" + secrets.token_hex(5)


def analyse_reflection(text: str, canary: str, suffix: str) -> dict:
    """Return which probe metacharacters survived reflection, in order.

    For each occurrence of the canary in ``text``, walk the characters that
    follow it and greedily match them against ``suffix``. The best (longest)
    survival across all occurrences wins — one occurrence may be truncated
    while another reflects fully.
    """
    best = ""
    start = 0
    while True:
        idx = text.find(canary, start)
        if idx < 0:
            break
        window = text[idx + len(canary): idx + len(canary) + len(suffix) + 16]
        survived = ""
        pos = 0
        for ch in suffix:
            found = window.find(ch, pos)
            if found < 0:
                continue
            survived += ch
            pos = found + 1
        if len(survived) > len(best):
            best = survived
        start = idx + 1
    return {"survived": best}


def _first_reflection_snippet(text: str, canary: str) -> str:
    return snippet(text, canary, width=90)


class XssModule(VulnModule):
    id = "xss"
    name = "Reflected XSS"

    def __init__(self):
        self.canary = make_canary()

    def test_point(self, ctx: ScanContext, point: AttackPoint) -> list:
        # Step 1: harmless canary reflection check
        canary_resp = ctx.send(point, self.canary)
        canary_text = response_text(canary_resp)
        if not canary_text or self.canary not in canary_text:
            return []

        # Step 2: metacharacter survival probe
        probe = self.canary + PROBE_SUFFIX
        probe_resp = ctx.send(point, probe)
        probe_text = response_text(probe_resp)
        if not probe_text or self.canary not in probe_text:
            return []  # probe dropped (e.g. WAF) — cannot conclude anything

        analysis = analyse_reflection(probe_text, self.canary, PROBE_SUFFIX)
        survived = analysis["survived"]
        evidence = _first_reflection_snippet(probe_text, self.canary)

        if "<" in survived and ">" in survived:
            severity, check_id = "high", "xss.reflected_html"
            title = f"Reflected XSS in parameter '{point.param}'"
            description = (f"The {point.method} parameter '{point.param}' reflects input without HTML-encoding: "
                           f"both '<' and '>' survive reflection, so arbitrary tags (e.g. <script>) can be injected.")
            fix = ("HTML-escape everything by context: use auto-escaping templates, escape on output "
                   "(never input), and add a Content-Security-Policy as a second line of defence.")
        elif "'" in survived or '"' in survived:
            severity, check_id = "medium", "xss.reflected_attribute"
            title = f"Possible reflected XSS in parameter '{point.param}' (attribute context)"
            description = (f"The {point.method} parameter '{point.param}' reflects input with quote "
                           f"characters intact ({survived.strip()!r} survived). If the reflection lands inside "
                           f"an HTML attribute, quotes allow breaking out into an event handler.")
            fix = ("HTML-escape output including quotes (&quot; &#39;); validate attribute contexts "
                   "specifically and avoid interpolating user input into attributes/events.")
        else:
            return [Finding(
                module=self.id,
                check_id="xss.reflected_encoded",
                severity="info",
                title=f"Parameter '{point.param}' is reflected but encoded",
                description=f"The {point.method} parameter '{point.param}' reflects input into the page, "
                            f"however HTML metacharacters did not survive reflection — output encoding "
                            f"appears to be in place. Manual review of the reflection context is still prudent.",
                evidence=evidence,
                fix="Keep the encoding; re-test whenever template or framework versions change.",
                cwe="CWE-79",
                url=point.url,
                param=point.param,
            )]

        return [Finding(
            module=self.id,
            check_id=check_id,
            severity=severity,
            title=title,
            description=description,
            evidence=evidence,
            fix=fix,
            cwe="CWE-79",
            url=point.url,
            param=point.param,
        )]
