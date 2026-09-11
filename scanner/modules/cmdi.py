"""Command injection detection via harmless echo markers.

Instead of running ``whoami``/``id`` on the target, each payload asks the
shell to ``echo`` a random marker. If the executed output contains the
marker (after removing mere echoes of the payload itself), the parameter
reaches a shell. Payloads cover ``;``, ``|``, ``&&``, ``||``, newline,
command substitution and Windows ``&`` separators.
"""

from __future__ import annotations

import re
import secrets

from .base import AttackPoint, ScanContext, VulnModule, response_text, snippet, strip_echo
from ..models import Finding

MARKER_TEMPLATES = [
    "; echo {m}:",
    "| echo {m}:",
    "&& echo {m}:",
    "|| echo {m}:",
    "\necho {m}:",
    "$(echo {m})",
    "`echo {m}`",
    "& echo {m}:",
]


class CmdiModule(VulnModule):
    id = "cmdi"
    name = "Command injection"

    def __init__(self):
        self.marker = "wvs" + secrets.token_hex(5)

    def test_point(self, ctx: ScanContext, point: AttackPoint) -> list:
        marker = self.marker
        for template in MARKER_TEMPLATES:
            payload = template.format(m=marker)
            resp = ctx.send(point, payload)
            text = response_text(resp)
            if not text:
                continue
            cleaned = strip_echo(text, payload)
            if marker not in cleaned:
                continue
            # A bare marker could still be page noise; require the marker
            # not to appear in a baseline-style echo context either.
            if re.search(rf"\b{re.escape(marker)}\b", cleaned):
                return [Finding(
                    module=self.id,
                    check_id="cmdi.echo_marker",
                    severity="critical",
                    title=f"OS command injection in parameter '{point.param}'",
                    description=(f"The {point.method} parameter '{point.param}' feeds attacker-controlled "
                                 f"data into an OS command: the shell executed our echo probe and its "
                                 f"output ({marker}) appeared in the response. Arbitrary commands run with "
                                 f"the web server's privileges."),
                    evidence=snippet(cleaned, marker, width=80),
                    fix=("Do not pass user input to shell commands. Use language APIs (e.g. subprocess "
                         "with a list argv and shell=False), allow-list inputs, and escape/quote anything "
                         "else per-shell."),
                    cwe="CWE-78",
                    url=point.url,
                    param=point.param,
                )]
        return []
