"""Server-side template injection detection (CWE-1336).

Sends arithmetic template expressions in several engine syntaxes and
requires the *computed product* to appear in the response — the payload
echo itself never contains it, and a per-point random factor pair keeps
the product from colliding with page content that happens to contain a
common number.
"""

from __future__ import annotations

import secrets

from .base import AttackPoint, ScanContext, VulnModule, response_text, snippet, strip_echo
from ..models import Finding

SYNTAXES = (
    lambda a, b: f"{{{{{a}*{b}}}}}",        # Jinja2 / Twig / Handlebars-ish
    lambda a, b: f"${{{a}*{b}}}",           # FreeMarker / Velocity / EL
    lambda a, b: f"<%= {a}*{b} %>",         # ERB / EJS
    lambda a, b: f"#{{{a}*{b}}}",           # Ruby interpolation
)


class SstiModule(VulnModule):
    id = "ssti"
    name = "Template injection (SSTI)"

    def test_point(self, ctx: ScanContext, point: AttackPoint) -> list:
        baseline_value = point.params.get(point.param) or "hello"
        base_resp = ctx.send(point, baseline_value)
        base_text = response_text(base_resp)
        if not base_text:
            return []

        for build in SYNTAXES:
            factor_a = 100 + secrets.randbelow(800)   # 100-899
            factor_b = 100 + secrets.randbelow(800)
            product = factor_a * factor_b
            payload = build(factor_a, factor_b)

            resp = ctx.send(point, payload)
            text = response_text(resp)
            if not text:
                continue
            cleaned = strip_echo(text, payload)
            if str(product) not in cleaned:
                continue
            if str(product) in base_text:
                continue  # number already on the page: proves nothing
            return [Finding(
                module=self.id,
                check_id="ssti.eval",
                severity="critical",
                title=f"Server-side template injection in parameter '{point.param}'",
                description=(f"The {point.method} parameter '{point.param}' is evaluated by a "
                             f"template engine: the expression {payload!r} returned the computed "
                             f"result {product} instead of being rendered as text. SSTI typically "
                             f"escalates directly to remote code execution."),
                evidence=snippet(cleaned, str(product)),
                fix="Never pass user input into template *code*. Render templates from trusted "
                    "sources only; pass user data as template variables, and use "
                    "sandboxed/auto-escaping template environments.",
                cwe="CWE-1336",
                url=point.url,
                param=point.param,
            )]
        return []
