"""Local file inclusion / path traversal detection.

Traverses toward ``/etc/passwd`` (unix) and ``windows/win.ini`` (windows)
with several notations (plain ``../``, filter-bypass ``....//``, absolute
path). A finding requires the canonical file *content* marker, not just an
HTTP 200.
"""

from __future__ import annotations

import re

from .base import AttackPoint, ScanContext, VulnModule, response_text, snippet, strip_echo
from ..models import Finding

LFI_PAYLOADS = [
    "../../../../../../../etc/passwd",
    "....//....//....//....//....//....//etc/passwd",
    "/etc/passwd",
    "..\\..\\..\\..\\..\\..\\windows\\win.ini",
]

FILE_MARKERS = [
    (re.compile(r"root:[x*!]:0:0:"), "/etc/passwd"),
    (re.compile(r"(?m)^[^:\n]+:/bin/(?:ba|z|da)?sh"), "/etc/passwd"),
    (re.compile(r"(?i)\[fonts\]"), "win.ini"),
    (re.compile(r"(?i)for 16-bit app support"), "win.ini"),
]


class LfiModule(VulnModule):
    id = "lfi"
    name = "Path traversal / LFI"

    def test_point(self, ctx: ScanContext, point: AttackPoint) -> list:
        for payload in LFI_PAYLOADS:
            resp = ctx.send(point, payload)
            text = response_text(resp)
            if not text:
                continue
            cleaned = strip_echo(text, payload)
            for marker, source_file in FILE_MARKERS:
                match = marker.search(cleaned)
                if not match:
                    continue
                return [Finding(
                    module=self.id,
                    check_id="lfi.traversal",
                    severity="high",
                    title=f"Path traversal in parameter '{point.param}'",
                    description=(f"The {point.method} parameter '{point.param}' allows reading files outside "
                                 f"the intended directory: content of {source_file} was returned for payload "
                                 f"{payload!r}. Depending on the runtime this often escalates to RCE "
                                 f"(log/poison, wrappers, file upload)."),
                    evidence=snippet(cleaned, match.group(0)),
                    fix=("Never build file paths from user input. Map user values to an allow-list of "
                         "files or ids, canonicalise with realpath and verify the result stays inside "
                         "the intended base directory; run the app with least privileges."),
                    cwe="CWE-22",
                    url=point.url,
                    param=point.param,
                )]
        return []
