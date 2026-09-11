"""Time-based blind injection detection (opt-in via ``--time-based``).

Error-based and marker-based checks only work when the application leaks
something back. When output channels are fully blind, injection can still
be inferred from response timing: a ``SLEEP`` payload that actually runs
delays the answer by the requested seconds.

Cost control (this module is opt-in because each winning probe sleeps for
real):

* the baseline response must be fast (below half the sleep delay);
* a payload counts only when the measured delay reaches the threshold;
* every hit is confirmed by a second identical request — a single slow
  response (GC pause, cold cache) is never reported.

Because network jitter can mimic or mask short delays, findings are
worded as "possible" and capped at high severity.
"""

from __future__ import annotations

import time

from .base import AttackPoint, ScanContext, VulnModule, response_text
from ..models import Finding

SLEEP_SECONDS = 3
HIT_THRESHOLD = SLEEP_SECONDS - 0.6
BASELINE_MAX = SLEEP_SECONDS / 2

SQLI_SLEEP_PAYLOADS = [
    "1' AND SLEEP({d})-- -",          # MySQL
    "1 AND SLEEP({d})-- -",           # MySQL, numeric context
    "1; SELECT pg_sleep({d})--",      # PostgreSQL
    "1'; WAITFOR DELAY '0:0:{d}'--",  # SQL Server
]

CMDI_SLEEP_PAYLOADS = [
    "; sleep {d}",
    "| sleep {d}",
    "&& sleep {d}",
    "\nsleep {d}",
]


class TimingModule(VulnModule):
    id = "timing"
    name = "Time-based blind injection"

    def _elapsed(self, ctx: ScanContext, point: AttackPoint, value: str) -> float | None:
        started = time.monotonic()
        resp = ctx.send(point, value)
        elapsed = time.monotonic() - started
        if resp is None or not response_text(resp):
            return None
        return elapsed

    def _confirm(self, ctx, point, payload: str) -> bool:
        first = self._elapsed(ctx, point, payload)
        if first is None or first < HIT_THRESHOLD:
            return False
        second = self._elapsed(ctx, point, payload)
        return second is not None and second >= HIT_THRESHOLD

    def test_point(self, ctx: ScanContext, point: AttackPoint) -> list:
        baseline_value = point.params.get(point.param) or "1"
        baseline = self._elapsed(ctx, point, baseline_value)
        if baseline is None or baseline >= BASELINE_MAX:
            return []  # page is inherently slow: timing proves nothing

        for template in SQLI_SLEEP_PAYLOADS:
            payload = template.format(d=SLEEP_SECONDS)
            if self._confirm(ctx, point, payload):
                return [Finding(
                    module=self.id,
                    check_id="timing.sqli_sleep",
                    severity="high",
                    title=f"Possible time-based SQL injection in parameter '{point.param}'",
                    description=(f"The {point.method} parameter '{point.param}' delayed the response "
                                 f"by ~{SLEEP_SECONDS}s when given the sleep payload {payload!r} "
                                 f"(confirmed by a repeat request; baseline {baseline:.2f}s). "
                                 f"This indicates the input reaches a SQL query even though no "
                                 f"output or error is visible."),
                    evidence=f"baseline {baseline:.2f}s, payload response >= {HIT_THRESHOLD:.1f}s "
                             f"(two consecutive confirmations)",
                    fix="Use parameterised queries / prepared statements; alert on unexpected "
                        "query durations. Verify manually before treating as confirmed.",
                    cwe="CWE-89",
                    url=point.url,
                    param=point.param,
                )]

        for template in CMDI_SLEEP_PAYLOADS:
            payload = template.format(d=SLEEP_SECONDS)
            if self._confirm(ctx, point, payload):
                return [Finding(
                    module=self.id,
                    check_id="timing.cmdi_sleep",
                    severity="high",
                    title=f"Possible time-based command injection in parameter '{point.param}'",
                    description=(f"The {point.method} parameter '{point.param}' delayed the response "
                                 f"by ~{SLEEP_SECONDS}s when given the shell payload {payload!r} "
                                 f"(confirmed by a repeat request; baseline {baseline:.2f}s). "
                                 f"The input likely reaches an OS command even though no output "
                                 f"is visible."),
                    evidence=f"baseline {baseline:.2f}s, payload response >= {HIT_THRESHOLD:.1f}s "
                             f"(two consecutive confirmations)",
                    fix="Never pass user input to shell commands; use language APIs with explicit "
                        "argv lists. Verify manually before treating as confirmed.",
                    cwe="CWE-78",
                    url=point.url,
                    param=point.param,
                )]
        return []
