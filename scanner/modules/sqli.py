"""SQL injection detection: error-based (primary) + boolean-based (differential).

The v1 scanner flagged any response merely containing the words
"error"/"sql"/"mysql" — a page footer mentioning "sql error" was enough.
This module instead:

* skips parameters whose *baseline* response already matches DB error
  patterns (page is inherently erroring → nothing new is learned);
* matches specific database error signatures (MySQL, PostgreSQL, SQLite,
  SQL Server, Oracle, DB2, JDBC, PDO);
* for boolean-based detection, uses a **calibration pair**: the baseline
  is fetched twice and token positions that drift between the two
  fetches (session ids, timestamps) are ignored when comparing probe
  responses. ``AND '1'='1`` must look like the baseline while
  ``AND '1'='2`` clearly differs — reported as "possible", never
  "confirmed".
"""

from __future__ import annotations

import difflib
import re

from .base import AttackPoint, ScanContext, VulnModule, response_text, snippet
from ..models import Finding

ERROR_PAYLOADS = ["'", '"', "')", "'\"", "1'", "1\"", "\\", "') OR ('1'='1"]

ERROR_PATTERNS = re.compile(
    "("
    r"you have an error in your sql syntax"
    r"|sql syntax.{0,80}mysql"
    r"|warning.{0,60}mysql"
    r"|uncaught mysql"
    r"|mysql_(?:fetch|query|connect|num_rows|result|error)"
    r"|mariadb.{0,40}(?:syntax|error)"
    r"|correct syntax.{0,60}(?:mysql|mariadb)"
    r"|ERROR:\s+\d+\s+.?syntax error at or near"
    r"|pg_query|pg_exec|psql.*ERROR|PostgreSQL.{0,60}ERROR"
    r"|org\.postgresql\.util\.PSQLException"
    r"|sqlite3?(?:_exec)?\.(?:query|exec)"
    r"|SQLITE_(?:ERROR|MISUSE|CORRUPT)"
    r"|SQLite3?::query"
    r"|SQLite error"
    r"|unclosed quotation mark after the character string"
    r"|incorrect syntax near"
    r"|Microsoft OLE DB Provider for SQL Server"
    r"|ODBC SQL Server Driver"
    r"|Microsoft SQL Native Client"
    r"|com\.microsoft\.sqlserver"
    r"|SQLException"
    r"|quoted string not properly terminated"
    r"|ORA-\d{5}"
    r"|DB2 SQL error|SQLCODE=-?\d+"
    r"|PDOException"
    r"|Doctrine\\DBAL"
    ")",
    re.IGNORECASE,
)

# (true_payload, false_payload) pairs tried in order.
BOOLEAN_PAIRS = [
    ("{v}' AND 'a'='a", "{v}' AND 'a'='b"),
    ("1 AND 1=1", "1 AND 1=2"),
    ("{v}' OR 'a'='a", "{v}' OR 'a'='b"),
]

# Response equivalence for boolean-based detection. Real pages carry
# session tokens, nonces and timestamps that change between requests, so a
# raw comparison would call every page "different". Instead the module
# fetches the baseline **twice**; token positions where the two fetches
# disagree are treated as naturally volatile and ignored when comparing
# probe responses. A query-driven change (e.g. "3 results" vs "0 results")
# sits at a stable position, so it still registers as a difference.
EQUIVALENCE_RATIO = 0.985
MIN_PAGE_SIZE = 100  # bytes; tiny fragments are too noisy to compare


def pages_equivalent(
    page_a: str,
    page_b: str,
    calibration: tuple | None = None,
    ratio: float = EQUIVALENCE_RATIO,
) -> bool:
    """True when two response bodies are 'the same page'.

    ``calibration`` is a pair of baseline bodies fetched back-to-back.
    When all four token sequences align (same template), comparison is
    exact outside the volatile positions. Otherwise a strict similarity
    ratio is used as fallback.
    """
    tokens_a, tokens_b = page_a.split(), page_b.split()
    if calibration:
        cal_a, cal_b = calibration[0].split(), calibration[1].split()
        if len(tokens_a) == len(tokens_b) == len(cal_a) == len(cal_b):
            volatile = {i for i, (x, y) in enumerate(zip(cal_a, cal_b)) if x != y}
            return all(
                ta == tb
                for i, (ta, tb) in enumerate(zip(tokens_a, tokens_b))
                if i not in volatile
            )
    if page_a == page_b:
        return True
    # autojunk=False: whitespace would otherwise be treated as junk on long
    # pages, collapsing the matching blocks and wrecking the ratio
    return difflib.SequenceMatcher(None, page_a, page_b, autojunk=False).ratio() >= ratio


class SqliModule(VulnModule):
    id = "sqli"
    name = "SQL injection"

    def test_point(self, ctx: ScanContext, point: AttackPoint) -> list:
        baseline_value = point.params.get(point.param) or "1"
        base_resp = ctx.send(point, baseline_value)
        base_text = response_text(base_resp)
        if not base_text or base_resp.status_code >= 500:
            return []
        if ERROR_PATTERNS.search(base_text):
            return []  # baseline already errors: any error match proves nothing

        for payload in ERROR_PAYLOADS:
            resp = ctx.send(point, payload)
            text = response_text(resp)
            if not text:
                continue
            match = ERROR_PATTERNS.search(text)
            if match:
                return [Finding(
                    module=self.id,
                    check_id="sqli.error_based",
                    severity="high",
                    title=f"SQL injection (error-based) in parameter '{point.param}'",
                    description=f"The {point.method} parameter '{point.param}' reflects attacker input into a "
                                f"database query; a crafted value ({payload!r}) made the backend return a "
                                f"database error message.",
                    evidence=snippet(text, match.group(0)),
                    fix="Use parameterised queries / prepared statements everywhere; never build SQL by "
                        "string concatenation. Least-privilege DB accounts and generic error pages limit the blast radius.",
                    cwe="CWE-89",
                    url=point.url,
                    param=point.param,
                )]

        # Boolean-based differential
        if len(base_text) < MIN_PAGE_SIZE:
            return []
        calibration_resp = ctx.send(point, baseline_value)
        calibration = (base_text, response_text(calibration_resp) or base_text)
        for true_tpl, false_tpl in BOOLEAN_PAIRS:
            true_payload = true_tpl.format(v=baseline_value or "1")
            false_payload = false_tpl.format(v=baseline_value or "1")
            true_resp = ctx.send(point, true_payload)
            false_resp = ctx.send(point, false_payload)
            true_text, false_text = response_text(true_resp), response_text(false_resp)
            if not true_text or not false_text:
                continue
            if ERROR_PATTERNS.search(true_text) or ERROR_PATTERNS.search(false_text):
                continue
            true_matches_baseline = pages_equivalent(true_text, base_text, calibration)
            if not true_matches_baseline:
                continue
            if pages_equivalent(false_text, true_text, calibration):
                continue  # false condition changed nothing
            return [Finding(
                module=self.id,
                check_id="sqli.boolean_based",
                severity="medium",
                title=f"Possible SQL injection (boolean-based) in parameter '{point.param}'",
                description=f"Parameter '{point.param}' produces a baseline-like response for "
                            f"{true_payload!r} but a clearly different response for {false_payload!r}, "
                            f"which matches boolean-based injection behaviour.",
                evidence=f"baseline {len(base_text)}B | true payload {len(true_text)}B | "
                         f"false payload {len(false_text)}B",
                fix="Use parameterised queries / prepared statements; verify with manual testing "
                    "before treating as confirmed.",
                cwe="CWE-89",
                url=point.url,
                param=point.param,
            )]

        return []
