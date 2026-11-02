"""NoSQL (MongoDB-style) operator injection — error-based (CWE-943).

Sends MongoDB operator payloads (``$ne`` / ``$gt`` / ``$regex`` /
``$where``) as plain string values. When the backend feeds them into a
query without parsing them as data, the driver rejects the unknown
operator and its error message (MongoError / BSON / Mongo::Error ...)
leaks into the response.

Deliberately **error-based only**: boolean differentials on NoSQL endpoints
are extremely noisy (login forms return different pages for every
malformed input), so this module reports nothing unless a database error
signature is actually present. That keeps it at zero false positives at
the cost of missing silent injections — documented as a limitation.
"""

from __future__ import annotations

import re

from .base import AttackPoint, ScanContext, VulnModule, response_text, snippet
from ..models import Finding

NOSQL_PAYLOADS = [
    '{"$ne": "x"}',
    '{"$gt": ""}',
    '{"$regex": "^."}',
    "' || '1'=='1",        # classic NoSQL string-injection shape
    "1'; return true; var x='",  # $where style
]

NOSQL_ERROR_PATTERNS = re.compile(
    "("
    r"MongoError|MongoServerError|MongoDB\."
    r"|Mongo::Error|Mongo::OperationFailure|BSONError|BSONTypeError"
    r"|mongo reply error|BSON field"
    r"|unknown (?:top-?level )?operator"
    r"|.*\$where.*(?:syntax|error)"
    r"|failed to (?:parse|deserialize).{0,40}(?:bson|mongo)"
    ")",
    re.IGNORECASE,
)


class NoSqlModule(VulnModule):
    id = "nosqli"
    name = "NoSQL injection (error-based)"

    def test_point(self, ctx: ScanContext, point: AttackPoint) -> list:
        for payload in NOSQL_PAYLOADS:
            resp = ctx.send(point, payload)
            text = response_text(resp)
            if not text:
                continue
            match = NOSQL_ERROR_PATTERNS.search(text)
            if match:
                return [Finding(
                    module=self.id,
                    check_id="nosqli.error",
                    severity="high",
                    title=f"NoSQL injection in parameter '{point.param}'",
                    description=(f"The {point.method} parameter '{point.param}' feeds a MongoDB-"
                                 f"style operator payload ({payload!r}) into a query without "
                                 f"sanitisation: the driver rejected it and the database error "
                                 f"reached the response. Depending on the query this typically "
                                 f"allows authentication bypass or data extraction."),
                    evidence=snippet(text, match.group(0)),
                    fix="Validate that inputs are plain strings/numbers before querying; never "
                        "JSON-decode or eval user input into query documents; use typed schema "
                        "validation and operators only from server-side code.",
                    cwe="CWE-943",
                    url=point.url,
                    param=point.param,
                )]
        return []
