"""Core data models: findings, severity, crawl artifacts and scan results."""

from __future__ import annotations

import time
from dataclasses import dataclass, field

SEVERITY_ORDER = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}

SEVERITY_LABELS_ZH = {
    "critical": "严重",
    "high": "高危",
    "medium": "中危",
    "low": "低危",
    "info": "信息",
}


@dataclass
class Finding:
    """A single scan finding. All text fields are plain text; the report
    layer is responsible for escaping when rendering."""

    module: str            # module id, e.g. "sqli"
    check_id: str          # specific check, e.g. "sqli.error_based"
    severity: str          # critical | high | medium | low | info
    title: str
    description: str = ""
    evidence: str = ""
    fix: str = ""
    cwe: str = ""          # e.g. "CWE-89"
    url: str = ""          # affected URL (form action or parameterised URL)
    param: str = ""        # affected parameter, if any

    @property
    def dedup_key(self) -> tuple:
        return (self.module, self.check_id, self.url.rstrip("/"), self.param)

    def to_dict(self) -> dict:
        return {
            "module": self.module,
            "check_id": self.check_id,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "evidence": self.evidence,
            "fix": self.fix,
            "cwe": self.cwe,
            "url": self.url,
            "param": self.param,
        }


@dataclass
class FormSpec:
    """A parsed HTML form, used as an attack surface by vuln modules."""

    action: str
    method: str                     # "get" | "post"
    inputs: list                    # list of {"name","type","value"}
    source_url: str = ""

    @property
    def signature(self) -> tuple:
        return (self.action, self.method, tuple(sorted(i["name"] for i in self.inputs)))


@dataclass
class PageData:
    """One crawled page: final URL plus a capped raw response."""

    url: str
    status: int
    headers: dict
    body: bytes
    set_cookies: list = field(default_factory=list)

    @property
    def content_type(self) -> str:
        return self.headers.get("Content-Type", "")

    @property
    def is_html(self) -> bool:
        ct = self.content_type.lower()
        return "html" in ct or (not ct and self.body[:1].lstrip()[:1] == b"<")

    @property
    def text(self) -> str:
        charset = "utf-8"
        for part in self.content_type.split(";"):
            part = part.strip()
            if part.lower().startswith("charset="):
                charset = part.split("=", 1)[1].strip(" '\"")
                break
        try:
            return self.body.decode(charset, errors="replace")
        except (LookupError, UnicodeDecodeError):
            return self.body.decode("utf-8", errors="replace")


@dataclass
class CrawlResult:
    """Everything the crawler discovered, consumed by the modules."""

    entry_url: str
    entry: PageData | None = None
    pages: list = field(default_factory=list)          # list[PageData]
    param_urls: list = field(default_factory=list)     # URLs carrying a query string
    forms: list = field(default_factory=list)          # list[FormSpec]
    robots_found: bool = False


@dataclass
class RequestStats:
    requests: int = 0
    errors: int = 0
    blocked: int = 0
    redirects: int = 0
    rate_limited: int = 0


@dataclass
class ScanResult:
    target: str
    started_at: float = field(default_factory=time.time)
    finished_at: float = 0.0
    findings: list = field(default_factory=list)       # list[Finding]
    modules_run: list = field(default_factory=list)
    stats: RequestStats = field(default_factory=RequestStats)
    pages_crawled: int = 0
    attack_points: int = 0
    # populated by the CLI when --compare is used:
    # {"previous": path, "new": [dict], "fixed": [dict], "unchanged": int}
    comparison: dict | None = None

    @property
    def duration(self) -> float:
        return max(self.finished_at - self.started_at, 0.0)

    @property
    def severity_counts(self) -> dict:
        counts: dict = {}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts

    def sorted_findings(self) -> list:
        return sorted(
            self.findings,
            key=lambda f: (SEVERITY_ORDER.get(f.severity, 0), f.module, f.check_id),
            reverse=True,
        )

    def to_dict(self) -> dict:
        payload = {
            "meta": {
                "target": self.target,
                "started_at": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.started_at)),
                "finished_at": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.finished_at)),
                "duration_seconds": round(self.duration, 2),
                "pages_crawled": self.pages_crawled,
                "attack_points": self.attack_points,
                "requests": self.stats.requests,
                "request_errors": self.stats.errors,
                "blocked_requests": self.stats.blocked,
                "modules": self.modules_run,
                "severity_counts": self.severity_counts,
            },
            "findings": [f.to_dict() for f in self.sorted_findings()],
        }
        if self.comparison:
            payload["comparison"] = self.comparison
        return payload
