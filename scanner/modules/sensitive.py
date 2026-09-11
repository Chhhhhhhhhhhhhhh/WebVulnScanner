"""Sensitive file & directory exposure detection.

Two false-positive guards over the naive v1 "any HTTP 200 counts" logic:

1. **Soft-404 calibration** — many apps answer 200 with a friendly
   "not found" page. Before testing, the module fetches a guaranteed
   non-existent path and records its signature. A candidate path only
   counts when its response is clearly *different* from that baseline.
2. **Content validators** — each entry carries a regex the body must
   match (e.g. a real ``.git/HEAD`` starts with ``ref: refs/``).

Extra paths can be supplied at runtime via ``--wordlist``.
"""

from __future__ import annotations

import difflib
import hashlib
import re
import secrets
from concurrent.futures import as_completed

from .base import BaseModule, ScanContext
from ..models import Finding

# path, check id suffix, severity, title, description, fix, validator (bytes -> bool)
SENSITIVE_PATHS = [
    ("/.git/HEAD", "git_head", "critical", "Git repository exposed (.git/HEAD)",
     "The .git directory is web-accessible; source code and possibly credentials in history can be reconstructed with tools like git-dumper.",
     "Remove the .git directory from the web root and block dot-directories at the web server.",
     lambda b: re.search(rb"ref:\s*refs/", b[:512]) is not None),
    ("/.git/config", "git_config", "critical", "Git repository exposed (.git/config)",
     "The Git configuration file is downloadable, confirming a full repository disclosure.",
     "Remove the .git directory from the web root.",
     lambda b: b.lstrip()[:1] == b"[" and b"core" in b[:512]),
    ("/.git/index", "git_index", "critical", "Git repository exposed (.git/index)",
     "The Git index file is downloadable; it lists every tracked filename.",
     "Remove the .git directory from the web root.",
     lambda b: b[:4] == b"DIRC"),
    ("/.svn/wc.db", "svn_db", "high", "Subversion metadata exposed (.svn/wc.db)",
     "The SVN working-copy database is web-accessible and reveals source paths and history.",
     "Remove the .svn directory from the web root.",
     lambda b: b[:15] == b"SQLite format 3"),
    ("/.env", "env", "high", "Environment file exposed (.env)",
     "The .env file is downloadable and typically contains database credentials and API keys.",
     "Never deploy .env inside the web root; block dot-files at the web server.",
     lambda b: re.search(rb"(?mi)^[A-Z0-9_]{2,}\s*=", b[:4096]) is not None),
    ("/.env.bak", "env_backup", "high", "Environment file backup exposed (.env.bak)",
     "A backup of the environment configuration is downloadable.",
     "Remove backup files from the web root.",
     lambda b: re.search(rb"(?mi)^[A-Z0-9_]{2,}\s*=", b[:4096]) is not None),
    ("/.DS_Store", "ds_store", "medium", "macOS directory metadata exposed (.DS_Store)",
     "A Finder .DS_Store file lists names of files that once existed in the directory.",
     "Remove .DS_Store files and block dot-files at the web server.",
     lambda b: b[:8] == b"\x00\x00\x00\x01Bud1"),
    ("/.htaccess", "htaccess", "low", "Apache configuration exposed (.htaccess)",
     "The .htaccess file is readable and discloses rewrite rules and auth settings.",
     "Deny access to .ht* files (Apache does this by default in recent versions).",
     lambda b: re.search(rb"(?i)rewriteengine|authtype|deny from", b[:4096]) is not None),
    ("/web.config", "web_config", "medium", "IIS configuration exposed (web.config)",
     "The IIS configuration file is readable and may contain connection strings or secrets.",
     "Restrict access to web.config.",
     lambda b: b.lstrip()[:1] == b"<" and b"configuration" in b[:2048].lower()),
    ("/phpinfo.php", "phpinfo", "high", "phpinfo() page exposed",
     "A phpinfo() page discloses the PHP version, loaded modules, paths and environment variables.",
     "Delete the phpinfo script from production systems.",
     lambda b: re.search(rb"(?i)phpversion|phpinfo|php version", b[:8192]) is not None),
    ("/info.php", "phpinfo", "high", "phpinfo() page exposed",
     "A phpinfo() page discloses the PHP version, loaded modules, paths and environment variables.",
     "Delete the phpinfo script from production systems.",
     lambda b: re.search(rb"(?i)phpversion|phpinfo|php version", b[:8192]) is not None),
    ("/server-status", "server_status", "medium", "Apache server-status exposed",
     "The mod_status page reveals live requests, URLs and client IPs.",
     "Require local access or disable mod_status.",
     lambda b: re.search(rb"(?i)apache (server status|status for)", b[:4096]) is not None),
    ("/actuator/env", "actuator_env", "high", "Spring Boot Actuator exposed (/actuator/env)",
     "The Actuator environment endpoint dumps all configuration properties, often including credentials.",
     "Restrict or disable Actuator endpoints in production.",
     lambda b: re.search(rb"(?i)(java\.version|spring|propertySources|\"property\")", b[:8192]) is not None),
    ("/actuator/health", "actuator_health", "medium", "Spring Boot Actuator exposed (/actuator/health)",
     "The Actuator health endpoint is unauthenticated and leaks component status and versions.",
     "Restrict or disable Actuator endpoints in production.",
     lambda b: re.search(rb'(?i)"status"\s*:', b[:4096]) is not None),
    ("/backup.sql", "sql_backup", "critical", "Database backup exposed (backup.sql)",
     "A SQL dump is downloadable from the web root.",
     "Never store database backups inside the web root.",
     lambda b: re.search(rb"(?i)create table|insert into", b[:8192]) is not None),
    ("/dump.sql", "sql_backup", "critical", "Database backup exposed (dump.sql)",
     "A SQL dump is downloadable from the web root.",
     "Never store database backups inside the web root.",
     lambda b: re.search(rb"(?i)create table|insert into", b[:8192]) is not None),
    ("/adminer.php", "adminer", "high", "Adminer database UI exposed",
     "An Adminer installation is publicly reachable and can be brute-forced or exploited (CVE-2021-21311 etc.).",
     "Remove Adminer from production or restrict it by IP.",
     lambda b: re.search(rb"(?i)adminer", b[:4096]) is not None),
    ("/swagger/index.html", "swagger", "medium", "API documentation exposed (Swagger UI)",
     "Interactive API documentation is public, giving attackers a full endpoint map.",
     "Restrict documentation endpoints to authenticated users.",
     lambda b: re.search(rb"(?i)swagger|openapi", b[:8192]) is not None),
]

# Directories probed for auto-generated listings (only flagged when the
# classic "Index of" markup is present).
LISTING_DIRS = [
    "/admin/", "/backup/", "/backups/", "/uploads/", "/upload/",
    "/config/", "/includes/", "/static/", "/images/", "/assets/",
    "/tmp/", "/log/", "/logs/", "/old/", "/test/", "/data/",
    "/files/", "/download/", "/downloads/", "/media/",
]

LISTING_MARKERS = re.compile(r"(?i)index of /|parent directory")


def _normalise(body: bytes) -> bytes:
    return re.sub(rb"\s+", b" ", body.strip().lower())


def _looks_like_baseline(body: bytes, baseline_body: bytes | None) -> bool:
    """True when a response is byte-identical or near-identical to the
    soft-404 baseline (dynamic pages that always differ by a token stay
    'similar' because the comparison is ratio-based, not hash-based)."""
    if baseline_body is None:
        return False
    norm_a, norm_b = _normalise(body)[:65536], _normalise(baseline_body)[:65536]
    if hashlib.md5(norm_a).hexdigest() == hashlib.md5(norm_b).hexdigest():
        return True
    return difflib.SequenceMatcher(None, norm_a, norm_b, autojunk=False).ratio() >= 0.90


def load_wordlist(path: str) -> list:
    """Read extra paths to probe (one per line, '#' comments, '/'-prefixed)."""
    entries = []
    seen = set()
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            entry = line.split("#", 1)[0].strip()
            if not entry or entry in seen:
                continue
            if not entry.startswith("/"):
                entry = "/" + entry
            seen.add(entry)
            entries.append(entry)
    return entries


def _wordlist_entries(wordlist_path) -> list:
    """Turn wordlist lines into SENSITIVE_PATHS-shaped tuples."""
    if not wordlist_path:
        return []
    try:
        paths = load_wordlist(wordlist_path)
    except OSError:
        return []  # caller logs; a broken wordlist must not kill the module
    entries = []
    for path in paths:
        suffix = re.sub(r"[^a-z0-9]+", "_", path.lower()).strip("_")[:40] or "entry"
        entries.append((
            path, f"wordlist_{suffix}", "medium",
            f"Exposed path from wordlist: {path}",
            "This path (from the user-supplied wordlist) returned content that "
            "differs from the application's not-found baseline. Review whether "
            "it should be publicly served.",
            "Restrict or remove the path if it is not intended to be public.",
            None,
        ))
    return entries


class SensitiveModule(BaseModule):
    id = "sensitive"
    name = "Sensitive files & listings"

    def run(self, ctx: ScanContext) -> list:
        from urllib.parse import urljoin

        base = ctx.crawl.entry_url
        nonce = secrets.token_hex(8)
        baseline_resp = ctx.client.get_page(urljoin(base, f"/wvs-nonexistent-{nonce}.html"),
                                            cap=64 * 1024, follow=False)
        baseline_body = baseline_resp.body if baseline_resp is not None else None

        def is_real(status: int, body: bytes) -> bool:
            if status != 200 or not body:
                return False
            return not _looks_like_baseline(body, baseline_body)

        findings: list[Finding] = []
        probe_entries = list(SENSITIVE_PATHS) + _wordlist_entries(
            ctx.config.get("wordlist"))
        if ctx.config.get("wordlist") and not probe_entries[len(SENSITIVE_PATHS):]:
            ctx.log("[!] wordlist yielded no usable entries")
        futures = {}
        for entry in probe_entries:
            full_url = urljoin(base, entry[0])
            futures[ctx.submit(self._probe_sensitive, ctx, full_url, entry[0], entry, is_real)] = full_url
        for future in as_completed(futures):
            try:
                findings.extend(future.result())
            except Exception:
                continue

        dir_futures = {}
        for directory in LISTING_DIRS:
            full_url = urljoin(base, directory)
            dir_futures[ctx.submit(self._probe_listing, ctx, full_url, directory, is_real)] = full_url
        for future in as_completed(dir_futures):
            try:
                findings.extend(future.result())
            except Exception:
                continue

        if baseline_resp is not None and baseline_resp.status == 200:
            findings.append(Finding(
                module=self.id, check_id="sensitive.soft404",
                severity="info",
                title="Soft 404 responses detected",
                description="The application returns HTTP 200 for non-existent paths. "
                            "File-exposure results were calibrated against this baseline to "
                            "avoid false positives.",
                evidence=f"Baseline probe returned 200 with {len(baseline_resp.body)} bytes.",
                url=base,
            ))

        return findings

    def _probe_sensitive(self, ctx, full_url, path, entry, is_real):
        _, suffix, severity, title, description, fix, validator = entry
        page = ctx.client.get_page(full_url, cap=512 * 1024, follow=False)
        if page is None or not is_real(page.status, page.body):
            return []
        if validator is not None and not validator(page.body):
            return []
        return [Finding(
            module=self.id,
            check_id=f"sensitive.{suffix}",
            severity=severity,
            title=title,
            description=description,
            fix=fix,
            cwe="CWE-538" if severity != "critical" else "CWE-540",
            url=full_url,
            evidence=f"HTTP {page.status}, {len(page.body)} bytes",
        )]

    def _probe_listing(self, ctx, full_url, directory, is_real):
        page = ctx.client.get_page(full_url, cap=256 * 1024)
        if page is None or not is_real(page.status, page.body):
            return []
        if not LISTING_MARKERS.search(page.body[:65536].decode("utf-8", errors="replace")):
            return []
        return [Finding(
            module=self.id,
            check_id="sensitive.directory_listing",
            severity="medium",
            title=f"Directory listing enabled: {directory}",
            description="The web server generates a file listing for this directory, exposing "
                        "filenames and structure.",
            fix="Disable auto-indexing (Apache: Options -Indexes; nginx: autoindex off).",
            cwe="CWE-548",
            url=full_url,
            evidence=f"HTTP 200 with listing markup, {len(page.body)} bytes",
        )]
