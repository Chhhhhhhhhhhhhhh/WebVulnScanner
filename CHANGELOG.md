# Changelog

## 2.4.0 (2026-11)

Performance and three more detection modules.

### Changed (performance)
- **Crawler fetches pages layer-by-layer in parallel** (up to `--threads`
  concurrent requests within one BFS depth). Depth semantics, page budget,
  logout avoidance and the global rate limiter are unchanged; a dedicated
  test asserts the parallel crawl discovers the same page/param/form set
  as the serial one and is measurably faster on slow targets.
- **Batch mode scans targets concurrently** (`--batch-threads`, default 2).
  Each target keeps its own rate limiting; console output is prefixed per
  target. Note this multiplies total load across targets.

### Added
- `methods` module (CWE-749): TRACE echo detection (XST) and
  unauthenticated PUT write probing. The PUT probe uploads one
  uniquely-named marker file, deletes it immediately, and verifies the
  cleanup by content (soft-404-safe), flagging leftovers separately.
- `hostheader` module (CWE-644): spoofed `Host` reflected into response
  bodies or `Location` headers, sampled across the entry page plus crawled
  pages; keeps the original port so probes reach the same listener.
- `nosqli` module (CWE-943): error-based MongoDB operator injection
  (`$ne`/`$gt`/`$regex`/`$where` shapes). Error-signature-only by design —
  boolean differentials on NoSQL endpoints are too noisy for a scanner
  this size, so silent injections are a documented limitation.
- Vuln test app: PUT/DELETE/TRACE/OPTIONS handlers with in-memory file
  store, `/canonical` (Host reflection), `/login-nosql` (Mongo errors),
  `/slow-hub` (crawl-parallelism test entry).

## 2.3.0 (2026-09)

Daily-driver features: batch scanning, authenticated scanning, broader
discovery, and packaging.

> Note: the local working copy was lost to an unrelated workspace cleanup
> and rebuilt from the conversation record at this version; the git history
> therefore restarts here with the v2.3.0 code state.

### Added
- **Batch scanning** (`--targets FILE`): one URL per line (comments and
  duplicates handled), per-target reports plus a combined batch summary
  (HTML + JSON), aggregated `--fail-on` gating, per-target failure
  isolation.
- **Authenticated scanning** (`--login-url` + `--auth-user/--auth-pass`):
  auto-detects the password form, fills and submits it once, harvests the
  session cookies into every worker thread, and the crawler refuses to
  follow logout links so the session survives the whole scan.
- **`--wordlist FILE`**: extra file-exposure paths merged into the
  sensitive module (soft-404 calibration still applies).
- **Crawler discovery**: `sitemap.xml` parsing (incl. one level of
  sitemapindex nesting) and static endpoint extraction from `.js` sources
  and inline `<script>` blocks — SPA/hidden API surfaces become attack
  points.
- **mypy** type checking (clean) wired into CI next to ruff; `dev` extra
  now ships pytest/ruff/mypy/types-requests/build.
- **PyPI release workflow** via Trusted Publishing on GitHub Release.

## 2.2.0 (2026-09)

Blind-injection coverage, browser-confirmed DOM XSS, and CI-grade outputs.

### Added
- **`timing` module** (opt-in `--time-based`): time-based blind SQLi
  (SLEEP / pg_sleep / WAITFOR DELAY) and command injection (shell `sleep`)
  inferred from response delays. Requires a fast baseline, a
  threshold-clearing payload, and a second confirming request; findings are
  worded "possible".
- **`domxss` module** (opt-in `-m domxss`): loads pages in headless
  Chromium via the optional `webvulnscanner[dom]` extra; an init script
  patches innerHTML/outerHTML/document.write/eval/string-setTimeout/
  insertAdjacentHTML and reports when a canary parameter actually reaches
  a sink. Text-Content sinks stay clean by design.
- **SARIF 2.1.0 output** (`--sarif PATH`) for GitHub code scanning.
- **Scan diffing** (`--compare PREV_JSON`): new / fixed / unchanged
  sections in console, JSON and HTML reports; with `--fail-on`, only NEW
  findings can fail the gate (regression-only CI semantics).
- ruff lint (clean) wired into CI; pyproject gains the `dom` and `dev`
  extras and the `slow` pytest marker.

### Fixed
- `resolve_modules` filtered against the default module set, making it
  impossible to select opt-in modules (`-m timing` silently ran nothing).

## 2.1.0 (2026-09)

Hardening for real targets, three new detection modules, and CI integration.

### Added
- New modules: **open redirect** (`redirect`, CWE-601, with a neutral
  control request to avoid flagging fixed SSO bounces), **CORS
  misconfiguration** (`cors`, CWE-942, reflected origins / wildcards),
  **template injection** (`ssti`, CWE-1336, random arithmetic expressions
  in four engine syntaxes with baseline collision guard).
- Adaptive backoff: 429/503 responses honour `Retry-After` (capped at 30s),
  the global request pace doubles (up to a ceiling), and idempotent
  requests retry twice before surfacing the throttled response.
- CSRF-token refresh: POST form probes re-fetch the source page per probe
  so single-use tokens stay valid throughout testing.
- Header/cookie checks now aggregate across every crawled page instead of
  the entry page only.
- CI integration: `--fail-on {info..critical}` exit-code gate and
  `--format json` machine-readable stdout; GitHub Actions workflow running
  the test suite on Python 3.9/3.11/3.13 plus a CLI smoke test.

### Changed
- Boolean-based SQLi differential now uses a **calibration pair** (two
  baseline fetches) with position-aligned volatile-token masking, replacing
  the length/hash heuristic that misjudged dynamic pages.
- `difflib` comparisons run with `autojunk=False` (whitespace was being
  junked on long pages, skewing similarity ratios).

## 2.0.0 (2026-09)

Complete rebuild of the scanner as a modular, tested tool.

### Added
- Same-host BFS crawler: links, HTML forms, robots.txt Disallow discovery.
- New modules: command injection (echo-marker based), path traversal / LFI,
  cookie-attribute checks, WAF/CDN fingerprinting, Spring Actuator / Swagger /
  Adminer exposure checks.
- Soft-404 calibration for sensitive-file detection (content-similarity
  baseline against a random non-existent path).
- Content validators per sensitive path (a real `.git/HEAD` must start with
  `ref: refs/`, etc.).
- XSS canary + metacharacter-survival analysis with context classification
  (HTML / attribute / encoded).
- Boolean-based SQLi differential detection (reported as "possible").
- SSRF/network guard: per-request DNS + IP-category checks including every
  redirect hop; `--allow-private` escape hatch for lab targets.
- Thread pool execution, global rate limiting, capped response bodies.
- HTML report: full HTML escaping, severity filter, CWE links, evidence
  excerpts; timestamped filenames; additional JSON report.
- Bundled vulnerable test app (`tests/vulnapp.py`, 127.0.0.1 only) and a
  pytest suite including end-to-end false-positive control.
- `scripts/generate_sample_report.py` → `docs/sample-report.html`.

### Fixed (vs 1.x)
- `normalize_url` no longer appends `/` to URLs with query strings
  (`http://a.com/page.php?id=1` was corrupted in v1).
- SQLi detection no longer flags any page containing the word "error".
- Sensitive-file detection no longer trusts every HTTP 200 (soft 404s).
- robots.txt is no longer reported as a "sensitive file".
- CLI actually implements the `-u/-r/-m` flags documented in the README.
- Report generation escapes untrusted content (the v1 report could itself
  carry reflected payloads).
- Removed the broken dual `scanner/`+`reference/` package layout.

### Removed
- X-XSS-Protection "missing" finding (header is deprecated; modern browsers
  ignore it).
- lxml hard dependency (falls back to `html.parser`).
