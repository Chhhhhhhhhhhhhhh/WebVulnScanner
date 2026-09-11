# WebVulnScanner

[![CI](https://github.com/Chhhhhhhhhhhhhhh/WebVulnScanner/actions/workflows/ci.yml/badge.svg)](https://github.com/Chhhhhhhhhhhhhhh/WebVulnScanner/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/webvulnscanner)](https://pypi.org/project/webvulnscanner/)

A lightweight, dependency-minimal web vulnerability scanner for **authorised
security testing**. Point it at a target you are allowed to test (or a whole
file of them) and it crawls the attack surface — links, forms, robots.txt,
sitemap.xml, endpoints embedded in JavaScript — logs in if you give it
credentials, runs focused detection modules, and produces HTML + JSON (+SARIF)
reports with severity ratings, evidence, CWE references and remediation
advice, plus CI-friendly exit codes and machine-readable output.

> 🔬 A fully self-contained **vulnerable test app** ships in `tests/vulnapp.py`
> (binds to 127.0.0.1, fictional data only) so you can try every module
> without touching any real target. See [Try it safely](#try-it-safely-in-30-seconds).

**[View a sample report](docs/sample-report.html)** — generated from the bundled
test app.

## What's new in v2

v1 was a single-file prototype: it matched the words "error/sql" in any
response to "detect SQLi", counted any HTTP 200 as a sensitive file, and
never escaped its own report. v2 is a ground-up rebuild:

| Area | v1 | v2 |
|------|----|----|
| Architecture | two parallel packages with broken cross-imports | one package, module registry, thread pool |
| Discovery | single URL only | BFS crawler (links + forms + robots.txt + sitemap.xml + JS-embedded endpoints) |
| Auth | manual cookie only | automatic form login (`--login-url`), session maintained, logout links refused |
| Scale | one target | batch mode (`--targets file`) with per-target + summary reports |
| SQLi | `"error" in page` → false positives on any error page | DB-specific error signatures + calibrated boolean differential; opt-in time-based blind checks |
| XSS | raw payload substring match | canary + metacharacter-survival analysis; opt-in browser-confirmed DOM XSS |
| Command injection | documented, never implemented | harmless `echo <random-marker>` probes with echo-stripping; time-based variant |
| Path traversal / SSTI / CORS / open redirect | none | content-verified detection with neutral-control guards |
| Sensitive files | any HTTP 200 counts (soft-404 chaos) | soft-404 calibration + per-file content validators + user wordlists |
| Reports | unescaped HTML (XSS-in-the-report), overwritten each run | escaped HTML with severity filter + CWE links, JSON, SARIF 2.1.0, batch summaries, scan diffing |
| Concurrency / politeness | none | thread pool, rate limiting, capped bodies, 429/503 adaptive backoff |
| SSRF safety | one DNS check at startup | per-request guard incl. **every redirect hop**; private ranges blocked unless `--allow-private` |
| Quality | no tests, no CI | 104 pytest tests (e2e + false-positive control), ruff + mypy clean, GitHub Actions matrix + CLI smoke test |

## Modules

| Module id | What it detects |
|-----------|-----------------|
| `headers` | Missing CSP / HSTS / X-Frame-Options / nosniff / Referrer-Policy / Permissions-Policy, HTTPS not enforced, server version disclosure, cookie flags (HttpOnly / Secure / SameSite) — aggregated across all crawled pages |
| `fingerprint` | Server & runtime software, CMS/framework signatures, backend language from cookies, WAF/CDN presence |
| `sensitive` | Exposed `.git`, `.svn`, `.env`, DB dumps, phpinfo, Adminer, Actuator, Swagger, `.htaccess`, `web.config`, `.DS_Store`, directory listings — soft-404-calibrated, extensible via `--wordlist` |
| `sqli` | Error-based SQL injection (MySQL/MariaDB/PostgreSQL/SQLite/SQL Server/Oracle/DB2/JDBC/PDO signatures); boolean-based differential with volatile-content calibration (reported as *possible*) |
| `xss` | Reflected XSS via canary + character-survival analysis; distinguishes HTML-context, attribute-context and properly-encoded reflections |
| `cmdi` | OS command injection via harmless `echo` markers (`;` `\|` `&&` `\|\|` newline, `$()`, backticks, Windows `&`) |
| `lfi` | Path traversal / local file inclusion with content verification |
| `redirect` | Open redirects (CWE-601) with a neutral control request so pages that legitimately bounce off-site are not flagged |
| `cors` | CORS misconfiguration (CWE-942): reflected arbitrary origins (with/without credentials) and wildcard policies |
| `ssti` | Server-side template injection (CWE-1336) via random arithmetic expressions in four engine syntaxes |
| `timing` *(opt-in, `--time-based`)* | Blind SQL/command injection inferred from response delays (SLEEP/pg_sleep/WAITFOR and shell `sleep`), double-confirmed; slower because winning probes really sleep |
| `domxss` *(opt-in, `-m domxss`)* | DOM XSS confirmed in a real browser: canary parameters + patched sinks (innerHTML, document.write, eval, …). Requires `pip install "webvulnscanner[dom]" && playwright install chromium` |

## Install

```bash
git clone <this-repo> && cd WebVulnScanner
pip install -r requirements.txt      # requests + beautifulsoup4
```

Python 3.9+. No compiled dependencies (parses with `html.parser`).
Also publishable as a package: `pip install webvulnscanner` once the
release workflow has run.

## Usage

```bash
# Basic scan (all default modules, HTML + JSON report in reports/)
python -m scanner -u https://target.example.com

# Only injection modules, 8 threads, custom report path
python -m scanner -u "https://target.example.com/search?q=test" -m sqli,xss,cmdi -t 8 -r out/report.html

# Batch: a file of targets, per-target reports + a summary report
python -m scanner --targets urls.txt --fail-on high --format json

# Authenticated scanning: auto-fill the login form, keep the session
python -m scanner -u https://target.example.com \
    --login-url https://target.example.com/login --auth-user demo --auth-pass demo123

# Extra sensitive paths from your own wordlist
python -m scanner -u https://target.example.com --wordlist paths.txt

# Politeness: 0.5s between requests, single URL only (no crawling)
python -m scanner -u https://target.example.com --delay 0.5 --no-crawl

# Lab target on localhost (e.g. DVWA): allow private ranges, skip TLS verify
python -m scanner -u http://127.0.0.1:8080/ --allow-private -k --cookie "PHPSESSID=abc; security=low"

# CI gate: fail the pipeline when high/critical findings exist; JSON to stdout
python -m scanner -u https://target.example.com --fail-on high --format json --no-report

# Regression gate against yesterday's report (only NEW findings can fail)
python -m scanner -u https://target.example.com --compare reports/scan_prev.json \
    --fail-on high --sarif out.sarif --format json --no-report

# Blind injection via timing + DOM XSS with a real browser
python -m scanner -u https://target.example.com --time-based
pip install "webvulnscanner[dom]" && playwright install chromium
python -m scanner -u https://target.example.com -m domxss
```

### All options

| Option | Default | Description |
|--------|---------|-------------|
| `-u, --url` / `--targets FILE` | — | Single target URL, or a file with one URL per line (batch mode; mutually exclusive, one required) |
| `-m, --modules` | all defaults | Comma-separated module ids from the table above |
| `-r, --report PATH` | `reports/scan_<host>_<ts>.html` | HTML report path (single-target only) |
| `--json PATH` | next to HTML | Additional JSON report |
| `--sarif PATH` | — | Additional SARIF 2.1.0 report (GitHub code scanning; single-target only) |
| `--compare PREV_JSON` | — | Diff against a previous JSON report; with `--fail-on`, only NEW findings count (single-target only) |
| `--no-report` | — | Print findings to console only |
| `--no-crawl` | — | Test only the given URL and its forms |
| `--depth N` | 2 | Crawl depth |
| `--max-pages N` | 30 | Crawl page budget |
| `-t, --threads N` | 4 | Worker threads |
| `--delay SEC` | 0 | Minimum delay between any two requests |
| `--timeout SEC` | 10 | Per-request timeout |
| `--cookie STR` | — | Cookie header for authenticated scanning |
| `--login-url URL` | — | Login page for automatic form login |
| `--auth-user` / `--auth-pass` | — | Credentials for `--login-url` |
| `--wordlist FILE` | — | Extra file-exposure paths (one per line, `#` comments) |
| `-A, --user-agent` | WebVulnScanner | Custom User-Agent |
| `--proxy URL` | — | HTTP(S) proxy |
| `-k, --insecure` | — | Skip TLS certificate verification |
| `--allow-private` | — | Permit loopback/private targets (labs only) |
| `-v, --verbose` | — | Log every request |
| `--fail-on {none,info,low,medium,high,critical}` | `none` | Exit code 1 when findings at/above this severity exist (CI gate) |
| `--format {text,json}` | `text` | `json` prints the machine-readable result to stdout and silences progress output |
| `--time-based` | off | Add the time-based blind injection module (slower; probes really sleep) |

## Try it safely in 30 seconds

```bash
# Terminal 1: start the bundled vulnerable app
python tests/vulnapp.py            # http://127.0.0.1:8099

# Terminal 2: scan it
python -m scanner -u http://127.0.0.1:8099/ --allow-private
```

The app intentionally contains reflected XSS, error-based SQLi (GET and a
CSRF-protected POST form with single-use tokens), command injection, path
traversal, open redirect, template injection, a CORS misconfiguration, an
exposed `.env`, soft-404 behaviour (to demonstrate calibration), a
rate-limit endpoint, a login-gated area (for authenticated scanning),
sitemap/JS-only endpoints (for discovery tests) and a safe page that must
produce **no** false positives.

## Testing

```bash
pip install "webvulnscanner[dev]"
python -m pytest
```

104 tests: unit tests (URL handling, reflection analysis, echo stripping,
network guard, adaptive backoff, page-equivalence calibration, report
escaping, CLI gate/format/SARIF/diff) and end-to-end scans of the bundled
app asserting both true positives **and** false-positive control. The
browser-based DOM XSS test runs when playwright is installed and skips
otherwise. GitHub Actions runs ruff + mypy and the suite on Python
3.9/3.11/3.13 plus a CLI smoke test (`.github/workflows/ci.yml`); releases
publish to PyPI via Trusted Publishing (`.github/workflows/pypi.yml`).

## Project layout

```
scanner/
├── cli.py            # argument parsing, single-target + batch orchestration
├── scanner.py        # ScanConfig + Scanner (orchestrator)
├── httpclient.py     # thread-safe client: guard, redirects, rate limit, backoff
├── crawler.py        # same-host BFS crawler (links/forms/robots/sitemap/JS)
├── auth.py           # automatic login for authenticated scanning
├── target.py         # URL normalisation & scope helpers
├── models.py         # Finding / CrawlResult / ScanResult
├── report.py         # HTML + JSON + batch report rendering
├── sarif.py          # SARIF 2.1.0 rendering
└── modules/          # one file per detection module + registry
tests/
├── vulnapp.py        # bundled vulnerable app (127.0.0.1, fictional data)
└── test_*.py         # unit + end-to-end suite
scripts/
└── generate_sample_report.py
docs/
└── sample-report.html
```

## Design notes & limitations

* **False-positive control is a feature.** Findings carry evidence excerpts
  for manual verification; boolean-based SQLi, time-based findings and
  attribute-context XSS are deliberately downgraded to *possible / medium*.
* Time-based and DOM-XSS modules are opt-in because they trade speed (real
  sleeps, a full browser) for coverage of blind and client-side bugs.
* The crawler executes no JavaScript itself; JS is mined statically for
  endpoint paths, and the `domxss` module covers client-side sinks when a
  browser is available.
* The network guard resolves DNS once per host per run; a determined
  DNS-rebinding setup is out of scope for a lightweight scanner.
* Respect your authorisation, your target's capacity, and the law: use
  `--delay`, keep `--threads` modest, and scan only what you own or are
  explicitly permitted to test.

## Contributing

PRs welcome — new modules should subclass `BaseModule` (or `VulnModule` for
parameter-oriented checks), register in `scanner/modules/__init__.py`, and
come with tests against the bundled app (add a route to `tests/vulnapp.py`).
`ruff check` and `mypy` must stay clean.

## License

[MIT](LICENSE)

## Disclaimer

This tool is for **educational purposes and authorised security testing
only**. Always obtain written permission before scanning any target you do
not own. The authors accept no liability for misuse.
