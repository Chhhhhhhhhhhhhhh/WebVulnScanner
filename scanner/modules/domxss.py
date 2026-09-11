"""DOM-based XSS detection via a real browser (opt-in: ``-m domxss``).

Requires the optional extra::

    pip install "webvulnscanner[dom]"      # or: pip install playwright
    playwright install chromium

For every discovered GET parameter the module loads the page in headless
Chromium with an alphanumeric canary in that parameter. An init script —
injected *before* the page's own scripts run — patches the classic DOM XSS
sinks (``innerHTML``/``outerHTML`` setters, ``document.write``, ``eval``,
string ``setTimeout``, ``insertAdjacentHTML``) and records any call whose
argument carries the canary. A hit means attacker-controlled URL data
actually flows into an HTML/script sink, which static "scan the JS for
innerHTML" heuristics can only guess at.

The module runs sequentially: one browser, one page, no thread pool.
"""

from __future__ import annotations

import secrets
from urllib.parse import urlencode, urlsplit, urlunsplit

from .base import BaseModule, ScanContext
from ..models import Finding

MAX_URLS = 25
PAGE_LOAD_TIMEOUT_MS = 15000
SETTLE_DELAY_MS = 700

SINK_PATCH_JS = """
(() => {
  const canary = '%(canary)s';
  window.__wvsSinks = [];
  const record = (sink, arg) => {
    try {
      const text = String(arg);
      if (text.indexOf(canary) !== -1) {
        window.__wvsSinks.push(sink + ' :: ' + text.slice(0, 160));
      }
    } catch (e) {}
  };
  const patch = (obj, prop) => {
    try {
      const desc = Object.getOwnPropertyDescriptor(obj, prop);
      if (!desc || !desc.set) return;
      Object.defineProperty(obj, prop, {
        set(v) { record(prop, v); desc.set.call(this, v); },
        get() { return desc.get.call(this); },
        configurable: true,
      });
    } catch (e) {}
  };
  patch(Element.prototype, 'innerHTML');
  patch(Element.prototype, 'outerHTML');
  patch(ShadowRoot.prototype, 'innerHTML');
  const docWrite = document.write.bind(document);
  document.write = (...args) => { record('document.write', args.join(' ')); return docWrite(...args); };
  const docWriteln = document.writeln.bind(document);
  document.writeln = (...args) => { record('document.writeln', args.join(' ')); return docWriteln(...args); };
  const origEval = window.eval;
  window.eval = (code) => { record('eval', code); return origEval(code); };
  const origTimeout = window.setTimeout;
  window.setTimeout = (fn, ...rest) => {
    if (typeof fn === 'string') record('setTimeout', fn);
    return origTimeout(fn, ...rest);
  };
  const origInsert = Element.prototype.insertAdjacentHTML;
  Element.prototype.insertAdjacentHTML = function (pos, html) {
    record('insertAdjacentHTML', html);
    return origInsert.call(this, pos, html);
  };
})();
"""


def build_probe_url(url: str, params: dict, param: str, value: str) -> str:
    merged = dict(params)
    merged[param] = value
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(merged), ""))


class DomXssModule(BaseModule):
    id = "domxss"
    name = "DOM XSS (browser)"

    def run(self, ctx: ScanContext) -> list:
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            ctx.log(f"[!] {self.name}: playwright is not installed; skipping "
                    '(pip install "webvulnscanner[dom]" && playwright install chromium)')
            return []

        points = [p for p in ctx.build_attack_points() if p.method == "GET"][:MAX_URLS]
        if not points:
            ctx.log(f"[*] {self.name}: no GET parameters found, skipping")
            return []

        canary = "wvs" + secrets.token_hex(6)
        findings: list[Finding] = []

        with sync_playwright() as pw:
            try:
                browser = pw.chromium.launch(headless=True)
            except Exception as exc:
                ctx.log(f"[!] {self.name}: cannot launch Chromium ({exc.__class__.__name__}); "
                        "run `playwright install chromium`")
                return []
            context = browser.new_context(
                ignore_https_errors=not ctx.client.verify_tls,
                user_agent=ctx.client.user_agent,
            )
            context.add_init_script(SINK_PATCH_JS % {"canary": canary})
            page = context.new_page()

            for point in points:
                probe_url = build_probe_url(point.url, point.params, point.param, canary)
                try:
                    page.goto(probe_url, timeout=PAGE_LOAD_TIMEOUT_MS,
                              wait_until="domcontentloaded")
                    page.wait_for_timeout(SETTLE_DELAY_MS)
                    hits = page.evaluate("window.__wvsSinks || []")
                except Exception:
                    continue
                for hit in hits[:3]:
                    sink = hit.split(" :: ", 1)[0]
                    is_script_sink = sink in ("eval", "setTimeout")
                    findings.append(Finding(
                        module=self.id,
                        check_id="domxss.sink",
                        severity="critical" if is_script_sink else "high",
                        title=f"DOM XSS: parameter '{point.param}' reaches {sink}()",
                        description=(f"The URL parameter '{point.param}' flows into the "
                                     f"{sink} sink during page load in a real browser. "
                                     + ("Script sinks allow direct JavaScript execution; "
                                        if is_script_sink else
                                        "HTML sinks allow arbitrary markup injection; ")
                                     + "payloads require no server-side reflection."),
                        evidence=hit[:240],
                        fix="Avoid feeding URL data (location.search/hash/referrer) into "
                             "innerHTML/eval-style sinks. Use textContent for text, "
                             "DOMPurify for HTML, and never eval dynamic strings.",
                        cwe="CWE-79",
                        url=point.url,
                        param=point.param,
                    ))

            context.close()
            browser.close()
        return findings
