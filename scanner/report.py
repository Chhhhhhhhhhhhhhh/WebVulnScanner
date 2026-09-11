"""Report generation: a self-contained HTML page plus JSON exports.

Every dynamic value goes through ``html.escape`` — a report about XSS
findings must not itself be an XSS vector (the v1 report interpolated
evidence raw).
"""

from __future__ import annotations

import html
import json
import os
import time

from . import __version__
from .models import SEVERITY_LABELS_ZH, SEVERITY_ORDER, ScanResult

SEVERITY_META = {
    "critical": {"color": "#c0392b", "label": "严重", "en": "CRITICAL"},
    "high": {"color": "#e74c3c", "label": "高危", "en": "HIGH"},
    "medium": {"color": "#f39c12", "label": "中危", "en": "MEDIUM"},
    "low": {"color": "#3498db", "label": "低危", "en": "LOW"},
    "info": {"color": "#7f8c8d", "label": "信息", "en": "INFO"},
}

CSS = """
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI","Microsoft YaHei",Roboto,sans-serif;
     background:#f4f5f7;color:#24292f;line-height:1.65;padding:24px}
.container{max-width:960px;margin:0 auto}
.header{background:#1b1f24;color:#fff;padding:28px 32px;border-radius:10px 10px 0 0}
.header h1{font-size:22px;font-weight:700}
.header .sub{font-size:13px;color:#9aa4b2;margin-top:4px}
.meta{background:#fff;padding:16px 32px;border-left:1px solid #e1e4e8;border-right:1px solid #e1e4e8;
      display:grid;grid-template-columns:1fr 1fr;gap:4px 32px;font-size:13px}
.meta .label{color:#57606a;font-weight:600;margin-right:6px}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(110px,1fr));gap:12px;
       padding:20px 32px;background:#fff;border-left:1px solid #e1e4e8;border-right:1px solid #e1e4e8}
.stat-card{text-align:center;padding:14px 8px;border-radius:8px;background:#f6f8fa}
.stat-card .num{font-size:28px;font-weight:800}
.stat-card .label{font-size:12px;color:#57606a;margin-top:2px}
.toolbar{display:flex;gap:8px;flex-wrap:wrap;padding:16px 32px;background:#fff;
         border-left:1px solid #e1e4e8;border-right:1px solid #e1e4e8}
.toolbar button{border:1px solid #d0d7de;background:#f6f8fa;border-radius:16px;padding:4px 14px;
                font-size:12px;cursor:pointer;color:#24292f}
.toolbar button.active{background:#1b1f24;color:#fff;border-color:#1b1f24}
.body{background:#fff;padding:8px 32px 32px;border:1px solid #e1e4e8;border-top:none;
      border-radius:0 0 10px 10px}
.module-title{font-size:15px;font-weight:700;margin:26px 0 12px;padding-bottom:6px;
              border-bottom:2px solid #1b1f24}
.finding{border:1px solid #e1e4e8;border-left-width:4px;border-radius:8px;margin-bottom:10px;overflow:hidden}
.finding-header{display:flex;justify-content:space-between;align-items:center;gap:10px;
                padding:10px 14px;background:#f6f8fa;flex-wrap:wrap}
.finding-title{font-size:14px;font-weight:600}
.severity-badge{font-size:11px;font-weight:700;padding:2px 10px;border-radius:12px;color:#fff;white-space:nowrap}
.finding-body{padding:10px 14px;font-size:13px}
.finding-body p{margin-bottom:6px}
.kv{color:#57606a;font-weight:600;margin-right:4px}
details.evidence-box{margin-top:8px}
details.evidence-box summary{cursor:pointer;color:#57606a;font-size:12px}
details.evidence-box pre{background:#f6f8fa;border:1px solid #e1e4e8;border-radius:6px;padding:10px;
     font-family:Consolas,"SFMono-Regular",Menlo,monospace;font-size:12px;white-space:pre-wrap;
     word-break:break-all;margin-top:6px}
.fix-box{background:#eef6ee;border:1px solid #cde5cd;border-radius:6px;padding:8px 12px;margin-top:8px;font-size:13px}
.finding-meta{font-size:12px;color:#57606a;margin-top:8px;word-break:break-all}
.finding-meta a{color:#0969da;text-decoration:none}
.no-findings{text-align:center;padding:28px;color:#57606a}
.footer{text-align:center;padding:18px;color:#9aa4b2;font-size:11px;margin-top:16px}
@media print{.toolbar{display:none}body{padding:0}}
"""

JS_FILTER = """
function filterFindings(sev, btn){
  document.querySelectorAll('.toolbar button').forEach(function(b){b.classList.remove('active')});
  btn.classList.add('active');
  document.querySelectorAll('.finding').forEach(function(el){
    el.style.display = (sev === 'all' || el.dataset.sev === sev) ? '' : 'none';
  });
}
"""


def _esc(value) -> str:
    return html.escape(str(value if value is not None else ""), quote=True)


def _cwe_link(cwe: str) -> str:
    if not cwe or not cwe.upper().startswith("CWE-"):
        return ""
    number = cwe.split("-", 1)[1]
    return (f'<a href="https://cwe.mitre.org/data/definitions/{_esc(number)}.html" '
            f'target="_blank" rel="noopener">{_esc(cwe)}</a>')


def _stat_cards(result: ScanResult) -> str:
    counts = result.severity_counts
    cards = []
    for sev in sorted(SEVERITY_ORDER, key=lambda s: SEVERITY_ORDER[s], reverse=True):
        meta = SEVERITY_META[sev]
        cards.append(
            f'<div class="stat-card"><div class="num" style="color:{meta["color"]}">'
            f'{counts.get(sev, 0)}</div><div class="label">{meta["label"]} {meta["en"]}</div></div>'
        )
    return "".join(cards)


def _toolbar() -> str:
    buttons = ['<button class="active" onclick="filterFindings(\'all\',this)">全部 All</button>']
    for sev in ("critical", "high", "medium", "low", "info"):
        meta = SEVERITY_META[sev]
        buttons.append(
            f'<button onclick="filterFindings(\'{sev}\',this)">{meta["label"]} {meta["en"]}</button>'
        )
    return "".join(buttons)


def _finding_html(finding) -> str:
    meta = SEVERITY_META.get(finding.severity, SEVERITY_META["info"])
    zh = SEVERITY_LABELS_ZH.get(finding.severity, finding.severity)

    evidence_html = ""
    if finding.evidence:
        evidence_html = (
            '<details class="evidence-box"><summary>证据 Evidence</summary>'
            f"<pre>{_esc(finding.evidence)}</pre></details>"
        )
    fix_html = ""
    if finding.fix:
        fix_html = f'<div class="fix-box"><span class="kv">修复建议 Fix:</span>{_esc(finding.fix)}</div>'

    meta_bits = []
    if finding.url:
        meta_bits.append(f'<span class="kv">URL:</span>{_esc(finding.url)}')
    if finding.param:
        meta_bits.append(f'<span class="kv">参数 Param:</span><code>{_esc(finding.param)}</code>')
    if finding.cwe:
        meta_bits.append(f'<span class="kv">CWE:</span>{_cwe_link(finding.cwe)}')
    meta_html = f'<div class="finding-meta">{" &nbsp;|&nbsp; ".join(meta_bits)}</div>' if meta_bits else ""

    return (
        f'<div class="finding" data-sev="{_esc(finding.severity)}" '
        f'style="border-left-color:{meta["color"]}">'
        f'<div class="finding-header">'
        f'<span class="finding-title">{_esc(finding.title)}</span>'
        f'<span class="severity-badge" style="background:{meta["color"]}">{zh} / {meta["en"]}</span>'
        f"</div>"
        f'<div class="finding-body">'
        f"<p>{_esc(finding.description)}</p>"
        f"{evidence_html}{fix_html}{meta_html}"
        f"</div></div>"
    )


def _comparison_html(comparison: dict | None) -> str:
    if not comparison:
        return ""
    new_items = comparison.get("new", [])
    fixed_items = comparison.get("fixed", [])
    rows = [
        f'<div class="stat-card"><div class="num" style="color:#c0392b">{len(new_items)}</div>'
        f'<div class="label">新增 New</div></div>',
        f'<div class="stat-card"><div class="num" style="color:#27ae60">{len(fixed_items)}</div>'
        f'<div class="label">已修复 Fixed</div></div>',
        f'<div class="stat-card"><div class="num" style="color:#57606a">{comparison.get("unchanged", 0)}</div>'
        f'<div class="label">未变化 Unchanged</div></div>',
    ]
    listing = ""
    for item in new_items[:5]:
        listing += (f'<div class="finding" data-sev="{_esc(item.get("severity", "info"))}" '
                    f'style="border-left-color:#c0392b"><div class="finding-header">'
                    f'<span class="finding-title">新增: {_esc(item.get("title", ""))}</span>'
                    f'<span class="severity-badge" style="background:#c0392b">NEW</span></div></div>')
    for item in fixed_items[:5]:
        listing += (f'<div class="finding" data-sev="info" style="border-left-color:#27ae60">'
                    f'<div class="finding-header">'
                    f'<span class="finding-title">已修复: {_esc(item.get("title", ""))}</span>'
                    f'<span class="severity-badge" style="background:#27ae60">FIXED</span></div></div>')
    caption = _esc(comparison.get("previous", ""))
    return (
        f'<div class="module-title">与上次扫描对比 vs previous scan</div>'
        f'<p style="font-size:13px;color:#57606a">基准 Baseline: {caption}</p>'
        f'<div class="stats" style="border:1px solid #e1e4e8;border-radius:8px;margin-bottom:10px">'
        + "".join(rows) + "</div>" + listing
    )


def render_html(result: ScanResult, tool_version: str | None = None) -> str:
    tool_version = tool_version or __version__
    total = len(result.findings)
    started = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(result.started_at))

    modules_html = []
    for module_id in result.modules_run:
        module_findings = [f for f in result.sorted_findings() if f.module == module_id]
        cards = "".join(_finding_html(f) for f in module_findings)
        body = cards or '<div class="no-findings">未发现问题 No findings</div>'
        modules_html.append(f'<div class="module-title">{_esc(module_id)}</div>{body}')

    if not result.modules_run:
        modules_html.append('<div class="no-findings">没有运行任何模块</div>')

    comparison_block = _comparison_html(result.comparison)

    return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>WebVulnScanner 报告 - {_esc(result.target)}</title>
<style>{CSS}</style>
</head>
<body>
<div class="container">
  <div class="header">
    <h1>WebVulnScanner 扫描报告</h1>
    <div class="sub">仅供授权安全测试使用 For authorised security testing only</div>
  </div>
  <div class="meta">
    <div><span class="label">目标 Target</span><span class="value">{_esc(result.target)}</span></div>
    <div><span class="label">扫描时间 Time</span>{started}</div>
    <div><span class="label">耗时 Duration</span>{result.duration:.1f} s</div>
    <div><span class="label">工具版本 Tool</span>v{_esc(tool_version)}</div>
    <div><span class="label">抓取页面 Pages</span>{result.pages_crawled}</div>
    <div><span class="label">测试参数 Params</span>{result.attack_points}</div>
    <div><span class="label">发出请求 Requests</span>{result.stats.requests}</div>
    <div><span class="label">发现问题 Findings</span>{total}</div>
  </div>
  <div class="stats">{_stat_cards(result)}</div>
  <div class="toolbar">{_toolbar()}</div>
  <div class="body">{comparison_block}{''.join(modules_html)}</div>
  <div class="footer">Generated by WebVulnScanner v{_esc(tool_version)} · 扫描结果为自动化判断，请人工复核后处置</div>
</div>
<script>{JS_FILTER}</script>
</body>
</html>"""


def render_json(result: ScanResult) -> str:
    return json.dumps(result.to_dict(), ensure_ascii=False, indent=2)


def render_batch_html(results: list, tool_version: str | None = None) -> str:
    """Summary page for a multi-target batch; details live in per-target reports."""
    tool_version = tool_version or __version__
    total_counts: dict = {}
    for result in results:
        for sev, count in result.severity_counts.items():
            total_counts[sev] = total_counts.get(sev, 0) + count
    total_findings = sum(total_counts.values())
    started = min((r.started_at for r in results), default=time.time())

    cards = "".join(
        f'<div class="stat-card"><div class="num" style="color:{SEVERITY_META[sev]["color"]}">'
        f'{total_counts.get(sev, 0)}</div>'
        f'<div class="label">{SEVERITY_META[sev]["label"]} {SEVERITY_META[sev]["en"]}</div></div>'
        for sev in sorted(SEVERITY_ORDER, key=lambda s: SEVERITY_ORDER[s], reverse=True)
    )

    rows = ""
    for result in results:
        counts = result.severity_counts
        chips = " ".join(
            f'<span class="severity-badge" style="background:{SEVERITY_META[sev]["color"]}">'
            f'{SEVERITY_META[sev]["label"]} {counts[sev]}</span>'
            for sev in ("critical", "high", "medium", "low", "info") if counts.get(sev)
        )
        rows += (
            f'<div class="finding" data-sev="info" style="border-left-color:#57606a">'
            f'<div class="finding-header"><span class="finding-title">{_esc(result.target)}</span>'
            f'<span>{chips or "无发现 No findings"}</span></div>'
            f'<div class="finding-body"><p>'
            f'<span class="kv">页面:</span>{result.pages_crawled} &nbsp; '
            f'<span class="kv">请求:</span>{result.stats.requests} &nbsp; '
            f'<span class="kv">耗时:</span>{result.duration:.1f}s &nbsp; '
            f'<span class="kv">共:</span>{len(result.findings)}'
            f"</p></div></div>"
        )

    return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>WebVulnScanner 批量报告 - {len(results)} target(s)</title>
<style>{CSS}</style>
</head>
<body>
<div class="container">
  <div class="header">
    <h1>WebVulnScanner 批量扫描报告</h1>
    <div class="sub">{len(results)} 个目标 · {time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(started))} · 仅供授权安全测试使用</div>
  </div>
  <div class="stats" style="border:1px solid #e1e4e8;border-radius:10px 10px 0 0;padding-top:20px">{cards}</div>
  <div class="body" style="border-radius:0 0 10px 10px">
    <div class="module-title">目标明细 ({len(results)}) · 共 {total_findings} 个发现</div>
    {rows or '<div class="no-findings">没有结果</div>'}
  </div>
  <div class="footer">Generated by WebVulnScanner v{_esc(tool_version)} · 每个目标的完整报告见各自的 scan_*.html</div>
</div>
</body>
</html>"""


def render_batch_json(results: list) -> str:
    payload = {
        "meta": {
            "targets": len(results),
            "total_findings": sum(len(r.findings) for r in results),
        },
        "targets": [r.to_dict() for r in results],
    }
    return json.dumps(payload, ensure_ascii=False, indent=2)


def default_report_paths(result: ScanResult, base_dir: str = "reports") -> tuple:
    host = result.target.split("//", 1)[-1].split("/")[0].replace(":", "_")
    stamp = time.strftime("%Y%m%d_%H%M%S", time.localtime(result.started_at))
    stem = os.path.join(base_dir, f"scan_{host}_{stamp}")
    return f"{stem}.html", f"{stem}.json"


def write_reports(result: ScanResult, html_path: str, json_path: str | None = None) -> tuple:
    written = []
    for path, content in ((html_path, render_html(result)), (json_path, render_json(result))):
        if not path:
            continue
        directory = os.path.dirname(os.path.abspath(path))
        os.makedirs(directory, exist_ok=True)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(content)
        written.append(os.path.abspath(path))
    return tuple(written)
