"""
HTML 报告生成模块
根据扫描结果自动生成结构化的安全报告
"""

import os
from datetime import datetime
from scanner.utils import severity_level

SEVERITY_STYLES = {
    "critical": {"color": "#dc3545", "label": "严重", "icon": "X"},
    "high": {"color": "#e67e22", "label": "高危", "icon": "!"},
    "medium": {"color": "#f39c12", "label": "中危", "icon": "?"},
    "low": {"color": "#3498db", "label": "低危", "icon": "i"},
    "info": {"color": "#95a5a6", "label": "信息", "icon": "-"},
}


REPORT_TEMPLATE = """<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<title>WebVulnScanner - 安全扫描报告</title>
<style>
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
    background: #f5f6fa; color: #2d3436; line-height: 1.7; padding: 24px;
  }}
  .container {{ max-width: 900px; margin: 0 auto; }}
  .header {{
    background: #2d3436; color: #fff; padding: 32px; border-radius: 8px 8px 0 0;
    text-align: center;
  }}
  .header h1 {{ font-size: 24px; font-weight: 700; margin-bottom: 8px; }}
  .header p {{ font-size: 13px; color: #b2bec3; }}
  .meta {{
    background: #fff; padding: 20px 32px; border-left: 1px solid #e0e0e0;
    border-right: 1px solid #e0e0e0; font-size: 13px;
  }}
  .meta grid {{
    display: grid; grid-template-columns: 1fr 1fr; gap: 8px;
  }}
  .meta .label {{ color: #636e72; font-weight: 500; }}
  .stats {{
    display: grid; grid-template-columns: repeat({col_count}, 1fr);
    gap: 12px; padding: 20px 32px; background: #fff;
    border-left: 1px solid #e0e0e0; border-right: 1px solid #e0e0e0;
  }}
  .stat-card {{
    text-align: center; padding: 16px; border-radius: 6px;
    background: #f8f9fa;
  }}
  .stat-card .num {{ font-size: 32px; font-weight: 700; }}
  .stat-card .label {{ font-size: 12px; color: #636e72; margin-top: 4px; }}
  .body {{
    background: #fff; padding: 24px 32px 32px;
    border: 1px solid #e0e0e0; border-top: none; border-radius: 0 0 8px 8px;
  }}
  .module-title {{
    font-size: 18px; font-weight: 700; margin: 24px 0 16px;
    padding-bottom: 8px; border-bottom: 2px solid #2d3436;
  }}
  .module-title:first-child {{ margin-top: 0; }}
  .finding {{
    border: 1px solid #e0e0e0; border-radius: 6px;
    margin-bottom: 12px; overflow: hidden;
    border-left: 4px solid {left_color};
  }}
  .finding-header {{
    display: flex; justify-content: space-between; align-items: center;
    padding: 12px 16px; background: #f8f9fa; flex-wrap: wrap; gap: 8px;
  }}
  .finding-title {{ font-size: 14px; font-weight: 600; }}
  .severity-badge {{
    font-size: 11px; font-weight: 600; padding: 2px 10px;
    border-radius: 12px; color: #fff;
  }}
  .finding-body {{ padding: 12px 16px; font-size: 13px; }}
  .finding-body p {{ margin-bottom: 6px; }}
  .finding-body .label-text {{ color: #636e72; font-weight: 500; }}
  .evidence {{
    background: #f1f3f5; padding: 8px 12px; border-radius: 4px;
    font-family: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, monospace;
    font-size: 12px; word-break: break-all; margin-top: 8px;
  }}
  .fix {{
    background: #dfe6e9; padding: 8px 12px; border-radius: 4px;
    margin-top: 8px;
  }}
  .fix .label-text {{ color: #2d3436; font-weight: 600; }}
  .no-findings {{
    text-align: center; padding: 32px; color: #636e72; font-size: 14px;
  }}
  .footer {{
    text-align: center; padding: 20px; color: #b2bec3; font-size: 11px;
    margin-top: 24px;
  }}
</style>
</head>
<body>
<div class="container">

  <div class="header">
    <h1>WebVulnScanner</h1>
    <p>自动化 Web 安全扫描报告</p>
  </div>

  <div class="meta">
    <p><span class="label">目标：</span>{target}</p>
    <p><span class="label">扫描时间：</span>{scan_time}</p>
    <p><span class="label">扫描模块：</span>{modules}</p>
    <p><span class="label">发现问题：</span>{total_count} 个</p>
  </div>

  <div class="stats">
    {stat_cards}
  </div>

  <div class="body">
    {findings_html}
  </div>

  <div class="footer">
    <p>本报告由 WebVulnScanner 自动生成 | 仅供授权安全测试使用</p>
  </div>

</div>
</body>
</html>"""


def generate_report(scan_results, target_url, output_path="report.html"):
    """根据扫描结果生成 HTML 报告"""
    all_findings = []
    for module_result in scan_results:
        all_findings.extend(module_result.get("findings", []))

    # 统计各级别数量
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in all_findings:
        sev = f.get("severity", "info")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    # 统计卡片（只显示有发现的级别）
    active_levels = [(k, v) for k, v in severity_counts.items() if v > 0]
    col_count = max(len(active_levels), 2)

    stat_cards = ""
    for level, count in active_levels:
        style = SEVERITY_STYLES.get(level, SEVERITY_STYLES["info"])
        stat_cards += f"""
    <div class="stat-card">
      <div class="num" style="color: {style['color']}">{count}</div>
      <div class="label">{style['label']}</div>
    </div>"""

    # 生成发现详情
    findings_html = ""
    for module_result in scan_results:
        findings = module_result.get("findings", [])
        module_name = module_result.get("module", "未知模块")

        findings_html += f'<div class="module-title">{module_name}</div>'

        if not findings:
            findings_html += '<div class="no-findings">未发现问题</div>'
            continue

        for f in sorted(findings, key=lambda x: severity_level(x.get("severity", "info")), reverse=True):
            sev = f.get("severity", "info")
            style = SEVERITY_STYLES.get(sev, SEVERITY_STYLES["info"])

            fix_html = ""
            if f.get("fix"):
                fix_html = f'<div class="fix"><span class="label-text">修复建议：</span>{f["fix"]}</div>'

            evidence_html = ""
            if f.get("evidence"):
                evidence_html = f'<div class="evidence">{f["evidence"]}</div>'

            findings_html += f"""
    <div class="finding" style="border-left-color: {style['color']}">
      <div class="finding-header">
        <span class="finding-title">{f.get('title', '未知发现')}</span>
        <span class="severity-badge" style="background: {style['color']}">{style['label']}</span>
      </div>
      <div class="finding-body">
        <p>{f.get('description', '')}</p>
        {evidence_html}
        {fix_html}
      </div>
    </div>"""

    # 渲染报告
    report = REPORT_TEMPLATE.format(
        target=target_url,
        scan_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        modules=", ".join(r.get("module", "") for r in scan_results),
        total_count=len(all_findings),
        col_count=col_count,
        stat_cards=stat_cards,
        findings_html=findings_html,
        left_color="#e74c3c",
    )

    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write(report)

    return output_path, len(all_findings)
