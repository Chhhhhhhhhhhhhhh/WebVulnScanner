def generate_report(url, info_findings, vuln_findings):
    all_findings = info_findings + vuln_findings
    
    html = f"""
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <title>WebVulnScanner 报告</title>
    <style>
        body {{ font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; }}
        h1 {{ color: #333; }}
        .finding {{ border: 1px solid #ddd; padding: 15px; margin: 10px 0; border-radius: 5px; }}
        .high {{ border-left: 5px solid #e74c3c; }}
        .medium {{ border-left: 5px solid #f39c12; }}
        .low {{ border-left: 5px solid #3498db; }}
        .info {{ border-left: 5px solid #95a5a6; }}
        .severity {{ display: inline-block; padding: 3px 8px; border-radius: 3px; font-size: 12px; color: white; }}
        .severity.high {{ background: #e74c3c; }}
        .severity.medium {{ background: #f39c12; }}
        .severity.low {{ background: #3498db; }}
        .severity.info {{ background: #95a5a6; }}

    </style>
</head>
<body>
    <h1>WebVulnScanner 扫描报告</h1>
    <p>目标: {url}</p>
    <p>共发现 {len(all_findings)} 个问题</p>
"""
    # 遍历每个 finding，拼接到 html 里
    for f in all_findings:
        html += f"""
    <div class="finding {f['severity']}">
        <h3>{f['title']}</h3>
        <span class="severity {f['severity']}">{f['severity']}</span>
        <p>{f['description']}</p>
    </div>
"""

    html += """
</body>
</html>"""
    return html