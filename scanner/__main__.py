import sys
import os
from .utils import normalize_url
from .info_scanner import check_security_headers, check_sensitive_files, check_server_fingerprint
from .vuln_scanner import check_sql_injection, check_xss
from .report import generate_report

def main():
    if len(sys.argv) < 2:
        print("用法：python scanner <URL> ")
        print("示例：python scanner http://example.com")
        return
    
    target_url = normalize_url(sys.argv[1])
    print(f"正在扫描: {target_url}")

    print("[*]检测安全头...")
    info_findings = check_security_headers(target_url)

    print("[*]检测服务器指纹...")
    info_findings += check_server_fingerprint(target_url)

    print("[*]检测敏感文件...")
    info_findings += check_sensitive_files(target_url)

    print("[*]检测 SQL 注入...")
    vuln_findings = check_sql_injection(target_url)

    print("[*]检测 XSS...")
    vuln_findings += check_xss(target_url)

    print("[*]生成报告...")
    report_html = generate_report(target_url, info_findings, vuln_findings)

    report_dir = os.path.join(os.path.dirname(__file__),"..", "reports")
    os.makedirs(report_dir, exist_ok=True)
    report_path = os.path.join(report_dir, "report.html")
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(report_html)

    total = len(info_findings) + len(vuln_findings)
    print(f"扫描完成！共发现 {total} 个问题。报告已保存到 {report_path}")

if __name__ == "__main__":
    main()