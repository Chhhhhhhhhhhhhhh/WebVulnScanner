"""
Web漏洞扫描模块
检测 SQL 注入、XSS（反射型）、命令注入
使用无害的测试 payload，仅检测漏洞是否存在
"""

import re
import requests
from urllib.parse import urlencode, urljoin, urlparse, parse_qs
from scanner.utils import safe_request, extract_forms, normalize_url


# ============================================================
#  SQL 注入检测
# ============================================================

SQLI_PAYLOADS = [
    # 基于 SQL 语法错误检测
    ("'", "'"),                                    # 单引号触发语法错误
    ("1 OR 1=1", "1 OR 1=1"),                     # 永真条件
    ("1 AND 1=2", "1 AND 1=2"),                   # 永假条件
    ("1; SELECT 1", "1; SELECT 1"),                # 堆叠查询
    # 基于响应差异检测
    ("test' AND '1'='1", "test' AND '1'='1"),     # 闭合引号
    ("test' AND '1'='2", "test' AND '1'='2"),     # 闭合引号（假）
]

SQLI_ERROR_PATTERNS = [
    r"sql syntax.*mysql",
    r"warning.*mysql",
    r"valid mysql",
    r"mysql_fetch",
    r"mysql_num_rows",
    r"pg_query\(\)",
    r"pg_exec\(\)",
    r"postgres",
    r"sqlite.*error",
    r"sqlite3",
    r"oracle.*error",
    r"ora-\d{5}",
    r"microsoft.*odbc",
    r"sql server.*error",
    r"odbc.*driver",
    r"syntax error.*sql",
    r"unclosed quotation mark",
    r"quoted string not properly terminated",
    r"sqlstate\[\d+\]",
    r"you have an error in your sql syntax",
    r"warning.*pg_",
    r"warning.*mysql",
    r"unclosed parenthetical",
]


def detect_sqli(url, session):
    """检测 SQL 注入漏洞（基于 URL 参数和表单）"""
    findings = []

    # 测试 URL 参数中的 SQL 注入
    findings.extend(_test_url_params_sqli(url, session))
    # 测试表单中的 SQL 注入
    findings.extend(_test_forms_sqli(url, session))

    return findings


def _test_url_params_sqli(url, session):
    """测试 URL 查询参数中的 SQL 注入"""
    findings = []
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)

    if not params:
        return findings

    base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

    for param_name in params:
        # 先获取正常响应作为基准
        original_params = dict(params)
        normal_resp = safe_request(session, f"{base_url}?{urlencode(original_params, doseq=True)}", timeout=10)
        if normal_resp is None:
            continue
        normal_text = normal_resp.text
        normal_length = len(normal_text)

        # 逐个 payload 测试
        vulnerable = False
        for payload_marker, payload in SQLI_PAYLOADS:
            test_params = dict(params)
            test_params[param_name] = [payload]
            test_url = f"{base_url}?{urlencode(test_params, doseq=True)}"
            test_resp = safe_request(session, test_url, timeout=10)
            if test_resp is None:
                continue

            test_text = test_resp.text

            # 检查 SQL 错误信息
            for pattern in SQLI_ERROR_PATTERNS:
                if re.search(pattern, test_text, re.IGNORECASE):
                    findings.append({
                        "type": "sqli",
                        "severity": "high",
                        "title": f"SQL 注入漏洞 (参数: {param_name})",
                        "description": f"URL 参数 '{param_name}' 存在 SQL 注入风险，测试触发了数据库错误信息",
                        "fix": "使用参数化查询/预编译语句替代字符串拼接",
                        "evidence": f"参数: {param_name} | Payload: {payload[:30]} | 错误匹配: {pattern}",
                    })
                    vulnerable = True
                    break

            if vulnerable:
                break

            # 基于响应长度差异判断（非错误注入）
            if not vulnerable:
                # 检查闭合引号后的差异
                if "1 AND '1'='1" in payload or "AND '1'='1" in payload:
                    if abs(len(test_text) - normal_length) > 50:
                        findings.append({
                            "type": "sqli",
                            "severity": "medium",
                            "title": f"疑似 SQL 注入 (参数: {param_name})",
                            "description": f"URL 参数 '{param_name}' 对不同 SQL payload 返回了显著不同的响应，可能存在注入点",
                            "fix": "使用参数化查询/预编译语句替代字符串拼接",
                            "evidence": f"正常响应长度: {normal_length}, 测试响应长度: {len(test_text)}",
                        })
                        vulnerable = True
                        break

    return findings


def _test_forms_sqli(url, session):
    """测试表单中的 SQL 注入"""
    findings = []
    resp = safe_request(session, url, timeout=10)
    if resp is None:
        return findings

    forms = extract_forms(resp.text, url)
    for form in forms:
        for inp in form["inputs"]:
            if inp["type"] in ("hidden", "submit", "button"):
                continue

            for _, payload in SQLI_PAYLOADS[:3]:  # 只用前3个payload测试表单
                test_data = {i["name"]: i["value"] for i in form["inputs"]}
                test_data[inp["name"]] = payload

                try:
                    if form["method"] == "post":
                        test_resp = session.post(form["action"], data=test_data, timeout=10, verify=False)
                    else:
                        test_resp = session.get(
                            f"{form['action']}?{urlencode(test_data)}",
                            timeout=10, verify=False,
                        )

                    if test_resp:
                        for pattern in SQLI_ERROR_PATTERNS:
                            if re.search(pattern, test_resp.text, re.IGNORECASE):
                                findings.append({
                                    "type": "sqli",
                                    "severity": "high",
                                    "title": f"SQL 注入漏洞 (表单字段: {inp['name']})",
                                    "description": f"表单 '{form['action']}' 的字段 '{inp['name']}' 存在 SQL 注入风险",
                                    "fix": "使用参数化查询/预编译语句替代字符串拼接",
                                    "evidence": f"字段: {inp['name']} | 表单: {form['action']} | Payload: {payload[:30]}",
                                })
                                break
                        else:
                            continue
                        break
                except Exception:
                    continue

    return findings


# ============================================================
#  XSS 检测
# ============================================================

XSS_PAYLOADS = [
    ('<script>alert("XSS")</script>', 'scriptalertxssscript'),
    ('"><img src=x onerror=alert(1)>', 'imgsrconerroralert1'),
    ("'><svg onload=alert(1)>", 'svgonloadalert1'),
    ('javascript:alert(1)', 'javascriptalert1'),
    ('"><iframe src="javascript:alert(1)">', 'iframesrcjavascriptalert1'),
]


def detect_xss(url, session):
    """检测反射型 XSS 漏洞"""
    findings = []

    findings.extend(_test_url_params_xss(url, session))
    findings.extend(_test_forms_xss(url, session))

    return findings


def _test_url_params_xss(url, session):
    """测试 URL 参数中的反射型 XSS"""
    findings = []
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)

    if not params:
        return findings

    base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

    for param_name in params:
        for payload, marker in XSS_PAYLOADS:
            test_params = dict(params)
            test_params[param_name] = [payload]
            test_url = f"{base_url}?{urlencode(test_params, doseq=True)}"

            test_resp = safe_request(session, test_url, timeout=10)
            if test_resp is None:
                continue

            # 检查 payload 是否被原样反射到响应中（对响应也做字符清理后再匹配）
            clean_text = re.sub(r'[^a-zA-Z0-9]', '', test_resp.text.lower())
            if marker.lower() in clean_text:
                findings.append({
                    "type": "xss",
                    "severity": "high",
                    "title": f"反射型 XSS (参数: {param_name})",
                    "description": f"URL 参数 '{param_name}' 的值被原样输出到页面中，未经过滤或转义",
                    "fix": "对所有用户输入进行 HTML 实体编码后再输出 (htmlspecialchars / escape)",
                    "evidence": f"参数: {param_name} | Payload: {payload[:40]} | 反射特征: {marker[:30]}",
                })
                break  # 一个参数只报告一次

    return findings


def _test_forms_xss(url, session):
    """测试表单中的反射型 XSS"""
    findings = []
    resp = safe_request(session, url, timeout=10)
    if resp is None:
        return findings

    forms = extract_forms(resp.text, url)
    for form in forms:
        for inp in form["inputs"]:
            if inp["type"] in ("hidden", "submit", "button"):
                continue

            for payload, marker in XSS_PAYLOADS[:3]:
                test_data = {i["name"]: i["value"] for i in form["inputs"]}
                test_data[inp["name"]] = payload

                try:
                    if form["method"] == "post":
                        test_resp = session.post(form["action"], data=test_data, timeout=10, verify=False)
                    else:
                        test_resp = session.get(
                            f"{form['action']}?{urlencode(test_data)}",
                            timeout=10, verify=False,
                        )

                    if test_resp:
                        clean_text = re.sub(r'[^a-zA-Z0-9]', '', test_resp.text.lower())
                        if marker.lower() in clean_text:
                            findings.append({
                                "type": "xss",
                                "severity": "high",
                                "title": f"反射型 XSS (表单字段: {inp['name']})",
                                "description": f"表单 '{form['action']}' 的字段 '{inp['name']}' 输入的内容被原样反射到页面",
                                "fix": "对所有用户输入进行 HTML 实体编码后再输出",
                                "evidence": f"字段: {inp['name']} | Payload: {payload[:30]}",
                            })
                            break
                except Exception:
                    continue

    return findings


# ============================================================
#  命令注入检测
# ============================================================

CMDI_PAYLOADS = [
    "; whoami",
    "| whoami",
    "&& whoami",
    "| id",
    "; id",
    "$(whoami)",
    "`whoami`",
]

CMDI_RESPONSE_MARKERS = [
    "uid=",       # Linux id 命令输出
    "gid=",
    "root",
    "www-data",
    "wwwrun",
    "nginx",
    "apache",
    "iis apppool",
    "nt authority",
]


def detect_cmdi(url, session):
    """检测命令注入漏洞"""
    findings = []

    findings.extend(_test_url_params_cmdi(url, session))
    findings.extend(_test_forms_cmdi(url, session))

    return findings


def _test_url_params_cmdi(url, session):
    """测试 URL 参数中的命令注入"""
    findings = []
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)

    if not params:
        return findings

    base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

    for param_name in params:
        for payload in CMDI_PAYLOADS:
            test_params = dict(params)
            test_params[param_name] = [payload]
            test_url = f"{base_url}?{urlencode(test_params, doseq=True)}"

            test_resp = safe_request(session, test_url, timeout=10)
            if test_resp is None:
                continue

            for marker in CMDI_RESPONSE_MARKERS:
                if marker in test_resp.text:
                    findings.append({
                        "type": "cmdi",
                        "severity": "critical",
                        "title": f"命令注入漏洞 (参数: {param_name})",
                        "description": f"URL 参数 '{param_name}' 存在操作系统命令注入风险，命令输出被返回到响应中",
                        "fix": "禁止将用户输入直接传递给系统命令，使用语言内置的函数替代 shell 命令",
                        "evidence": f"参数: {param_name} | Payload: {payload} | 命令输出特征: {marker}",
                    })
                    break
            else:
                continue
            break  # 一个参数只报告一次

    return findings


def _test_forms_cmdi(url, session):
    """测试表单中的命令注入"""
    findings = []
    resp = safe_request(session, url, timeout=10)
    if resp is None:
        return findings

    forms = extract_forms(resp.text, url)
    for form in forms:
        for inp in form["inputs"]:
            if inp["type"] in ("hidden", "submit", "button"):
                continue

            for payload in CMDI_PAYLOADS[:4]:
                test_data = {i["name"]: i["value"] for i in form["inputs"]}
                test_data[inp["name"]] = payload

                try:
                    if form["method"] == "post":
                        test_resp = session.post(form["action"], data=test_data, timeout=10, verify=False)
                    else:
                        test_resp = session.get(
                            f"{form['action']}?{urlencode(test_data)}",
                            timeout=10, verify=False,
                        )

                    if test_resp:
                        for marker in CMDI_RESPONSE_MARKERS:
                            if marker in test_resp.text:
                                findings.append({
                                    "type": "cmdi",
                                    "severity": "critical",
                                    "title": f"命令注入漏洞 (表单字段: {inp['name']})",
                                    "description": f"表单 '{form['action']}' 的字段 '{inp['name']}' 存在命令注入风险",
                                    "fix": "禁止将用户输入直接传递给系统命令",
                                    "evidence": f"字段: {inp['name']} | Payload: {payload} | 命令输出: {marker}",
                                })
                                break
                        else:
                            continue
                        break
                except Exception:
                    continue

    return findings


# ============================================================
#  整合入口
# ============================================================

def run_vuln_scan(url, session):
    """运行漏洞扫描模块"""
    results = {"module": "漏洞扫描", "findings": []}

    print("  [*] 检测 SQL 注入...")
    results["findings"].extend(detect_sqli(url, session))

    print("  [*] 检测 XSS (反射型)...")
    results["findings"].extend(detect_xss(url, session))

    print("  [*] 检测命令注入...")
    results["findings"].extend(detect_cmdi(url, session))

    return results
