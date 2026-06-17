import requests

def check_sql_injection(url):
    findings = []

    if "?" not in url:
        return findings
    
    base = url.split("?")[0]
    params = url.split("?")[1]

    for param in params.split("&"):
        key = param.split("=")[0]

        test_url = base + "?" + key + "='"

        try:
            resp = requests.get(test_url, timeout=10)
            text_lower = resp.text.lower()

            if "error" in text_lower or "sql" in text_lower or "mysql" in text_lower:
                findings.append({
                    "type": "sql_injection",
                    "severity": "high",
                    "title": f"SQL Injection (param: {key})",
                    "description": f"参数 '{key}' 可能存在 SQL 注入 ",
                })
        except Exception:
            pass

    return findings


def check_xss(url):
    findings = []

    if "?" not in url:
        return findings
    
    base = url.split("?")[0]
    params = url.split("?")[1]

    xss_payload = [
        "<script>alert(1)</script>",
        '"><img src=x onerror=alert(1)>',
    ]

    for param in params.split("&"):
        key = param.split("=")[0]

        for payload in xss_payload:
            test_url = base + "?" + key + "=" + payload

            try:
                resp = requests.get(test_url, timeout=10)
                if payload in resp.text:
                    findings.append({
                        "type": "xss",
                        "severity": "high",
                        "title": f"XSS (param: {key})",
                        "description": f"参数 '{key}' 存在反射型 XSS 漏洞",
                    })
                    break
            except Exception:
                pass

    return findings

