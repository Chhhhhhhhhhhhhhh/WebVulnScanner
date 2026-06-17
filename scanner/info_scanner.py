import requests

def check_security_headers(url):
    try:
        resp = requests.get(url, timeout=10)
    except Exception as e:
        print(f"Request failed: {e}")
        return []
    
    findings = []
    headers_to_check = [
        "X-Frame-Options",
        "X-Content-Type-Options",
        "X-XSS-Protection",
        "Content-Security-Policy",
        "Strict-Transport-Security"
    ]

    for header_name in headers_to_check:
        if header_name not in resp.headers:
            findings.append({
                "type": "missing_header",
                "severity": "medium",
                "title": f"Missing: {header_name}",
                "description": f"Security header '{header_name}' is not set"
            })

    return findings


def check_sensitive_files(url):
    sensitive_paths = [
        ".git/config",
        ".env",
        "robots.txt",
        "sitemap.xml",
        "wp-config.php",
        "admin/",
        "backup.sql",
    ]
    findings = []

    for path in sensitive_paths:
        test_url = url + path
        try:
            resp = requests.get(test_url, timeout=10)
            if resp.status_code == 200:
                findings.append({
                    "type": "sensitive_file",
                    "severity": "high",
                    "title": f"Exposed: {path}",
                    "description": f"Sensitive file '{path}' is publicly accessible"
                })
        except Exception:
            pass

    return findings

def check_server_fingerprint(url):
    findings = []
    try:
        resp = requests.get(url, timeout=10)
    except Exception:
        return findings
    
    server = resp.headers.get("Server", "")
    if server:
        findings.append({
            "type": "fingerprint",
            "severity": "info",
            "title": f"Server: {server}",
            "description": f"服务器软件: {server}",
        })
    
    powered = resp.headers.get("X-Powered-By", "")
    if powered:
        findings.append({
            "type": "fingerprint",
            "severity": "info",
            "title": f"X-Powered-By: {powered}",
            "description": f"后端技术: {powered}",
        })

    return findings