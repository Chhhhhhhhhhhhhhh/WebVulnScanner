"""
信息泄露检测 + 服务指纹识别模块
检测 HTTP 安全头、敏感文件暴露、目录遍历、服务指纹
"""

import requests
from urllib.parse import urljoin
from scanner.utils import normalize_url, safe_request


def check_security_headers(url, session):
    """检查 HTTP 安全响应头"""
    findings = []
    try:
        resp = safe_request(session, url, timeout=10)
        if resp is None:
            return findings

        headers = resp.headers

        security_headers = {
            "X-Content-Type-Options": {
                "expected": "nosniff",
                "severity": "low",
                "description": "防止浏览器 MIME 类型嗅探",
                "fix": "添加响应头: X-Content-Type-Options: nosniff",
            },
            "X-Frame-Options": {
                "expected_options": ["DENY", "SAMEORIGIN"],
                "severity": "medium",
                "description": "防止点击劫持攻击",
                "fix": "添加响应头: X-Frame-Options: DENY 或 SAMEORIGIN",
            },
            "X-XSS-Protection": {
                "expected": "1; mode=block",
                "severity": "low",
                "description": "启用浏览器内置的 XSS 过滤器",
                "fix": "添加响应头: X-XSS-Protection: 1; mode=block",
            },
            "Strict-Transport-Security": {
                "expected": "required",
                "severity": "medium",
                "description": "强制使用 HTTPS 连接 (HSTS)",
                "fix": "添加响应头: Strict-Transport-Security: max-age=31536000; includeSubDomains",
            },
            "Content-Security-Policy": {
                "expected": "required",
                "severity": "medium",
                "description": "限制页面可加载的资源来源，防止 XSS 和数据注入",
                "fix": "配置合适的 Content-Security-Policy 策略",
            },
        }

        for header_name, config in security_headers.items():
            header_value = headers.get(header_name, "")
            is_missing = not header_value

            if is_missing:
                findings.append({
                    "type": "missing_header",
                    "header": header_name,
                    "severity": config["severity"],
                    "title": f"缺少安全响应头: {header_name}",
                    "description": config["description"],
                    "fix": config["fix"],
                    "evidence": f"响应中未检测到 {header_name}",
                })
            elif "expected_options" in config:
                if header_value.split("=")[0].strip().upper() not in config["expected_options"]:
                    findings.append({
                        "type": "weak_header",
                        "header": header_name,
                        "severity": "low",
                        "title": f"安全响应头配置不足: {header_name}",
                        "description": f"当前值: {header_value}",
                        "fix": config["fix"],
                        "evidence": header_value,
                    })

        # 检查是否暴露了服务器版本信息
        server_header = headers.get("Server", "")
        if server_header and any(v in server_header.lower() for v in ["apache/2", "nginx/1", "iis/", "php/"]):
            findings.append({
                "type": "info_disclosure",
                "header": "Server",
                "severity": "low",
                "title": "服务器版本信息泄露",
                "description": f"Server 响应头暴露了详细版本号",
                "fix": "在服务器配置中隐藏版本号 (ServerTokens Prod / server_tokens off)",
                "evidence": server_header,
            })

    except Exception as e:
        findings.append({
            "type": "error",
            "severity": "info",
            "title": "安全头检测失败",
            "description": str(e),
            "evidence": "",
            "fix": "",
        })

    return findings


def check_sensitive_files(url, session):
    """检测敏感文件暴露"""
    findings = []
    base = normalize_url(url)

    sensitive_paths = [
        ("/.git/HEAD", "Git 仓库泄露", "可能泄露完整源代码", "删除线上 .git 目录，或在 .htaccess 中屏蔽"),
        ("/.env", "环境配置文件泄露", "可能泄露数据库密码、API密钥等敏感信息", "将 .env 加入 .gitignore，不要部署到 Web 根目录"),
        ("/robots.txt", "robots.txt 可访问", "可能暴露不想公开的目录结构", "确保 robots.txt 中只包含允许搜索引擎抓取的内容"),
        ("/.git/config", "Git 配置文件泄露", "可能泄露仓库远程地址", "删除线上 .git 目录"),
        ("/.DS_Store", "macOS 目录文件泄露", "可能暴露目录结构和文件名", "从项目中删除 .DS_Store 文件"),
        ("/backup.sql", "数据库备份文件泄露", "可能泄露完整数据库内容", "不要将备份文件放在 Web 可访问的目录"),
        ("/phpinfo.php", "phpinfo 页面泄露", "暴露 PHP 版本和完整配置信息", "移除 phpinfo.php 文件"),
        ("/wp-config.php.bak", "WordPress 配置备份泄露", "可能泄露数据库凭据", "清理所有备份文件"),
        ("/server-status", "Apache 服务器状态页", "暴露服务器运行状态和请求信息", "限制 server-status 的访问权限"),
    ]

    for path, title, description, fix in sensitive_paths:
        try:
            target = urljoin(base, path)
            resp = safe_request(session, target, timeout=5, allow_redirects=False)
            if resp is not None and resp.status_code == 200:
                content_length = int(resp.headers.get("Content-Length", len(resp.text)))
                if content_length > 0:
                    findings.append({
                        "type": "sensitive_file",
                        "severity": "high" if ".git" in path or ".env" in path or ".sql" in path else "medium",
                        "title": title,
                        "description": description,
                        "fix": fix,
                        "evidence": f"{path} (HTTP 200, {content_length} bytes)",
                    })
        except Exception:
            pass

    return findings


def check_directory_listing(url, session):
    """检测目录遍历"""
    findings = []
    base = normalize_url(url)

    common_dirs = [
        "/admin/", "/backup/", "/uploads/", "/config/",
        "/includes/", "/static/", "/images/", "/tmp/",
        "/log/", "/logs/", "/old/", "/test/",
    ]

    for directory in common_dirs:
        try:
            target = urljoin(base, directory)
            resp = safe_request(session, target, timeout=5)
            if resp is not None and resp.status_code == 200:
                # 简单判断是否存在目录列表特征
                text = resp.text.lower()
                if "index of" in text or "parent directory" in text or "last modified" in text:
                    findings.append({
                        "type": "directory_listing",
                        "severity": "medium",
                        "title": f"目录列表可访问: {directory}",
                        "description": "该目录启用了目录浏览，任何人都可以查看其中的文件列表",
                        "fix": "在服务器配置中禁用目录浏览 (AutoIndex off / Options -Indexes)",
                        "evidence": target,
                    })
        except Exception:
            pass

    return findings


def fingerprint_service(url, session):
    """服务指纹识别"""
    findings = []
    try:
        resp = safe_request(session, url, timeout=10)
        if resp is None:
            return findings

        headers = resp.headers
        html = resp.text[:5000].lower()

        # Server 检测
        server = headers.get("Server", "Unknown")
        findings.append({
            "type": "fingerprint",
            "severity": "info",
            "title": "服务器类型",
            "description": f"检测到 Web 服务器: {server}",
            "evidence": server,
            "fix": "",
        })

        # CMS 检测
        cms_signatures = {
            "WordPress": ["wp-content", "wp-includes", "wordpress"],
            "Joomla": ["joomla", "/media/jui/"],
            "Drupal": ["drupal", "sites/all/themes"],
            "Laravel": ["laravel_session", "laravel"],
            "Django": ["csrfmiddlewaretoken", "django"],
            "Flask": ["flask", "werkzeug"],
            "React": ["react", "__next", "_next"],
            "Vue.js": ["vue", "vuex", "/static/js/chunk-"],
            "Spring": ["spring", "x-application-context"],
        }

        detected_cms = []
        for cms, signatures in cms_signatures.items():
            if any(sig in html or sig in str(headers).lower() for sig in signatures):
                detected_cms.append(cms)

        if detected_cms:
            findings.append({
                "type": "fingerprint",
                "severity": "info",
                "title": "检测到技术栈",
                "description": f"识别到的框架/CMS: {', '.join(detected_cms)}",
                "evidence": ", ".join(detected_cms),
                "fix": "",
            })

        # WAF 检测
        waf_signatures = {
            "Cloudflare": ["cf-ray", "cloudflare"],
            "阿里云 WAF": ["aliyun", "acs-sc"],
            "腾讯云 WAF": ["tencent", "qwaf"],
            "ModSecurity": ["mod_security", "modsecurity"],
            "AWS WAF": ["awselb", "awswaf"],
            "Akamai": ["akamai", "x-akamai"],
        }

        headers_str = str(headers).lower()
        for waf, signatures in waf_signatures.items():
            if any(sig in headers_str or sig in html for sig in signatures):
                findings.append({
                    "type": "fingerprint",
                    "severity": "info",
                    "title": f"检测到 WAF/CDN: {waf}",
                    "description": "目标可能部署了 Web 应用防火墙或 CDN，扫描结果可能受限",
                    "evidence": waf,
                    "fix": "",
                })
                break  # 只报告第一个检测到的

        # Cookie 安全属性检测
        cookies = resp.cookies
        insecure_cookies = []
        for cookie in cookies:
            if not cookie.secure:
                insecure_cookies.append(cookie.name)
            if not cookie.has_nonstandard_attr("httponly") and not cookie.has_nonstandard_attr("HttpOnly"):
                insecure_cookies.append(f"{cookie.name}(no-httponly)")

        if insecure_cookies:
            findings.append({
                "type": "insecure_cookie",
                "severity": "medium",
                "title": "Cookie 安全属性缺失",
                "description": "部分 Cookie 缺少 Secure 或 HttpOnly 属性，可能被 XSS 利用",
                "fix": "为所有 Cookie 添加 Secure 和 HttpOnly 属性",
                "evidence": ", ".join(insecure_cookies[:5]),
            })

    except Exception as e:
        findings.append({
            "type": "error",
            "severity": "info",
            "title": "指纹识别失败",
            "description": str(e),
            "evidence": "",
            "fix": "",
        })

    return findings


def run_info_scan(url, session):
    """运行信息收集模块（整合所有子模块）"""
    results = {"module": "信息收集与指纹识别", "findings": []}

    print("  [*] 检查 HTTP 安全响应头...")
    results["findings"].extend(check_security_headers(url, session))

    print("  [*] 检测敏感文件暴露...")
    results["findings"].extend(check_sensitive_files(url, session))

    print("  [*] 检测目录列表...")
    results["findings"].extend(check_directory_listing(url, session))

    print("  [*] 识别服务指纹...")
    results["findings"].extend(fingerprint_service(url, session))

    return results
