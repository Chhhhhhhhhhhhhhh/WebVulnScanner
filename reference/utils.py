"""
工具函数模块
"""

import re
import socket
import requests
from urllib.parse import urlparse


def normalize_url(url):
    """确保 URL 以 / 结尾且格式正确"""
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    parsed = urlparse(url)
    if not parsed.path:
        url += "/"
    return url


def is_in_scope(url, base_domain):
    """检查 URL 是否在扫描范围内（防止SSRF）"""
    try:
        parsed = urlparse(url)
        target_host = parsed.hostname
        if not target_host:
            return False
        # 解析目标域名IP
        target_ip = socket.gethostbyname(target_host)
        # 解析本地地址
        local_ips = {
            socket.gethostbyname("localhost"),
            socket.gethostbyname(socket.gethostname()),
        }
        local_ranges = ["127.", "10.", "192.168.", "172.16.", "172.17.",
                        "172.18.", "172.19.", "172.20.", "172.21.", "172.22.",
                        "172.23.", "172.24.", "172.25.", "172.26.", "172.27.",
                        "172.28.", "172.29.", "172.30.", "172.31."]
        if target_ip in local_ips or any(target_ip.startswith(r) for r in local_ranges):
            return False
        return True
    except Exception:
        return False


def safe_request(session, url, timeout=10, allow_redirects=True):
    """安全的 HTTP 请求，避免扫描器自身触发异常"""
    try:
        resp = session.get(
            url,
            timeout=timeout,
            allow_redirects=allow_redirects,
            verify=False,
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            },
        )
        return resp
    except requests.exceptions.Timeout:
        return None
    except requests.exceptions.ConnectionError:
        return None
    except Exception:
        return None


def extract_forms(html, base_url):
    """从 HTML 中提取表单（action + inputs）"""
    soup = None
    try:
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(html, "lxml")
    except ImportError:
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(html, "html.parser")

    forms = []
    for form in soup.find_all("form"):
        action = form.get("action", "")
        method = form.get("method", "get").lower()
        if action and not action.startswith(("http://", "https://")):
            from urllib.parse import urljoin
            action = urljoin(base_url, action)

        inputs = []
        for inp in form.find_all(["input", "textarea", "select"]):
            inp_type = inp.get("type", "text")
            if inp_type in ("submit", "button", "image", "reset"):
                continue
            inputs.append({
                "name": inp.get("name", ""),
                "type": inp_type,
                "value": inp.get("value", ""),
            })

        if inputs:
            forms.append({
                "action": action or base_url,
                "method": method,
                "inputs": inputs,
            })

    return forms


def severity_level(level):
    """返回严重等级排序值"""
    order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    return order.get(level, 0)
