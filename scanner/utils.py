import ipaddress

def normalize_url(url):
    url = url.strip()
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "http://" + url
    if not url.endswith("/"):
        url += "/"
    return url

def is_private_ip(url):
    host = url.split("://")[-1].split("/")[0]
    host = host.split(":")[0]  # 去掉端口

    try:
        ip = ipaddress.ip_address(host)
        return ip.is_private
    except ValueError:
        return False
    
def is_in_scope(url,base_url):
    if is_private_ip(url):
        return False
    return url.startswith(base_url)


