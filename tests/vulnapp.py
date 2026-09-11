"""A deliberately vulnerable local web app used by the test suite and demo
reports. It runs on 127.0.0.1 only and exists so the scanner can be tested
end-to-end without touching any real target.

Routes:
  /                 index with links + a search form + a CSRF-protected
                    login form (single-use tokens, like real frameworks)
  /search?q=        reflects q unescaped (XSS)
  /item?id=         error-based SQLi when id contains a quote
  /login (POST)     SQLi in username, but ONLY with a valid single-use
                    CSRF token (exercises the scanner's token refresh)
  /ping?host=       command injection: simulates `echo <marker>` output;
                    also sleeps ~3s for shell sleep payloads (time-based)
  /download?file=   path traversal: serves fake /etc/passwd content
  /render?tpl=      template injection: evaluates {{a*b}} expressions
  /query?user=      time-based SQLi: sleeps ~3s when the value contains
                   a SLEEP expression (otherwise a normal fast page)
  /go?url=          open redirect: 302 to whatever url points at
  /goto?next=       safe redirect: relative paths only
  /api/data         CORS misconfig: reflects any Origin + credentials
  /api/safe         fixed Access-Control-Allow-Origin (no reflection)
  /dom?name=        DOM XSS: innerHTML sink fed from location.search
  /domsafe?name=    safe counterpart: textContent only
  /ratelimit        always answers 429 + Retry-After: 0 (backoff testing)
  /safe/page?id=    never vulnerable (encodes everything)
  /login-page       login form for authenticated scanning
  /auth (POST)      issues a session cookie for demo@example.com/secret123
  /account?id=      XSS behind authentication (403 without the session)
  /logout           clears the session (the crawler must refuse it)
  /sitemap.xml      sitemap advertising /hidden?id=1
  /hidden?id=       raw reflection, discoverable only via sitemap.xml
  /static/app.js    JS bundle referencing /secretapi?cmd= (JS discovery)
  /secretapi?cmd=   raw reflection, discoverable only via app.js
  /custom-secret.txt  wordlist target: content differing from soft-404s
  /.env             exposed environment file (real finding)
  /robots.txt       robots file with a Disallow entry
  everything else   soft-404: returns HTTP 200 with a generic page
"""

from __future__ import annotations

import re
import secrets
import threading
import time
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

# Valid credentials for /auth (authenticated-scanning tests)
VALID_USER = "demo@example.com"
VALID_PASS = "secret123"

# Tokens issued by GET / stay valid until consumed by a POST (single-use,
# with a small grace window so concurrent probes don't race each other).
TOKEN_GRACE = 8


class TokenStore:
    def __init__(self):
        self._lock = threading.Lock()
        self._issued: deque = deque(maxlen=TOKEN_GRACE)

    def issue(self) -> str:
        token = secrets.token_hex(8)
        with self._lock:
            self._issued.append(token)
        return token

    def consume(self, token: str) -> bool:
        with self._lock:
            if token in self._issued:
                self._issued.remove(token)
                return True
        return False


class VulnHandler(BaseHTTPRequestHandler):
    server_version = "VulnApp/1.0"

    def log_message(self, *args):  # silence request logging
        pass

    # -- helpers -------------------------------------------------------
    def _send(self, status: int, body: str, content_type: str = "text/html; charset=utf-8",
              extra_headers: dict | None = None):
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        for name, value in (extra_headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(data)

    def _redirect(self, location: str):
        location = re.sub(r"[\r\n\0]", "", location)[:2048]
        self.send_response(302)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _query(self) -> dict:
        return {k: v[0] for k, v in parse_qs(urlsplit(self.path).query).items()}

    def _body(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length).decode("utf-8", errors="replace") if length else ""
        return {k: v[0] for k, v in parse_qs(raw).items()}

    def _index(self):
        token = self.server.token_store.issue()
        page = f"""<html>
<head><title>Vulnerable Test App</title></head>
<body>
<h1>Test Shop</h1>
<a href="/search?q=laptop">Search laptops</a>
<a href="/item?id=1">Item 1</a>
<a href="/item?id=2">Item 2</a>
<a href="/ping?host=127.0.0.1">Ping tool</a>
<a href="/download?file=manual.pdf">Downloads</a>
<a href="/render?tpl=Welcome">Render</a>
<a href="/go?url=/home">Go</a>
<a href="/goto?next=/about">Goto</a>
<a href="/api/data">API data</a>
<a href="/login-page">Sign in</a>
<a href="/account?id=1">My account</a>
<a href="/query?user=1">Slow query</a>
<a href="/dom?name=world">DOM greet</a>
<a href="/domsafe?name=world">DOM greet (safe)</a>
<a href="/safe/page?id=7">Safe page</a>
<form action="/search" method="get">
  <input type="text" name="q" value="">
  <input type="submit" value="Search">
</form>
<form action="/login" method="post">
  <input type="hidden" name="csrf_token" value="{token}">
  <input type="text" name="username" value="">
  <input type="password" name="password" value="">
  <input type="submit" value="Login">
</form>
<script src="/static/app.js"></script>
</body>
</html>"""
        self._send(200, page)

    # -- routes --------------------------------------------------------
    def do_GET(self):
        path = urlsplit(self.path).path
        params = self._query()

        if path == "/":
            self._index()
            return

        if path == "/search":
            q = params.get("q", "")
            self._send(200, f"<html><body><h1>Results for {q}</h1>"
                            f"<p>10 items found.</p></body></html>")
            return

        if path == "/item":
            item_id = params.get("id", "1")
            if any(ch in item_id for ch in ("'", '"')):
                self._send(200, "<html><body><h1>Database error</h1>"
                                "<pre>You have an error in your SQL syntax; check the manual "
                                "that corresponds to your MySQL server version</pre></body></html>")
            else:
                self._send(200, f"<html><body><h1>Item #{item_id}</h1>"
                                f"<p>Name: Sample product</p></body></html>")
            return

        if path == "/ping":
            host = params.get("host", "")
            if "sleep" in host.lower() and re.search(r"(?:^|[;|&`\n]|\$\()\s*sleep", host):
                time.sleep(3)                    # time-based cmdi (simulated)
            marker = re.search(r"wvs[0-9a-f]{10}", host)
            separator = re.search(r"(?:;|\||&&|\|\||\n|&|\$\(|`)", host)
            if marker and separator and "echo" in host:
                # Simulated shell execution output (nothing really runs).
                self._send(200, f"<html><body><pre>PING output\n{marker.group(0)}:\n</pre></body></html>")
            else:
                self._send(200, f"<html><body><pre>Pinging {host} ... 4 packets transmitted</pre></body></html>")
            return

        if path == "/download":
            name = params.get("file", "")
            if "../" in name or name.startswith("/etc"):
                self._send(200, "<html><body><pre>root:x:0:0:root:/root:/bin/bash\n"
                                "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n</pre></body></html>")
            else:
                self._send(200, f"<html><body><p>File {name} not found in allowed directory.</p></body></html>")
            return

        if path == "/render":
            tpl = params.get("tpl", "")
            match = re.search(r"\{\{(\d+)\*(\d+)\}\}", tpl)
            if match:
                product = int(match.group(1)) * int(match.group(2))
                self._send(200, f"<html><body><p>Rendered: {product}</p></body></html>")
            else:
                self._send(200, f"<html><body><p>Rendered: {tpl}</p></body></html>")
            return

        if path == "/query":
            user = params.get("user", "1")
            if "sleep" in user.lower():          # time-based SQLi (simulated)
                time.sleep(3)
            self._send(200, f"<html><body><p>Query done for {user}</p></body></html>")
            return

        if path == "/go":
            url = params.get("url", "/")
            self._redirect(url)          # no validation at all
            return

        if path == "/goto":
            nxt = params.get("next", "/")
            if nxt.startswith("/") and not nxt.startswith("//") and not nxt.startswith("/\\"):
                self._redirect(nxt)      # validated: relative paths only
            else:
                self._redirect("/")
            return

        if path == "/api/data":
            origin = self.headers.get("Origin")
            headers = {}
            if origin:
                headers["Access-Control-Allow-Origin"] = origin
                headers["Access-Control-Allow-Credentials"] = "true"
            self._send(200, '{"user":"demo","email":"demo@example.com","items":3}',
                       content_type="application/json", extra_headers=headers)
            return

        if path == "/api/safe":
            self._send(200, '{"status":"ok"}', content_type="application/json",
                       extra_headers={"Access-Control-Allow-Origin": "https://trusted.example"})
            return

        if path == "/dom":
            self._send(200, """<html><body>
<h1>Greeting</h1><div id="g"></div>
<script>
  var name = new URLSearchParams(location.search).get('name') || '';
  document.getElementById('g').innerHTML = 'Hello, ' + name;
</script>
</body></html>""")
            return

        if path == "/domsafe":
            self._send(200, """<html><body>
<h1>Greeting</h1><div id="g"></div>
<script>
  var name = new URLSearchParams(location.search).get('name') || '';
  document.getElementById('g').textContent = 'Hello, ' + name;
</script>
</body></html>""")
            return

        if path == "/sitemap.xml":
            host = self.headers.get("Host", "127.0.0.1")
            body = (f'<?xml version="1.0" encoding="UTF-8"?>\n'
                    f'<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
                    f'<url><loc>http://{host}/hidden?id=1</loc></url>\n'
                    f'<url><loc>http://{host}/search?q=book</loc></url>\n'
                    f'</urlset>\n')
            self._send(200, body, content_type="application/xml")
            return

        if path == "/hidden":
            hidden_id = params.get("id", "")
            self._send(200, f"<html><body><h1>Hidden page {hidden_id}</h1></body></html>")
            return

        if path == "/static/app.js":
            body = ('// frontend bundle\n'
                    'function load(cmd){ fetch("/secretapi?cmd=" + cmd); }\n'
                    'var CFG = { logoutUrl: "/logout", api: "/api/data" };\n')
            self._send(200, body, content_type="application/javascript")
            return

        if path == "/secretapi":
            cmd = params.get("cmd", "")
            self._send(200, f"<html><body><p>Result for {cmd}</p></body></html>")
            return

        if path == "/custom-secret.txt":
            self._send(200, "TOP_SECRET_TOKEN=abcdef123456\n", content_type="text/plain")
            return

        if path == "/login-page":
            token = self.server.token_store.issue()
            self._send(200, f"""<html><body>
<h1>Sign in</h1>
<form action="/auth" method="post">
  <input type="hidden" name="csrf_token" value="{token}">
  <input type="text" name="email" value="">
  <input type="password" name="password" value="">
  <input type="submit" value="Login">
</form>
</body></html>""")
            return

        if path == "/account":
            cookie = self.headers.get("Cookie", "")
            if "session=ok" in cookie:
                acct_id = params.get("id", "")
                self._send(200, f"<html><body><h1>Account #{acct_id}</h1></body></html>")
            else:
                self._send(403, "<html><body>403: login required</body></html>")
            return

        if path == "/logout":
            self._send(200, "<html><body>Bye</body></html>",
                       extra_headers={"Set-Cookie": "session=; Path=/; Max-Age=0"})
            return

        if path == "/ratelimit":
            data = "slow down"
            self.send_response(429)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Retry-After", "0")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data.encode())
            return

        if path == "/safe/page":
            from html import escape
            item_id = escape(params.get("id", ""))
            self._send(200, f"<html><body><h1>Item {item_id}</h1><p>Everything is escaped here.</p></body></html>")
            return

        if path == "/.env":
            self._send(200, "APP_ENV=production\nDB_HOST=localhost\nDB_PASSWORD=sup3rs3cret\n"
                            "API_KEY=ak_test_1234567890\n", content_type="text/plain")
            return

        if path == "/robots.txt":
            self._send(200, "User-agent: *\nDisallow: /admin/\n", content_type="text/plain")
            return

        if path == "/admin/":
            self._send(403, "<html><body>403 Forbidden</body></html>")
            return

        # Soft 404: HTTP 200 with a generic page (calibration trap)
        self._send(200, "<html><body><h1>Oops</h1><p>The page you requested could not be found.</p></body></html>")

    def do_POST(self):
        path = urlsplit(self.path).path
        form = self._body()

        if path == "/ratelimit":
            data = "slow down"
            self.send_response(429)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Retry-After", "0")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data.encode())
            return

        if path == "/auth":
            if not self.server.token_store.consume(form.get("csrf_token", "")):
                self._send(200, "<html><body>Session expired</body></html>")
                return
            email, password = form.get("email", ""), form.get("password", "")
            if email == VALID_USER and password == VALID_PASS:
                self._send(200, f"<html><body>Welcome, {email}</body></html>",
                           extra_headers={"Set-Cookie": "session=ok; Path=/"})
            else:
                self._send(200, "<html><body>Invalid credentials</body></html>")
            return

        if path == "/login":
            if not self.server.token_store.consume(form.get("csrf_token", "")):
                self._send(200, "<html><body><p>Session expired. Please reload the form.</p></body></html>")
                return
            username = form.get("username", "")
            if any(ch in username for ch in ("'", '"')):
                self._send(200, "<html><body><pre>SQLException: ORA-01756: quoted string not properly "
                                "terminated</pre></body></html>")
            else:
                self._send(200, f"<html><body><p>Welcome back, {username}.</p></body></html>")
            return

        self._send(404, "<html><body>Not found</body></html>")


def make_server(host: str = "127.0.0.1", port: int = 0) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer((host, port), VulnHandler)
    server.token_store = TokenStore()
    return server


def serve_forever_blocking(host: str = "127.0.0.1", port: int = 8099) -> None:
    server = make_server(host, port)
    print(f"Vulnerable test app listening on http://{host}:{port} (Ctrl+C to stop)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    serve_forever_blocking()
