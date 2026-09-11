"""Automatic login for authenticated scanning.

Given a login page URL and credentials, the module:

1. fetches the page and parses its forms;
2. picks the form containing a password field, auto-detects the username
   field (falls back to ``user``/``email``-looking names, else the first
   text input), and keeps hidden fields (CSRF tokens) as-is;
3. submits once, following redirects;
4. harvests every ``Set-Cookie`` seen along the redirect chain and hands
   the cookies back so the shared client (and all worker threads) inherit
   the session.

Success is judged pragmatically: we look for a session-ish cookie name.
If the login flow fails, scanning continues unauthenticated with a clear
warning (the crawler also refuses to follow logout links, so a successful
session survives the whole scan).
"""

from __future__ import annotations

from bs4 import BeautifulSoup

from .crawler import extract_forms
from .httpclient import HttpClient
from .models import PageData

USERNAME_HINTS = ("user", "email", "login", "account", "name", "mail", "phone")
SESSION_HINTS = ("sess", "auth", "login", "token", "sid", "jid", "remember")


def _harvest_cookies(resp) -> dict:
    """Collect name=value from Set-Cookie across a response chain."""
    cookies: dict = {}
    chain = list(getattr(resp, "history", []) or []) + [resp]
    for response in chain:
        try:
            raw = response.raw.headers.getlist("Set-Cookie")
        except Exception:
            raw = []
        for line in raw:
            pair = line.split(";", 1)[0]
            if "=" in pair:
                name, _, value = pair.partition("=")
                cookies[name.strip()] = value.strip()
    return cookies


def _looks_like_session(cookies: dict) -> bool:
    return any(any(hint in name.lower() for hint in SESSION_HINTS) for name in cookies)


def try_login(client: HttpClient, login_url: str, username: str, password: str, log=print) -> dict:
    """Attempt form login; return the harvested cookies ({} on failure)."""
    page = client.get_page(login_url)
    if page is None:
        log(f"[!] Login page unreachable: {login_url}")
        return {}

    try:
        # reuse PageData's charset-aware decoding of the raw body
        html = PageData(page.url, page.status, page.headers,
                        page.body, page.set_cookies).text
        soup = BeautifulSoup(html, "html.parser")
    except Exception:
        log("[!] Login page could not be parsed")
        return {}

    target_form = None
    for form in extract_forms(soup, page.url):
        if any(i["type"] == "password" for i in form.inputs):
            target_form = form
            break
    if target_form is None:
        log("[!] No form with a password field found on the login page")
        return {}

    data = {i["name"]: i["value"] for i in target_form.inputs}
    password_field = next(i["name"] for i in target_form.inputs if i["type"] == "password")

    username_field = None
    text_inputs = [i for i in target_form.inputs
                   if i["type"] in ("text", "email", "tel", "") and i["name"] != password_field]
    for i in text_inputs:
        if any(hint in i["name"].lower() for hint in USERNAME_HINTS):
            username_field = i["name"]
            break
    if username_field is None and text_inputs:
        username_field = text_inputs[0]["name"]
    if username_field is None:
        log("[!] Login form has no username-looking field")
        return {}

    data[username_field] = username
    data[password_field] = password

    if target_form.method == "post":
        resp = client.request("POST", target_form.action, data=data)
    else:
        resp = client.request("GET", target_form.action, params=data)
    if resp is None:
        log("[!] Login request failed")
        return {}

    cookies = _harvest_cookies(resp)
    if not cookies or not _looks_like_session(cookies):
        log("[!] Login did not yield a session cookie — continuing unauthenticated")
        return {}

    log(f"[*] Logged in as {username!r} via field {username_field!r} "
        f"(session cookie(s): {', '.join(sorted(cookies))[:80]})")
    return cookies
