"""Authenticated-scan session: attach a logged-in session to every request.

An `AuthSession` is just a bag of extra HTTP headers (typically a `Cookie` and/or
`Authorization`) that the fetchers merge onto their requests, so the crawler,
secret scan, API discovery and active checks run as a logged-in user instead of
anonymously.

`form_login()` performs a best-effort form login: it GETs the login page (to pick
up a session cookie and any CSRF hidden field), POSTs the credentials, and
returns an AuthSession carrying the resulting cookies.
"""

from __future__ import annotations

import http.cookiejar
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field

USER_AGENT = "celsius/1.1 (+authorized authenticated testing)"
TIMEOUT = 15

# hidden form fields commonly carrying a CSRF token
_INPUT_TAG = re.compile(r"<input\b[^>]*>", re.I)
_ATTR = re.compile(r"""([\w:-]+)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))""")
_CSRF_NAME = re.compile(r"csrf|_token|authenticity_token|verificationtoken", re.I)


def _extract_csrf(page: str) -> dict:
    """Pull hidden CSRF token fields from a login page, tolerant of attribute
    order and quoting."""
    out: dict[str, str] = {}
    for tag in _INPUT_TAG.findall(page):
        attrs = {}
        for m in _ATTR.finditer(tag):
            attrs[m.group(1).lower()] = m.group(2) or m.group(3) or m.group(4) or ""
        name = attrs.get("name", "")
        if name and "value" in attrs and _CSRF_NAME.search(name):
            out[name] = attrs["value"]
    return out


@dataclass
class AuthSession:
    """Extra headers attached to every request to act as a logged-in user."""
    headers: dict = field(default_factory=dict)
    source: str = ""   # human description for logs/audit (no secret values)

    def merge(self, base: dict) -> dict:
        out = dict(base)
        out.update(self.headers)
        return out

    def __bool__(self) -> bool:
        return bool(self.headers)


def from_options(*, cookie: str = "", bearer: str = "",
                 headers: list[str] | None = None) -> AuthSession:
    """Build a session from --cookie / --bearer / --header inputs."""
    h: dict[str, str] = {}
    parts: list[str] = []
    if cookie:
        h["Cookie"] = cookie.strip()
        parts.append("cookie")
    if bearer:
        h["Authorization"] = f"Bearer {bearer.strip()}"
        parts.append("bearer")
    for raw in headers or []:
        if ":" in raw:
            k, v = raw.split(":", 1)
            h[k.strip()] = v.strip()
            parts.append(k.strip())
    return AuthSession(headers=h, source=", ".join(parts))


def _opener(insecure: bool, cj: http.cookiejar.CookieJar) -> urllib.request.OpenerDirector:
    ctx = ssl.create_default_context()
    if insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(cj),
        urllib.request.HTTPSHandler(context=ctx),
    )


def form_login(login_url: str, data: dict, *, insecure: bool = False,
               extra_headers: dict | None = None) -> tuple[AuthSession, str]:
    """Log in via an HTML form. Returns (session, message). On failure the session
    is empty and the message explains why."""
    cj = http.cookiejar.CookieJar()
    opener = _opener(insecure, cj)
    base_headers = {"User-Agent": USER_AGENT}
    base_headers.update(extra_headers or {})
    post_data = dict(data)

    # GET the login page first: seed cookies + auto-fill a CSRF hidden field.
    try:
        req = urllib.request.Request(login_url, headers=base_headers)
        with opener.open(req, timeout=TIMEOUT) as resp:
            page = resp.read(500_000).decode("utf-8", "replace")
        for name, value in _extract_csrf(page).items():
            post_data.setdefault(name, value)
    except (urllib.error.URLError, OSError, ValueError):
        pass  # some logins are a bare POST; continue

    # POST credentials.
    body = urllib.parse.urlencode(post_data).encode()
    headers = dict(base_headers)
    headers["Content-Type"] = "application/x-www-form-urlencoded"
    try:
        req = urllib.request.Request(login_url, data=body, headers=headers, method="POST")
        with opener.open(req, timeout=TIMEOUT) as resp:
            resp.read(1)  # drain
    except urllib.error.HTTPError as e:
        if e.code not in (301, 302, 303, 200):
            return AuthSession(), f"login POST returned HTTP {e.code}"
    except (urllib.error.URLError, OSError, ValueError) as e:
        return AuthSession(), f"login request failed: {e}"

    cookies = [c for c in cj]
    if not cookies:
        return AuthSession(), "login produced no session cookie (wrong fields/credentials?)"
    cookie_hdr = "; ".join(f"{c.name}={c.value}" for c in cookies)
    h = {"Cookie": cookie_hdr}
    h.update(extra_headers or {})
    names = ", ".join(c.name for c in cookies)
    return AuthSession(headers=h, source=f"form-login ({names})"), f"logged in; cookies: {names}"


def build_session(*, cookie: str = "", bearer: str = "", headers=None,
                  login_url: str = "", login_data: str = "", login_user: str = "",
                  login_pass: str = "", login_field_user: str = "username",
                  login_field_pass: str = "password", insecure: bool = False,
                  log=None):
    """Assemble an AuthSession from cookie/bearer/header inputs and an optional form
    login. Shared by the CLI and the web app. Returns an AuthSession, or None when
    nothing was supplied."""
    _log = log or (lambda _m: None)
    base = from_options(cookie=cookie or "", bearer=bearer or "", headers=headers or [])
    if login_url:
        data: dict = {}
        if login_data:
            data.update(dict(urllib.parse.parse_qsl(login_data)))
        if login_user:
            data[login_field_user or "username"] = login_user
        if login_pass:
            data[login_field_pass or "password"] = login_pass
        session, msg = form_login(login_url, data, insecure=insecure,
                                  extra_headers=base.headers)
        _log(f"auth: {msg}")
        if not session:
            _log("auth: form login failed — continuing UNauthenticated")
            return base if base else None
        return session
    if base:
        _log(f"auth: attaching session ({base.source})")
        return base
    return None
