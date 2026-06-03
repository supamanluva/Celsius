"""Static same-host crawler (stdlib only).

BFS over a target's pages up to a page/depth cap, staying on the same host. It
collects HTML pages, linked JavaScript URLs, form actions, and link targets.
This feeds JS intelligence, source-map recovery, and endpoint discovery.

A headless/dynamic crawler (Playwright) lives in `dynamic.py` and is used only
when installed; this static crawler is the always-available default.
"""

from __future__ import annotations

import re
import ssl
import urllib.error
import urllib.parse
import urllib.request
from collections import deque
from dataclasses import dataclass, field

USER_AGENT = "secscan/0.5 (+authorized security testing)"
TIMEOUT = 10
MAX_BYTES = 800_000

_HREF = re.compile(r"""\b(?:href|src|action)\s*=\s*['"]([^'"#]+)['"]""", re.I)
_SCRIPT_SRC = re.compile(r"""<script[^>]+src\s*=\s*['"]([^'"]+)['"]""", re.I)
_FORM = re.compile(r"<form\b[^>]*>", re.I)
_SKIP_EXT = {".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".pdf", ".zip",
             ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".mp3", ".css"}


@dataclass
class CrawlResult:
    base: str
    pages: dict = field(default_factory=dict)     # url -> body
    js_urls: set = field(default_factory=set)
    links: set = field(default_factory=set)       # all discovered same-host URLs
    forms: list = field(default_factory=list)     # [{action, method}]
    errors: list = field(default_factory=list)


def _fetch(url: str, insecure: bool, auth=None) -> tuple[int, str, str]:
    ctx = ssl.create_default_context()
    if insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    hdrs = auth.merge({"User-Agent": USER_AGENT}) if auth else {"User-Agent": USER_AGENT}
    req = urllib.request.Request(url, headers=hdrs)
    with urllib.request.urlopen(req, timeout=TIMEOUT, context=ctx) as resp:
        ctype = resp.headers.get("Content-Type", "")
        body = ""
        if "html" in ctype or "javascript" in ctype or "json" in ctype or not ctype:
            body = resp.read(MAX_BYTES).decode("utf-8", errors="replace")
        return resp.status, body, resp.geturl()


def crawl(base_url: str, *, max_pages: int = 40, max_depth: int = 3,
          insecure: bool = False, auth=None) -> CrawlResult:
    parsed = urllib.parse.urlparse(base_url)
    host = parsed.netloc
    result = CrawlResult(base=base_url)
    seen: set[str] = set()
    queue: deque = deque([(base_url, 0)])

    while queue and len(result.pages) < max_pages:
        url, depth = queue.popleft()
        norm = url.split("#")[0]
        if norm in seen or depth > max_depth:
            continue
        seen.add(norm)
        try:
            status, body, final = _fetch(norm, insecure, auth)
        except (urllib.error.URLError, ssl.SSLError, OSError, ValueError) as e:
            result.errors.append(f"crawl {norm}: {e}")
            continue
        if not body:
            continue
        result.pages[final] = body

        # scripts
        for m in _SCRIPT_SRC.finditer(body):
            js = urllib.parse.urljoin(final, m.group(1))
            if urllib.parse.urlparse(js).netloc in ("", host):
                result.js_urls.add(js)

        # forms
        for fm in _FORM.finditer(body):
            tag = fm.group(0)
            action = re.search(r"""action\s*=\s*['"]([^'"]+)['"]""", tag, re.I)
            method = re.search(r"""method\s*=\s*['"]([^'"]+)['"]""", tag, re.I)
            result.forms.append({
                "action": urllib.parse.urljoin(final, action.group(1)) if action else final,
                "method": (method.group(1).upper() if method else "GET"),
            })

        # links -> enqueue same-host HTML
        for m in _HREF.finditer(body):
            raw = m.group(1)
            if raw.startswith(("mailto:", "tel:", "javascript:", "data:")):
                continue
            link = urllib.parse.urljoin(final, raw)
            p = urllib.parse.urlparse(link)
            if p.netloc != host:
                continue
            result.links.add(link)
            ext = "." + p.path.rsplit(".", 1)[-1].lower() if "." in p.path.rsplit("/", 1)[-1] else ""
            if ext in _SKIP_EXT:
                continue
            if link.split("#")[0] not in seen:
                queue.append((link, depth + 1))

    return result
