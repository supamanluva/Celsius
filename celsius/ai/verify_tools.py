"""Safe, read-only tools the AI can call to PROVE or REFUTE a hypothesis.

The model never makes a request itself: it names a tool + arguments, this
dispatcher validates them (and locks every tool to the scanned host, so the AI
can't be steered off-scope or into SSRF), runs the tool through the lab harness
where applicable, and returns structured evidence for the model to judge.

All tools are non-destructive: an HTTP GET, a DNS/CNAME lookup, a TCP connect.
"""

from __future__ import annotations

import re
import socket
from typing import Callable, Optional
from urllib.parse import urlparse

from .. import webchecks

_TITLE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)

# What the model is told it can call. Kept tiny and high-signal.
TOOL_SPECS = [
    {"name": "http_get",
     "args": {"url": "absolute http(s) URL on the SCANNED host (any path/port)"},
     "use": "fetch a page to confirm it is reachable and see what it is — login "
            "pages, app banners, exposed admin panels, directory listings, errors"},
    {"name": "tcp_connect",
     "args": {"host": "the scanned host", "port": "integer port"},
     "use": "check whether a TCP port is open/reachable (confirm an exposed service)"},
    {"name": "takeover_check",
     "args": {"host": "the scanned host"},
     "use": "resolve the host's CNAME and look for a dangling third-party "
            "fingerprint — proves/refutes a subdomain takeover"},
]


def _same_host(candidate: str, host: str) -> bool:
    c = (candidate or "").lower().strip().rstrip(".")
    h = (host or "").lower().strip().rstrip(".")
    return bool(h) and (c == h)


def _http_get(args: dict, lab) -> Optional[dict]:
    url = (args or {}).get("url")
    if not isinstance(url, str) or not url.startswith(("http://", "https://")):
        return None
    if not _same_host(urlparse(url).hostname or "", lab.host):
        return {"tool": "http_get", "url": url, "error": "off-scope host refused"}
    resp = lab.send(url, method="GET", purpose="ai-tool:http_get", payload=False, follow=True)
    if resp is None:
        return {"tool": "http_get", "url": url, "error": "no response / halted"}
    body = resp.body or ""
    m = _TITLE.search(body)
    return {
        "tool": "http_get", "url": url, "status": resp.status,
        "final_url": resp.final_url,
        "server": (resp.headers or {}).get("server", ""),
        "www_authenticate": (resp.headers or {}).get("www-authenticate", ""),
        "title": (m.group(1).strip()[:120] if m else ""),
        "length": len(body),
        "snippet": re.sub(r"\s+", " ", body).strip()[:600],
    }


def _tcp_connect(args: dict, lab) -> Optional[dict]:
    host = (args or {}).get("host")
    port = (args or {}).get("port")
    try:
        port = int(port)
    except (TypeError, ValueError):
        return None
    if not _same_host(host, lab.host) or not (0 < port < 65536):
        return {"tool": "tcp_connect", "host": host, "port": port, "error": "off-scope or bad port"}
    is_open = False
    try:
        with socket.create_connection((host, port), timeout=5):
            is_open = True
    except OSError:
        is_open = False
    return {"tool": "tcp_connect", "host": host, "port": port, "open": is_open}


def _takeover_check(args: dict, lab) -> Optional[dict]:
    host = (args or {}).get("host")
    if not _same_host(host, lab.host):
        return {"tool": "takeover_check", "host": host, "error": "off-scope host refused"}
    cname = webchecks._cname(host)
    sig = next((s for s in webchecks._TAKEOVER_SIGS if s[0] in cname), None) if cname else None
    matched = False
    if sig:
        resp = lab.send(f"https://{host}/", method="GET",
                        purpose="ai-tool:takeover", payload=False, follow=True)
        body = (resp.body if resp else "") or ""
        matched = sig[1].lower() in body.lower()
    return {
        "tool": "takeover_check", "host": host, "cname": cname or "(none)",
        "dangling_provider": sig[2] if sig else "",
        "fingerprint_matched": matched,
    }


_TOOLS: dict[str, Callable[[dict, object], Optional[dict]]] = {
    "http_get": _http_get,
    "tcp_connect": _tcp_connect,
    "takeover_check": _takeover_check,
}


def run_tool(name: str, args: dict, lab) -> Optional[dict]:
    """Dispatch a validated tool call; never raises."""
    fn = _TOOLS.get(name)
    if fn is None:
        return None
    try:
        return fn(args, lab)
    except Exception:  # a tool must never break the loop
        return None
