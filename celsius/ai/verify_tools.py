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
_SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
TOOL_SPECS = [
    {"name": "http_get",
     "args": {"url": "absolute http(s) URL on the SCANNED host (any path/port)",
              "method": "GET|HEAD|OPTIONS (optional, default GET)",
              "headers": "optional dict of request headers, e.g. {\"Origin\":\"https://evil.test\"} "
                         "for CORS, or {\"Authorization\":\"\"} to test if auth is required"},
     "use": "fetch a URL and return its status + ALL response headers + title/snippet. "
            "Confirms: reachable panels/services, exposed paths, CORS misconfig (ACAO "
            "reflecting your Origin), missing auth (200 without credentials), allowed "
            "methods (OPTIONS -> Allow), security headers"},
    {"name": "tcp_connect",
     "args": {"host": "the scanned host", "port": "integer port"},
     "use": "check whether a TCP port is open/reachable (confirm an exposed service)"},
    {"name": "takeover_check",
     "args": {"host": "the scanned host"},
     "use": "resolve the host's CNAME and look for a dangling third-party "
            "fingerprint — proves/refutes a subdomain takeover"},
    {"name": "tls_probe",
     "args": {"host": "the scanned host", "port": "integer TLS port (default 443)"},
     "use": "TLS handshake details — cert subject/issuer/SAN/expiry, protocol, whether "
            "self-signed or hostname-mismatched. Identifies the service behind a TLS "
            "port and proves cert/protocol issues"},
    {"name": "dns_lookup",
     "args": {"host": "the scanned host"},
     "use": "resolve A/AAAA/CNAME/MX/TXT/CAA records (+ reverse DNS) — confirms DNS "
            "exposure, mail setup, missing CAA, dangling records"},
]


def _same_host(candidate: str, host: str) -> bool:
    c = (candidate or "").lower().strip().rstrip(".")
    h = (host or "").lower().strip().rstrip(".")
    return bool(h) and (c == h)


def _http_get(args: dict, lab) -> Optional[dict]:
    url = (args or {}).get("url")
    if not isinstance(url, str) or not url.startswith(("http://", "https://")):
        return None
    method = str((args or {}).get("method") or "GET").upper()
    if method not in _SAFE_METHODS:
        return {"tool": "http_get", "url": url,
                "error": f"method {method} not allowed (read-only: GET/HEAD/OPTIONS)"}
    req_headers = (args or {}).get("headers")
    req_headers = req_headers if isinstance(req_headers, dict) else None
    if not _same_host(urlparse(url).hostname or "", lab.host):
        return {"tool": "http_get", "url": url, "error": "off-scope host refused"}
    resp = lab.send(url, method=method, purpose="ai-tool:http_get", payload=False,
                    follow=False, headers=req_headers)
    if resp is None:
        return {"tool": "http_get", "url": url, "error": "no response / halted"}
    body = resp.body or ""
    m = _TITLE.search(body)
    return {
        "tool": "http_get", "url": url, "method": method, "status": resp.status,
        "location": resp.location, "final_url": resp.final_url,
        "request_headers_sent": req_headers or {},
        "response_headers": resp.headers or {},
        "title": (m.group(1).strip()[:120] if m else ""),
        "length": len(body),
        "snippet": re.sub(r"\s+", " ", body).strip()[:600],
    }


def _tls_probe(args: dict, lab) -> Optional[dict]:
    host = (args or {}).get("host")
    port = (args or {}).get("port", 443)
    try:
        port = int(port)
    except (TypeError, ValueError):
        port = 443
    if not _same_host(host, lab.host):
        return {"tool": "tls_probe", "host": host, "error": "off-scope host refused"}
    from ..recon import tls as tls_mod
    info, _f, errs = tls_mod.analyze(host, port)
    keep = {k: info.get(k) for k in
            ("protocol", "cipher", "verified", "subject", "issuer", "san",
             "not_after", "self_signed", "hostname_mismatch", "days_left")
            if k in info}
    return {"tool": "tls_probe", "host": host, "port": port, **keep, "errors": errs[:2]}


def _dns_lookup(args: dict, lab) -> Optional[dict]:
    host = (args or {}).get("host")
    if not _same_host(host, lab.host):
        return {"tool": "dns_lookup", "host": host, "error": "off-scope host refused"}
    from ..recon import dns as dns_mod
    data = dns_mod.lookup(host)
    return {"tool": "dns_lookup", "host": host,
            "records": data.get("records", {}), "reverse": data.get("reverse", {})}


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
    "tls_probe": _tls_probe,
    "dns_lookup": _dns_lookup,
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
