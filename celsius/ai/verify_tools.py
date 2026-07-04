"""Safe, read-only tools the AI can call to PROVE or REFUTE a hypothesis.

The model never makes a request itself: it names a tool + arguments, this
dispatcher validates them (and locks every tool to the scanned host, so the AI
can't be steered off-scope or into SSRF), runs the tool through the lab harness
where applicable, and returns structured evidence for the model to judge.

All tools are non-destructive: an HTTP GET, a DNS/CNAME lookup, a TCP connect.
"""

from __future__ import annotations

import re
import shlex
import socket
from typing import TYPE_CHECKING, Callable, Optional
from urllib.parse import urlencode, urlparse

from .. import webchecks

if TYPE_CHECKING:
    from ..active.harness import LabContext

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
    {"name": "poc",
     "args": {"method": "GET|HEAD|OPTIONS|POST", "url": "absolute URL on the scanned host",
              "headers": "optional request headers", "body": "optional POST form fields {key: value}"},
     "use": "DEMONSTRATE exploitability by sending one crafted request and capturing "
            "the result + a reproducible `curl`. Use the URL/headers/body to carry a "
            "benign detection payload that PROVES impact: an open-redirect to a canary, "
            "a unique XSS marker that comes back unescaped, an Origin that gets reflected "
            "with credentials, fetching an exposed file's contents, an SSRF callback URL. "
            "STRICTLY non-destructive: never delete/modify data, never brute-force creds."},
]


def _same_host(candidate: Optional[str], host: Optional[str]) -> bool:
    c = (candidate or "").lower().strip().rstrip(".")
    h = (host or "").lower().strip().rstrip(".")
    return bool(h) and (c == h)


def _http_get(args: dict, lab: "LabContext") -> Optional[dict]:
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


def _tls_probe(args: dict, lab: "LabContext") -> Optional[dict]:
    host = str((args or {}).get("host") or "")
    port_raw = (args or {}).get("port", 443)
    try:
        port = int(port_raw) if isinstance(port_raw, (int, str)) else 443
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


def _dns_lookup(args: dict, lab: "LabContext") -> Optional[dict]:
    host = str((args or {}).get("host") or "")
    if not _same_host(host, lab.host):
        return {"tool": "dns_lookup", "host": host, "error": "off-scope host refused"}
    from ..recon import dns as dns_mod
    data = dns_mod.lookup(host)
    return {"tool": "dns_lookup", "host": host,
            "records": data.get("records", {}), "reverse": data.get("reverse", {})}


def _tcp_connect(args: dict, lab: "LabContext") -> Optional[dict]:
    host = str((args or {}).get("host") or "")
    port_raw = (args or {}).get("port")
    if not isinstance(port_raw, (int, str)):
        return None
    try:
        port = int(port_raw)
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


def _takeover_check(args: dict, lab: "LabContext") -> Optional[dict]:
    host = str((args or {}).get("host") or "")
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


def _curl(method: str, url: str, headers: Optional[dict], body: Optional[dict]) -> str:
    """A copy-pasteable reproduction of the exact PoC request."""
    parts = ["curl", "-sk", "-i"]
    if method != "GET":
        parts += ["-X", method]
    for k, v in (headers or {}).items():
        parts += ["-H", shlex.quote(f"{k}: {v}")]
    if body:
        parts += ["--data", shlex.quote(urlencode(body))]
    parts.append(shlex.quote(url))
    return " ".join(parts)


_POC_METHODS = {"GET", "HEAD", "OPTIONS", "POST"}


def _poc_request(args: dict, lab: "LabContext") -> Optional[dict]:
    """Send ONE crafted PoC request through the harness and capture the proof.

    Guarded: read-only/benign only (a destructive filter blocks SQL-write/OS-cmd
    payloads), host-locked, and routed through the lab harness (scope, rate-limit,
    request cap, attestation, kill-switch, dry-run preview)."""
    from .agent import _DESTRUCTIVE  # lazy: avoids an import cycle
    url = (args or {}).get("url")
    method = str((args or {}).get("method") or "GET").upper()
    headers = (args or {}).get("headers")
    headers = headers if isinstance(headers, dict) else None
    body = (args or {}).get("body")
    body = body if isinstance(body, dict) else None
    if method not in _POC_METHODS:
        return {"tool": "poc", "error": f"method {method} not allowed"}
    if not isinstance(url, str) or not _same_host(urlparse(url).hostname or "", lab.host):
        return {"tool": "poc", "url": url, "error": "off-scope host refused"}
    blob = " ".join([url, *(f"{k}:{v}" for k, v in (headers or {}).items()),
                     *map(str, (body or {}).values())])
    if _DESTRUCTIVE.search(blob):
        return {"tool": "poc", "url": url, "error": "refused: request looks state-changing/destructive"}
    resp = lab.send(url, method=method, data=body, headers=headers,
                    purpose="ai-tool:poc", payload=True, follow=False)
    curl = _curl(method, url, headers, body)
    if resp is None:
        return {"tool": "poc", "url": url, "curl": curl, "error": "no response / halted (or dry-run preview)"}
    text = resp.body or ""
    m = _TITLE.search(text)
    return {
        "tool": "poc", "method": method, "url": url, "status": resp.status,
        "location": resp.location, "response_headers": resp.headers or {},
        "title": (m.group(1).strip()[:120] if m else ""),
        "snippet": re.sub(r"\s+", " ", text).strip()[:600],
        "curl": curl,
    }


_TOOLS: dict[str, Callable[[dict, "LabContext"], Optional[dict]]] = {
    "http_get": _http_get,
    "tcp_connect": _tcp_connect,
    "takeover_check": _takeover_check,
    "tls_probe": _tls_probe,
    "dns_lookup": _dns_lookup,
    "poc": _poc_request,
}


def run_tool(name: str, args: dict, lab: "LabContext") -> Optional[dict]:
    """Dispatch a validated tool call; never raises."""
    fn = _TOOLS.get(name)
    if fn is None:
        return None
    try:
        return fn(args, lab)
    except Exception:  # a tool must never break the loop
        return None
