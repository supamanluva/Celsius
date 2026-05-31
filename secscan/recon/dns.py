"""DNS reconnaissance via DNS-over-HTTPS (no third-party dependency).

stdlib has no MX/TXT/NS resolver, so we query a DoH JSON endpoint (dns.google).
Returns a dict of record-type -> [values], plus reverse-DNS for resolved IPs.
"""

from __future__ import annotations

import json
import socket
import urllib.parse
import urllib.request
from typing import Optional

DOH_URL = "https://dns.google/resolve"
USER_AGENT = "secscan/0.4 (+authorized security testing)"
TIMEOUT = 8
RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "CAA"]


def _query(name: str, rtype: str) -> list[str]:
    params = urllib.parse.urlencode({"name": name, "type": rtype})
    req = urllib.request.Request(f"{DOH_URL}?{params}", headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            data = json.loads(resp.read().decode())
    except (urllib.error.URLError, OSError, json.JSONDecodeError):
        return []
    out = []
    for ans in data.get("Answer", []) or []:
        val = ans.get("data", "")
        if val:
            out.append(val.strip())
    return out


def reverse_dns(ip: str) -> Optional[str]:
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        return None


def lookup(host: str) -> dict:
    """Return {records: {type: [..]}, reverse: {ip: ptr}}."""
    records: dict[str, list[str]] = {}
    for rtype in RECORD_TYPES:
        vals = _query(host, rtype)
        if vals:
            records[rtype] = vals

    reverse: dict[str, str] = {}
    for ip in records.get("A", []) + records.get("AAAA", []):
        ptr = reverse_dns(ip)
        if ptr:
            reverse[ip] = ptr

    return {"records": records, "reverse": reverse}


def summarize(dns: dict) -> str:
    rec = dns.get("records", {})
    parts = []
    for t in ("A", "AAAA", "MX", "NS"):
        if rec.get(t):
            parts.append(f"{t}: {', '.join(rec[t][:4])}")
    return " | ".join(parts)
