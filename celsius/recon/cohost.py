"""Co-hosted host discovery: other hostnames served from the same IP.

A reverse proxy serves many vhosts on one IP, routed by Host header / TLS SNI —
so scanning one hostname only ever sees that one vhost. This surfaces sibling
hostnames from two public signals:

  1. the TLS certificate's SAN list (already fetched during the scan), and
  2. a passive reverse-IP lookup (HackerTarget — free, rate-limited, no key).

The point: a site owner can then queue scans of the *other* services on the same
box. Honest limit — these are PUBLIC signals; a purely internal/unannounced vhost
won't appear and must be entered by hand.
"""

from __future__ import annotations

import re
import urllib.error
import urllib.parse
import urllib.request

USER_AGENT = "celsius/0.6 (+authorized security testing)"
TIMEOUT = 10
REVERSE_IP_URL = "https://api.hackertarget.com/reverseiplookup/?q="

# a plausible DNS hostname (at least two labels, no scheme/port/path)
_HOST_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)(?:\.(?!-)[a-z0-9-]{1,63}(?<!-))+$")


def _valid(h: str) -> bool:
    return bool(h) and len(h) < 254 and bool(_HOST_RE.match(h))


def _norm(h: str) -> str:
    return (h or "").strip().lower().lstrip("*.").rstrip(".")


def from_san(sans, scanned_host: str) -> list[str]:
    """Sibling hostnames from cert SANs (excludes the scanned host + wildcards)."""
    sh = _norm(scanned_host)
    out = {h for h in (_norm(s) for s in (sans or [])) if _valid(h) and h != sh}
    return sorted(out)


def reverse_ip(ip: str, *, timeout: int = TIMEOUT) -> tuple[list[str], str | None]:
    """Hostnames sharing `ip`, via a passive reverse-IP lookup. Returns
    (hosts, error) — error is a short note on rate-limit/failure (non-fatal)."""
    if not ip:
        return [], None
    url = REVERSE_IP_URL + urllib.parse.quote(ip)
    try:
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            text = r.read(200_000).decode("utf-8", "replace")
    except (urllib.error.URLError, OSError, ValueError) as e:
        return [], f"reverse-ip lookup failed ({e})"
    low = text.lower()
    if "api count exceeded" in low or "too many" in low or text.strip().startswith("error"):
        return [], "reverse-ip lookup rate-limited (try later or add a key)"
    hosts = {h for h in (_norm(ln) for ln in text.splitlines()) if _valid(h)}
    return sorted(hosts), None


def discover(host: str, ip: str, sans, *, do_reverse_ip: bool = True) -> dict:
    """Combine cert-SAN + reverse-IP into a deduped sibling-host list (≠ scanned host)."""
    san_hosts = from_san(sans, host)
    rip_hosts: list[str] = []
    err = None
    if do_reverse_ip:
        rip_hosts, err = reverse_ip(ip)
    sh = _norm(host)
    siblings = sorted({h for h in set(san_hosts) | set(rip_hosts) if h and h != sh})
    return {"ip": ip, "siblings": siblings, "from_san": san_hosts,
            "from_reverse_ip": rip_hosts, "error": err}
