"""Origin-exposure / CDN-bypass discovery.

When a target is fronted by a CDN (Cloudflare etc.) the origin server is hidden —
you see the CDN edge, not the real host/version. But subdomains and mail hosts are
frequently left *un-proxied*: they resolve straight to the origin IP. Resolve the
known hostnames and flag any that point at a non-CDN public address — those are
candidate origins you can scan directly (and, defensively, a leak to firewall
behind the CDN's published ranges).

Pure stdlib: IP classification via `ipaddress`, resolution via the DoH helper.
"""

from __future__ import annotations

import concurrent.futures
import ipaddress
from typing import Optional

from . import dns as dns_mod

# Published CDN/proxy IPv4 ranges (stable) — to tell a CDN edge IP from a subdomain
# pointing straight at the (un-proxied) origin. Cloudflare is by far the common one.
_CDN_RANGES = {
    "Cloudflare": [
        # IPv4 (https://www.cloudflare.com/ips-v4)
        "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
        "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
        "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
        "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
        # IPv6 (https://www.cloudflare.com/ips-v6) — without these, CF IPv6 edges
        # (e.g. 2a06:98c1::) look like a non-CDN origin and false-positive.
        "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32",
        "2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
    ],
    "Fastly": ["151.101.0.0/16", "199.232.0.0/16", "2a04:4e40::/32", "2a04:4e42::/32"],
}
_NETS = {name: [ipaddress.ip_network(c) for c in cidrs]
         for name, cidrs in _CDN_RANGES.items()}


def cdn_for_ip(ip: str) -> Optional[str]:
    """Name of the CDN owning `ip`, or None if it isn't in a known CDN range."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    for name, nets in _NETS.items():
        if any(addr in n for n in nets):
            return name
    return None


def _is_public(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def mx_hosts(dns_records: dict) -> list[str]:
    """Hostnames from MX records ('10 mail.example.com.' -> 'mail.example.com')."""
    out = []
    for raw in (dns_records or {}).get("MX", []) or []:
        parts = str(raw).split()
        if parts:
            out.append(parts[-1].rstrip("."))
    return out


def resolve(host: str) -> list[str]:
    """A/AAAA addresses for `host` via DoH."""
    return dns_mod._query(host, "A") + dns_mod._query(host, "AAAA")


def _classify(host: str) -> Optional[dict]:
    ips = resolve(host)
    if not ips:
        return None
    origin_ips = [ip for ip in ips if _is_public(ip) and not cdn_for_ip(ip)]
    if not origin_ips:
        return None
    cdn_ips = {ip: cdn_for_ip(ip) for ip in ips if cdn_for_ip(ip)}
    return {"host": host, "ips": ips, "origin_ips": origin_ips, "cdn_ips": cdn_ips}


def find_exposed_origins(hosts, *, max_hosts: int = 150) -> list[dict]:
    """Resolve each host (concurrently) and return those pointing at a non-CDN public
    IP — candidate origins behind the CDN. [{host, ips, origin_ips, cdn_ips}]."""
    uniq, seen = [], set()
    for h in hosts:
        h = (h or "").strip().lower().rstrip(".").lstrip("*.")
        if h and h not in seen:
            seen.add(h)
            uniq.append(h)
    uniq = uniq[:max_hosts]
    if not uniq:
        return []
    out = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as ex:
        for r in ex.map(_classify, uniq):
            if r:
                out.append(r)
    out.sort(key=lambda r: r["host"])
    return out
