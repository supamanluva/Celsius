"""Target parsing and resolution.

A target can be given as a URL (https://host[:port]/path), a bare hostname, or
an IP address. We normalize it into the pieces the scanners need.
"""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlparse


@dataclass
class Target:
    raw: str
    scheme: Optional[str]   # "http" / "https" / None
    host: str               # hostname or IP literal
    port: Optional[int]     # explicit port from the URL, if any
    path: str = "/"

    @property
    def is_ip(self) -> bool:
        try:
            ipaddress.ip_address(self.host)
            return True
        except ValueError:
            return False

    def resolve_ip(self) -> Optional[str]:
        """Best-effort A/AAAA resolution; returns None on failure."""
        if self.is_ip:
            return self.host
        try:
            return socket.gethostbyname(self.host)
        except (socket.gaierror, OSError):
            return None

    def web_url(self) -> str:
        """A URL suitable for HTTP analysis (defaults to https)."""
        scheme = self.scheme or "https"
        netloc = self.host
        if self.port and not _is_default_port(scheme, self.port):
            netloc = f"{self.host}:{self.port}"
        return f"{scheme}://{netloc}{self.path or '/'}"


def _is_default_port(scheme: str, port: int) -> bool:
    return (scheme == "https" and port == 443) or (scheme == "http" and port == 80)


def parse_target(raw: str) -> Target:
    raw = raw.strip()
    if "://" in raw:
        u = urlparse(raw)
        host = u.hostname or ""
        return Target(
            raw=raw,
            scheme=u.scheme or None,
            host=host,
            port=u.port,
            path=u.path or "/",
        )

    # No scheme. Could be "host", "host:port", or an IP.
    host = raw
    port: Optional[int] = None
    # IPv6 literal in brackets, e.g. [::1]:443
    if raw.startswith("[") and "]" in raw:
        host = raw[1 : raw.index("]")]
        rest = raw[raw.index("]") + 1 :]
        if rest.startswith(":"):
            port = _safe_int(rest[1:])
    elif raw.count(":") == 1:  # host:port (not IPv6)
        h, _, p = raw.partition(":")
        host, port = h, _safe_int(p)

    return Target(raw=raw, scheme=None, host=host, port=port, path="/")


def _safe_int(s: str) -> Optional[int]:
    try:
        return int(s)
    except ValueError:
        return None


def is_private_or_local(host_or_ip: str) -> bool:
    """True if the address is private/loopback/link-local/reserved.

    Used to warn (not block) and to allow a localhost-only safe mode.
    """
    try:
        ip = ipaddress.ip_address(host_or_ip)
    except ValueError:
        # Hostname — try to resolve.
        try:
            ip = ipaddress.ip_address(socket.gethostbyname(host_or_ip))
        except (socket.gaierror, OSError, ValueError):
            return False
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_unspecified
    )
