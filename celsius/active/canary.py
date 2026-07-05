"""Out-of-band (OOB) interaction canaries — the missing primitive for *blind* bugs.

Some vulnerabilities leave no trace in the response you get back: a blind SSRF
makes the server fetch a URL you don't see, a blind XSS fires in someone else's
browser, blind XXE resolves an entity server-side. The only proof is an out-of-band
callback — the target (or something in its network) reaching out to a host you
control.

Two transports, one interface:
  - ``OOBCanary``  — a self-hosted HTTP listener. Works when the target can reach
    the listener directly (lab/LAN/self-hosted). Simplest; needs no domain.
  - ``DNSCanary``  — a self-hosted authoritative DNS listener for a domain you
    delegate to this host. A *DNS query* for ``<token>.<domain>`` is the hit, which
    escapes even strict HTTP egress filtering (the target's resolver forwards the
    lookup up the chain to us). Needs a registered domain with NS records pointing
    here — real internet infrastructure, the trade-off for reaching filtered targets.

Both mint unique per-probe tokens and record which phone home; a recorded hit is
*deterministic* proof, the same corroboration bar the rest of the active layer holds.
The probes are transport-agnostic: they call ``new_token``/``url_for``/``wait_for_hit``.
"""

from __future__ import annotations

import http.server
import secrets
import socket
import threading
import time
from dataclasses import dataclass


def detect_callback_host() -> str:
    """Best-guess local address the target should call back to.

    Picks the IP of the interface that routes to the internet (a UDP 'connect'
    sends no packets — it just selects the egress interface). Falls back to
    loopback, which only works when the target is on this host — callers should
    warn if the target is remote and this returns 127.0.0.1.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("203.0.113.1", 9))   # TEST-NET-3, unrouteable; just picks the iface
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


@dataclass
class Hit:
    token: str
    src_ip: str
    path: str
    method: str
    user_agent: str = ""


class Canary:
    """Shared token minting + hit bookkeeping for both transports. Probes are
    written against this interface (new_token / url_for / wait_for_hit / hits), so
    they work with either the HTTP or the DNS canary."""

    def __init__(self) -> None:
        self._known: set[str] = set()
        self._hits: dict[str, list[Hit]] = {}
        self._lock = threading.Lock()

    # subclasses implement the listener lifecycle + the callback URL
    def start(self):  # pragma: no cover - overridden
        raise NotImplementedError

    def stop(self) -> None:  # pragma: no cover - overridden
        raise NotImplementedError

    def url_for(self, token: str, path_suffix: str = "") -> str:  # pragma: no cover
        raise NotImplementedError

    def __enter__(self):
        return self.start()

    def __exit__(self, *_exc) -> None:
        self.stop()

    def new_token(self) -> str:
        """A fresh, unguessable token, registered so its callbacks are recorded."""
        token = secrets.token_hex(8)
        with self._lock:
            self._known.add(token)
            self._hits.setdefault(token, [])
        return token

    def was_hit(self, token: str) -> bool:
        with self._lock:
            return bool(self._hits.get(token))

    def hits(self, token: str) -> list[Hit]:
        with self._lock:
            return list(self._hits.get(token, []))

    def wait_for_hit(self, token: str, timeout: float = 3.0, interval: float = 0.1) -> bool:
        """Poll up to `timeout` seconds — a server-side callback can land just after
        the probe's own response returns."""
        deadline = time.monotonic() + max(0.0, timeout)
        while True:
            if self.was_hit(token):
                return True
            if time.monotonic() >= deadline:
                return False
            time.sleep(interval)

    def _record(self, hit: Hit) -> None:
        with self._lock:
            if hit.token in self._known:      # ignore stray/unknown-token noise
                self._hits[hit.token].append(hit)

    def _known_token_in(self, labels) -> str:
        with self._lock:
            for t in self._known:
                if t in labels:
                    return t
        return ""


class OOBCanary(Canary):
    """A self-hosted HTTP callback listener::

        with OOBCanary(host="10.0.0.5") as canary:
            token = canary.new_token()
            url = canary.url_for(token)     # embed this in a probe payload
            ... send the probe ...
            if canary.wait_for_hit(token):  # deterministic OOB proof
                ...
    """

    def __init__(self, *, host: str = "127.0.0.1", bind: str = "127.0.0.1", port: int = 0):
        # `bind`/`port` are the local socket (port 0 -> an ephemeral port). `host`
        # is the address the *target* should call back to — often a LAN/public IP
        # that differs from the bind interface; it defaults to `bind`.
        super().__init__()
        self.bind = bind
        self.port = port
        self.host = host
        self._server: http.server.ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    def start(self) -> "OOBCanary":
        self._server = http.server.ThreadingHTTPServer((self.bind, self.port),
                                                       self._handler())
        self.port = self._server.server_address[1]   # resolve the ephemeral port
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None

    def url_for(self, token: str, path_suffix: str = "") -> str:
        """The callback URL to embed in a probe (e.g. an SSRF ``url=`` value)."""
        return f"http://{self.host}:{self.port}/{token}{path_suffix}"

    def _handler(self):
        canary = self

        class _H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_a):       # silence default stderr logging
                pass

            def _record_and_ack(self):
                token = self.path.lstrip("/").split("/", 1)[0].split("?", 1)[0]
                if token:
                    canary._record(Hit(token=token, src_ip=self.client_address[0],
                                       path=self.path, method=self.command,
                                       user_agent=self.headers.get("User-Agent", "")))
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(b"ok")

            do_GET = _record_and_ack
            do_POST = _record_and_ack
            do_HEAD = _record_and_ack

        return _H


# ---- DNS canary ---------------------------------------------------------------

def _parse_qname(data: bytes) -> str:
    """Extract the queried name from a DNS query packet (header is 12 bytes; QNAME
    is length-prefixed labels terminated by a zero byte). Queries don't use name
    compression, so no pointer handling is needed."""
    labels, i = [], 12
    try:
        while i < len(data):
            ln = data[i]
            i += 1
            if ln == 0:
                break
            if ln & 0xC0:        # a compression pointer shouldn't appear in a query
                break
            labels.append(data[i:i + ln].decode("ascii", "replace"))
            i += ln
    except IndexError:
        pass
    return ".".join(labels)


def _dns_response(query: bytes, answer_ip: str) -> bytes:
    """Minimal NOERROR response echoing the question with a single A answer, so the
    resolver is satisfied and doesn't retry. Content is irrelevant — the query we
    already received is the signal."""
    try:
        # question section spans bytes 12..(end of qname)+4 (qtype+qclass)
        i = 12
        while i < len(query) and query[i] != 0:
            i += query[i] + 1
        q_end = i + 1 + 4
        header = query[0:2] + b"\x81\x80" + b"\x00\x01" + b"\x00\x01" + b"\x00\x00\x00\x00"
        answer = (b"\xc0\x0c" + b"\x00\x01" + b"\x00\x01" + b"\x00\x00\x00\x1e"
                  + b"\x00\x04" + socket.inet_aton(answer_ip))
        return header + query[12:q_end] + answer
    except (OSError, IndexError):
        return b""


class DNSCanary(Canary):
    """A self-hosted authoritative DNS listener for ``domain``. A DNS query for
    ``<token>.<domain>`` is the hit — it reaches us even when the target can't make
    outbound HTTP, because its resolver forwards the lookup up the chain.

    Requires that ``domain``'s NS records point at this host (real infrastructure).
    ``dns_port`` defaults to 53 (needs root/CAP_NET_BIND); use a high port in tests.
    """

    def __init__(self, *, domain: str, bind: str = "0.0.0.0", dns_port: int = 53,
                 answer_ip: str = "0.0.0.0"):
        super().__init__()
        self.domain = (domain or "").strip(".").lower()
        self.bind = bind
        self.dns_port = dns_port
        self.answer_ip = answer_ip
        self._sock: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._stop = False

    def start(self) -> "DNSCanary":
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((self.bind, self.dns_port))
        self.dns_port = self._sock.getsockname()[1]   # resolve if 0 was passed
        self._sock.settimeout(0.3)
        self._stop = False
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        self._stop = True
        if self._thread is not None:
            self._thread.join(timeout=1.0)
            self._thread = None
        if self._sock is not None:
            self._sock.close()
            self._sock = None

    def hostname_for(self, token: str) -> str:
        return f"{token}.{self.domain}"

    def url_for(self, token: str, path_suffix: str = "") -> str:
        """A URL on the canary domain — a probe that fetches it triggers the DNS
        lookup even if the HTTP connection is then blocked."""
        return f"http://{self.hostname_for(token)}/{path_suffix.lstrip('/')}"

    def _loop(self) -> None:
        while not self._stop:
            try:
                data, addr = self._sock.recvfrom(2048)   # type: ignore[union-attr]
            except socket.timeout:
                continue
            except OSError:
                break
            name = _parse_qname(data).lower().rstrip(".")
            token = self._known_token_in(set(name.split(".")))
            if token:
                self._record(Hit(token=token, src_ip=addr[0], path=name, method="DNS"))
            resp = _dns_response(data, self.answer_ip)
            if resp:
                try:
                    self._sock.sendto(resp, addr)        # type: ignore[union-attr]
                except OSError:
                    pass
