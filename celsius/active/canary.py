"""Out-of-band (OOB) interaction canary — the missing primitive for *blind* bugs.

Some vulnerabilities leave no trace in the response you get back: a blind SSRF
makes the server fetch a URL you don't see, a blind XSS fires in someone else's
browser, a blind SQLi exfiltrates over DNS. The only proof is an out-of-band
callback — the target (or something in its network) reaching out to a host you
control.

This is that host: a tiny, stdlib-only HTTP listener that hands out unique
per-probe tokens and records which ones phone home. A recorded hit for a token is
*deterministic* proof the injected URL was fetched — which is exactly the kind of
independent corroboration the rest of the active layer already insists on before
calling something confirmed. No third-party collaborator service, nothing leaves
the operator's control.

Reachability caveat: the target must be able to reach this listener. That holds
for a lab/LAN/self-hosted run (bind to an address the target can route to); for a
target behind strict egress filtering, an HTTP callback may be blocked and a DNS
canary (a natural follow-up to this module) would be needed instead.
"""

from __future__ import annotations

import http.server
import secrets
import threading
import time
from dataclasses import dataclass


@dataclass
class Hit:
    token: str
    src_ip: str
    path: str
    method: str
    user_agent: str = ""


class OOBCanary:
    """A callback listener. ``new_token()`` mints a token + returns its callback
    URL; ``was_hit(token)`` reports whether anything reached that URL.

    Use as a context manager so the listener is always torn down::

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
        self.bind = bind
        self.port = port
        self.host = host
        self._known: set[str] = set()
        self._hits: dict[str, list[Hit]] = {}
        self._lock = threading.Lock()
        self._server: http.server.ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    # ---- lifecycle ----
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

    def __enter__(self) -> "OOBCanary":
        return self.start()

    def __exit__(self, *_exc) -> None:
        self.stop()

    # ---- tokens / callback URLs ----
    def new_token(self) -> str:
        """A fresh, unguessable token, registered so its callbacks are recorded."""
        token = secrets.token_hex(8)
        with self._lock:
            self._known.add(token)
            self._hits.setdefault(token, [])
        return token

    def url_for(self, token: str, path_suffix: str = "") -> str:
        """The callback URL to embed in a probe (e.g. an SSRF ``url=`` value)."""
        return f"http://{self.host}:{self.port}/{token}{path_suffix}"

    # ---- results ----
    def was_hit(self, token: str) -> bool:
        with self._lock:
            return bool(self._hits.get(token))

    def hits(self, token: str) -> list[Hit]:
        with self._lock:
            return list(self._hits.get(token, []))

    def wait_for_hit(self, token: str, timeout: float = 3.0, interval: float = 0.1) -> bool:
        """Poll up to `timeout` seconds — a server-side fetch can land just after
        the probe's own response returns."""
        deadline = time.monotonic() + max(0.0, timeout)
        while True:
            if self.was_hit(token):
                return True
            if time.monotonic() >= deadline:
                return False
            time.sleep(interval)

    # ---- internals ----
    def _record(self, hit: Hit) -> None:
        with self._lock:
            if hit.token in self._known:      # ignore stray/unknown-token noise
                self._hits[hit.token].append(hit)

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
