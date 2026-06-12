"""Tests for the exposed-unauthenticated-service probes (svcprobe).

Stdlib-only: run directly (`python tests/test_svcprobe.py`) or under pytest.

Uses tiny in-process fake TCP/HTTP servers so the probes exercise real sockets
without any external service. Verifies: dispatch by port/name, the open vs
auth-required distinction, the MongoDB wire-message construction, and that a
crashing/closed port degrades to None (never raises).
"""

from __future__ import annotations

import os
import socket
import struct
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from celsius import svcprobe  # noqa: E402


# ---- fake servers -------------------------------------------------------------

def _tcp_server(handler) -> tuple[str, int, threading.Thread, socket.socket]:
    """Start a one-shot TCP server; handler(conn) does the protocol. Returns
    (host, port, thread, sock) — close sock to stop."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    host, port = srv.getsockname()

    def serve():
        try:
            conn, _ = srv.accept()
            with conn:
                handler(conn)
        except OSError:
            pass

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    return host, port, t, srv


def _http_server(routes: dict) -> tuple[str, int, HTTPServer, threading.Thread]:
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):  # silence
            pass

        def do_GET(self):
            path = self.path
            if path in routes:
                status, body = routes[path]
                self.send_response(status)
                self.end_headers()
                self.wfile.write(body)
            else:
                self.send_response(404)
                self.end_headers()

    srv = HTTPServer(("127.0.0.1", 0), H)
    host, port = srv.server_address
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return host, port, srv, t


# ---- dispatch -----------------------------------------------------------------

def test_checker_by_port():
    assert svcprobe.checker_for(6379) is svcprobe.check_redis
    assert svcprobe.checker_for(2375) is svcprobe.check_docker
    assert svcprobe.checker_for(27017) is svcprobe.check_mongodb
    assert svcprobe.checker_for(443) is None


def test_checker_by_name_on_nonstandard_port():
    # nmap reports redis on an odd port — still picked up by the name hint
    assert svcprobe.checker_for(7777, "redis") is svcprobe.check_redis
    assert svcprobe.checker_for(12345, "", "MongoDB 6.0") is svcprobe.check_mongodb


# ---- redis --------------------------------------------------------------------

def test_redis_unauthenticated_is_flagged():
    def handler(conn):
        conn.recv(64)             # "PING\r\n"
        conn.sendall(b"+PONG\r\n")
    host, port, _t, srv = _tcp_server(handler)
    try:
        r = svcprobe.check_redis(host, port)
    finally:
        srv.close()
    assert r is not None and r.exposed is True and r.severity == "HIGH"
    assert r.service == "Redis"


def test_redis_with_auth_is_not_exposed():
    def handler(conn):
        conn.recv(64)
        conn.sendall(b"-NOAUTH Authentication required.\r\n")
    host, port, _t, srv = _tcp_server(handler)
    try:
        r = svcprobe.check_redis(host, port)
    finally:
        srv.close()
    assert r is not None and r.exposed is False and r.severity == "LOW"


def test_closed_port_returns_none_never_raises():
    # nothing listening on this port
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    _h, port = s.getsockname()
    s.close()
    assert svcprobe.check_redis("127.0.0.1", port) is None
    assert svcprobe.check_memcached("127.0.0.1", port) is None


# ---- memcached ----------------------------------------------------------------

def test_memcached_stats_is_flagged():
    def handler(conn):
        conn.recv(64)             # "stats\r\n"
        conn.sendall(b"STAT pid 1234\r\nSTAT uptime 5\r\nEND\r\n")
    host, port, _t, srv = _tcp_server(handler)
    try:
        r = svcprobe.check_memcached(host, port)
    finally:
        srv.close()
    assert r is not None and r.exposed is True and r.service == "Memcached"


# ---- docker (http) ------------------------------------------------------------

def test_docker_api_unauthenticated_is_critical():
    host, port, srv, _t = _http_server({
        "/version": (200, b'{"ApiVersion":"1.45","GoVersion":"go1.22"}'),
    })
    try:
        r = svcprobe.check_docker(host, port)
    finally:
        srv.shutdown()
    assert r is not None and r.exposed is True and r.severity == "CRITICAL"


# ---- elasticsearch (http) -----------------------------------------------------

def test_elasticsearch_open_indices_is_high():
    host, port, srv, _t = _http_server({
        "/": (200, b'{"cluster_name":"prod","version":{"lucene_version":"9.7.0"}}'),
        "/_cat/indices?format=json": (200, b'[{"index":".kibana"},{"index":"users"}]'),
    })
    try:
        r = svcprobe.check_elasticsearch(host, port)
    finally:
        srv.shutdown()
    assert r is not None and r.exposed is True and r.severity == "HIGH"


def test_elasticsearch_auth_required_is_low():
    host, port, srv, _t = _http_server({})  # everything 404 except we want 401
    # override: respond 401 to "/"
    srv.RequestHandlerClass  # noqa
    # easiest: a server that returns 401 on /
    srv.shutdown()
    host, port, srv2, _t2 = _http_server({"/": (401, b"unauthorized")})
    try:
        r = svcprobe.check_elasticsearch(host, port)
    finally:
        srv2.shutdown()
    assert r is not None and r.exposed is False and r.severity == "LOW"


# ---- mongodb wire protocol ----------------------------------------------------

def test_mongo_ismaster_message_is_well_formed():
    msg = svcprobe._mongo_ismaster_msg()
    # header: length, requestID, responseTo, opCode
    length, req_id, resp_to, opcode = struct.unpack("<iiii", msg[:16])
    assert length == len(msg)          # declared length matches actual
    assert opcode == 2004              # OP_QUERY
    assert resp_to == 0
    assert b"admin.$cmd\x00" in msg
    assert b"isMaster" in msg


def test_mongo_unauth_listdatabases_is_critical():
    # Fake mongod: reply to isMaster, then to listDatabases with a db listing.
    def handler(conn):
        conn.recv(512)                                  # isMaster query
        conn.sendall(b"\x00" * 20 + b"ismaster\x00maxWireVersion\x00")
        conn.recv(512)                                  # listDatabases query
        conn.sendall(b"\x00" * 20 + b"databases\x00sizeOnDisk\x00totalSize\x00")
    host, port, _t, srv = _tcp_server(handler)
    try:
        r = svcprobe.check_mongodb(host, port)
    finally:
        srv.close()
    assert r is not None and r.exposed is True and r.severity == "CRITICAL"


def test_mongo_auth_required_is_low():
    def handler(conn):
        conn.recv(512)
        conn.sendall(b"\x00" * 20 + b"ismaster\x00maxWireVersion\x00")
        conn.recv(512)
        conn.sendall(b"\x00" * 20 + b"errmsg\x00command listDatabases requires authentication\x00")
    host, port, _t, srv = _tcp_server(handler)
    try:
        r = svcprobe.check_mongodb(host, port)
    finally:
        srv.close()
    assert r is not None and r.exposed is False and r.severity == "LOW"


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    failed = 0
    for fn in fns:
        try:
            fn()
            print(f"PASS {fn.__name__}")
        except AssertionError as e:
            failed += 1
            print(f"FAIL {fn.__name__}: {e}")
        except Exception as e:  # noqa
            failed += 1
            print(f"ERROR {fn.__name__}: {type(e).__name__}: {e}")
    print(f"\n{len(fns) - failed}/{len(fns)} passed")
    sys.exit(1 if failed else 0)
