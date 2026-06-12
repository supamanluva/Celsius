"""Safe-active checks for internet-exposed, unauthenticated services.

Given an open port discovered by the port scan, send ONE benign, read-only probe
to determine whether a high-risk datastore/control service is answering WITHOUT
authentication — the single most common way an internet-exposed system is fully
compromised (open Redis, Memcached, MongoDB, Elasticsearch, the Docker Engine API,
CouchDB, the Kubernetes kubelet).

Every probe is the service's own status/handshake command (Redis `PING`, Mongo
`isMaster`, Docker `GET /version`, …). Nothing is written, mutated, or brute-forced;
no payloads beyond a status request are sent. Stdlib-only (socket / ssl / urllib).
"""

from __future__ import annotations

import socket
import ssl
import struct
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Callable, Optional

CONNECT_TIMEOUT = 4.0
READ_BYTES = 8192


@dataclass
class ProbeResult:
    service: str          # "Redis", "MongoDB", ...
    exposed: bool         # True = reachable AND unauthenticated (the real finding)
    severity: str         # "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
    title: str
    detail: str
    evidence: str = ""


# ---- low-level transports -----------------------------------------------------

def _tcp_roundtrip(host: str, port: int, payload: bytes,
                   *, read: int = READ_BYTES) -> Optional[bytes]:
    """Open a TCP socket, send `payload`, return up to `read` bytes (or None)."""
    try:
        with socket.create_connection((host, port), timeout=CONNECT_TIMEOUT) as s:
            s.settimeout(CONNECT_TIMEOUT)
            if payload:
                s.sendall(payload)
            return s.recv(read)
    except (OSError, socket.timeout):
        return None


def _http_get(host: str, port: int, path: str, *, tls: bool = False,
              read: int = READ_BYTES) -> tuple[int, bytes]:
    """Plain GET to host:port/path. Returns (status, body[:read]); status 0 on
    connection failure. TLS uses an unverified context (we're probing, not trusting)."""
    scheme = "https" if tls else "http"
    url = f"{scheme}://{host}:{port}{path}"
    ctx = ssl._create_unverified_context() if tls else None
    req = urllib.request.Request(url, headers={"User-Agent": "celsius-svcprobe"})
    try:
        with urllib.request.urlopen(req, timeout=CONNECT_TIMEOUT, context=ctx) as resp:
            return resp.status, resp.read(read)
    except urllib.error.HTTPError as e:
        try:
            body = e.read(read)
        except Exception:
            body = b""
        return e.code, body
    except (urllib.error.URLError, OSError, ValueError):
        return 0, b""


# ---- per-service probes -------------------------------------------------------

def check_redis(host: str, port: int) -> Optional[ProbeResult]:
    data = _tcp_roundtrip(host, port, b"PING\r\n")
    if data is None:
        return None
    head = data[:120]
    if head.startswith(b"+PONG"):
        return ProbeResult(
            "Redis", True, "HIGH",
            "Redis reachable without authentication",
            "The Redis instance answered PING with +PONG and no authentication — anyone "
            "who can reach this port has full read/write access to the keyspace (and can "
            "often achieve RCE via the module/RDB tricks). Internet-exposed Redis should "
            "never be unauthenticated.",
            "PING -> +PONG")
    if b"NOAUTH" in head or b"operation not permitted" in head:
        return ProbeResult(
            "Redis", False, "LOW",
            "Redis exposed to the network (authentication required)",
            "Redis is reachable but demands authentication. Still safest firewalled to "
            "trusted hosts only.",
            head.decode("latin1", "replace").strip()[:80])
    return None


def check_memcached(host: str, port: int) -> Optional[ProbeResult]:
    data = _tcp_roundtrip(host, port, b"stats\r\n")
    if data and data.startswith(b"STAT "):
        return ProbeResult(
            "Memcached", True, "MEDIUM",
            "Memcached reachable without authentication",
            "The server answered the 'stats' command with no authentication — cached "
            "data is readable and, if UDP is also open, the service can be abused for "
            "reflection/amplification DDoS.",
            data[:80].decode("latin1", "replace").strip())
    return None


def check_docker(host: str, port: int) -> Optional[ProbeResult]:
    status, body = _http_get(host, port, "/version", tls=(port == 2376))
    if status == 200 and (b'"ApiVersion"' in body or b'"GoVersion"' in body):
        return ProbeResult(
            "Docker Engine API", True, "CRITICAL",
            "Docker Engine API exposed without authentication",
            "The Docker daemon answered /version with no authentication. This is "
            "equivalent to unauthenticated root RCE on the host: anyone reachable can "
            "launch a privileged container that mounts the host filesystem. Bind the "
            "API to localhost or require mutual TLS, and firewall the port immediately.",
            body[:120].decode("latin1", "replace").strip())
    return None


def check_elasticsearch(host: str, port: int) -> Optional[ProbeResult]:
    status, body = _http_get(host, port, "/")
    looks_es = (b'"cluster_name"' in body or b'"lucene_version"' in body
                or b"You Know, for Search" in body)
    if status == 200 and looks_es:
        st2, idx = _http_get(host, port, "/_cat/indices?format=json")
        if st2 == 200 and idx.strip().startswith(b"["):
            return ProbeResult(
                "Elasticsearch", True, "HIGH",
                "Elasticsearch exposed without authentication (indices readable)",
                "The cluster returned its index list to an unauthenticated request — all "
                "indexed documents are readable (and writable/deletable). Enable security "
                "(authentication) and firewall the HTTP port.",
                idx[:160].decode("latin1", "replace").strip())
        return ProbeResult(
            "Elasticsearch", True, "MEDIUM",
            "Elasticsearch cluster info exposed without authentication",
            "The cluster answered an unauthenticated request with version/cluster "
            "metadata. Enable authentication and restrict network access.",
            body[:160].decode("latin1", "replace").strip())
    if status in (401, 403):
        return ProbeResult(
            "Elasticsearch", False, "LOW",
            "Elasticsearch exposed to the network (authentication required)",
            "Reachable but requires authentication. Prefer firewalling to trusted hosts.",
            f"HTTP {status}")
    return None


def check_couchdb(host: str, port: int) -> Optional[ProbeResult]:
    status, body = _http_get(host, port, "/")
    if status == 200 and b'"couchdb":"Welcome"' in body.replace(b" ", b""):
        st2, dbs = _http_get(host, port, "/_all_dbs")
        if st2 == 200 and dbs.strip().startswith(b"["):
            return ProbeResult(
                "CouchDB", True, "HIGH",
                "CouchDB exposed without authentication (databases listable)",
                "The server returned its database list to an unauthenticated request — "
                "documents are readable without credentials. Configure an admin and "
                "require authentication.",
                dbs[:160].decode("latin1", "replace").strip())
        return ProbeResult(
            "CouchDB", True, "MEDIUM",
            "CouchDB welcome banner exposed without authentication",
            "CouchDB answered an unauthenticated request. Lock it down with an admin "
            "account and firewall the port.",
            body[:120].decode("latin1", "replace").strip())
    return None


# MongoDB legacy OP_QUERY {isMaster:1} against admin.$cmd (works pre-auth and
# confirms a reachable mongod). We then look at the raw reply for auth markers.
def _mongo_ismaster_msg() -> bytes:
    bson = (b"\x10isMaster\x00" + struct.pack("<i", 1))          # int32 isMaster=1
    doc = struct.pack("<i", len(bson) + 5) + bson + b"\x00"      # len + elems + terminator
    body = (struct.pack("<i", 0)                                  # flags
            + b"admin.$cmd\x00"                                   # fullCollectionName
            + struct.pack("<i", 0)                                # numberToSkip
            + struct.pack("<i", 1)                                # numberToReturn
            + doc)
    length = 16 + len(body)
    header = struct.pack("<iiii", length, 1, 0, 2004)            # len, reqID, respTo, OP_QUERY
    return header + body


def _mongo_listdb_msg() -> bytes:
    listdb = (b"\x10listDatabases\x00" + struct.pack("<i", 1))
    doc = struct.pack("<i", len(listdb) + 5) + listdb + b"\x00"
    body = (struct.pack("<i", 0) + b"admin.$cmd\x00"
            + struct.pack("<i", 0) + struct.pack("<i", 1) + doc)
    return struct.pack("<iiii", 16 + len(body), 2, 0, 2004) + body


def check_mongodb(host: str, port: int) -> Optional[ProbeResult]:
    # Both commands go on ONE connection (how a real client speaks to mongod):
    # isMaster confirms a reachable mongod (works pre-auth), then listDatabases
    # tells an open instance (data listed) from a secured one (auth error).
    try:
        with socket.create_connection((host, port), timeout=CONNECT_TIMEOUT) as s:
            s.settimeout(CONNECT_TIMEOUT)
            s.sendall(_mongo_ismaster_msg())
            data = s.recv(READ_BYTES)
            if not data or (b"ismaster" not in data and b"isWritablePrimary" not in data
                            and b"maxWireVersion" not in data):
                return None
            s.sendall(_mongo_listdb_msg())
            reply = s.recv(READ_BYTES) or b""
    except (OSError, socket.timeout):
        return None
    auth_required = (b"requires authentication" in reply or b"not authorized" in reply
                     or b"Unauthorized" in reply or b"command listDatabases requires" in reply)
    if (b"sizeOnDisk" in reply or b"totalSize" in reply) and not auth_required:
        return ProbeResult(
            "MongoDB", True, "CRITICAL",
            "MongoDB exposed without authentication (databases listable)",
            "The server returned its database list to an unauthenticated request — all "
            "data is readable (and writable) without credentials. Enable authorization "
            "(--auth) and bind to localhost / a private network immediately.",
            reply[:160].decode("latin1", "replace").strip())
    if auth_required:
        return ProbeResult(
            "MongoDB", False, "LOW",
            "MongoDB exposed to the network (authentication required)",
            "Reachable but enforces authentication. Prefer firewalling to trusted hosts.",
            "listDatabases -> authentication required")
    # Reachable mongod, listDatabases inconclusive — still a notable exposure.
    return ProbeResult(
        "MongoDB", True, "HIGH",
        "MongoDB reachable from the network",
        "A MongoDB server answered the isMaster handshake. Modern MongoDB binds to "
        "localhost by default, so a network-reachable instance is a misconfiguration — "
        "verify authentication is enforced and firewall the port.",
        "isMaster handshake answered")


# ---- dispatch -----------------------------------------------------------------

# Default port -> probe. Also matched by nmap service-name hint so non-standard
# ports are still covered.
_BY_PORT: dict[int, Callable[[str, int], Optional[ProbeResult]]] = {
    6379: check_redis, 6380: check_redis,
    11211: check_memcached,
    2375: check_docker, 2376: check_docker,
    9200: check_elasticsearch,
    5984: check_couchdb,
    27017: check_mongodb, 27018: check_mongodb, 27019: check_mongodb,
}

_BY_NAME: list[tuple[str, Callable[[str, int], Optional[ProbeResult]]]] = [
    ("redis", check_redis),
    ("memcache", check_memcached),
    ("docker", check_docker),
    ("elasticsearch", check_elasticsearch),
    ("couchdb", check_couchdb),
    ("mongod", check_mongodb), ("mongodb", check_mongodb),
]


def checker_for(port: Optional[int], name: str = "", product: str = "") \
        -> Optional[Callable[[str, int], Optional[ProbeResult]]]:
    """Pick a probe for an open port — by well-known port first, then by nmap
    service-name/product hint (catches services on non-standard ports)."""
    if port and port in _BY_PORT:
        return _BY_PORT[port]
    hint = f"{name} {product}".lower()
    for needle, fn in _BY_NAME:
        if needle in hint:
            return fn
    return None
