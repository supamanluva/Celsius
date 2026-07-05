"""DNS canary — a self-hosted authoritative listener whose *hit* is a DNS query
for <token>.<domain>. Driven here with hand-crafted DNS packets over UDP on a
high port (port 53 needs root); no network beyond loopback.
"""

from __future__ import annotations

import os
import socket
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from celsius.active.canary import DNSCanary, _parse_qname  # noqa: E402


def _query(name: str) -> bytes:
    tid = b"\x12\x34"
    flags = b"\x01\x00"                       # standard query, recursion desired
    counts = b"\x00\x01\x00\x00\x00\x00\x00\x00"   # QD=1
    qname = b"".join(bytes([len(lbl)]) + lbl.encode() for lbl in name.split(".")) + b"\x00"
    return tid + flags + counts + qname + b"\x00\x01\x00\x01"   # QTYPE=A, QCLASS=IN


def _resolve(name: str, port: int) -> bytes:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(2)
    try:
        s.sendto(_query(name), ("127.0.0.1", port))
        try:
            data, _ = s.recvfrom(2048)
            return data
        except socket.timeout:
            return b""
    finally:
        s.close()


def test_parse_qname_roundtrips():
    assert _parse_qname(_query("abc.canary.test")) == "abc.canary.test"


def test_dns_query_records_a_hit():
    with DNSCanary(domain="canary.test", bind="127.0.0.1", dns_port=0) as c:
        token = c.new_token()
        assert c.was_hit(token) is False
        resp = _resolve(c.hostname_for(token), c.dns_port)
        assert c.wait_for_hit(token) is True
        hits = c.hits(token)
        assert len(hits) == 1 and hits[0].method == "DNS" and hits[0].src_ip == "127.0.0.1"
        assert len(resp) >= 12   # got a DNS response back (resolver satisfied)


def test_hit_matches_token_even_with_a_prefix():
    # a resolver/app may prepend labels (e.g. "www.<token>.domain"); still a hit
    with DNSCanary(domain="canary.test", bind="127.0.0.1", dns_port=0) as c:
        token = c.new_token()
        _resolve(f"www.{token}.canary.test", c.dns_port)
        assert c.wait_for_hit(token) is True


def test_unknown_token_not_recorded():
    with DNSCanary(domain="canary.test", bind="127.0.0.1", dns_port=0) as c:
        _resolve("deadbeefdeadbeef.canary.test", c.dns_port)   # never minted
        assert c.was_hit("deadbeefdeadbeef") is False


def test_url_and_hostname_use_the_domain():
    c = DNSCanary(domain="canary.test", dns_port=0)
    assert c.hostname_for("tok") == "tok.canary.test"
    assert c.url_for("tok") == "http://tok.canary.test/"


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
