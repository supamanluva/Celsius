"""Offline tests for hostname and bare-IP DNS reconnaissance.
Stdlib-only: run directly (`python tests/test_dns.py`) or under pytest.
"""
from __future__ import annotations

import os
import sys
from types import SimpleNamespace

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from celsius.models import ScanResult  # noqa: E402
from celsius.plugins import builtin  # noqa: E402
from celsius.recon import dns  # noqa: E402


def test_lookup_ip_returns_ptr_in_shared_shape():
    real = dns.reverse_dns
    try:
        dns.reverse_dns = lambda ip: "host.example.com"
        result = dns.lookup_ip("192.0.2.10")
    finally:
        dns.reverse_dns = real
    assert result == {
        "records": {"PTR": ["host.example.com"]},
        "reverse": {"192.0.2.10": "host.example.com"},
    }
    assert dns.summarize(result) == "PTR: host.example.com"


def test_lookup_ip_without_ptr_is_empty():
    real = dns.reverse_dns
    try:
        dns.reverse_dns = lambda ip: None
        result = dns.lookup_ip("192.0.2.10")
    finally:
        dns.reverse_dns = real
    assert result == {"records": {}, "reverse": {}}
    assert dns.summarize(result) == ""


def test_dns_plugin_uses_ip_lookup_without_forward_enumeration():
    real_lookup_ip = builtin.dns_mod.lookup_ip
    real_lookup = builtin.dns_mod.lookup
    builtin.dns_mod.lookup_ip = lambda ip: {
        "records": {"PTR": ["host.example.com"]},
        "reverse": {ip: "host.example.com"},
    }
    builtin.dns_mod.lookup = lambda host: (_ for _ in ()).throw(
        AssertionError("forward lookup should not run for a bare IP"))
    ctx = SimpleNamespace(
        config=SimpleNamespace(dns=True),
        target=SimpleNamespace(is_ip=True, host="192.0.2.10"),
        result=ScanResult(target="192.0.2.10"),
    )
    try:
        plugin = builtin.DnsRecon()
        assert plugin.enabled(ctx) is True
        plugin.run(ctx)
    finally:
        builtin.dns_mod.lookup_ip = real_lookup_ip
        builtin.dns_mod.lookup = real_lookup
    assert ctx.result.recon["dns"]["records"]["PTR"] == ["host.example.com"]
    assert len(ctx.result.findings) == 1
    assert ctx.result.findings[0].description == "PTR: host.example.com"


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
    print(f"\n{len(fns) - failed}/{len(fns)} passed")
    sys.exit(1 if failed else 0)
