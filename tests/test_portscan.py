"""Offline tests for the IP-deduped port-scan cache."""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from celsius import portscan as P  # noqa: E402

_XML = (
    '<nmaprun><host><ports>'
    '<port protocol="tcp" portid="22"><state state="open"/>'
    '<service name="ssh" product="OpenSSH" version="9.6"/></port>'
    '<port protocol="tcp" portid="443"><state state="open"/>'
    '<service name="http" product="nginx" version="1.29.8"/></port>'
    '</ports></host></nmaprun>'
)


class _Result:
    returncode = 0
    stdout = _XML
    stderr = ""


def _setup():
    P._CACHE_DIR = Path(tempfile.mkdtemp())
    P.nmap_path = lambda: "/usr/bin/nmap"
    calls = []
    P.subprocess.run = lambda *a, **k: (calls.append(1), _Result())[1]
    return calls


def test_same_ip_runs_nmap_once_and_reuses():
    calls = _setup()
    ip = "203.0.113.7"  # TEST-NET, never real
    s1, _o1, e1 = P.scan("a.test", resolved_ip=ip)
    s2, _o2, e2 = P.scan("b.test", resolved_ip=ip)  # different host, same IP
    assert len(calls) == 1, "nmap should run once for a shared IP"
    assert {x.port for x in s1} == {22, 443} == {x.port for x in s2}
    assert any("reused" in x for x in e2) and e1 == []


def test_different_ip_runs_again():
    calls = _setup()
    P.scan("a.test", resolved_ip="203.0.113.7")
    P.scan("b.test", resolved_ip="203.0.113.8")  # different IP
    assert len(calls) == 2


def test_different_portspec_not_shared():
    calls = _setup()
    P.scan("a.test", resolved_ip="203.0.113.7", top_ports=100)
    P.scan("a.test", resolved_ip="203.0.113.7", ports="1-1000")  # different spec
    assert len(calls) == 2


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
