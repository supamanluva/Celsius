"""Offline tests for co-hosted host discovery (cert SAN + reverse-IP).

reverse_ip()'s network call is monkeypatched; the rest is pure.
Stdlib-only: run directly (`python tests/test_cohost.py`) or under pytest.
"""

from __future__ import annotations

import os
import sys
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from celsius.recon import cohost  # noqa: E402


class _Resp:
    def __init__(self, text):
        self._b = text.encode()

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def read(self, *a):
        return self._b


def test_from_san_excludes_self_and_wildcards():
    sans = ["secop.se", "www.secop.se", "*.secop.se", "guac.luhn.se", "secop.se"]
    out = cohost.from_san(sans, "secop.se")
    assert out == ["guac.luhn.se", "www.secop.se"]   # self + bare wildcard dropped, deduped


def test_reverse_ip_parses_hostlist():
    real = urllib.request.urlopen
    try:
        urllib.request.urlopen = lambda req, **k: _Resp("secop.se\nguac.luhn.se\nportainer.luhn.se\n")
        hosts, err = cohost.reverse_ip("1.2.3.4")
        assert err is None
        assert hosts == ["guac.luhn.se", "portainer.luhn.se", "secop.se"]
    finally:
        urllib.request.urlopen = real


def test_reverse_ip_rate_limit_is_soft_error():
    real = urllib.request.urlopen
    try:
        urllib.request.urlopen = lambda req, **k: _Resp("API count exceeded - upgrade")
        hosts, err = cohost.reverse_ip("1.2.3.4")
        assert hosts == [] and "rate-limited" in err
    finally:
        urllib.request.urlopen = real


def test_discover_merges_and_dedupes():
    real = urllib.request.urlopen
    try:
        urllib.request.urlopen = lambda req, **k: _Resp("secop.se\nthelounge.luhn.se\nguac.luhn.se\n")
        info = cohost.discover("secop.se", "1.2.3.4", ["guac.luhn.se", "*.secop.se"])
        assert "secop.se" not in info["siblings"]                 # self excluded
        assert set(info["siblings"]) == {"guac.luhn.se", "thelounge.luhn.se"}
    finally:
        urllib.request.urlopen = real


def test_discover_skips_reverse_ip_when_disabled():
    real = urllib.request.urlopen
    try:
        urllib.request.urlopen = lambda req, **k: (_ for _ in ()).throw(AssertionError("should not call"))
        info = cohost.discover("secop.se", "1.2.3.4", ["guac.luhn.se"], do_reverse_ip=False)
        assert info["siblings"] == ["guac.luhn.se"] and info["from_reverse_ip"] == []
    finally:
        urllib.request.urlopen = real


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
