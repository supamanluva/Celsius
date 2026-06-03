"""Offline tests for favicon fingerprinting.

The MurmurHash3 implementation is pinned to reference values produced by the
real `mmh3` library, so the core stays stdlib-only without risking a silent
hashing regression.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from celsius.recon import favicon as F  # noqa: E402


def test_murmur3_matches_reference_vectors():
    assert F.murmur3_32(b"") == 0
    assert F.murmur3_32(b"hello") == 613153351
    # Shodan-style favicon hash = mmh3 of base64.encodebytes(...)
    assert F.favicon_hash(b"celsius-test" * 9) == 917394382


def test_known_app_emits_service_and_finding():
    raw = bytes(range(64)) * 4
    h = F.favicon_hash(raw)
    F._KNOWN[h] = ("TestPanel", True)
    F._fetch = lambda *a, **k: (200, raw)
    try:
        svcs, finds, hh, _ = F.analyze("https://x.test")
    finally:
        del F._KNOWN[h]
    assert hh == h
    assert any(s.name == "TestPanel" for s in svcs)
    assert any(f.category == "exposure" for f in finds)


def test_unknown_hash_still_reports_and_suggests_pivot():
    raw = b"\x89PNG\r\n" + bytes(range(50))
    F._fetch = lambda *a, **k: (200, raw)
    svcs, finds, hh, _ = F.analyze("https://x.test")
    assert hh is not None and svcs == []
    assert finds and "shodan" in finds[0].description.lower()


def test_no_favicon_is_quiet():
    F._fetch = lambda *a, **k: (404, b"")
    svcs, finds, hh, _ = F.analyze("https://x.test")
    assert svcs == [] and finds == [] and hh is None


def test_icon_url_prefers_link_tag():
    html = '<link rel="shortcut icon" href="/static/fav.png">'
    assert F._icon_url("https://x.test/", html).endswith("/static/fav.png")
    assert F._icon_url("https://x.test/", None).endswith("/favicon.ico")


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
