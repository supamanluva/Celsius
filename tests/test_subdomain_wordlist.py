"""The brute-force wordlist must cover self-hosted app subdomains (request, radarr,
…) — those sit under wildcard certs and are invisible to crt.sh, so DNS
brute-force is the only way to catch them."""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from celsius.recon import subdomains as subs  # noqa: E402


def test_self_hosted_names_present():
    for w in ("request", "overseerr", "radarr", "sonarr", "vikunja", "immich",
              "vaultwarden", "jellyfin", "nextcloud"):
        assert w in subs.DEFAULT_WORDLIST, w


def test_corporate_names_still_present():
    for w in ("www", "admin", "api", "vpn", "mail"):
        assert w in subs.DEFAULT_WORDLIST, w


def test_default_wordlist_is_union_and_deduped():
    assert set(subs.DEFAULT_WORDLIST) == set(subs.COMMON) | set(subs.SELF_HOSTED)
    assert len(subs.DEFAULT_WORDLIST) == len(set(subs.DEFAULT_WORDLIST))


def test_resolve_wordlist_defaults_to_combined():
    import inspect
    assert inspect.signature(subs.resolve_wordlist).parameters["words"].default is subs.DEFAULT_WORDLIST


def test_five_passive_sources():
    assert len(subs._SOURCES) == 5
    assert subs.from_rapiddns in subs._SOURCES and subs.from_otx in subs._SOURCES


def test_rapiddns_parses_and_keeps_domain():
    subs._fetch = lambda url, **k: ("<td>a.geek.nu</td> <td>b.geek.nu</td> <td>geek.nu</td>", "")
    found, errs = subs.from_rapiddns("geek.nu")
    assert found == {"a.geek.nu", "b.geek.nu"} and not errs   # apex itself excluded


def test_otx_parses_passive_dns():
    subs._fetch = lambda url, **k: ('{"passive_dns":[{"hostname":"x.geek.nu"},{"hostname":"geek.nu"}]}', "")
    found, errs = subs.from_otx("geek.nu")
    assert found == {"x.geek.nu"}


def test_sources_degrade_on_fetch_failure():
    subs._fetch = lambda url, **k: (None, "timeout")
    for fn in (subs.from_rapiddns, subs.from_otx):
        found, errs = fn("geek.nu")
        assert found == set() and errs   # empty + a non-fatal note, never raises


def test_detect_wildcard(monkeypatch=None):
    import socket
    orig = subs.socket.gethostbyname
    try:
        subs.socket.gethostbyname = lambda h: "203.0.113.9"      # everything resolves
        assert subs.detect_wildcard("x.com") == {"203.0.113.9"}
        def nx(h):
            raise socket.gaierror()
        subs.socket.gethostbyname = nx                            # nothing resolves
        assert subs.detect_wildcard("x.com") == set()
    finally:
        subs.socket.gethostbyname = orig


def test_enumerate_skips_bruteforce_on_wildcard():
    o_wc, o_wl, o_cache = subs.detect_wildcard, subs.resolve_wordlist, subs._cache_read
    try:
        called = []
        subs._cache_read = lambda *a, **k: ["seed.x.com"]   # fresh cache hit -> skip live sources
        subs.detect_wildcard = lambda d: {"203.0.113.9"}
        subs.resolve_wordlist = lambda d, **k: called.append(d) or {f"x.{d}"}
        _out, errs = subs.enumerate_subdomains("x.com", bruteforce=True)
        assert not called                                # brute-force NOT run under wildcard
        assert any("wildcard" in e.lower() for e in errs)
    finally:
        subs.detect_wildcard, subs.resolve_wordlist, subs._cache_read = o_wc, o_wl, o_cache


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
