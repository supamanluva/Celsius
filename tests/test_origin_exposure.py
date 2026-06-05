"""Origin-exposure / CDN-bypass discovery: classify CDN vs origin IPs (incl. IPv6)
and flag hostnames that resolve to a non-CDN public address."""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from celsius.recon import origin  # noqa: E402


def test_cdn_for_ip_v4():
    assert origin.cdn_for_ip("188.114.97.1") == "Cloudflare"
    assert origin.cdn_for_ip("104.16.1.1") == "Cloudflare"
    assert origin.cdn_for_ip("151.101.1.1") == "Fastly"
    assert origin.cdn_for_ip("157.180.68.157") is None      # Hetzner — a real origin
    assert origin.cdn_for_ip("not-an-ip") is None


def test_cdn_for_ip_v6_regression():
    # the bug the live geek.nu run caught: CF IPv6 must not look like an origin
    assert origin.cdn_for_ip("2a06:98c1:3120::1") == "Cloudflare"
    assert origin.cdn_for_ip("2606:4700::1") == "Cloudflare"
    assert origin.cdn_for_ip("2a01:4f9:c011::1") is None     # Hetzner v6 — real origin


def test_mx_hosts_parse():
    assert origin.mx_hosts({"MX": ["10 mail.example.com.", "20 alt.mx.example.com."]}) \
        == ["mail.example.com", "alt.mx.example.com"]
    assert origin.mx_hosts({}) == []


def test_find_exposed_origins():
    mapping = {
        "leak.x.com": ["157.180.68.157"],        # public, non-CDN -> EXPOSED
        "www.x.com": ["188.114.97.1"],           # Cloudflare v4 -> hidden
        "v6.x.com": ["2a06:98c1:3120::1"],       # Cloudflare v6 -> hidden
        "internal.x.com": ["10.0.0.5"],          # private -> not a public origin
        "dead.x.com": [],                         # no record
    }
    origin.resolve = lambda h: mapping.get(h, [])   # avoid real DNS
    out = origin.find_exposed_origins(list(mapping))
    assert [e["host"] for e in out] == ["leak.x.com"]
    assert out[0]["origin_ips"] == ["157.180.68.157"]


def test_pivot_queries_with_favicon():
    pivots = origin.pivot_queries("geek.nu", favicon_hash=-12345, sans=["snaptrack.geek.nu"])
    qs = [p["query"] for p in pivots]
    assert any("http.favicon.hash:-12345" in q for q in qs)
    assert any('ssl.cert.subject.CN:"geek.nu"' == q for q in qs)
    assert any(p["engine"] == "Censys" for p in pivots)
    assert all(p["url"].startswith("https://") for p in pivots)


def test_pivot_queries_without_favicon():
    pivots = origin.pivot_queries("geek.nu")
    assert not any("favicon" in p["query"] for p in pivots)
    assert any(p["engine"] == "Shodan" for p in pivots)


def test_shodan_search_without_key():
    ips, err = origin.shodan_search("http.favicon.hash:1", "")
    assert ips == [] and "SHODAN_API_KEY" in err


def test_censys_search_without_creds():
    assert origin.censys_search("q", "", "") == ([], "no CENSYS_API_ID/SECRET")
    assert origin.censys_search("q", "id", "")[0] == []


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
