"""IP topology mapping: classify each host (VPS / home / SaaS / CDN) and group the
subdomains behind it — the picture of *where* a domain's services actually run."""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from celsius.recon import topology as t  # noqa: E402


def test_classify_by_org_ptr_and_shodan_signal():
    assert t._classify("netcup GmbH", "netcup GmbH", "gotlandia.net", True)[0] == "vps"
    assert t._classify("SE-TELENOR", "Telenor", "c-1-2-3-4.bbcust.telenor.se", False)[0] == "home"
    assert t._classify("QuickPacket", "QuickPacket", "witcher.mxrouting.net", True)[0] == "saas"
    assert t._classify("Cloudflare", "Cloudflare", "", True)[0] == "cdn"
    # public IP that Shodan never indexed + a non-hosting org -> lean home
    assert t._classify("Some Local ISP AB", "", "", False)[0] == "home"
    # nothing to go on
    assert t._classify("", "", "", True)[0] == "unknown"


def test_map_topology_groups_and_orders(monkeypatch=None):
    fake_ips = {
        "gotlandia.net": {"5.5.5.5"},
        "cloud.gotlandia.net": {"1.1.1.1"}, "auth.gotlandia.net": {"1.1.1.1"},
        "mail.gotlandia.net": {"2.2.2.2"},
    }
    fake_ptr = {"1.1.1.1": "host.bbcust.telenor.se", "2.2.2.2": "x.mxrouting.net", "5.5.5.5": ""}
    fake_rdap = {"1.1.1.1": ("SE-TELENOR", "AS2119"), "2.2.2.2": ("QuickPacket", "AS46261"),
                 "5.5.5.5": ("netcup GmbH", "AS197540")}
    o_res, o_ptr, o_sho, o_rdap = t._resolve, t._ptr, t._shodan_host, t._rdap
    try:
        t._resolve = lambda n: fake_ips.get(n, set())
        t._ptr = lambda ip: fake_ptr.get(ip, "")
        t._shodan_host = lambda ip, k, to: ({}, False, None)   # nothing in Shodan -> RDAP fallback
        t._rdap = lambda ip, to: fake_rdap.get(ip, ("", ""))
        info, errs = t.map_topology("gotlandia.net",
                                    list(fake_ips) , shodan_key="")
        kinds = {h["ip"]: h["kind"] for h in info["hosts"]}
        assert info["n_hosts"] == 3
        assert kinds["1.1.1.1"] == "home"      # telenor + bbcust PTR
        assert kinds["2.2.2.2"] == "saas"      # mxrouting PTR
        assert kinds["5.5.5.5"] == "vps"       # netcup
        # home is ordered first, and its two subdomains are grouped together
        assert info["hosts"][0]["ip"] == "1.1.1.1"
        assert info["hosts"][0]["hostnames"] == ["auth.gotlandia.net", "cloud.gotlandia.net"]
    finally:
        t._resolve, t._ptr, t._shodan_host, t._rdap = o_res, o_ptr, o_sho, o_rdap


def test_map_topology_no_resolve_is_empty():
    o_res = t._resolve
    try:
        t._resolve = lambda n: set()
        info, errs = t.map_topology("nope.example", [], shodan_key="")
        assert info["n_hosts"] == 0 and info["summary"] == ""
    finally:
        t._resolve = o_res


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
