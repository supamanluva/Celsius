"""When a reverse proxy/CDN fronts the origin, the Server-header version is not a
confirmed edge identity — reconcile_server_identity must flag the ambiguity."""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from celsius.http_analysis import (  # noqa: E402
    HttpResult, detect_services, reconcile_server_identity,
)


def _res(headers):
    return HttpResult("https://x/", 200, headers, "https://x/")


def test_via_caddy_fronting_nginx_is_flagged():
    # the luhn.se case: Server says nginx, Via says Caddy
    r = _res({"server": "nginx/1.29.8", "via": "1.1 Caddy"})
    svcs = detect_services(r)
    finds = reconcile_server_identity(r, svcs)
    assert len(finds) == 1
    assert "behind Caddy" in finds[0].title and "nginx" in finds[0].title
    origin = next(s for s in svcs if s.source == "http-header:server")
    assert origin.extra.get("behind_proxy") == "Caddy"


def test_direct_origin_not_flagged():
    r = _res({"server": "nginx/1.29.8"})            # no proxy header
    assert reconcile_server_identity(r, detect_services(r)) == []


def test_proxy_equals_origin_not_flagged():
    # Caddy in front AND Caddy is the origin → no ambiguity
    r = _res({"server": "Caddy", "via": "1.1 Caddy"})
    assert reconcile_server_identity(r, detect_services(r)) == []


def test_cloudflare_cf_ray_detected():
    r = _res({"server": "nginx/1.25.0", "cf-ray": "abc-LHR"})
    finds = reconcile_server_identity(r, detect_services(r))
    assert len(finds) == 1 and "Cloudflare" in finds[0].title


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
