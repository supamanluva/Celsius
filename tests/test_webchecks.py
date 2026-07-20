"""Offline tests for the breadth web checks: CSP deep-eval and JWT analysis.

CORS and subdomain-takeover are network checks — they are exercised here with
`urllib.request.urlopen` faked at the module boundary (no live traffic).
"""

from __future__ import annotations

import base64
import os
import sys
import urllib.error

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from celsius import webchecks as W  # noqa: E402


def _titles(findings):
    return [f.title for f in findings]


def test_csp_flags_unsafe_inline_and_wildcard():
    csp = {"content-security-policy": "default-src 'self'; script-src 'self' 'unsafe-inline' *"}
    titles = _titles(W.analyze_csp(csp))
    assert any("unsafe-inline" in t for t in titles)
    assert any("wildcard" in t for t in titles)


def test_csp_strong_policy_quiet_on_script():
    csp = {"content-security-policy":
           "default-src 'none'; script-src 'self'; object-src 'none'; "
           "base-uri 'none'; frame-ancestors 'none'"}
    titles = _titles(W.analyze_csp(csp))
    assert not any("unsafe" in t or "wildcard" in t for t in titles)


def test_no_csp_header_no_findings():
    assert W.analyze_csp({}) == []


def test_csp_is_authoritative_severity_source():
    # webchecks.analyze_csp is the single CSP evaluator — pin its severities so
    # http_analysis (which only checks presence) can't quietly reintroduce a
    # conflicting duplicate.
    csp = {"content-security-policy":
           "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' * data:; "
           "base-uri 'none'; frame-ancestors 'none'; object-src 'none'"}
    by_title = {f.title: f.severity for f in W.analyze_csp(csp)}
    assert by_title["CSP allows 'unsafe-inline' scripts"] == "HIGH"
    assert by_title["CSP script-src uses a wildcard"] == "HIGH"
    assert by_title["CSP allows 'unsafe-eval'"] == "MEDIUM"
    assert by_title["CSP allows data: in script-src"] == "MEDIUM"


def test_csp_complete_policy_no_missing_directive_findings():
    csp = {"content-security-policy":
           "default-src 'none'; script-src 'self'; object-src 'none'; "
           "base-uri 'none'; frame-ancestors 'none'"}
    titles = _titles(W.analyze_csp(csp))
    assert not any("missing" in t for t in titles)


def _jwt(header: dict, payload: dict) -> str:
    enc = lambda d: base64.urlsafe_b64encode(  # noqa: E731
        __import__("json").dumps(d).encode()).decode().rstrip("=")
    return f"{enc(header)}.{enc(payload)}.sig"


def test_jwt_alg_none_is_critical():
    tok = _jwt({"alg": "none", "typ": "JWT"}, {"user": "admin"})
    fs = W.analyze_jwt({"set-cookie": f"auth={tok}"}, "")
    assert any(f.severity.value == "CRITICAL" and "alg=none" in f.title for f in fs)


def test_jwt_hs256_and_missing_exp():
    tok = _jwt({"alg": "HS256"}, {"sub": "x"})  # no exp
    fs = W.analyze_jwt({}, f"token={tok}")
    titles = _titles(fs)
    assert any("HS256" in t for t in titles)
    assert any("expiry" in t for t in titles)


def test_jwt_with_exp_no_expiry_finding():
    tok = _jwt({"alg": "RS256"}, {"exp": 9999999999})
    titles = _titles(W.analyze_jwt({}, f"x={tok}"))
    assert not any("expiry" in t for t in titles)


def test_takeover_signature_table_sane():
    # each signature is (cname-substr, fingerprint, service)
    for cname, fp, svc in W._TAKEOVER_SIGS:
        assert cname and fp and svc
    # expanded from the original 15 to the can-i-take-over-xyz set (~40+)
    assert len(W._TAKEOVER_SIGS) >= 40


# ---- faked HTTP layer for the network checks -----------------------------------

class _Resp:
    def __init__(self, status, headers, body=""):
        self.status = status
        self.headers = headers
        self._body = body.encode()

    def read(self, n=-1):
        return self._body[:n] if n and n > 0 else self._body

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _patch_urlopen(fake):
    """Swap urllib.request.urlopen for `fake`; returns a restore() callable."""
    real = W.urllib.request.urlopen
    W.urllib.request.urlopen = fake
    return lambda: setattr(W.urllib.request, "urlopen", real)


def _cors_fake(calls, reflect_paths=(), reflect_null=()):
    """Fake urlopen: reflects the Origin back (with credentials) on the given
    URL paths; records every requested URL in `calls`."""
    def fake(req, timeout=None, context=None):
        url = req.full_url
        calls.append(url)
        path = W.urllib.parse.urlparse(url).path or "/"
        origin = req.headers.get("Origin")
        headers = {}
        if origin == W._EVIL_ORIGIN and path in reflect_paths:
            headers["access-control-allow-origin"] = origin
            headers["access-control-allow-credentials"] = "true"
        elif origin == "null" and path in reflect_null:
            headers["access-control-allow-origin"] = "null"
        return _Resp(200, headers, "ok")
    return fake


def test_cors_reflects_arbitrary_origin_with_credentials():
    calls = []
    restore = _patch_urlopen(_cors_fake(calls, reflect_paths={"/"}))
    try:
        fs = W.check_cors("https://t.example/")
    finally:
        restore()
    assert len(fs) == 1
    assert "reflects arbitrary Origin with credentials" in fs[0].title
    assert fs[0].severity.value == "HIGH"


def test_cors_no_reflection_no_findings():
    restore = _patch_urlopen(_cors_fake([]))
    try:
        assert W.check_cors("https://t.example/") == []
    finally:
        restore()


def test_cors_unreachable_root_stops_early():
    def fake(req, timeout=None, context=None):
        raise urllib.error.URLError("down")
    restore = _patch_urlopen(fake)
    try:
        assert W.check_cors("https://t.example/", paths=["/api"]) == []
    finally:
        restore()


def test_cors_probes_extra_api_paths():
    calls = []
    fake = _cors_fake(calls, reflect_paths={"/api"})
    restore = _patch_urlopen(fake)
    try:
        fs = W.check_cors("https://t.example/app/",
                          paths=["/api", "/graphql", "/v1/users", "/v2/extra"])
    finally:
        restore()
    # root + at most 3 extra paths, 2 probes (evil + null origin) each
    assert sorted(set(calls)) == sorted(
        ["https://t.example/app/", "https://t.example/api",
         "https://t.example/graphql", "https://t.example/v1/users"])
    assert len(fs) == 1  # deduped across paths
    assert "https://t.example/api" in fs[0].evidence
    assert fs[0].severity.value == "HIGH"


def test_cors_null_origin_on_api_path():
    calls = []
    restore = _patch_urlopen(_cors_fake(calls, reflect_null={"/graphql"}))
    try:
        fs = W.check_cors("https://t.example/", paths=["/graphql"])
    finally:
        restore()
    assert any("null" in f.title for f in fs)


def test_cors_candidate_paths_from_recon():
    recon = {"crawl": {"endpoints": ["/", "/about", "/api/users", "/api/users",
                                     "https://t.example/rest/items"],
                       "routes": ["/app", "/v1/orders", "/v2/cart"]},
             "api": {"endpoints": ["/internal/health"],
                     "graphql": {"url": "https://t.example/graphql"}}}
    paths = W.cors_candidate_paths(recon)
    # graphql endpoint first, then API-ish crawl paths; "/" and non-API paths out
    assert paths == ["/graphql", "/api/users", "/rest/items"]


def test_cors_candidate_paths_empty_recon():
    assert W.cors_candidate_paths({}) == []
    assert W.cors_candidate_paths({"crawl": {"endpoints": ["/", "/about"]}}) == []


def test_takeover_matches_new_signatures():
    for cname, fp, svc in [("abc.vercel.app", "DEPLOYMENT_NOT_FOUND", "Vercel"),
                           ("app.netlify.app", "Not Found - Request ID", "Netlify"),
                           ("x.s3.amazonaws.com", "<Code>NoSuchBucket</Code>", "AWS S3")]:
        real_cname = W._cname
        W._cname = lambda host, _c=cname: _c
        restore = _patch_urlopen(
            lambda req, timeout=None, context=None, _b=fp: _Resp(404, {}, _b))
        try:
            fs = W.check_takeover(["sub.example.com"])
        finally:
            restore()
            W._cname = real_cname
        assert len(fs) == 1 and svc in fs[0].title and fs[0].severity.value == "HIGH"


def test_takeover_no_dangling_cname_no_request():
    real_cname = W._cname
    W._cname = lambda host: ""
    calls = []
    restore = _patch_urlopen(_cors_fake(calls))
    try:
        assert W.check_takeover(["sub.example.com"]) == []
    finally:
        restore()
        W._cname = real_cname
    assert calls == []  # dangling-CNAME precondition keeps FPs (and traffic) down


def test_takeover_unknown_provider_not_probed():
    real_cname = W._cname
    W._cname = lambda host: "cdn.some-other-cdn.example"
    calls = []
    restore = _patch_urlopen(_cors_fake(calls))
    try:
        assert W.check_takeover(["sub.example.com"]) == []
    finally:
        restore()
        W._cname = real_cname
    assert calls == []


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
