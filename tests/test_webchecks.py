"""Offline tests for the breadth web checks: CSP deep-eval and JWT analysis.

(CORS, security.txt and subdomain-takeover are network-dependent and exercised
via live runs; the parsing/logic that can be tested offline lives here.)
"""

from __future__ import annotations

import base64
import os
import sys

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
