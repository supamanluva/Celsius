"""Offline tests for the HTTP security-header audit: CSP presence handling
(directive quality is evaluated once, by webchecks.analyze_csp), per-cookie
flag auditing, and the missing-CSP downgrade for API responses."""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from celsius.http_analysis import HttpResult, audit_security_headers  # noqa: E402
from celsius.models import Severity  # noqa: E402


def _res(headers, url="https://x/", ctype="text/html"):
    h = {"content-type": ctype}
    h.update(headers)
    return HttpResult(url, 200, h, url)


def _csp(findings):
    return [f for f in findings if f.category == "csp"]


def _cookies(findings):
    return [f for f in findings if f.category == "cookies"]


def test_missing_csp_html_is_medium():
    fs = _csp(audit_security_headers(_res({})))
    assert any(f.title == "Missing Content-Security-Policy"
               and f.severity == Severity.MEDIUM for f in fs)


def test_missing_csp_json_api_is_info():
    fs = _csp(audit_security_headers(_res({}, ctype="application/json; charset=utf-8")))
    assert any("API response" in f.title and f.severity == Severity.INFO for f in fs)
    assert not any(f.severity == Severity.MEDIUM for f in fs)


def test_missing_csp_xml_api_is_info():
    for ctype in ("application/xml", "text/xml"):
        fs = _csp(audit_security_headers(_res({}, ctype=ctype)))
        assert any(f.severity == Severity.INFO for f in fs), ctype
        assert not any(f.severity == Severity.MEDIUM for f in fs), ctype


def test_missing_csp_structured_suffix_is_info():
    fs = _csp(audit_security_headers(_res({}, ctype="application/problem+json")))
    assert any(f.severity == Severity.INFO for f in fs)
    assert not any(f.severity == Severity.MEDIUM for f in fs)


def test_weak_csp_not_evaluated_here():
    # directive quality (unsafe-inline, wildcards, missing default-src) is the
    # job of webchecks.analyze_csp — this audit must stay silent when CSP exists
    weak = "default-src *; script-src 'unsafe-inline' 'unsafe-eval'"
    assert _csp(audit_security_headers(_res({"content-security-policy": weak}))) == []


def test_cookie_flags_audited_per_cookie():
    # a fully-flagged cookie must not mask a second, unflagged one
    blob = "session=abc; Secure; HttpOnly; SameSite=Lax\ntracker=xyz"
    fs = _cookies(audit_security_headers(_res({"set-cookie": blob})))
    assert any("'tracker'" in f.title and "Secure" in f.title for f in fs)
    assert any("'tracker'" in f.title and "HttpOnly" in f.title for f in fs)
    assert not any("'session'" in f.title for f in fs)


def test_session_cookie_missing_flags_is_medium():
    fs = _cookies(audit_security_headers(_res({"set-cookie": "session_id=abc"})))
    assert any("Secure" in f.title and f.severity == Severity.MEDIUM for f in fs)
    assert any("HttpOnly" in f.title and f.severity == Severity.MEDIUM for f in fs)


def test_session_cookie_missing_samesite_is_low():
    blob = "auth_token=abc; Secure; HttpOnly"
    fs = _cookies(audit_security_headers(_res({"set-cookie": blob})))
    assert any("SameSite" in f.title and f.severity == Severity.LOW for f in fs)


def test_non_session_cookie_missing_flags_is_low():
    fs = _cookies(audit_security_headers(_res({"set-cookie": "_ga=1"})))
    assert fs
    assert all(f.severity == Severity.LOW for f in fs)
    assert not any("SameSite" in f.title for f in fs)  # SameSite only for session-ish


def test_fully_flagged_cookie_is_quiet():
    blob = "jwt=abc; Secure; HttpOnly; SameSite=Strict"
    assert _cookies(audit_security_headers(_res({"set-cookie": blob}))) == []


def test_cookie_secure_flag_only_over_https():
    fs = _cookies(audit_security_headers(
        _res({"set-cookie": "session=abc; HttpOnly; SameSite=Lax"}, url="http://x/")))
    assert not any("Secure" in f.title for f in fs)


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
