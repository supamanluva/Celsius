"""Offline tests for the HTTP security-header audit: CSP presence handling
(directive quality is evaluated once, by webchecks.analyze_csp), per-cookie
flag auditing, and the missing-CSP downgrade for API responses."""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from celsius import http_analysis  # noqa: E402
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


# ── error-page version probe ────────────────────────────────────────────────
_NGINX_414 = ("<html><head><title>414 Request-URI Too Large</title></head><body>"
              "<center><h1>414</h1></center><hr><center>nginx/1.25.3</center></body></html>")


def _stub_probe(monkeypatch, responses):
    """responses: list of (status, body) returned in order per request."""
    calls = {"i": 0}

    def fake(url, *, method="GET", insecure=False, auth=None):
        i = calls["i"]
        calls["i"] += 1
        return responses[i] if i < len(responses) else (None, "")
    monkeypatch.setattr(http_analysis, "_fetch_body", fake)
    return calls


def test_probe_recovers_version_from_error_page(monkeypatch):
    _stub_probe(monkeypatch, [(414, _NGINX_414)])
    rec, notes = http_analysis.probe_server_version("https://x")
    assert rec == ("nginx", "1.25.3")
    assert any("1.25.3" in n for n in notes)


def test_probe_tries_later_probes_until_a_version_leaks(monkeypatch):
    # first probe returns a page with no version, second leaks it
    _stub_probe(monkeypatch, [(404, "<h1>custom 404</h1>"), (405, _NGINX_414)])
    rec, _ = http_analysis.probe_server_version("https://x")
    assert rec == ("nginx", "1.25.3")


def test_probe_returns_none_when_tokens_off(monkeypatch):
    # bare product, no version anywhere — must recover nothing
    _stub_probe(monkeypatch, [(414, "<hr><center>openresty</center>"),
                              (405, "<hr><center>openresty</center>"),
                              (404, "<hr><center>openresty</center>")])
    rec, notes = http_analysis.probe_server_version("https://x")
    assert rec is None
    assert any("did not leak" in n for n in notes)


if __name__ == "__main__":
    import inspect
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)
           and not inspect.signature(v).parameters]  # skip pytest-fixture tests
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
