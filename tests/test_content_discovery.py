"""Offline tests for content-discovery probing.

The network fetch is monkeypatched so we can exercise the real detection logic:
signature confirmation and soft-404 / catch-all suppression.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from celsius.recon import content_discovery as CD  # noqa: E402


def _patch(responses, *, catchall_body=None):
    """Make CD._fetch return canned (status, body) keyed by URL suffix.

    Nonsense baseline paths return `catchall_body` (200) when set, else 404.
    Any path in `responses` returns (200, body); everything else 404.
    """
    def fake(url, insecure, auth):
        for suffix, body in responses.items():
            if url.endswith(suffix):
                return 200, body
        if catchall_body is not None:
            return 200, catchall_body
        return 404, ""
    CD._fetch = fake


def _titles(findings):
    return [f.title for f in findings]


def test_detects_exposed_git_and_env():
    _patch({".git/config": "[core]\n\trepositoryformatversion = 0\n",
            ".env": "APP_KEY=base64:xxxx\nDB_PASSWORD=hunter2\n"})
    findings, paths, _ = CD.discover("https://example.test")
    titles = _titles(findings)
    assert any("Git repository" in t for t in titles), titles
    assert any(".env file" in t for t in titles), titles
    assert ".git/config" in paths and ".env" in paths


def test_signature_mismatch_is_not_reported():
    # 200 but the body is an SPA shell, not a real .git/config -> must be dropped.
    _patch({".git/config": "<!doctype html><title>App</title>"})
    findings, _, _ = CD.discover("https://example.test")
    assert findings == [], _titles(findings)


def test_catchall_suppresses_without_signature_match():
    # Every path (incl. baseline) returns the same SPA 200 -> nothing should fire.
    _patch({}, catchall_body="<html>single page app</html>")
    findings, _, _ = CD.discover("https://example.test")
    assert findings == [], _titles(findings)


def test_real_signature_fires_even_on_catchall():
    # Catch-all server, but .git/config genuinely leaks -> signature still wins.
    _patch({".git/config": "[core]\n\tbare = false\n"},
           catchall_body="<html>spa</html>")
    findings, _, _ = CD.discover("https://example.test")
    assert any("Git repository" in t for t in _titles(findings))


def test_severity_high_for_secrets():
    _patch({".env": "SECRET_KEY=abc\n"})
    findings, _, _ = CD.discover("https://example.test")
    env = next(f for f in findings if ".env file" in f.title)
    assert env.severity.value == "HIGH"


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
