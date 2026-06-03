"""Tests for API-discovery heuristics: GraphQL risky-field flagging and the
BOLA/IDOR endpoint-surface detector. Pure functions, no network.

Stdlib-only: run directly (`python tests/test_apidisco.py`) or under pytest.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from celsius.recon import apidisco as a  # noqa: E402


def test_graphql_flags_file_read_and_ssrf():
    ops = [
        {"name": "getFile", "kind": "query", "args": ["name"]},
        {"name": "getWebsiteSeoScore", "kind": "query", "args": ["url"]},
        {"name": "createFunnyPicture", "kind": "mutation", "args": ["text"]},  # benign
        {"name": "currentUser", "kind": "query", "args": []},                  # no args
    ]
    findings = a._graphql_risky(ops, "http://x/graphql")
    titles = " || ".join(f.title for f in findings)
    assert "arbitrary file read: getFile" in titles
    assert "SSRF: getWebsiteSeoScore" in titles
    # benign / arg-less fields are not flagged
    assert "createFunnyPicture" not in titles
    assert "currentUser" not in titles


def test_bola_candidate_patterns():
    paths = [
        "/api/users/1", "/api/users/2",          # collapse to one /api/users/{id}
        "/api/users/{id}",                        # templated
        "/users/:userId",                         # colon style
        "/v1/accounts/{accountKey}/balance",
        "http://h/api/orders/4821/items",         # absolute URL, nested id
        "/static/logo.png", "/about", "/",        # not object endpoints
    ]
    cands = a._bola_candidates(paths)
    assert "/api/users/{id}" in cands
    assert "/users/:userId" in cands
    assert "/api/orders/{id}/items" in cands
    assert "/v1/accounts/{accountKey}/balance" in cands
    # concrete numeric ids are collapsed, not double-listed
    assert cands.count("/api/users/{id}") == 1
    # non-object paths excluded
    assert not any("logo.png" in c or c in ("/about", "/") for c in cands)


def test_bola_finding_only_when_candidates():
    assert a._bola_finding([]) == []
    f = a._bola_finding(["/api/users/{id}"])
    assert len(f) == 1 and f[0].category == "api-discovery"


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
