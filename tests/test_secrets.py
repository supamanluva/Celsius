"""Regression tests for the front-end secret scanner's high-entropy pass.

Pinned against the real false positives seen on example.com (URL slugs, a
Facebook domain-verification token, a webpack public path) plus genuine secrets
that must still be detected. Stdlib-only: run directly (`python tests/test_secrets.py`)
or under pytest.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from secscan import secrets  # noqa: E402


def _high_entropy_hits(text: str) -> list[str]:
    return [m.match for m in secrets.scan_text(text) if m.rule_id == "high-entropy"]


def _any_secret(text: str) -> list[str]:
    return [m.rule_id for m in secrets.scan_text(text)]


# ---- must NOT be flagged (real example.com false positives) --------------------

BENIGN = [
    # public Facebook domain-verification meta token
    '<meta name="facebook-domain-verification" content="x6dtf5i818eeznymy1khs29ng19pvj">',
    # google variant
    '<meta name="google-site-verification" content="aB3dEfGhIjKlMnOpQrStUvWxYz012345">',
    # news-article URL slugs in href
    '<h3 class="heading3"><a href="/nyheter/nyhetsarkiv/2026-05-06-sommarstangt-hos-handlaggningen">x</a>',
    '<a href="/nyheter/nyhetsarkiv/2026-05-19-har-ar-alla-medverkande-i-hostens-djupet-2026">x</a>',
    # webpack public path -> SiteVision asset with a content hash
    'o.p="/sitevision/system-resource/555f1319f4123ed62b6fc6dc06c326a139b08be0e4561fa4c7556c35e5ae5300"',
    # plain asset URL reference
    'src="/dist/app.7f3a9c2e1b8d4f6a0c5e2d1f.js"',
]


# ---- must STILL be flagged (genuine secrets) ---------------------------------

REAL_HIGH_ENTROPY = [
    # bare high-entropy token only the entropy pass catches (no leading slash)
    'var t = "aZ9kQ2mWpX7vL4nR8sT1uY6bC3dE0fG";',
    # base64-ish value containing "/" mid-string but NOT a URL path
    'config = {token: "aGVsbG8/d29ybGQ+secretToken12345AbCdXyZ"}',
]

REAL_NAMED = [
    ("AKIAIOSFODNN7EXAMPLE", "aws-access-key-id"),
    ('apiKey: "9f8e7d6c5b4a39281706f5e4d3c2b1a0ffee"', "generic-assignment"),
]


def test_benign_not_flagged_as_high_entropy():
    for s in BENIGN:
        hits = _high_entropy_hits(s)
        assert not hits, f"false positive: {s!r} -> {hits}"


def test_real_high_entropy_still_flagged():
    for s in REAL_HIGH_ENTROPY:
        hits = _high_entropy_hits(s)
        assert hits, f"missed high-entropy secret: {s!r}"


def test_named_secret_rules_still_fire():
    for s, rule in REAL_NAMED:
        rules = _any_secret(s)
        assert rule in rules, f"missed {rule} in {s!r} (got {rules})"


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
