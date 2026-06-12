"""Tests for typosquat / lookalike-domain detection.

Stdlib-only: run directly (`python tests/test_typosquat.py`) or under pytest.
DNS is mocked so the tests are fully offline and deterministic.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from celsius import typosquat  # noqa: E402
from celsius.recon import dns as dns_mod  # noqa: E402


# ---- generation ---------------------------------------------------------------

def test_registrable_splits_apex():
    assert typosquat.registrable("a.b.example.com") == ("example", "com")
    assert typosquat.registrable("example.io") == ("example", "io")


def test_generate_includes_classic_lookalikes():
    cands = set(typosquat.generate("example.com", max_candidates=5000))
    assert "exmple.com" in cands          # omission
    assert "eample.com" in cands          # omission
    assert "examplee.com" in cands        # repetition
    assert "example.net" in cands         # TLD swap
    assert "example.com" not in cands     # never the original


def test_generate_homoglyph_and_validity():
    cands = set(typosquat.generate("google.com", max_candidates=5000))
    assert "g0ogle.com" in cands          # o->0 homoglyph (single edit)
    assert "go0gle.com" in cands
    # all candidates are valid DNS labels
    for c in cands:
        name = c.rsplit(".", 1)[0]
        assert name and not name.startswith("-") and not name.endswith("-")


def test_generate_is_bounded():
    cands = typosquat.generate("example.com", max_candidates=20)
    assert len(cands) <= 20


# ---- liveness (mocked DNS) ----------------------------------------------------

def _mock_dns(live_a: dict, mx: set):
    def fake_query(name, rtype):
        if rtype == "A":
            return [live_a[name]] if name in live_a else []
        if rtype == "AAAA":
            return []
        if rtype == "MX":
            return ["mail.x"] if name in mx else []
        return []
    dns_mod._query = fake_query
    typosquat.dns_mod._query = fake_query


def test_check_live_flags_resolving_and_mail():
    _mock_dns({"evil.com": "6.6.6.6"}, mx={"evil.com"})
    r = typosquat.check_live("evil.com")
    assert r == {"domain": "evil.com", "ip": "6.6.6.6", "mail": True}
    assert typosquat.check_live("dead.com") is None


def test_scan_returns_live_mail_capable_first():
    # one mail-capable + one plain live among the generated candidates
    cands = typosquat.generate("example.com", max_candidates=5000)
    a = {cands[3]: "1.1.1.1", cands[7]: "2.2.2.2"}
    _mock_dns(a, mx={cands[7]})
    live = typosquat.scan("example.com")
    domains = [r["domain"] for r in live]
    assert set(domains) == {cands[3], cands[7]}
    assert live[0]["domain"] == cands[7]      # mail-capable sorted first
    assert live[0]["mail"] is True


# ---- monitor integration (new-since-baseline) ---------------------------------

def test_monitor_new_lookalike_detection(tmp_path_factory=None):
    from celsius import monitor
    import tempfile
    monitor._TYPO_STATE_DIR = tempfile.mkdtemp()

    calls = {"n": 0}

    def fake_scan(domain, log=lambda m: None):
        # first run: one live; second run: a NEW one appears
        calls["n"] += 1
        if calls["n"] == 1:
            return [{"domain": "examp1e.com", "ip": "1.1.1.1", "mail": False}]
        return [{"domain": "examp1e.com", "ip": "1.1.1.1", "mail": False},
                {"domain": "exampie.com", "ip": "9.9.9.9", "mail": True}]
    import celsius.typosquat as ts_mod
    orig_scan = ts_mod.scan
    ts_mod.scan = fake_scan
    try:
        first = monitor._new_lookalikes("example.com", log=lambda m: None)
        assert first == []                                   # first run seeds, no alert
        second = monitor._new_lookalikes("example.com", log=lambda m: None)
        assert [r["domain"] for r in second] == ["exampie.com"]   # only the new one
    finally:
        ts_mod.scan = orig_scan                              # don't leak into other tests


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
        except Exception as e:  # noqa
            failed += 1
            print(f"ERROR {fn.__name__}: {type(e).__name__}: {e}")
    print(f"\n{len(fns) - failed}/{len(fns)} passed")
    sys.exit(1 if failed else 0)
