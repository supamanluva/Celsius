"""Tests for CVE re-evaluation of stored scans (reeval).

Stdlib-only: run directly (`python tests/test_reeval.py`) or under pytest.

Uses a fake store and a monkeypatched cve.lookup_all so the logic is exercised
fully offline: service reconstruction, the new-vs-known CVE diff, latest-per-host
selection, and skipping scans with no versioned software.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from celsius import reeval  # noqa: E402
from celsius import cve as cve_mod  # noqa: E402
from celsius.models import CVE, Severity  # noqa: E402


class FakeStore:
    def __init__(self, scans):
        # scans: list of (meta, full) in newest-first order
        self._scans = scans

    def list_scans(self, target=None, limit=100):
        metas = [m for m, _f in self._scans]
        if target:
            metas = [m for m in metas if m["target"] == target]
        return metas[:limit]

    def get_scan(self, scan_id):
        for m, f in self._scans:
            if m["id"] == scan_id:
                return f
        return None


def _cve(cid, sev=Severity.HIGH, conf="firm"):
    return CVE(id=cid, severity=sev, cvss=7.5, url=f"https://nvd/{cid}",
               description="x", confidence=conf, affects="nginx 1.20.0")


def _scan(scan_id, target, version="1.20.0", known_cves=()):
    return (
        {"id": scan_id, "target": target, "finished_at": "2026-01-01"},
        {"target": target,
         "services": [{"name": "nginx", "version": version, "source": "http-header"}],
         "cves": [{"id": c} for c in known_cves]},
    )


def _patch_lookup(returns):
    """Patch cve.lookup_all to return a fixed CVE list (records force_refresh)."""
    calls = {}

    def fake(services, *, api_key=None, progress=None, force_refresh=False):
        calls["force_refresh"] = force_refresh
        calls["services"] = services
        return list(returns), []

    cve_mod.lookup_all = fake          # reeval calls cve_mod.lookup_all
    reeval.cve_mod.lookup_all = fake
    return calls


# ---- tests --------------------------------------------------------------------

def test_new_cve_since_scan_is_reported():
    store = FakeStore([_scan("s1", "example.com", known_cves=["CVE-2023-1"])])
    _patch_lookup([_cve("CVE-2023-1"), _cve("CVE-2026-9999")])  # one old, one new
    results = reeval.reevaluate(store)
    assert len(results) == 1
    ids = [c.id for c in results[0].new_cves]
    assert ids == ["CVE-2026-9999"]            # only the newly-published one
    assert results[0].host == "example.com"
    assert results[0].checked_services == 1


def test_no_new_cves_when_nothing_changed():
    store = FakeStore([_scan("s1", "a.com", known_cves=["CVE-2023-1"])])
    _patch_lookup([_cve("CVE-2023-1")])         # same as stored
    results = reeval.reevaluate(store)
    assert results[0].new_cves == []


def test_force_refresh_passed_through_by_default():
    store = FakeStore([_scan("s1", "a.com")])
    calls = _patch_lookup([])
    reeval.reevaluate(store)
    assert calls["force_refresh"] is True       # bypasses NVD cache by default


def test_latest_scan_per_host_only():
    # two scans for the same target — only the newest is re-checked
    newest = _scan("new", "dup.com", version="1.21.0")
    oldest = _scan("old", "dup.com", version="1.18.0")
    store = FakeStore([newest, oldest])         # newest-first
    calls = _patch_lookup([_cve("CVE-2026-1")])
    results = reeval.reevaluate(store)
    assert len(results) == 1 and results[0].scan_id == "new"
    assert calls["services"][0].version == "1.21.0"


def test_scan_without_versioned_services_is_skipped():
    meta = {"id": "s1", "target": "novers.com", "finished_at": "2026-01-01"}
    full = {"target": "novers.com",
            "services": [{"name": "nginx", "source": "http-header"}],  # no version
            "cves": []}
    store = FakeStore([(meta, full)])
    _patch_lookup([_cve("CVE-2026-1")])
    results = reeval.reevaluate(store)
    assert results == []                        # nothing to match -> skipped


def test_firm_new_filters_weak_leads():
    store = FakeStore([_scan("s1", "a.com")])
    _patch_lookup([_cve("CVE-2026-1", conf="firm"), _cve("CVE-2026-2", conf="weak")])
    r = reeval.reevaluate(store)[0]
    assert len(r.new_cves) == 2
    assert [c.id for c in r.firm_new()] == ["CVE-2026-1"]


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
