"""Tests for continuous monitoring (monitor) and notification dispatch.

Stdlib-only: run directly (`python tests/test_monitor.py`) or under pytest.

Fully offline: a fake store, a monkeypatched reeval.reevaluate, and a captured
notify layer. Covers watchlist resolution, change detection in recheck mode,
notify-only-on-change (vs --always), and report formatting.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from celsius import monitor as mon  # noqa: E402
from celsius import reeval  # noqa: E402
from celsius.models import CVE, Severity  # noqa: E402


class FakeStore:
    def __init__(self, targets):
        self._targets = targets

    def list_scans(self, target=None, limit=200):
        rows = [{"id": f"id-{t}", "target": t} for t in self._targets]
        if target:
            rows = [r for r in rows if r["target"] == target]
        return rows[:limit]


def _cve(cid, sev=Severity.CRITICAL, conf="firm"):
    return CVE(id=cid, severity=sev, cvss=9.8, url=f"https://nvd/{cid}",
               description="x", confidence=conf, affects="nginx 1.20.0")


def _patch_reeval(mapping):
    """reeval.reevaluate(store, target=t, ...) -> [HostReeval] with mapping[t] CVEs."""
    def fake(store, *, target=None, api_key=None, force_refresh=True, limit=100,
             progress=None, log=lambda m: None):
        cves = mapping.get(target, [])
        hr = reeval.HostReeval(scan_id=f"id-{target}", target=target, host=target,
                               last_scanned="2026-01-01", checked_services=1, new_cves=cves)
        return [hr]
    mon.reeval.reevaluate = fake


# ---- watchlist ----------------------------------------------------------------

def test_watchlist_explicit_targets_win():
    store = FakeStore(["a.com", "b.com", "c.com"])
    assert mon.resolve_watchlist(store, targets=["x.com", "x.com", "y.com"]) == ["x.com", "y.com"]


def test_watchlist_defaults_to_all_stored_hosts():
    store = FakeStore(["a.com", "b.com", "a.com"])
    assert mon.resolve_watchlist(store) == ["a.com", "b.com"]


# ---- change detection ---------------------------------------------------------

def test_new_cve_produces_a_change():
    store = FakeStore(["a.com", "b.com"])
    _patch_reeval({"a.com": [_cve("CVE-2026-1")], "b.com": []})
    report = mon.run_monitor(store)
    assert report.checked == 2
    assert [c.host for c in report.changes] == ["a.com"]      # only a.com changed
    assert report.any_changes() is True


def test_no_changes_when_nothing_new():
    store = FakeStore(["a.com"])
    _patch_reeval({"a.com": []})
    report = mon.run_monitor(store)
    assert report.changes == [] and report.any_changes() is False


def test_firm_only_filters_weak():
    store = FakeStore(["a.com"])
    _patch_reeval({"a.com": [_cve("CVE-2026-1", conf="weak")]})
    report = mon.run_monitor(store, firm_only=True)
    assert report.any_changes() is False                     # weak-only -> no alert


# ---- dispatch -----------------------------------------------------------------

def test_alert_sent_only_on_change():
    sent = []
    mon.notify_mod.send_email = lambda to, subj, body, **k: (sent.append((to, subj)) or (True, "sent"))

    empty = mon.MonitorReport(mode="recheck", checked=1, changes=[])
    mon.dispatch_alerts(empty, email="me@x.com")
    assert sent == []                                        # nothing new -> no email

    changed = mon.MonitorReport(mode="recheck", checked=1,
                                changes=[mon.HostChange(host="a.com", target="a.com",
                                                        new_cves=[_cve("CVE-2026-1")])])
    mon.dispatch_alerts(changed, email="me@x.com")
    assert len(sent) == 1 and "a.com" not in sent[0][1]      # subject is the summary line


def test_always_sends_heartbeat_even_with_no_changes():
    sent = []
    mon.notify_mod.send_email = lambda to, subj, body, **k: (sent.append(subj) or (True, "sent"))
    empty = mon.MonitorReport(mode="recheck", checked=3, changes=[])
    mon.dispatch_alerts(empty, email="me@x.com", always=True)
    assert len(sent) == 1 and "no new exposure" in sent[0]


# ---- formatting ---------------------------------------------------------------

def test_format_report_lists_cves():
    report = mon.MonitorReport(mode="recheck", checked=2,
                               changes=[mon.HostChange(host="a.com", target="a.com",
                                                       new_cves=[_cve("CVE-2026-1")])])
    subject, body = mon.format_report(report)
    assert "1 host(s)" in subject
    assert "CVE-2026-1" in body and "a.com" in body


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
