"""Continuous monitoring: watch known hosts for NEW exposure and alert.

Built on top of the re-evaluation (#3) and the engine's temporal diff. Two modes:

  * recheck (default) — re-match stored fingerprints against the latest CVE feed.
    Sends ZERO new requests to the targets, so it's cheap and safe for frequent
    cron (e.g. hourly).
  * rescan (--rescan) — run a fresh scan per host with temporal diff, surfacing
    new subdomains / services / ports / CVEs since the previous scan. This DOES
    send traffic to the targets, so use it for hosts you own, on a slower cadence.

An alert (email and/or webhook) is sent only when something new appears, unless
`always` is set. The summary is also returned/printed for cron logs.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Callable, Optional

from . import notify as notify_mod
from . import reeval

_TYPO_STATE_DIR = os.path.expanduser("~/.cache/celsius/typosquat")


@dataclass
class HostChange:
    host: str
    target: str
    new_cves: list = field(default_factory=list)          # list[CVE] newly applicable
    diff_findings: list = field(default_factory=list)      # "NEW since last scan" findings
    new_lookalikes: list = field(default_factory=list)     # newly-live typosquat domains

    def has_changes(self) -> bool:
        return bool(self.new_cves or self.diff_findings or self.new_lookalikes)


def _typo_baseline(apex: str) -> tuple[set, str]:
    """(known-live lookalike set, path) for an apex domain."""
    path = os.path.join(_TYPO_STATE_DIR, apex.replace("/", "_") + ".json")
    try:
        with open(path) as fh:
            return set(json.load(fh)), path
    except (OSError, ValueError):
        return set(), path


def _save_typo_baseline(path: str, live: set) -> None:
    try:
        os.makedirs(_TYPO_STATE_DIR, exist_ok=True)
        with open(path, "w") as fh:
            json.dump(sorted(live), fh)
    except OSError:
        pass


def _new_lookalikes(apex: str, log) -> list[dict]:
    """Live lookalikes that are NEW vs the stored baseline (first run seeds it)."""
    from . import typosquat
    baseline, path = _typo_baseline(apex)
    live = typosquat.scan(apex, log=log)
    live_domains = {r["domain"] for r in live}
    seeding = not os.path.exists(path)
    _save_typo_baseline(path, live_domains)
    if seeding:
        log(f"typosquat: seeded baseline for {apex} ({len(live_domains)} live) — "
            "no alert on first run")
        return []
    return [r for r in live if r["domain"] not in baseline]


@dataclass
class MonitorReport:
    mode: str
    checked: int
    changes: list = field(default_factory=list)            # list[HostChange] with changes

    def any_changes(self) -> bool:
        return bool(self.changes)


def resolve_watchlist(store, *, targets: Optional[list] = None,
                      watchlist_file: Optional[str] = None, limit: int = 200) -> list[str]:
    """Explicit targets win; then a watchlist file (one host per line, '#' comments);
    otherwise every distinct host with a stored scan (newest first)."""
    if targets:
        return list(dict.fromkeys(targets))
    if watchlist_file:
        with open(watchlist_file) as fh:
            return [ln.strip() for ln in fh
                    if ln.strip() and not ln.lstrip().startswith("#")]
    seen: list[str] = []
    for m in store.list_scans(limit=limit):
        if m["target"] not in seen:
            seen.append(m["target"])
    return seen


def run_monitor(store, *, targets: Optional[list] = None,
                watchlist_file: Optional[str] = None, rescan: bool = False,
                scan_config_factory: Optional[Callable[[str], object]] = None,
                api_key: Optional[str] = None, firm_only: bool = False,
                typosquat: bool = False,
                limit: int = 200, log: Callable[[str], None] = lambda _m: None) -> MonitorReport:
    hosts = resolve_watchlist(store, targets=targets, watchlist_file=watchlist_file, limit=limit)
    changes: list[HostChange] = []

    # Typosquat watch runs once per registrable apex (not per subdomain).
    typo_by_apex: dict = {}
    if typosquat:
        from .typosquat import registrable
        for tgt in hosts:
            name, tld = registrable(tgt)
            apex = f"{name}.{tld}" if tld else tgt
            typo_by_apex.setdefault(apex, None)
        for apex in typo_by_apex:
            new = _new_lookalikes(apex, log)
            if new:
                changes.append(HostChange(host=apex, target=apex, new_lookalikes=new))

    for tgt in hosts:
        if rescan and scan_config_factory is not None:
            from .engine import run_scan
            log(f"re-scanning {tgt} ...")
            res = run_scan(scan_config_factory(tgt), store=store, log=log)
            diff = [f for f in res.findings if getattr(f, "category", "") == "diff"]
            host = getattr(res, "ip", None) or tgt
            try:
                from .targets import parse_target
                host = parse_target(tgt).host
            except Exception:
                pass
            ch = HostChange(host=host, target=tgt, diff_findings=diff)
        else:
            results = reeval.reevaluate(store, target=tgt, api_key=api_key,
                                        force_refresh=True, log=log)
            new_cves = []
            host = tgt
            for hr in results:
                host = hr.host
                new_cves.extend(hr.firm_new() if firm_only else hr.new_cves)
            ch = HostChange(host=host, target=tgt, new_cves=new_cves)

        if ch.has_changes():
            changes.append(ch)

    return MonitorReport(mode="rescan" if rescan else "recheck",
                         checked=len(hosts), changes=changes)


def format_report(report: MonitorReport) -> tuple[str, str]:
    """(subject, plain-text body) summarising the changes for an alert / log."""
    n = len(report.changes)
    if n == 0:
        return ("Celsius monitor — no new exposure",
                f"Checked {report.checked} host(s) ({report.mode}); nothing new.")

    subject = f"Celsius monitor — {n} host(s) with new exposure"
    lines = [subject, "=" * len(subject), ""]
    for ch in report.changes:
        lines.append(f"⚠  {ch.host}")
        if ch.new_cves:
            cves = sorted(ch.new_cves, key=lambda c: (c.severity.rank, c.cvss or 0), reverse=True)
            lines.append(f"   {len(cves)} new CVE(s) since last scan:")
            for c in cves[:25]:
                cvss = f" CVSS {c.cvss}" if c.cvss else ""
                weak = "  [weak]" if getattr(c, "confidence", "firm") == "weak" else ""
                lines.append(f"     {c.severity.value:<8} {c.id:<18} {c.affects or ''}{cvss}{weak}")
        for f in ch.diff_findings:
            lines.append(f"   {f.title}")
            if getattr(f, "description", ""):
                lines.append(f"     {f.description[:200]}")
        if ch.new_lookalikes:
            lines.append(f"   {len(ch.new_lookalikes)} new look-alike/phishing domain(s):")
            for r in ch.new_lookalikes[:25]:
                mail = "  ✉ mail-capable" if r.get("mail") else ""
                lines.append(f"     {r['domain']:<38} {r.get('ip', '')}{mail}")
        lines.append("")
    lines.append(f"Checked {report.checked} host(s) ({report.mode}). "
                 "Re-scan affected hosts to confirm and remediate.")
    return subject, "\n".join(lines)


def dispatch_alerts(report: MonitorReport, *, email: Optional[str] = None,
                    webhook: Optional[str] = None, always: bool = False,
                    log: Callable[[str], None] = lambda _m: None) -> None:
    """Send the configured alerts when there are changes (or always)."""
    if not (report.any_changes() or always):
        return
    subject, body = format_report(report)
    if email:
        ok, detail = notify_mod.send_email(email, subject, body)
        log(f"email -> {email}: {'ok' if ok else 'FAILED: ' + detail}")
    if webhook:
        payload = {
            "subject": subject,
            "mode": report.mode,
            "checked": report.checked,
            "changes": [{
                "host": ch.host, "target": ch.target,
                "new_cves": [c.to_dict() for c in ch.new_cves],
                "diff": [f.to_dict() for f in ch.diff_findings],
                "new_lookalikes": ch.new_lookalikes,
            } for ch in report.changes],
        }
        ok, detail = notify_mod.send_webhook(webhook, payload)
        log(f"webhook -> {webhook}: {'ok' if ok else 'FAILED: ' + detail}")
