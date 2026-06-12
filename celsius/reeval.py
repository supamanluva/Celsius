"""Re-evaluate stored scan fingerprints against the latest CVE feed.

A scan only knows the CVEs that existed when it ran. New CVEs are published every
day. This re-runs CVE matching for the software already fingerprinted in stored
scans — bypassing the NVD discovery cache so freshly published CVEs surface — and
reports the ones that are NEW since each scan.

Crucially it sends **zero new requests to the target**: it only re-queries the CVE
data sources for software we already detected. That makes it cheap and safe to run
on a schedule (the basis for continuous monitoring).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Optional

from . import cve as cve_mod
from .models import CVE, Service
from .targets import parse_target

_SVC_FIELDS = {"name", "version", "port", "protocol", "product", "source", "extra"}


@dataclass
class HostReeval:
    scan_id: str
    target: str
    host: str
    last_scanned: str
    checked_services: int
    new_cves: list           # list[CVE] — applicable now but not in the stored scan
    notes: list = field(default_factory=list)

    def firm_new(self) -> list:
        return [c for c in self.new_cves if getattr(c, "confidence", "firm") != "weak"]


def _services_from(scan: dict) -> list[Service]:
    """Reconstruct versioned Service objects from a stored scan dict."""
    out: list[Service] = []
    for sd in scan.get("services", []) or []:
        if not sd.get("version"):
            continue
        kw = {k: sd.get(k) for k in _SVC_FIELDS if k in sd}
        try:
            out.append(Service(**kw))
        except TypeError:
            continue
    return out


def reevaluate_scan(scan: dict, *, scan_id: str = "", api_key: Optional[str] = None,
                    force_refresh: bool = True,
                    progress: Optional[Callable[[str], None]] = None) -> HostReeval:
    """Re-match one stored scan's fingerprints against current CVE data."""
    services = _services_from(scan)
    known = {c.get("id") for c in (scan.get("cves") or [])}
    cves, notes = cve_mod.lookup_all(services, api_key=api_key,
                                     force_refresh=force_refresh, progress=progress)
    new = [c for c in cves if c.id not in known]
    target = scan.get("target", "")
    try:
        host = parse_target(target).host
    except Exception:
        host = target
    return HostReeval(
        scan_id=scan_id or scan.get("scan_id", ""),
        target=target, host=host,
        last_scanned=scan.get("finished_at") or scan.get("started_at") or "",
        checked_services=len(services), new_cves=new, notes=notes,
    )


def reevaluate(store, *, target: Optional[str] = None, limit: int = 100,
               api_key: Optional[str] = None, force_refresh: bool = True,
               progress: Optional[Callable[[str], None]] = None,
               log: Callable[[str], None] = lambda _m: None) -> list[HostReeval]:
    """Re-evaluate the LATEST stored scan per host (or just `target`).

    Skips scans with no versioned services (nothing to match). Returns one
    HostReeval per host that had something to check, newest scan first."""
    metas = store.list_scans(target=target, limit=limit)
    results: list[HostReeval] = []
    seen: set = set()
    for meta in metas:                       # newest first (created_at DESC)
        tgt = meta.get("target")
        if tgt in seen:
            continue
        seen.add(tgt)
        full = store.get_scan(meta["id"])
        if not full or not _services_from(full):
            continue
        log(f"re-evaluating {tgt} (last scanned {meta.get('finished_at') or meta.get('started_at')}) ...")
        r = reevaluate_scan(full, scan_id=meta["id"], api_key=api_key,
                            force_refresh=force_refresh, progress=progress)
        results.append(r)
    return results
