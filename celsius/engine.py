"""Reusable scan engine: a plugin pipeline shared by the CLI and the web app.

`run_scan(ScanConfig)` builds a ScanContext, runs the registered plugins in phase
order — skipping any whose required mode is not permitted by scope/config —
records an audit trail, optionally persists the result, and returns a ScanResult.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Callable, Optional

# Re-export ScanConfig so existing imports (`from .engine import ScanConfig`) work.
from .config import ScanConfig  # noqa: F401
from . import plugins as _plugins_pkg  # noqa: F401  (triggers base import)
from .audit import AuditLog
from .models import ScanResult
from .plugins import builtin as _builtin  # noqa: F401  (registers built-in plugins)
from .plugins.base import Mode, ScanContext, all_plugins
from .scope import Scope, load_scope
from .targets import is_private_or_local, parse_target

Logger = Callable[[str], None]


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")


def run_scan(
    config: ScanConfig,
    log: Optional[Logger] = None,
    *,
    scope: Optional[Scope] = None,
    store=None,
) -> ScanResult:
    """Run a full scan. If `store` is given (a store.Store), the result is saved
    and its id is recorded in result.extra via errors/notes is avoided — the id is
    returned on the result object as `.scan_id` attribute for the caller."""
    log = log or (lambda _m: None)
    target = parse_target(config.target)
    result = ScanResult(target=config.target, started_at=_now())

    scope = scope or load_scope(config.scope_file)
    # Apply the scope's request-rate cap to the shared active-HTTP helpers.
    try:
        from . import webchecks
        webchecks.set_rate_limit(getattr(scope, "rate_limit_rps", 0))
    except Exception:
        pass
    audit = AuditLog()

    # resolve + record
    ip = target.resolve_ip()
    result.ip = ip
    if ip is None and not target.is_ip:
        result.errors.append(f"could not resolve hostname '{target.host}'")
    if ip and is_private_or_local(ip):
        result.errors.append(f"note: {ip} is a private/loopback address (lab/local target).")

    # global scope check (exclusions)
    if scope.is_excluded(target.host):
        result.errors.append(f"BLOCKED: {target.host} is excluded by scope; no checks run.")
        result.finished_at = _now()
        return result

    audit.scan_start(target.host, modes=_enabled_modes(config))
    if getattr(config, "auth", None):
        audit.event("auth_session", host=target.host,
                    source=getattr(config.auth, "source", "") or "session")

    ctx = ScanContext(config=config, target=target, result=result,
                      scope=scope, audit=audit, log=log)

    for plugin in all_plugins():
        try:
            if not plugin.enabled(ctx):
                continue
        except Exception:
            continue  # a misbehaving enabled() shouldn't block the scan

        # mode / scope gating
        need = plugin.mode
        if need == Mode.SAFE_ACTIVE and not config.allow_active:
            audit.skipped(plugin.id, target.host, "safe-active disabled for this scan")
            result.errors.append(f"{plugin.id}: skipped (safe-active checks disabled)")
            continue
        if need == Mode.EXPLOIT and not config.allow_exploit:
            audit.skipped(plugin.id, target.host, "exploit mode not enabled")
            continue
        if not scope.allows(target.host, need):
            reason = scope.reason(target.host, need)
            audit.skipped(plugin.id, target.host, reason)
            result.errors.append(f"{plugin.id}: skipped ({reason})")
            continue

        log(f"[{plugin.phase.name.lower()}] {plugin.id} ...")
        try:
            plugin.run(ctx)
        except Exception as e:  # a check must never crash the whole scan
            result.errors.append(f"{plugin.id} error: {e}")

    # temporal diff vs the most recent prior scan (before saving this one)
    if config.diff and store is not None:
        try:
            _temporal_diff(result, store, log)
        except Exception as e:
            result.errors.append(f"diff failed: {e}")

    result.finished_at = _now()
    audit.scan_end(target.host, findings=len(result.findings), cves=len(result.cves))

    if store is not None and config.persist:
        try:
            scan_id = store.save_scan(result.to_dict())
            setattr(result, "scan_id", scan_id)
        except Exception as e:
            result.errors.append(f"persist failed: {e}")

    return result


def _temporal_diff(result, store, log) -> None:
    """Compare against the latest prior scan of the same target; flag new items."""
    from .models import Finding, Severity

    prior_list = store.list_scans(target=result.target, limit=1)
    if not prior_list:
        return
    prior = store.get_scan(prior_list[0]["id"])
    if not prior:
        return

    def svc_keys(d):
        return {f"{s.get('name')}:{s.get('version') or '?'}:{s.get('port') or ''}"
                for s in d.get("services", [])}

    prev_subs = set((prior.get("recon") or {}).get("subdomains", []) or [])
    cur_subs = set(result.recon.get("subdomains", []) or [])
    new_subs = sorted(cur_subs - prev_subs)

    prev_svc = svc_keys(prior)
    cur_svc = {f"{s.name}:{s.version or '?'}:{s.port or ''}" for s in result.services}
    new_svc = sorted(cur_svc - prev_svc)

    prev_cves = {c.get("id") for c in prior.get("cves", [])}
    new_cves = sorted({c.id for c in result.cves} - prev_cves)

    if new_subs:
        result.findings.append(Finding(
            title=f"NEW since last scan: {len(new_subs)} subdomain(s)",
            severity=Severity.LOW, category="diff",
            description=", ".join(new_subs[:20]),
            recommendation="Newly appeared attack surface — review promptly.",
        ))
    if new_svc:
        result.findings.append(Finding(
            title=f"NEW since last scan: {len(new_svc)} service/version",
            severity=Severity.LOW, category="diff",
            description=", ".join(new_svc[:20]),
        ))
    if new_cves:
        result.findings.append(Finding(
            title=f"NEW since last scan: {len(new_cves)} CVE(s)",
            severity=Severity.MEDIUM, category="diff",
            description=", ".join(new_cves[:20]),
            recommendation="New CVEs affecting this target since the previous scan.",
        ))


def _enabled_modes(config: ScanConfig) -> list[str]:
    modes = [Mode.PASSIVE.value]
    if config.allow_active:
        modes.append(Mode.SAFE_ACTIVE.value)
    if config.allow_exploit:
        modes.append(Mode.EXPLOIT.value)
    return modes
