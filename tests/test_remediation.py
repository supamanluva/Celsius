"""Tests for copy-paste remediation playbooks (remediation) + the enrich plugin.

Stdlib-only: run directly (`python tests/test_remediation.py`) or under pytest.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from celsius import remediation  # noqa: E402


def test_redis_finding_gets_redis_playbook():
    pb = remediation.playbook_for(
        {"title": "Redis reachable without authentication", "category": "exposure"})
    assert pb is not None
    assert "requirepass" in pb["snippet"]
    assert pb["lang"] == "bash" and pb["steps"]


def test_weak_tls_gets_nginx_protocols():
    pb = remediation.playbook_for(
        {"title": "Weak TLS protocol negotiated: TLSv1.1", "category": "tls"})
    assert pb and "ssl_protocols TLSv1.2 TLSv1.3" in pb["snippet"]


def test_spf_gets_dns_record():
    pb = remediation.playbook_for({"title": "SPF — no fail mechanism", "category": "mailsec"})
    assert pb and pb["lang"] == "dns" and "v=spf1" in pb["snippet"]


def test_default_creds_has_steps_without_snippet():
    pb = remediation.playbook_for(
        {"title": "Default credentials accepted (HTTP Basic auth)", "category": "exposure"})
    assert pb and pb["steps"] and pb["snippet"] == ""


def test_exposed_git_advises_rotation():
    pb = remediation.playbook_for({"title": "Exposed .git directory", "category": "content"})
    assert pb and "deny all" in pb["snippet"]
    assert any("rotate" in s.lower() for s in pb["steps"])


def test_unknown_finding_has_no_playbook():
    assert remediation.playbook_for({"title": "Some novel issue", "category": "misc"}) is None


def test_enrich_plugin_attaches_remediation():
    # the plugin should stash the playbook under finding.exploitability['remediation']
    import celsius.plugins.builtin  # noqa: F401  (register)
    from celsius.plugins.base import all_plugins, ScanContext
    from celsius.models import ScanResult, Finding, Severity
    from celsius.config import ScanConfig
    from celsius.scope import Scope
    from celsius.audit import AuditLog
    from celsius.targets import parse_target

    res = ScanResult(target="x", started_at="now")
    res.findings.append(Finding(title="Redis reachable without authentication",
                                severity=Severity.HIGH, category="exposure"))
    res.findings.append(Finding(title="Totally novel thing",
                                severity=Severity.LOW, category="misc"))
    ctx = ScanContext(config=ScanConfig(target="x"), target=parse_target("x"), result=res,
                      scope=Scope.permissive_default(), audit=AuditLog(), log=lambda m: None)
    plugin = [p for p in all_plugins() if p.id == "remediation"][0]
    plugin.run(ctx)
    assert res.findings[0].exploitability.get("remediation")          # matched
    assert "remediation" not in (res.findings[1].exploitability or {})  # unmatched


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
