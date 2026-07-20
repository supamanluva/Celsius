"""Offline tests for the WordPress checks (recon/wpcheck.py + plugin).

The network fetch is monkeypatched so we exercise the real detection logic:
content-signature confirmation, soft-404 suppression, REST author enumeration,
and the plugin's fingerprint gate (runs only when WordPress was detected).
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from celsius.audit import AuditLog  # noqa: E402
from celsius.config import ScanConfig  # noqa: E402
from celsius.models import ScanResult  # noqa: E402
from celsius.plugins.base import ScanContext  # noqa: E402
from celsius.plugins.builtin import WordPressChecks  # noqa: E402
from celsius.recon import wpcheck as WP  # noqa: E402
from celsius.scope import Scope  # noqa: E402
from celsius.targets import Target  # noqa: E402

_BASE = "https://example.test"


def _patch(responses):
    """Make WP._fetch return canned (status, body) keyed by URL suffix."""
    def fake(url, insecure, auth):
        for suffix, body in responses.items():
            if url.rstrip("/").endswith(suffix.rstrip("/")):
                return 200, body
        return 404, ""
    WP._fetch = fake


def _titles(findings):
    return [f.title for f in findings]


def test_readme_version_disclosed():
    _patch({"readme.html": "<html><h1>WordPress</h1><p>Version 6.5.2</p></html>"})
    findings, info, _ = WP.check(_BASE)
    f = next(f for f in findings if "readme.html" in f.title)
    assert f.severity.value == "LOW"
    assert info["version"] == "6.5.2"
    assert "6.5.2" in f.evidence


def test_meta_generator_version_disclosed():
    _patch({})
    html = '<head><meta name="generator" content="WordPress 6.4.1" /></head>'
    findings, info, _ = WP.check(_BASE, html=html)
    f = next(f for f in findings if "meta generator" in f.title)
    assert f.severity.value == "LOW"
    assert info["version"] == "6.4.1"


def test_readme_version_wins_over_generator():
    _patch({"readme.html": "Welcome to WordPress. Version 6.5.2"})
    html = '<meta name="generator" content="WordPress 6.4.1">'
    findings, info, _ = WP.check(_BASE, html=html)
    assert info["version"] == "6.5.2"
    assert len(findings) == 2


def test_rest_users_enumeration_is_medium():
    _patch({"wp-json/wp/v2/users": '[{"id":1,"slug":"admin"},{"id":2,"slug":"editor.jane"}]'})
    findings, info, _ = WP.check(_BASE)
    f = next(f for f in findings if "author enumeration" in f.title)
    assert f.severity.value == "MEDIUM"
    assert info["users"] == ["admin", "editor.jane"]
    assert "admin" in f.evidence


def test_rest_users_non_json_not_reported():
    _patch({"wp-json/wp/v2/users": "<html>SPA shell</html>"})
    findings, info, _ = WP.check(_BASE)
    assert not any("enumeration" in t for t in _titles(findings))
    assert "users" not in info


def test_xmlrpc_enabled():
    _patch({"xmlrpc.php": "XML-RPC server accepts POST requests only."})
    findings, info, _ = WP.check(_BASE)
    f = next(f for f in findings if "XML-RPC" in f.title)
    assert f.severity.value == "MEDIUM"
    assert info["xmlrpc"] is True


def test_uploads_directory_listing():
    _patch({"wp-content/uploads/": "<html><title>Index of /wp-content/uploads</title>"})
    findings, info, _ = WP.check(_BASE)
    f = next(f for f in findings if "directory listing" in f.title)
    assert f.severity.value == "LOW"
    assert info["uploads_listing"] is True


def test_soft_404_signatures_suppress_findings():
    # A catch-all that answers 200 with a generic page to every path -> nothing.
    _patch({"readme.html": "<html>page not found?</html>",
            "xmlrpc.php": "<html>hello</html>",
            "wp-content/uploads/": "<html>fancy 404</html>",
            "wp-json/wp/v2/users": "<html>fancy 404</html>"})
    findings, info, _ = WP.check(_BASE)
    assert findings == [], _titles(findings)
    assert info == {}


def test_all_paths_missing_is_quiet():
    _patch({})
    findings, info, errors = WP.check(_BASE)
    assert findings == [] and info == {} and errors == []


# -- plugin gating -------------------------------------------------------------

def _ctx(tech):
    cfg = ScanConfig(target="example.com", persist=False)
    ctx = ScanContext(
        config=cfg,
        target=Target(raw="example.com", scheme="https", host="example.com",
                      port=443, path="/"),
        result=ScanResult(target="example.com", url=_BASE),
        scope=Scope.permissive_default(),
        audit=AuditLog(path="/tmp/celsius-test-wpcheck-audit.log"))
    if tech:
        ctx.result.recon["tech"] = tech
    return ctx


def test_plugin_enabled_only_for_wordpress():
    wp = [{"name": "WordPress", "category": "cms", "version": "6.5"}]
    assert WordPressChecks().enabled(_ctx(wp)) is True
    assert WordPressChecks().enabled(_ctx([{"name": "Drupal", "category": "cms"}])) is False
    assert WordPressChecks().enabled(_ctx(None)) is False


def test_plugin_runs_checks_and_feeds_cve_lookup():
    _patch({"readme.html": "Welcome. Version 6.5.2",
            "wp-json/wp/v2/users": '[{"id":1,"slug":"admin"}]'})
    ctx = _ctx([{"name": "WordPress", "category": "cms", "version": None}])
    WordPressChecks().run(ctx)
    titles = _titles(ctx.result.findings)
    assert any("readme.html" in t for t in titles), titles
    assert any("author enumeration" in t for t in titles), titles
    assert ctx.result.recon["wordpress"]["version"] == "6.5.2"
    svc = next(s for s in ctx.result.services if s.name == "WordPress")
    assert svc.version == "6.5.2" and svc.source == "wp-check"


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
