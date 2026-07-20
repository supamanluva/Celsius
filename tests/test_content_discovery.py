"""Offline tests for content-discovery probing.

The network fetch is monkeypatched so we can exercise the real detection logic:
signature confirmation and soft-404 / catch-all suppression.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from celsius.recon import content_discovery as CD  # noqa: E402


def _patch(responses, *, catchall_body=None):
    """Make CD._fetch return canned (status, body) keyed by URL suffix.

    Nonsense baseline paths return `catchall_body` (200) when set, else 404.
    Any path in `responses` returns (200, body); everything else 404.
    """
    def fake(url, insecure, auth):
        for suffix, body in responses.items():
            if url.endswith(suffix):
                return 200, body
        if catchall_body is not None:
            return 200, catchall_body
        return 404, ""
    CD._fetch = fake


def _titles(findings):
    return [f.title for f in findings]


def test_detects_exposed_git_and_env():
    _patch({".git/config": "[core]\n\trepositoryformatversion = 0\n",
            ".git/HEAD": "ref: refs/heads/main\n",
            "refs/heads/main": "0123456789abcdef0123456789abcdef01234567\n",
            ".env": "APP_KEY=base64:xxxx\nDB_PASSWORD=hunter2\n"})
    findings, paths, _ = CD.discover("https://example.test")
    titles = _titles(findings)
    assert any("Git repository" in t for t in titles), titles
    assert any(".env file" in t for t in titles), titles
    assert ".git/config" in paths and ".env" in paths


def test_git_recoverable_is_high():
    # config + parseable HEAD + fetchable ref -> HIGH 'recoverable'.
    _patch({".git/config": "[core]\n\tbare = false\n",
            ".git/HEAD": "ref: refs/heads/master\n",
            "refs/heads/master": "0123456789abcdef0123456789abcdef01234567\n"})
    findings, _, _ = CD.discover("https://example.test")
    git = next(f for f in findings if "Git" in f.title)
    assert git.title == "Exposed Git repository (recoverable)", git.title
    assert git.severity.value == "HIGH"


def test_git_recoverable_via_packed_refs():
    # Detached HEAD (40-hex) + packed-refs -> also HIGH 'recoverable'.
    _patch({".git/config": "[core]\n\tbare = false\n",
            ".git/HEAD": "0123456789abcdef0123456789abcdef01234567\n",
            ".git/packed-refs": "# pack-refs with: peeled\n0123456789abcdef0123456789abcdef01234567 refs/heads/main\n"})
    findings, _, _ = CD.discover("https://example.test")
    git = next(f for f in findings if "Git" in f.title)
    assert git.title == "Exposed Git repository (recoverable)", git.title
    assert git.severity.value == "HIGH"


def test_git_config_without_head_is_medium():
    # config parses but HEAD is gone -> MEDIUM metadata, recovery unconfirmed.
    _patch({".git/config": "[core]\n\trepositoryformatversion = 0\n"})
    findings, paths, _ = CD.discover("https://example.test")
    git = next(f for f in findings if "Git" in f.title)
    assert git.title == "Exposed Git metadata (.git/config)", git.title
    assert git.severity.value == "MEDIUM"
    assert "recovery was not confirmed" in git.description
    assert ".git/config" in paths


def test_git_head_unparseable_is_medium():
    # HEAD answers 200 but is an HTML error page -> MEDIUM, not HIGH.
    _patch({".git/config": "[core]\n\tbare = false\n",
            ".git/HEAD": "<!doctype html><title>oops</title>"})
    findings, _, _ = CD.discover("https://example.test")
    git = next(f for f in findings if "Git" in f.title)
    assert git.severity.value == "MEDIUM"
    assert "Git metadata" in git.title


def test_git_head_without_refs_is_medium():
    # HEAD parses but neither the ref nor packed-refs is fetchable -> MEDIUM.
    _patch({".git/config": "[core]\n\tbare = false\n",
            ".git/HEAD": "ref: refs/heads/main\n"})
    findings, _, _ = CD.discover("https://example.test")
    git = next(f for f in findings if "Git" in f.title)
    assert git.severity.value == "MEDIUM"
    assert "Git metadata" in git.title


def test_signature_mismatch_is_not_reported():
    # 200 but the body is an SPA shell, not a real .git/config -> must be dropped.
    _patch({".git/config": "<!doctype html><title>App</title>"})
    findings, _, _ = CD.discover("https://example.test")
    assert findings == [], _titles(findings)


def test_catchall_suppresses_without_signature_match():
    # Every path (incl. baseline) returns the same SPA 200 -> nothing should fire.
    _patch({}, catchall_body="<html>single page app</html>")
    findings, _, _ = CD.discover("https://example.test")
    assert findings == [], _titles(findings)


def test_real_signature_fires_even_on_catchall():
    # Catch-all server, but .git/config genuinely leaks -> signature still wins.
    # HEAD/refs return the SPA shell too, so certainty stays MEDIUM metadata.
    _patch({".git/config": "[core]\n\tbare = false\n"},
           catchall_body="<html>spa</html>")
    findings, _, _ = CD.discover("https://example.test")
    git = next(f for f in findings if "Git" in f.title)
    assert "Git metadata" in git.title, git.title
    assert git.severity.value == "MEDIUM"


def test_git_recoverable_even_on_catchall():
    # Catch-all server with a real repo: config, HEAD and refs all have genuine
    # bodies -> full confirmation wins over the catch-all and reports HIGH.
    _patch({".git/config": "[core]\n\tbare = false\n",
            ".git/HEAD": "ref: refs/heads/main\n",
            "refs/heads/main": "0123456789abcdef0123456789abcdef01234567\n"},
           catchall_body="<html>spa</html>")
    findings, _, _ = CD.discover("https://example.test")
    git = next(f for f in findings if "Git" in f.title)
    assert git.title == "Exposed Git repository (recoverable)", git.title
    assert git.severity.value == "HIGH"


def test_severity_high_for_secrets():
    _patch({".env": "SECRET_KEY=abc\n"})
    findings, _, _ = CD.discover("https://example.test")
    env = next(f for f in findings if ".env file" in f.title)
    assert env.severity.value == "HIGH"


def test_new_candidate_paths_detected():
    _patch({".well-known/security.txt": "Contact: mailto:sec@example.test\nExpires: 2030-01-01T00:00:00.000Z\n",
            "config.json": '{"api_key": "abc123", "database": "prod"}\n',
            ".htaccess": "RewriteEngine On\nRequire all denied\n"})
    findings, paths, _ = CD.discover("https://example.test")
    titles = _titles(findings)
    assert any("security.txt" in t for t in titles), titles
    assert any("config.json" in t for t in titles), titles
    assert any(".htaccess" in t for t in titles), titles
    assert ".well-known/security.txt" in paths
    assert "config.json" in paths and ".htaccess" in paths


def test_new_candidate_signature_mismatch_dropped():
    # 200 with unrelated bodies (SPA shells) -> new paths must not fire.
    _patch({".well-known/security.txt": "<!doctype html><title>App</title>",
            "config.json": "<html>not json</html>",
            ".htaccess": "<html>single page app</html>"})
    findings, _, _ = CD.discover("https://example.test")
    assert findings == [], _titles(findings)


def test_backup_and_env_variants_detected():
    # .env backups + dumps/archives (zip/gzip magic) all report HIGH.
    _patch({".env.old": "DB_PASSWORD=hunter2\n",
            ".env.save": "APP_KEY=base64:xxxx\n",
            "db.sql": "CREATE TABLE users (id int);\nINSERT INTO users VALUES (1);\n",
            "backup.zip": "PK\x03\x04fake-zip-bytes",
            "site.tar.gz": "\x1f\ufffd\x08fake-gzip-stream"})  # gzip magic after UTF-8 'replace' decoding
    findings, paths, _ = CD.discover("https://example.test")
    titles = _titles(findings)
    assert any(".env.old" in t for t in titles), titles
    assert any(".env.save" in t for t in titles), titles
    assert any("db.sql" in t for t in titles), titles
    assert any("backup.zip" in t for t in titles), titles
    assert any("site.tar.gz" in t for t in titles), titles
    assert all(f.severity.value == "HIGH" for f in findings), titles
    assert "backup.zip" in paths and "site.tar.gz" in paths and "db.sql" in paths


def test_config_and_credential_leaks_detected():
    _patch({"config.php": "<?php\ndefine('DB_PASSWORD', 'x');\n",
            "settings.py": "SECRET_KEY = 'abc'\nDEBUG = True\n",
            "config.yaml": "database:\n  password: s3cret\n",
            "application.properties": "spring.datasource.password=s3cret\n",
            ".dockercfg": '{"https://index.docker.io/v1/": {"auth": "dXNlcjpwYXNz"}}',
            ".htpasswd": "admin:$apr1$xyz$abc\n"})
    findings, paths, _ = CD.discover("https://example.test")
    titles = _titles(findings)
    assert any("config.php" in t for t in titles), titles
    assert any("settings.py" in t for t in titles), titles
    assert any("config.yaml" in t for t in titles), titles
    assert any("application.properties" in t for t in titles), titles
    assert any(".dockercfg" in t for t in titles), titles
    assert any(".htpasswd" in t for t in titles), titles
    assert "settings.py" in paths and ".htpasswd" in paths


def test_vcs_and_ci_candidates_detected():
    _patch({".svn/entries": "10\n\ndir\nhttps://svn.example.test/repo\n",
            ".hg/store/00manifest.i": "\x00\x00\x00\x01\x00\x00\x00\x00revlog-data",
            ".bzr/README": "This is a Bazaar control directory.\n",
            ".gitlab-ci.yml": "stages:\n  - build\n  - deploy\n",
            "Jenkinsfile": "pipeline {\n  agent any\n  stages {\n    stage('build') {\n"})
    findings, paths, _ = CD.discover("https://example.test")
    titles = _titles(findings)
    assert any(".svn/entries" in t for t in titles), titles
    assert any("Mercurial repository store" in t for t in titles), titles
    assert any("Bazaar" in t for t in titles), titles
    assert any(".gitlab-ci.yml" in t for t in titles), titles
    assert any("Jenkinsfile" in t for t in titles), titles
    assert ".svn/entries" in paths and ".gitlab-ci.yml" in paths


def test_serverinfo_and_debug_candidates_detected():
    _patch({"nginx_status": "Active connections: 291 \nserver accepts handled requests\n",
            "metrics": "# HELP go_goroutines Number of goroutines\n# TYPE go_goroutines gauge\n",
            "api/v1/namespaces": '{"kind": "NamespaceList", "items": []}',
            "debug/vars": '{"cmdline": ["./app"], "memstats": {"Alloc": 1234}}',
            "debug/pprof/": "<html>/debug/pprof/<br>goroutine<br>heap</html>",
            "elmah.axd": "<html>Error log for / on web01 &mdash; ELMAH</html>",
            "console/": "<title>Interactive Console</title> __debugger__",
            "phpmyadmin/": "<title>phpMyAdmin</title>",
            "adminer.php": "<title>Login - Adminer</title>",
            "graphql": '{"errors": [{"message": "Must provide query string."}]}',
            "actuator/heapdump": "JAVA PROFILE 1.0.2, created ...",
            ".well-known/openid-configuration": '{"issuer": "https://idp.example.test"}'})
    findings, paths, _ = CD.discover("https://example.test")
    titles = _titles(findings)
    assert any("nginx" in t.lower() for t in titles), titles
    assert any("metrics" in t.lower() for t in titles), titles
    assert any("Kubernetes API" in t for t in titles), titles
    assert any("expvar" in t for t in titles), titles
    assert any("pprof" in t for t in titles), titles
    assert any("ELMAH" in t for t in titles), titles
    assert any("Werkzeug" in t for t in titles), titles
    assert any("phpMyAdmin" in t for t in titles), titles
    assert any("Adminer" in t for t in titles), titles
    assert any("GraphQL" in t for t in titles), titles
    assert any("heapdump" in t for t in titles), titles
    assert any("OpenID Connect" in t for t in titles), titles
    # k8s API and the werkzeug console are the dangerous ones here.
    k8s = next(f for f in findings if "Kubernetes" in f.title)
    assert k8s.severity.value == "HIGH"
    console = next(f for f in findings if "Werkzeug" in f.title)
    assert console.severity.value == "HIGH"
    assert "api/v1/namespaces" in paths and "console/" in paths


def test_change_password_endpoint_detected():
    # A real change-password form (current + new password) fires; a plain login
    # form with a single password field must not (see suppression test below).
    _patch({".well-known/change-password":
            '<html><form><input name="current-password">'
            '<input name="new-password"></form></html>'})
    findings, paths, _ = CD.discover("https://example.test")
    assert any("Change-password" in t for t in _titles(findings)), _titles(findings)
    assert ".well-known/change-password" in paths


def test_new_candidates_suppressed_on_catchall():
    # Catch-all login shell mentions "password" and JSON-ish text, but none of
    # the new tight signatures should bite.
    _patch({}, catchall_body='<html><form>Login <input type="password"></form>{"data": null}</html>')
    findings, _, _ = CD.discover("https://example.test")
    assert findings == [], _titles(findings)


def test_new_signatures_fire_even_on_catchall():
    # Catch-all server, but these two bodies genuinely match -> they still fire.
    _patch({"db.sql": "CREATE TABLE t (id int);\n",
            "api/v1/namespaces": '{"kind": "NamespaceList", "items": []}'},
           catchall_body="<html>spa</html>")
    findings, paths, _ = CD.discover("https://example.test")
    titles = _titles(findings)
    assert any("SQL database dump" in t for t in titles), titles
    assert any("Kubernetes API" in t for t in titles), titles
    assert "db.sql" in paths and "api/v1/namespaces" in paths


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
