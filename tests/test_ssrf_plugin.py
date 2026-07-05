"""Integration test for the SsrfOob plugin: the OOB canary wired end-to-end
through a real ScanContext against a local target that fetches ?url= server-side.

Offline/deterministic: local vulnerable server + local canary, target pinned to
loopback so the callback is reachable. No network, no model.
"""

from __future__ import annotations

import http.server
import os
import sys
import threading
import time
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from celsius.audit import AuditLog  # noqa: E402
from celsius.config import ScanConfig  # noqa: E402
from celsius.models import ScanResult  # noqa: E402
from celsius.plugins.base import ScanContext  # noqa: E402
from celsius.plugins.builtin import SsrfOob  # noqa: E402
from celsius.scope import Scope  # noqa: E402
from celsius.targets import Target  # noqa: E402


def _vuln_server():
    class _H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_a):
            pass

        def do_GET(self):
            url = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query).get("url", [None])[0]
            if url and url.startswith("http"):
                try:
                    urllib.request.urlopen(url, timeout=2)   # SSRF: fetch attacker URL
                except Exception:
                    pass
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")

    srv = http.server.HTTPServer(("127.0.0.1", 0), _H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.1)
    return srv, srv.server_address[1]


def _ctx(config, host="127.0.0.1", url=None):
    return ScanContext(
        config=config,
        target=Target(raw=host, scheme="http", host=host, port=80, path="/"),
        result=ScanResult(target=host, url=url),
        scope=Scope.permissive_default(),
        audit=AuditLog(path="/tmp/celsius-ssrf-plugin-audit.log"),
    )


def _cfg(**kw):
    base = dict(target="127.0.0.1", allow_exploit=True, ssrf_oob=True,
                lab_attestation="I am authorized to actively test this target",
                oob_callback_host="127.0.0.1", persist=False)
    base.update(kw)
    return ScanConfig(**base)


def test_enabled_only_with_lab_and_ssrf():
    assert SsrfOob().enabled(_ctx(_cfg())) is True
    assert SsrfOob().enabled(_ctx(_cfg(allow_exploit=False))) is False
    assert SsrfOob().enabled(_ctx(_cfg(ssrf_oob=False))) is False


def test_confirms_ssrf_end_to_end():
    srv, port = _vuln_server()
    try:
        url = f"http://127.0.0.1:{port}/fetch?url=x"
        ctx = _ctx(_cfg(), url=url)
        SsrfOob().run(ctx)
        ssrf = [f for f in ctx.result.findings if "SSRF" in f.title]
        assert len(ssrf) == 1
        assert ssrf[0].exploitability["verdict"] == "confirmed-exploitable"
        rec = ctx.result.recon.get("ssrf_oob")
        assert rec and rec["confirmed"] == 1 and rec["callback_host"] == "127.0.0.1"
    finally:
        srv.shutdown()


def test_skips_when_callback_unreachable_from_remote_target():
    # loopback callback + a remote target -> guarded skip, no crash, no network.
    ctx = _ctx(_cfg(target="10.0.0.99"), host="10.0.0.99")
    SsrfOob().run(ctx)
    assert not ctx.result.findings
    assert any("loopback" in e for e in ctx.result.errors)


def test_dry_run_is_skipped():
    ctx = _ctx(_cfg(dry_run=True), url="http://127.0.0.1:1/fetch?url=x")
    SsrfOob().run(ctx)
    assert not ctx.result.findings
    assert any("dry-run" in e for e in ctx.result.errors)


def test_missing_attestation_is_skipped():
    ctx = _ctx(_cfg(lab_attestation=None), url="http://127.0.0.1:1/fetch?url=x")
    SsrfOob().run(ctx)
    assert not ctx.result.findings
    assert any("ssrf-oob: skipped" in e for e in ctx.result.errors)


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
