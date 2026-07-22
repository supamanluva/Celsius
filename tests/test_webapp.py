"""Offline tests for the FastAPI backend (celsius/web/app.py) and the engine
plumbing it relies on (progress callback, cancellation).

No TestClient (httpx is not a dependency): endpoints are plain callables, so
they are invoked directly and HTTPException status codes are asserted. Jobs
still run through the real ThreadPoolExecutor with `run_scan` monkeypatched —
no network. Skips cleanly when the `web` extra is not installed so the
stdlib-only standalone loop stays green.

Run standalone:  python tests/test_webapp.py
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from fastapi import HTTPException
    from celsius.web import app as webapp
    HAVE_WEB = True
except ImportError:  # stdlib-only environment (CI stdlib job) — nothing to test
    HAVE_WEB = False

if HAVE_WEB:
    from celsius import __version__, engine
    from celsius.config import ScanConfig
    from celsius.models import ScanResult
    from celsius.plugins.base import Phase, Plugin
    from celsius.store import Store

    class _FakePlugin(Plugin):
        """Minimal engine-test plugin: records that it ran, does nothing else."""

        def __init__(self, pid: str, phase: "Phase", sink: list):
            self.id = pid
            self.title = f"title-{pid}"
            self.phase = phase
            self._sink = sink

        def run(self, ctx) -> None:
            self._sink.append(self.id)


# ---- helpers ------------------------------------------------------------------

def _fresh_store() -> "Store":
    tmp = tempfile.mkdtemp(prefix="celsius-webtest-")
    st = Store(os.path.join(tmp, "test.db"))
    webapp._store = st
    return st


def _scan_dict(target: str = "https://example.com") -> dict:
    return {
        "target": target, "url": target, "ip": "93.184.216.34",
        "services": [{"name": "nginx", "version": "1.25.4", "port": 443,
                      "protocol": "tcp", "product": None, "source": "http-header",
                      "extra": {}}],
        "cves": [{"id": "CVE-2024-0001", "severity": "HIGH", "cvss": 7.5,
                  "description": "demo", "url": "https://nvd.nist.gov/vuln/detail/CVE-2024-0001",
                  "published": None, "affects": "nginx 1.25.4 (port 443/tcp)",
                  "product": "nginx", "version": "1.25.4", "port": 443,
                  "references": [], "verified": False, "confidence": "firm",
                  "caveat": "", "exploitability": {}}],
        "findings": [{"title": "Missing HSTS", "severity": "MEDIUM",
                      "category": "headers", "description": "no hsts",
                      "recommendation": "add it", "evidence": "",
                      "confidence": "", "exploitability": {}}],
        "errors": [], "recon": {}, "chains": [], "coverage": {},
        "started_at": "2026-07-20 12:00:00Z", "finished_at": "2026-07-20 12:00:05Z",
    }


def _wait_done(job_id: str, timeout: float = 5.0) -> dict:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        st = webapp.scan_status(job_id)
        if st["status"] != "running":
            return st
        time.sleep(0.01)
    raise AssertionError(f"job {job_id} did not finish")


def _raises(fn, code: int) -> None:
    try:
        fn()
    except HTTPException as e:
        assert e.status_code == code, f"expected {code}, got {e.status_code}"
        return
    raise AssertionError(f"expected HTTPException {code}")


class _DummyAudit:
    """engine.AuditLog replacement — keeps tests out of the real audit log."""
    def scan_start(self, *a, **k): pass
    def scan_end(self, *a, **k): pass
    def skipped(self, *a, **k): pass
    def event(self, *a, **k): pass


def _engine_with_plugins(plugins: list) -> None:
    engine.all_plugins = lambda: plugins
    engine.AuditLog = _DummyAudit


# ---- engine plumbing ------------------------------------------------------------

def test_engine_reports_progress():
    ran: list = []
    _engine_with_plugins([_FakePlugin("a", Phase.RECON, ran),
                          _FakePlugin("b", Phase.DETECT, ran),
                          _FakePlugin("c", Phase.ENRICH, ran)])
    events: list = []
    engine.run_scan(ScanConfig(target="127.0.0.1"), progress=events.append)
    assert ran == ["a", "b", "c"]
    assert [e["index"] for e in events] == [1, 2, 3]
    assert all(e["total"] == 3 for e in events)
    assert events[0]["plugin"] == "title-a" and events[0]["phase"] == "recon"
    assert events[1]["phase"] == "detect" and events[2]["phase"] == "enrich"


def test_engine_progress_is_optional_and_crashproof():
    ran: list = []
    _engine_with_plugins([_FakePlugin("a", Phase.RECON, ran)])
    engine.run_scan(ScanConfig(target="127.0.0.1"))  # CLI path: no callback at all
    assert ran == ["a"]

    def boom(_info):
        raise RuntimeError("watcher exploded")
    ran.clear()
    engine.run_scan(ScanConfig(target="127.0.0.1"), progress=boom)
    assert ran == ["a"]  # a broken watcher must not stall the scan


def test_engine_cancel_aborts_between_plugins():
    ran: list = []
    _engine_with_plugins([_FakePlugin("a", Phase.RECON, ran),
                          _FakePlugin("b", Phase.DETECT, ran)])
    res = engine.run_scan(ScanConfig(target="127.0.0.1"),
                          cancelled=lambda: len(ran) >= 1)
    assert ran == ["a"]                       # second plugin never ran
    assert any("cancelled" in e for e in res.errors)
    assert res.finished_at


def test_engine_cancel_does_not_persist():
    ran: list = []
    _engine_with_plugins([_FakePlugin("a", Phase.RECON, ran)])
    st = _fresh_store()
    res = engine.run_scan(ScanConfig(target="127.0.0.1"), store=st,
                          cancelled=lambda: True)  # cancelled before plugin one
    assert ran == []
    assert st.list_scans() == []              # partial result discarded
    assert getattr(res, "scan_id", None) is None


# ---- web jobs: progress + cancel -------------------------------------------------

def _start_fake_job(fake_run_scan) -> str:
    webapp.run_scan = fake_run_scan
    return webapp.start_scan(webapp.ScanRequest(target="127.0.0.1", authorized=True))["job_id"]


def test_job_reports_progress_and_started_at():
    def fake(config, log=None, *, scope=None, store=None, progress=None, cancelled=None):
        assert callable(progress) and callable(cancelled)
        progress({"phase": "recon", "plugin": "Fake check", "index": 1, "total": 3})
        progress({"phase": "detect", "plugin": "Fake check 2", "index": 2, "total": 3})
        return ScanResult(target=config.target, started_at="s", finished_at="f")

    job_id = _start_fake_job(fake)
    st = _wait_done(job_id)
    assert st["status"] == "done"
    assert st["started_at"]                      # ISO timestamp for the UI clock
    p = st["progress"]
    assert p["index"] == 2 and p["total"] == 3 and p["phase"] == "detect"
    assert p["plugin"] == "Fake check 2"
    assert isinstance(p["elapsed"], (int, float)) and p["elapsed"] >= 0


def test_job_cancel_flow():
    def fake(config, log=None, *, scope=None, store=None, progress=None, cancelled=None):
        deadline = time.monotonic() + 5.0
        while not cancelled():
            if time.monotonic() > deadline:
                raise AssertionError("cancel flag never observed")
            time.sleep(0.01)
        return ScanResult(target=config.target)  # partial result — discarded

    job_id = _start_fake_job(fake)
    ack = webapp.cancel_scan(job_id)
    assert ack["status"] == "cancelling" and ack["job_id"] == job_id
    st = _wait_done(job_id)
    assert st["status"] == "cancelled"
    assert st["result"] is None


def test_job_cancel_unknown_or_finished():
    _raises(lambda: webapp.cancel_scan("no-such-job"), 404)

    def fake(config, log=None, **kw):
        return ScanResult(target=config.target)

    job_id = _start_fake_job(fake)
    assert _wait_done(job_id)["status"] == "done"
    _raises(lambda: webapp.cancel_scan(job_id), 409)  # safe no-op after completion


# ---- health -----------------------------------------------------------------------

def test_health():
    assert webapp.health() == {"status": "ok", "version": __version__}


# ---- export -------------------------------------------------------------------------

def _seed() -> tuple:
    st = _fresh_store()
    return st, st.save_scan(_scan_dict())


def test_export_json():
    _, sid = _seed()
    r = webapp.export_scan(sid, "json")
    assert r.media_type == "application/json"
    body = json.loads(r.body)
    assert body["target"] == "https://example.com" and body["cves"][0]["id"] == "CVE-2024-0001"
    disp = r.headers["content-disposition"]
    assert "attachment" in disp and disp.endswith('.json"')


def test_export_markdown():
    _, sid = _seed()
    r = webapp.export_scan(sid, "md")
    assert "text/markdown" in r.media_type
    text = r.body.decode()
    assert "# celsius report" in text and "CVE-2024-0001" in text and "Missing HSTS" in text


def test_export_sarif():
    _, sid = _seed()
    r = webapp.export_scan(sid, "sarif")
    assert r.media_type == "application/sarif+json"
    doc = json.loads(r.body)
    assert doc["version"] == "2.1.0"
    assert any(res["ruleId"] == "CVE-2024-0001" for res in doc["runs"][0]["results"])


def test_export_html():
    _, sid = _seed()
    r = webapp.export_scan(sid, "html")
    assert "text/html" in r.media_type
    assert b"CVE-2024-0001" in r.body and b"<" in r.body


def test_export_errors():
    _, sid = _seed()
    _raises(lambda: webapp.export_scan(sid, "pdf"), 400)
    _raises(lambda: webapp.export_scan("no-such-scan", "json"), 404)


# ---- history --------------------------------------------------------------------------

def test_history_substring_filter_case_insensitive():
    st = _fresh_store()
    st.save_scan(_scan_dict("https://Example.com"))
    st.save_scan(_scan_dict("https://sub.example.com"))
    st.save_scan(_scan_dict("https://other.org"))
    rows = webapp.list_scans(target="EXAMPLE")["scans"]
    assert len(rows) == 2
    assert all("example" in r["target"].lower() for r in rows)
    # LIKE wildcards in the query are escaped, not magic:
    assert webapp.list_scans(target="%")["scans"] == []
    assert webapp.list_scans(target="other.o_g")["scans"] == []
    # exact mode (temporal diff) still matches the whole string only:
    assert st.list_scans(target="example", exact=True) == []


def test_history_grade_and_score_stored():
    st = _fresh_store()
    st.save_scan(_scan_dict())
    row = webapp.list_scans()["scans"][0]
    assert row["grade"] in ("A+", "A", "B", "C", "D", "F")
    assert isinstance(row["score"], int) and 0 <= row["score"] <= 100
    # the seeded scan has a firm HIGH CVE -> grade capped at best C
    assert row["grade"] in ("C", "D", "F")


def test_history_pagination():
    st = _fresh_store()
    for i in range(5):
        st.save_scan(_scan_dict(f"https://host{i}.example.com"))
    page1 = webapp.list_scans(limit=2)["scans"]
    page2 = webapp.list_scans(limit=2, offset=2)["scans"]
    rest = webapp.list_scans(limit=2, offset=4)["scans"]
    assert len(page1) == 2 and len(page2) == 2 and len(rest) == 1
    ids = [r["id"] for r in page1 + page2 + rest]
    assert len(set(ids)) == 5  # pages don't overlap


def test_history_delete():
    st = _fresh_store()
    sid = st.save_scan(_scan_dict())
    assert webapp.delete_scan(sid) == {"deleted": sid}
    assert st.get_scan(sid) is None
    assert webapp.list_scans()["scans"] == []
    _raises(lambda: webapp.delete_scan(sid), 404)


# ---- code scan: upload + existing modes ------------------------------------------------

class _FakeUpload:
    def __init__(self, data: bytes):
        self._data = data
        self.filename = "snippet.py"

    async def read(self, n: int = -1) -> bytes:
        return self._data if n < 0 else self._data[:n]


class _FakeRequest:
    """Just enough of starlette.Request for the /api/code dispatcher."""
    def __init__(self, content_type: str, body=None, form=None):
        self.headers = {"content-type": content_type}
        self._body = body
        self._form = form

    async def json(self):
        if self._body is None:
            raise ValueError("no json")
        return self._body

    async def form(self):
        return self._form


def test_code_upload_multipart():
    orig = webapp.UploadFile
    webapp.UploadFile = _FakeUpload  # isinstance shim (restored by conftest)
    try:
        payload = b"import os\nos.system('id')\n"
        req = _FakeRequest("multipart/form-data; boundary=x",
                           form={"file": _FakeUpload(payload)})
        out = asyncio.run(webapp.code_scan(req))
        assert out["files_scanned"] >= 1 and isinstance(out["findings"], list)
    finally:
        webapp.UploadFile = orig


def test_code_upload_empty_and_oversize():
    _raises(lambda: webapp._scan_uploaded(b""), 400)
    _raises(lambda: webapp._scan_uploaded(b"x" * (webapp._MAX_UPLOAD + 1)), 413)


def test_code_json_modes_still_work():
    out = webapp._code_scan_request(webapp.CodeRequest(text="password = 'hunter2'\n"))
    assert isinstance(out["findings"], list)
    _raises(lambda: webapp._code_scan_request(webapp.CodeRequest()), 400)
    _raises(lambda: webapp._code_scan_request(
        webapp.CodeRequest(path="/etc/passwd")), 403)  # outside code root


def test_code_invalid_json_body():
    req = _FakeRequest("application/json", body=None)
    _raises(lambda: asyncio.run(webapp.code_scan(req)), 400)


# ---- AI status ---------------------------------------------------------------------------

def _env_patch(**vars):
    old = {k: os.environ.get(k) for k in vars}
    for k, v in vars.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v
    return old


def _env_restore(old):
    for k, v in old.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v


def test_ai_status_booleans_no_key_leak():
    old = _env_patch(DEEPSEEK_API_KEY="sk-super-secret-value",
                     OPENAI_API_KEY=None, ANTHROPIC_API_KEY=None, KIMI_API_KEY=None)
    orig = webapp._ollama_reachable
    webapp._ollama_reachable = lambda: False
    try:
        st = webapp.ai_status()
        assert st == {"providers": {"deepseek": True, "openai": False,
                                    "anthropic": False, "kimi": False,
                                    "local": False, "mock": True}}
        assert all(v is True or v is False for v in st["providers"].values())
        assert "sk-super-secret-value" not in json.dumps(st)  # never leak key material
    finally:
        webapp._ollama_reachable = orig
        _env_restore(old)


def test_ai_status_ollama_probe_cached():
    webapp._ollama_probe["at"] = 0.0
    webapp._ollama_probe["ok"] = False

    class _Sock:
        def __enter__(self): return self
        def __exit__(self, *a): return False

    orig = webapp.socket.create_connection
    try:
        calls = []
        webapp.socket.create_connection = lambda *a, **k: (calls.append(1), _Sock())[1]
        assert webapp._ollama_reachable() is True
        assert webapp._ollama_reachable() is True       # cached: no second probe
        assert len(calls) == 1

        def refuse(*a, **k):
            raise OSError("connection refused")
        webapp._ollama_probe["at"] = 0.0
        webapp.socket.create_connection = refuse
        assert webapp._ollama_reachable() is False
    finally:
        webapp.socket.create_connection = orig


if __name__ == "__main__":
    if not HAVE_WEB:
        print("SKIP: fastapi not installed (web extra) — 0 tests")
        sys.exit(0)
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
