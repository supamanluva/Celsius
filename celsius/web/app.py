"""FastAPI backend for celsius.

Endpoints:
  GET  /                      single-page UI
  POST /api/scan              start a host/web scan job (requires authorized=true)
  GET  /api/scan/{job_id}     poll job status / log / progress / result
  DELETE /api/scan/{job_id}   request cancellation of a running job
  GET  /api/health            liveness probe (open — no token needed)
  GET  /api/scans             scan history (target substring filter, limit/offset)
  DELETE /api/scans/{id}      remove a scan from history
  GET  /api/scans/{id}/export.{fmt}  download a stored scan (json|md|sarif|html)
  POST /api/code              static code/secret scan (path, pasted text, or upload)
  POST /api/poc               text-only reproduction steps for a finding/CVE
  GET  /api/ai/status         which AI providers are configured (booleans only)
  GET  /api/testsites         curated authorized vulnerable test targets

Scan jobs run in a thread pool; state is kept in-memory (single-process).
"""

from __future__ import annotations

import hmac
import ipaddress
import json
import os
import socket
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from starlette.datastructures import UploadFile

from .. import __version__, codescan, grade, poc, report
from ..engine import ScanConfig, run_scan
from ..logsetup import get_logger, setup_logging
from ..models import CVE, Finding, ScanResult, Service, Severity
from ..plugins.base import Mode
from ..scope import Scope
from ..store import Store
from ..targets import parse_target
from ..timeutil import utcnow_iso

# Ensure scans launched from the web UI are traced to the persistent log file
# too (the per-job in-memory log only lives as long as the process).
setup_logging()
_log = get_logger("web")

app = FastAPI(title="Celsius (celsius)", version="0.3.0")

_STATIC = os.path.join(os.path.dirname(__file__), "static")
_executor = ThreadPoolExecutor(max_workers=4)
_jobs: dict[str, dict[str, Any]] = {}
_jobs_lock = threading.Lock()
_store = Store()

# ---- access control -----------------------------------------------------------
# When CELSIUS_TOKEN is set, every /api/* request must present it (header
# `X-Celsius-Token`, `Authorization: Bearer <token>`, or `?token=` for the
# report links opened directly in a browser tab). When unset, the API is open —
# fine for a loopback-only bind, but `celsius serve` auto-generates a token when
# binding to a non-loopback host so LAN exposure is never unauthenticated.
_TOKEN = os.environ.get("CELSIUS_TOKEN", "").strip()

_SEV = {s.value: s for s in Severity}

# /api/code may only read files under this root (defaults to the working dir).
# Without it, an authenticated caller could read arbitrary host files (e.g.
# /proc/self/environ, which holds the API keys).
_CODE_ROOT = os.path.realpath(os.environ.get("CELSIUS_CODE_ROOT", os.getcwd()))


def _presented_token(request: "Request") -> str:
    auth = request.headers.get("authorization", "")
    if auth[:7].lower() == "bearer ":
        return auth[7:].strip()
    return (request.headers.get("x-celsius-token")
            or request.query_params.get("token") or "").strip()


# Harmless, read-only public endpoints — exempt from the token gate so the UI's
# legal-target list and health probe work before a token is entered.
_OPEN_PATHS = {"/api/testsites", "/api/health"}


@app.middleware("http")
async def _require_token(request: "Request", call_next):
    path = request.url.path
    if _TOKEN and path.startswith("/api/") and path not in _OPEN_PATHS:
        if not hmac.compare_digest(_presented_token(request), _TOKEN):
            return JSONResponse(
                {"detail": "Missing or invalid access token (X-Celsius-Token)."},
                status_code=401)
    return await call_next(request)


def _within_code_root(path: str) -> bool:
    rp = os.path.realpath(path)
    return rp == _CODE_ROOT or rp.startswith(_CODE_ROOT + os.sep)


def _is_metadata_or_linklocal(host: str) -> bool:
    """Block cloud-metadata / link-local targets outright — there is never a
    legitimate reason to scan 169.254.169.254 et al., and it's the classic SSRF
    pivot. RFC1918/loopback are allowed (legitimate lab targets the operator
    explicitly entered and attested to)."""
    if host.lower() in ("metadata.google.internal", "metadata.goog"):
        return True
    try:
        return ipaddress.ip_address(host).is_link_local
    except ValueError:
        return False


# ---- request models -----------------------------------------------------------

class ScanRequest(BaseModel):
    target: str
    authorized: bool = False
    web: bool = True
    cve: bool = True
    web_secrets: bool = True
    ports: bool = False
    default_creds: bool = False
    nuclei: bool = False
    top_ports: int = 100
    port_range: Optional[str] = None
    udp: bool = False
    insecure: bool = False
    dns: bool = True
    tls: bool = True
    mailsec: bool = False
    fingerprint: bool = True
    subdomains: bool = False
    topology: bool = False
    crawl: bool = False
    api_discovery: bool = False
    cve_verify: bool = False
    # extended recon (opt-in)
    wayback: bool = False
    content_discovery: bool = False
    dynamic: bool = False
    os_detect: bool = False
    subdomain_bruteforce: bool = False
    nuclei_full: bool = False
    nuclei_tags: Optional[str] = None
    # lab-mode active exploitation (guardrailed — needs an attestation)
    allow_exploit: bool = False
    lab_attestation: Optional[str] = None
    dry_run: bool = False
    ai: bool = False
    ai_provider: str = "deepseek"
    ai_model: Optional[str] = None
    ai_base_url: Optional[str] = None
    ai_api_key: Optional[str] = None
    ai_redact: bool = True  # mask secrets before sending to the AI (default ON)
    ai_hunt: bool = True    # lab mode: AI hunt planner proposes hypotheses from recon
    # authenticated scan (optional) — attach a session and/or log in via a form
    auth_cookie: Optional[str] = None
    auth_bearer: Optional[str] = None
    auth_headers: Optional[list] = None      # ["X-Api-Key: ...", ...]
    login_url: Optional[str] = None
    login_user: Optional[str] = None
    login_pass: Optional[str] = None
    login_field_user: str = "username"
    login_field_pass: str = "password"
    login_data: Optional[str] = None


class CodeRequest(BaseModel):
    path: Optional[str] = None
    text: Optional[str] = None
    use_external: bool = True


class PocRequest(BaseModel):
    kind: str                  # "finding" | "cve"
    data: dict
    url: Optional[str] = None


# ---- scan jobs ----------------------------------------------------------------

def _run_job(job_id: str, config: ScanConfig, scope: "Optional[Scope]" = None,
             auth_params: "Optional[dict]" = None) -> None:
    t0 = time.monotonic()

    def log(msg: str) -> None:
        _log.info("[job %s] %s", job_id, msg)
        with _jobs_lock:
            _jobs[job_id]["log"].append(msg)

    def progress(info: dict) -> None:
        # Engine reports {phase, plugin, index, total} before each plugin runs;
        # stamp elapsed so the poller can render it without clock math.
        with _jobs_lock:
            job = _jobs.get(job_id)
            if job is not None:
                job["progress"] = {**info, "elapsed": round(time.monotonic() - t0, 2)}

    def cancelled() -> bool:
        with _jobs_lock:
            job = _jobs.get(job_id)
            return bool(job and job.get("cancel_requested"))

    # Authenticated scan: build the session here (form login does network I/O — keep
    # it off the request thread). Failures degrade to an unauthenticated scan.
    if auth_params and any(auth_params.get(k) for k in
                           ("cookie", "bearer", "headers", "login_url")):
        from .. import auth as auth_mod
        try:
            config.auth = auth_mod.build_session(**auth_params, log=log)
        except Exception as e:
            log(f"auth: failed to build session ({e}) — continuing unauthenticated")

    _log.info("[job %s] scan starting: target=%s", job_id, config.target)
    try:
        result = run_scan(config, log=log, store=_store, scope=scope,
                          progress=progress, cancelled=cancelled)
        if cancelled():
            # Engine aborted between plugins; the partial result is discarded
            # (never persisted — the engine skips the store on cancel).
            _log.info("[job %s] scan cancelled", job_id)
            with _jobs_lock:
                _jobs[job_id]["status"] = "cancelled"
            return
        for e in result.errors:
            _log.warning("[job %s] note/error: %s", job_id, e)
        d = result.to_dict()
        d["assessment"] = grade.assess(d)
        with _jobs_lock:
            _jobs[job_id]["status"] = "done"
            _jobs[job_id]["result"] = d
            _jobs[job_id]["scan_id"] = getattr(result, "scan_id", None)
    except Exception as e:  # surface failures to the UI instead of 500-ing silently
        _log.exception("[job %s] scan crashed", job_id)
        with _jobs_lock:
            _jobs[job_id]["status"] = "error"
            _jobs[job_id]["error"] = str(e)


@app.post("/api/scan")
def start_scan(req: ScanRequest) -> dict:
    if not req.authorized:
        raise HTTPException(status_code=403,
                            detail="You must confirm you are authorized to scan this target.")
    if not req.target.strip():
        raise HTTPException(status_code=400, detail="Target is required.")

    if _is_metadata_or_linklocal(parse_target(req.target.strip()).host):
        raise HTTPException(
            status_code=400,
            detail="Refusing to scan a link-local / cloud-metadata address.")

    # Lab mode (active exploitation) is permissive-scope-blocked by default; it
    # needs an attestation and an explicit scope authorizing EXPLOIT for the host.
    scope: Optional[Scope] = None
    if req.allow_exploit:
        if len((req.lab_attestation or "").strip()) < 10:
            raise HTTPException(
                status_code=400,
                detail="Lab mode requires a meaningful authorization attestation (≥10 characters).")
        host = parse_target(req.target.strip()).host.lower()
        scope = Scope(targets={host: {Mode.PASSIVE.value, Mode.SAFE_ACTIVE.value,
                                      Mode.EXPLOIT.value}})

    job_id = uuid.uuid4().hex[:12]
    config = ScanConfig(
        target=req.target.strip(), web=req.web, cve=req.cve, web_secrets=req.web_secrets,
        ports=req.ports, default_creds=req.default_creds, nuclei=req.nuclei, nuclei_full=req.nuclei_full,
        nuclei_tags=req.nuclei_tags, top_ports=req.top_ports,
        port_range=req.port_range, udp=req.udp, insecure=req.insecure, os_detect=req.os_detect,
        nvd_api_key=os.environ.get("NVD_API_KEY"),   # faster NVD CVE lookups (6s -> 0.8s/req)
        dns=req.dns, tls=req.tls, mailsec=req.mailsec,
        fingerprint=req.fingerprint, subdomains=req.subdomains, topology=req.topology,
        subdomain_bruteforce=req.subdomain_bruteforce, wayback=req.wayback,
        crawl=req.crawl, api_discovery=req.api_discovery, content_discovery=req.content_discovery,
        dynamic=req.dynamic, cve_verify=req.cve_verify,
        allow_exploit=req.allow_exploit, lab_attestation=req.lab_attestation, dry_run=req.dry_run,
        ai=req.ai, ai_provider=req.ai_provider, ai_model=req.ai_model,
        ai_base_url=req.ai_base_url, ai_api_key=req.ai_api_key, ai_redact=req.ai_redact,
        ai_hunt=req.ai_hunt,
    )
    auth_params = {
        "cookie": req.auth_cookie or "", "bearer": req.auth_bearer or "",
        "headers": req.auth_headers or [], "login_url": req.login_url or "",
        "login_data": req.login_data or "", "login_user": req.login_user or "",
        "login_pass": req.login_pass or "",
        "login_field_user": req.login_field_user or "username",
        "login_field_pass": req.login_field_pass or "password",
        "insecure": req.insecure,
    }
    with _jobs_lock:
        _jobs[job_id] = {"status": "running", "log": [], "result": None, "error": None,
                         "started_at": utcnow_iso(), "progress": None,
                         "cancel_requested": False}
    _executor.submit(_run_job, job_id, config, scope, auth_params)
    return {"job_id": job_id}


@app.get("/api/scan/{job_id}")
def scan_status(job_id: str) -> dict:
    with _jobs_lock:
        job = _jobs.get(job_id)
        if not job:
            raise HTTPException(status_code=404, detail="Unknown job id.")
        return dict(job)


@app.delete("/api/scan/{job_id}")
def cancel_scan(job_id: str) -> dict:
    """Ask a running job to stop; the engine honors it between plugins."""
    with _jobs_lock:
        job = _jobs.get(job_id)
        if not job:
            raise HTTPException(status_code=404, detail="Unknown job id.")
        if job["status"] != "running":
            raise HTTPException(status_code=409,
                                detail=f"Job already {job['status']}.")
        job["cancel_requested"] = True
    return {"job_id": job_id, "status": "cancelling"}


@app.get("/api/health")
def health() -> dict:
    return {"status": "ok", "version": __version__}


# ---- history ------------------------------------------------------------------

@app.get("/api/scans")
def list_scans(target: Optional[str] = None, limit: int = 50, offset: int = 0) -> dict:
    # target is a case-insensitive substring filter (store escapes LIKE wildcards).
    return {"scans": _store.list_scans(target=target, limit=limit, offset=offset)}


@app.get("/api/scans/{scan_id}")
def get_scan(scan_id: str) -> dict:
    result = _store.get_scan(scan_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Unknown scan id.")
    result.setdefault("assessment", grade.assess(result))
    return result


@app.delete("/api/scans/{scan_id}")
def delete_scan(scan_id: str) -> dict:
    if not _store.delete_scan(scan_id):
        raise HTTPException(status_code=404, detail="Unknown scan id.")
    return {"deleted": scan_id}


_EXPORT_MIME = {
    "json": "application/json",
    "md": "text/markdown; charset=utf-8",
    "sarif": "application/sarif+json",
    "html": "text/html; charset=utf-8",
}


@app.get("/api/scans/{scan_id}/export.{fmt}")
def export_scan(scan_id: str, fmt: str) -> Response:
    """Download a stored scan as json / md / sarif / html (always an attachment)."""
    fmt = fmt.lower()
    if fmt not in _EXPORT_MIME:
        raise HTTPException(status_code=400,
                            detail=f"Unknown export format '{fmt}' (json|md|sarif|html).")
    result = _store.get_scan(scan_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Unknown scan id.")
    fname = f"celsius-{_safe_name(result.get('target', scan_id))}.{fmt}"
    return Response(
        content=_render_export(result, fmt),
        media_type=_EXPORT_MIME[fmt],
        headers={"Content-Disposition": f'attachment; filename="{fname}"'},
    )


def _render_export(data: dict, fmt: str) -> str:
    if fmt == "json":
        return json.dumps(data, indent=2)
    if fmt == "html":
        return report.html_report(data)
    # md/sarif writers take a ScanResult and a path: rebuild the dataclasses
    # and render into a temp file, then read it back.
    import tempfile

    result = _result_from_dict(data)
    fd, path = tempfile.mkstemp(suffix=f".{fmt}")
    os.close(fd)
    try:
        if fmt == "md":
            report.write_markdown(result, path)
        else:
            report.write_sarif(result, path)
        with open(path) as fh:
            return fh.read()
    finally:
        os.unlink(path)


def _result_from_dict(d: dict) -> ScanResult:
    """Rebuild a ScanResult from its to_dict() form (a stored scan)."""
    r = ScanResult(target=d.get("target", ""), url=d.get("url"), ip=d.get("ip"),
                   errors=list(d.get("errors", [])), recon=d.get("recon", {}),
                   chains=d.get("chains", []), coverage=d.get("coverage", {}),
                   started_at=d.get("started_at", ""), finished_at=d.get("finished_at", ""))
    r.services = [Service(**s) for s in d.get("services", [])]
    for c in d.get("cves", []):
        kw = dict(c)
        kw["severity"] = _SEV.get(str(kw.get("severity", "INFO")).upper(), Severity.INFO)
        r.cves.append(CVE(**kw))
    for f in d.get("findings", []):
        kw = dict(f)
        kw["severity"] = _SEV.get(str(kw.get("severity", "INFO")).upper(), Severity.INFO)
        r.findings.append(Finding(**kw))
    return r


def _safe_name(s: str) -> str:
    keep = "".join(ch if ch.isalnum() or ch in "-._" else "-" for ch in (s or "report"))
    return keep.strip("-") or "report"


@app.get("/api/scans/{scan_id}/report.html")
def scan_report(scan_id: str, download: bool = False) -> HTMLResponse:
    result = _store.get_scan(scan_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Unknown scan id.")
    fname = f"celsius-{_safe_name(result.get('target', scan_id))}.html"
    disp = "attachment" if download else "inline"   # ?download=1 forces a save
    return HTMLResponse(
        report.html_report(result),
        headers={"Content-Disposition": f'{disp}; filename="{fname}"'},
    )


@app.get("/api/domain/{domain}/report.html")
def domain_report(domain: str, download: bool = False) -> HTMLResponse:
    """Aggregate rollup across the latest stored scan per host for a domain."""
    scans = _store.scans_for_domain(domain)
    fname = f"celsius-{_safe_name(domain)}-domain.html"
    disp = "attachment" if download else "inline"   # ?download=1 forces a save
    return HTMLResponse(
        report.domain_rollup_html(domain, scans),
        headers={"Content-Disposition": f'{disp}; filename="{fname}"'},
    )


@app.get("/api/domain/{domain}/report.zip")
def domain_report_zip(domain: str) -> Response:
    """One ZIP for the whole domain: the aggregate overview + a per-host HTML report
    for every scanned subdomain."""
    import io
    import zipfile

    scans = _store.scans_for_domain(domain)
    if not scans:
        raise HTTPException(status_code=404, detail=f"No stored scans for {domain}.")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("00-domain-overview.html", report.domain_rollup_html(domain, scans))
        used: set = set()
        for s in scans:
            try:
                host = parse_target(s.get("url") or s.get("target") or "host").host or "host"
            except Exception:
                host = "host"
            name = _safe_name(host)
            fn, i = f"{name}.html", 2
            while fn in used:
                fn, i = f"{name}-{i}.html", i + 1
            used.add(fn)
            z.writestr(fn, report.html_report(s))
    fname = f"celsius-{_safe_name(domain)}-bundle.zip"
    return Response(content=buf.getvalue(), media_type="application/zip",
                    headers={"Content-Disposition": f'attachment; filename="{fname}"'})


# ---- email security -----------------------------------------------------------

class MailSecRequest(BaseModel):
    domain: str


@app.post("/api/mailsec")
def mailsec_check(req: MailSecRequest) -> dict:
    from ..recon import mailsec
    domain = (req.domain or "").strip()
    if not domain:
        raise HTTPException(status_code=400, detail="Enter a domain.")
    # tolerate a pasted URL or email address
    if "@" in domain:
        domain = domain.split("@", 1)[1]
    if "://" in domain:
        domain = domain.split("://", 1)[1]
    domain = domain.split("/")[0].strip()
    _log.info("mailsec check: %s", domain)
    info, findings, errors = mailsec.analyze(domain)
    info["findings"] = [f.to_dict() for f in findings]
    info["errors"] = errors
    return info


@app.get("/api/mailsec/report.html")
def mailsec_report(domain: str = "", download: bool = False) -> HTMLResponse:
    from ..recon import mailsec
    domain = (domain or "").strip()
    if "@" in domain:
        domain = domain.split("@", 1)[1]
    if "://" in domain:
        domain = domain.split("://", 1)[1]
    domain = domain.split("/")[0].strip()
    if not domain:
        raise HTTPException(status_code=400, detail="Enter a domain.")
    info, _findings, _errors = mailsec.analyze(domain)
    fname = f"celsius-mail-{_safe_name(domain)}.html"
    disp = "attachment" if download else "inline"   # ?download=1 forces a save
    return HTMLResponse(
        report.mailsec_html_report(info),
        headers={"Content-Disposition": f'{disp}; filename="{fname}"'},
    )


# ---- code scan ----------------------------------------------------------------

# Uploaded files are read fully in memory and scanned as text — never persisted.
_MAX_UPLOAD = 2 * 1024 * 1024


@app.post("/api/code")
async def code_scan(request: Request) -> dict:
    """Three input modes: JSON {"path": ...} (server-side, code-root restricted),
    JSON {"text": ...} (pasted code), or multipart/form-data file upload."""
    if request.headers.get("content-type", "").startswith("multipart/form-data"):
        form = await request.form()
        upload = form.get("file")
        if not isinstance(upload, UploadFile):
            raise HTTPException(status_code=400,
                                detail="Multipart request needs a 'file' field.")
        return _scan_uploaded(await upload.read(_MAX_UPLOAD + 1))
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body.") from None
    try:
        req = CodeRequest(**body)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid code-scan request.") from None
    return _code_scan_request(req)


def _scan_uploaded(data: bytes) -> dict:
    if not data:
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")
    if len(data) > _MAX_UPLOAD:
        raise HTTPException(status_code=413,
                            detail=f"Upload too large (max {_MAX_UPLOAD // (1024 * 1024)} MB).")
    return codescan.scan_text_blob(data.decode("utf-8", errors="replace")).to_dict()


def _code_scan_request(req: CodeRequest) -> dict:
    if req.text:
        return codescan.scan_text_blob(req.text).to_dict()
    if req.path:
        if not _within_code_root(req.path):
            raise HTTPException(
                status_code=403,
                detail="Path is outside the allowed code root "
                       "(set CELSIUS_CODE_ROOT to scan elsewhere).")
        if not os.path.exists(req.path):
            raise HTTPException(status_code=400, detail=f"Path not found: {req.path}")
        return codescan.scan_path(req.path, use_external=req.use_external).to_dict()
    raise HTTPException(status_code=400, detail="Provide a 'path' or 'text'.")


# ---- AI status ----------------------------------------------------------------

# Booleans only — the presence of a key is reported, never its value.
_AI_ENV = {"deepseek": "DEEPSEEK_API_KEY", "openai": "OPENAI_API_KEY",
           "anthropic": "ANTHROPIC_API_KEY", "kimi": "KIMI_API_KEY"}
_ollama_probe: dict[str, Any] = {"at": 0.0, "ok": False}


def _ollama_reachable() -> bool:
    """Is a local Ollama likely up? Cheap probe (0.5s connect, 30s cache) so the
    status endpoint never blocks meaningfully, and it can never raise."""
    now = time.monotonic()
    if now - _ollama_probe["at"] < 30.0:
        return bool(_ollama_probe["ok"])
    try:
        with socket.create_connection(("127.0.0.1", 11434), timeout=0.5):
            ok = True
    except OSError:
        ok = False
    _ollama_probe["at"] = now
    _ollama_probe["ok"] = ok
    return ok


@app.get("/api/ai/status")
def ai_status() -> dict:
    providers = {name: bool(os.environ.get(env, "").strip())
                 for name, env in _AI_ENV.items()}
    # kimi is also configured via the MOONSHOT_API_KEY fallback env var.
    providers["kimi"] = bool(providers["kimi"]
                             or os.environ.get("MOONSHOT_API_KEY", "").strip())
    return {"providers": {
        **providers,
        "local": _ollama_reachable(),
        "mock": True,  # always available — needs nothing
    }}


# ---- proof-of-concept ---------------------------------------------------------


@app.post("/api/poc")
def make_poc(req: PocRequest) -> dict:
    d = req.data
    if req.kind == "cve":
        cve = CVE(
            id=d.get("id", "CVE-?"), severity=_SEV.get(d.get("severity", "INFO"), Severity.INFO),
            cvss=d.get("cvss"), description=d.get("description", ""),
            url=d.get("url", ""), affects=d.get("affects", ""),
            references=d.get("references", []),
        )
        return poc.poc_for_cve(cve)
    if req.kind == "finding":
        finding = Finding(
            title=d.get("title", ""), severity=_SEV.get(d.get("severity", "INFO"), Severity.INFO),
            category=d.get("category", ""), description=d.get("description", ""),
        )
        return poc.poc_for_finding(finding, req.url or "<URL>")
    raise HTTPException(status_code=400, detail="kind must be 'finding' or 'cve'.")


@app.get("/api/testsites")
def list_testsites() -> dict:
    """Curated authorized vulnerable test targets to practise against legally."""
    from .. import testsites
    return {"groups": testsites.groups(), "note": testsites.NOTE}


# ---- frontend -----------------------------------------------------------------

@app.get("/")
def index() -> FileResponse:
    return FileResponse(os.path.join(_STATIC, "index.html"))


app.mount("/static", StaticFiles(directory=_STATIC), name="static")
