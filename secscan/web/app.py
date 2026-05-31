"""FastAPI backend for secscan.

Endpoints:
  GET  /                      single-page UI
  POST /api/scan              start a host/web scan job (requires authorized=true)
  GET  /api/scan/{job_id}     poll job status / log / result
  POST /api/code              static code/secret scan (path or pasted text)
  POST /api/poc               text-only reproduction steps for a finding/CVE

Scan jobs run in a thread pool; state is kept in-memory (single-process).
"""

from __future__ import annotations

import os
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Optional

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from .. import codescan, poc
from ..engine import ScanConfig, run_scan
from ..models import CVE, Finding, Severity
from ..store import Store

app = FastAPI(title="secscan", version="0.3.0")

_STATIC = os.path.join(os.path.dirname(__file__), "static")
_executor = ThreadPoolExecutor(max_workers=4)
_jobs: dict[str, dict[str, Any]] = {}
_jobs_lock = threading.Lock()
_store = Store()


# ---- request models -----------------------------------------------------------

class ScanRequest(BaseModel):
    target: str
    authorized: bool = False
    web: bool = True
    cve: bool = True
    web_secrets: bool = True
    ports: bool = False
    nuclei: bool = False
    top_ports: int = 100
    port_range: Optional[str] = None
    insecure: bool = False
    dns: bool = True
    tls: bool = True
    fingerprint: bool = True
    subdomains: bool = False
    crawl: bool = False
    api_discovery: bool = False
    cve_verify: bool = False
    ai: bool = False
    ai_provider: str = "deepseek"
    ai_model: Optional[str] = None
    ai_api_key: Optional[str] = None
    ai_redact: bool = False


class CodeRequest(BaseModel):
    path: Optional[str] = None
    text: Optional[str] = None
    use_external: bool = True


class PocRequest(BaseModel):
    kind: str                  # "finding" | "cve"
    data: dict
    url: Optional[str] = None


# ---- scan jobs ----------------------------------------------------------------

def _run_job(job_id: str, config: ScanConfig) -> None:
    def log(msg: str) -> None:
        with _jobs_lock:
            _jobs[job_id]["log"].append(msg)

    try:
        result = run_scan(config, log=log, store=_store)
        with _jobs_lock:
            _jobs[job_id]["status"] = "done"
            _jobs[job_id]["result"] = result.to_dict()
            _jobs[job_id]["scan_id"] = getattr(result, "scan_id", None)
    except Exception as e:  # surface failures to the UI instead of 500-ing silently
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

    job_id = uuid.uuid4().hex[:12]
    config = ScanConfig(
        target=req.target.strip(), web=req.web, cve=req.cve, web_secrets=req.web_secrets,
        ports=req.ports, nuclei=req.nuclei, top_ports=req.top_ports,
        port_range=req.port_range, insecure=req.insecure,
        dns=req.dns, tls=req.tls, fingerprint=req.fingerprint, subdomains=req.subdomains,
        crawl=req.crawl, api_discovery=req.api_discovery, cve_verify=req.cve_verify,
        ai=req.ai, ai_provider=req.ai_provider, ai_model=req.ai_model,
        ai_api_key=req.ai_api_key, ai_redact=req.ai_redact,
    )
    with _jobs_lock:
        _jobs[job_id] = {"status": "running", "log": [], "result": None, "error": None}
    _executor.submit(_run_job, job_id, config)
    return {"job_id": job_id}


@app.get("/api/scan/{job_id}")
def scan_status(job_id: str) -> dict:
    with _jobs_lock:
        job = _jobs.get(job_id)
        if not job:
            raise HTTPException(status_code=404, detail="Unknown job id.")
        return dict(job)


# ---- history ------------------------------------------------------------------

@app.get("/api/scans")
def list_scans(target: Optional[str] = None, limit: int = 50) -> dict:
    return {"scans": _store.list_scans(target=target, limit=limit)}


@app.get("/api/scans/{scan_id}")
def get_scan(scan_id: str) -> dict:
    result = _store.get_scan(scan_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Unknown scan id.")
    return result


# ---- code scan ----------------------------------------------------------------

@app.post("/api/code")
def code_scan(req: CodeRequest) -> dict:
    if req.text:
        return codescan.scan_text_blob(req.text).to_dict()
    if req.path:
        if not os.path.exists(req.path):
            raise HTTPException(status_code=400, detail=f"Path not found: {req.path}")
        return codescan.scan_path(req.path, use_external=req.use_external).to_dict()
    raise HTTPException(status_code=400, detail="Provide a 'path' or 'text'.")


# ---- proof-of-concept ---------------------------------------------------------

_SEV = {s.value: s for s in Severity}


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


# ---- frontend -----------------------------------------------------------------

@app.get("/")
def index() -> FileResponse:
    return FileResponse(os.path.join(_STATIC, "index.html"))


app.mount("/static", StaticFiles(directory=_STATIC), name="static")
