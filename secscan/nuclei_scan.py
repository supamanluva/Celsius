"""Optional nuclei wrapper for web-vulnerability templates.

nuclei is invoked with JSONL output (-jsonl) and parsed into Findings. If nuclei
is not installed we degrade gracefully (the caller checks is_available()).
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Optional

from .models import Finding, Severity

# nuclei is a Go binary; people often have it only under ~/go/bin.
_EXTRA_PATHS = [
    os.path.expanduser("~/go/bin/nuclei"),
    os.path.expanduser("~/.local/bin/nuclei"),
    "/usr/local/bin/nuclei",
    "/snap/bin/nuclei",
]

_SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
    "unknown": Severity.INFO,
}


def nuclei_path() -> Optional[str]:
    found = shutil.which("nuclei")
    if found:
        return found
    for p in _EXTRA_PATHS:
        if os.path.isfile(p) and os.access(p, os.X_OK):
            return p
    return None


def is_available() -> bool:
    return nuclei_path() is not None


def templates_installed() -> bool:
    """True if a nuclei templates directory exists and is non-empty.

    nuclei stores templates under (in priority) $NUCLEI_TEMPLATES_DIR,
    ~/nuclei-templates, or ~/.local/nuclei-templates.
    """
    candidates = [
        os.environ.get("NUCLEI_TEMPLATES_DIR", ""),
        os.path.expanduser("~/nuclei-templates"),
        os.path.expanduser("~/.local/nuclei-templates"),
    ]
    for d in candidates:
        if d and os.path.isdir(d):
            try:
                if any(name.endswith(".yaml") or os.path.isdir(os.path.join(d, name))
                       for name in os.listdir(d)):
                    return True
            except OSError:
                continue
    return False


def update_templates(path: Optional[str] = None, timeout: int = 600) -> tuple[bool, str]:
    """Run `nuclei -update-templates`. Returns (ok, message)."""
    path = path or nuclei_path()
    if not path:
        return False, "nuclei not found"
    try:
        proc = subprocess.run(
            [path, "-update-templates"],
            capture_output=True, text=True, timeout=timeout, check=False,
        )
    except subprocess.TimeoutExpired:
        return False, f"timed out after {timeout}s"
    if templates_installed() or proc.returncode == 0:
        return True, "templates installed"
    return False, (proc.stderr or proc.stdout or "unknown error").strip()[:300]


# A fast, high-signal default: tech/version detection, exposures, misconfigs,
# default logins, and known CVEs — skips the slow/noisy fuzzing & headless sets.
DEFAULT_TAGS = "cve,exposure,misconfig,tech,default-login,takeover"


def scan(
    url: str,
    *,
    severities: str = "critical,high,medium,low",
    tags: Optional[str] = DEFAULT_TAGS,
    rate_limit: int = 150,
    timeout: int = 600,
    extra_args: Optional[list[str]] = None,
) -> tuple[list[Finding], list[str]]:
    """Run nuclei against a URL. Returns (findings, errors).

    `tags` scopes the template set for speed; pass "" or None-via-full to run all.
    """
    path = nuclei_path()
    if not path:
        return [], ["nuclei not found"]

    errors: list[str] = []
    if not templates_installed():
        # First run after `go install` has no templates; nuclei won't fetch them
        # while update-checks are disabled, so install them once explicitly.
        ok, msg = update_templates(path)
        if not ok:
            return [], [f"nuclei has no templates and auto-install failed: {msg}. "
                        f"Run `{path} -update-templates` manually."]
        errors.append("nuclei: downloaded templates on first use")

    cmd = [
        path,
        "-target", url,
        "-jsonl",
        "-severity", severities,
        "-rate-limit", str(rate_limit),
        "-silent",
        "-disable-update-check",
    ]
    if tags:
        cmd += ["-tags", tags]
    if extra_args:
        cmd += extra_args

    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, check=False
        )
    except subprocess.TimeoutExpired:
        return [], errors + [f"nuclei timed out after {timeout}s"]

    findings: list[Finding] = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        findings.append(_to_finding(obj))

    if proc.returncode != 0 and not findings:
        stderr = proc.stderr.strip()
        if "no templates provided" in stderr.lower():
            errors.append("nuclei reported no templates even after install — run "
                          f"`{path} -update-templates` and retry.")
        elif stderr:
            errors.append(f"nuclei exited {proc.returncode}: {stderr[:300]}")
    return findings, errors


def _to_finding(obj: dict) -> Finding:
    info = obj.get("info", {})
    sev_raw = (info.get("severity") or "info").lower()
    severity = _SEVERITY_MAP.get(sev_raw, Severity.INFO)
    name = info.get("name") or obj.get("template-id", "nuclei finding")
    matched = obj.get("matched-at") or obj.get("host") or ""
    template_id = obj.get("template-id", "")
    desc = info.get("description") or ""
    refs = info.get("reference") or []
    ref_str = ""
    if isinstance(refs, list) and refs:
        ref_str = " | refs: " + ", ".join(refs[:3])
    return Finding(
        title=f"[nuclei] {name}",
        severity=severity,
        category="nuclei",
        description=(desc + ref_str).strip(),
        recommendation=f"Review template {template_id}; confirm and remediate.",
        evidence=f"matched: {matched}",
    )
