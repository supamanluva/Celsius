"""Static code scanning: hardcoded secrets, risky-pattern (SAST-lite) checks,
and integration with external scanners (gitleaks / semgrep / trufflehog) when
installed.

Pure-stdlib by default. External tools, if present, are run and merged in.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from dataclasses import asdict, dataclass, field
from typing import Optional

from . import secrets as secret_rules
from .models import severity_rank

# ---- result types -------------------------------------------------------------

@dataclass
class CodeFinding:
    title: str
    severity: str
    category: str         # "secret" | "sast" | "gitleaks" | "semgrep" | "trufflehog"
    file: str
    line: int
    rule_id: str = ""
    evidence: str = ""
    recommendation: str = ""
    confidence: str = ""     # set by the AI reviewer; "" for deterministic rules

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class CodeScanResult:
    root: str
    findings: list[CodeFinding] = field(default_factory=list)
    files_scanned: int = 0
    errors: list[str] = field(default_factory=list)
    tools_used: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "root": self.root,
            "files_scanned": self.files_scanned,
            "tools_used": self.tools_used,
            "findings": [f.to_dict() for f in self.findings],
            "errors": self.errors,
        }


# ---- file walking -------------------------------------------------------------

_SKIP_DIRS = {".git", "node_modules", "venv", ".venv", "__pycache__", "dist",
              "build", ".mypy_cache", ".pytest_cache", "vendor", ".idea", ".tox"}
_SKIP_EXT = {".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".zip", ".gz",
             ".tar", ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".mp3", ".so",
             ".dll", ".class", ".jar", ".pyc", ".wasm", ".bin", ".lock"}
_MAX_BYTES = 2_000_000  # skip files larger than 2 MB


def _iter_files(root: str):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for name in filenames:
            ext = os.path.splitext(name)[1].lower()
            if ext in _SKIP_EXT:
                continue
            path = os.path.join(dirpath, name)
            try:
                if os.path.getsize(path) > _MAX_BYTES:
                    continue
            except OSError:
                continue
            yield path


# ---- SAST-lite patterns -------------------------------------------------------
# (id, title, severity, regex, recommendation, file-extension filter or None)
_SAST: list[tuple[str, str, str, re.Pattern, str, Optional[set]]] = [
    ("py-eval-exec", "Use of eval()/exec()", "HIGH",
     re.compile(r"\b(eval|exec)\s*\("), "Avoid eval/exec on dynamic input; use safe parsers.", {".py"}),
    ("py-os-system", "Shell command via os.system/popen", "HIGH",
     re.compile(r"\bos\.(system|popen)\s*\("), "Use subprocess with a list and shell=False.", {".py"}),
    ("py-subprocess-shell", "subprocess with shell=True", "HIGH",
     re.compile(r"subprocess\.[A-Za-z_]+\([^)]*shell\s*=\s*True"), "Pass args as a list and shell=False.", {".py"}),
    ("py-yaml-load", "Unsafe yaml.load", "HIGH",
     re.compile(r"\byaml\.load\s*\((?![^)]*Loader\s*=\s*yaml\.SafeLoader)"), "Use yaml.safe_load().", {".py"}),
    ("py-pickle", "Unpickling untrusted data", "MEDIUM",
     re.compile(r"\bpickle\.loads?\s*\("), "Pickle is unsafe on untrusted input; use JSON.", {".py"}),
    ("py-flask-debug", "Flask debug mode enabled", "MEDIUM",
     re.compile(r"app\.run\([^)]*debug\s*=\s*True"), "Disable debug in production.", {".py"}),
    ("py-django-debug", "Django DEBUG = True", "MEDIUM",
     re.compile(r"\bDEBUG\s*=\s*True"), "Set DEBUG=False in production.", {".py"}),
    ("tls-verify-off-py", "TLS verification disabled", "HIGH",
     re.compile(r"verify\s*=\s*False"), "Do not disable certificate verification.", {".py"}),
    ("tls-verify-off-js", "TLS verification disabled (Node)", "HIGH",
     re.compile(r"rejectUnauthorized\s*:\s*false"), "Do not set rejectUnauthorized:false.", {".js", ".ts", ".jsx", ".tsx"}),
    ("js-eval", "Use of eval() (JS)", "HIGH",
     re.compile(r"\beval\s*\("), "Avoid eval; use JSON.parse or safe alternatives.", {".js", ".ts", ".jsx", ".tsx"}),
    ("js-innerhtml", "Assignment to innerHTML", "MEDIUM",
     re.compile(r"\.innerHTML\s*="), "Use textContent or sanitize to avoid DOM XSS.", {".js", ".ts", ".jsx", ".tsx"}),
    ("js-document-write", "document.write()", "LOW",
     re.compile(r"\bdocument\.write\s*\("), "Avoid document.write; build DOM safely.", {".js", ".ts", ".html"}),
    ("js-child-exec", "child_process exec", "HIGH",
     re.compile(r"child_process[\s\S]{0,40}?\bexec\s*\("), "Use execFile with an args array; validate input.", {".js", ".ts"}),
    ("sql-concat", "Possible SQL injection (string concat)", "HIGH",
     re.compile(r"""(?i)(select|insert|update|delete)\s+.*?["'].*?\+\s*\w"""), "Use parameterized queries.", None),
    ("weak-hash", "Weak hash (MD5/SHA1)", "LOW",
     re.compile(r"\b(md5|sha1)\s*\(", re.I), "Use SHA-256+ / bcrypt/argon2 for passwords.", None),
    ("cors-wildcard", "CORS wildcard origin", "MEDIUM",
     re.compile(r"Access-Control-Allow-Origin['\"]?\s*[:,]\s*['\"]\*"), "Avoid '*' with credentials; allow-list origins.", None),
]


def _scan_file(path: str, root: str) -> list[CodeFinding]:
    rel = os.path.relpath(path, root)
    ext = os.path.splitext(path)[1].lower()
    try:
        with open(path, "r", errors="replace") as fh:
            lines = fh.readlines()
    except (OSError, UnicodeError):
        return []

    findings: list[CodeFinding] = []
    for i, line in enumerate(lines, start=1):
        if len(line) > 5000:
            line = line[:5000]
        # secrets
        for sm in secret_rules.scan_text(line):
            findings.append(CodeFinding(
                title=f"Secret: {sm.title}", severity=sm.severity, category="secret",
                file=rel, line=i, rule_id=sm.rule_id, evidence=sm.redacted,
                recommendation="Remove the secret from source, rotate it, and load from env/secret store.",
            ))
        # SAST
        for rid, title, sev, pat, rec, exts in _SAST:
            if exts and ext not in exts:
                continue
            if pat.search(line):
                findings.append(CodeFinding(
                    title=title, severity=sev, category="sast", file=rel, line=i,
                    rule_id=rid, evidence=line.strip()[:160], recommendation=rec,
                ))
    return findings


# ---- external tool integration -----------------------------------------------

def _run(cmd: list[str], timeout: int = 300) -> tuple[int, str, str]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
        return p.returncode, p.stdout, p.stderr
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
        return 1, "", str(e)


def _gitleaks(root: str) -> tuple[list[CodeFinding], Optional[str]]:
    if not shutil.which("gitleaks"):
        return [], None
    out_path = os.path.join(root, ".celsius-gitleaks.json")
    code, _o, err = _run(["gitleaks", "detect", "--no-git", "-s", root,
                          "--report-format", "json", "--report-path", out_path])
    findings: list[CodeFinding] = []
    try:
        if os.path.exists(out_path):
            data = json.load(open(out_path))
            for d in data:
                findings.append(CodeFinding(
                    title=f"[gitleaks] {d.get('RuleID', 'secret')}", severity="HIGH",
                    category="gitleaks", file=d.get("File", ""), line=d.get("StartLine", 0),
                    rule_id=d.get("RuleID", ""), evidence=secret_rules.redact(d.get("Secret", "")),
                    recommendation="Rotate the leaked secret and remove from history.",
                ))
            os.remove(out_path)
    except (json.JSONDecodeError, OSError):
        pass
    return findings, "gitleaks"


def _semgrep(root: str) -> tuple[list[CodeFinding], Optional[str]]:
    if not shutil.which("semgrep"):
        return [], None
    code, out, err = _run(["semgrep", "--config", "auto", "--json", "-q", root], timeout=600)
    findings: list[CodeFinding] = []
    try:
        data = json.loads(out or "{}")
        for r in data.get("results", []):
            sev = {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW"}.get(
                r.get("extra", {}).get("severity", "INFO"), "LOW")
            findings.append(CodeFinding(
                title=f"[semgrep] {r.get('check_id', '').split('.')[-1]}", severity=sev,
                category="semgrep", file=r.get("path", ""), line=r.get("start", {}).get("line", 0),
                rule_id=r.get("check_id", ""), evidence=r.get("extra", {}).get("message", "")[:160],
                recommendation=r.get("extra", {}).get("metadata", {}).get("fix", "") or "See semgrep rule.",
            ))
    except json.JSONDecodeError:
        pass
    return findings, "semgrep" if not err.strip() or findings else "semgrep"


def _trufflehog(root: str) -> tuple[list[CodeFinding], Optional[str]]:
    if not shutil.which("trufflehog"):
        return [], None
    code, out, err = _run(["trufflehog", "filesystem", root, "--json", "--no-update"], timeout=600)
    findings: list[CodeFinding] = []
    for line in out.splitlines():
        try:
            d = json.loads(line)
        except json.JSONDecodeError:
            continue
        src = d.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {})
        findings.append(CodeFinding(
            title=f"[trufflehog] {d.get('DetectorName', 'secret')}",
            severity="CRITICAL" if d.get("Verified") else "HIGH",
            category="trufflehog", file=src.get("file", ""), line=src.get("line", 0),
            rule_id=d.get("DetectorName", ""), evidence=secret_rules.redact(d.get("Raw", "")),
            recommendation="Rotate the secret; verified=" + str(d.get("Verified", False)),
        ))
    return findings, "trufflehog"


# ---- public API ---------------------------------------------------------------

def scan_path(root: str, *, use_external: bool = True, sca: bool = True) -> CodeScanResult:
    root = os.path.abspath(root)
    result = CodeScanResult(root=root, tools_used=["builtin"])
    if not os.path.exists(root):
        result.errors.append(f"path does not exist: {root}")
        return result

    if os.path.isfile(root):
        files = [root]
        base = os.path.dirname(root)
    else:
        files = list(_iter_files(root))
        base = root

    for path in files:
        result.findings.extend(_scan_file(path, base))
        result.files_scanned += 1

    if use_external:
        for fn in (_gitleaks, _semgrep, _trufflehog):
            try:
                ext_findings, tool = fn(base if os.path.isdir(root) else os.path.dirname(root))
                if tool and ext_findings is not None:
                    result.findings.extend(ext_findings)
                    if ext_findings or tool not in result.tools_used:
                        if tool not in result.tools_used:
                            result.tools_used.append(tool)
            except Exception as e:  # never let an optional tool break the scan
                result.errors.append(f"external scanner error: {e}")

    # Software-composition analysis: known-vulnerable dependencies (OSV.dev).
    if sca:
        try:
            from . import sca as sca_mod
            sca_findings, sca_errs = sca_mod.scan_dependencies(base if os.path.isdir(root) else root)
            result.findings.extend(CodeFinding(**f) for f in sca_findings)
            result.errors.extend(sca_errs)
            if "osv" not in result.tools_used:
                result.tools_used.append("osv")
        except Exception as e:
            result.errors.append(f"sca error: {e}")

    result.findings = _dedupe(result.findings)
    return result


def scan_text_blob(text: str, label: str = "input") -> CodeScanResult:
    """Scan a pasted snippet of code/text (no filesystem)."""
    result = CodeScanResult(root=label, tools_used=["builtin"])
    for i, line in enumerate(text.splitlines(), start=1):
        for sm in secret_rules.scan_text(line):
            result.findings.append(CodeFinding(
                title=f"Secret: {sm.title}", severity=sm.severity, category="secret",
                file=label, line=i, rule_id=sm.rule_id, evidence=sm.redacted,
                recommendation="Remove the secret; rotate it; load from env/secret store.",
            ))
        for rid, title, sev, pat, rec, exts in _SAST:
            if pat.search(line):
                result.findings.append(CodeFinding(
                    title=title, severity=sev, category="sast", file=label, line=i,
                    rule_id=rid, evidence=line.strip()[:160], recommendation=rec,
                ))
    result.files_scanned = 1
    result.findings = _dedupe(result.findings)
    return result




def _dedupe(findings: list[CodeFinding]) -> list[CodeFinding]:
    seen: set[tuple] = set()
    out: list[CodeFinding] = []
    for f in sorted(findings, key=lambda x: severity_rank(x.severity), reverse=True):
        key = (f.file, f.line, f.rule_id, f.title)
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out
