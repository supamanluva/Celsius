"""Software-composition analysis: find known-vulnerable dependencies.

Parses dependency manifests / lockfiles in a project tree, then queries the
public OSV.dev database (no API key) for known vulnerabilities affecting the
exact pinned versions. Returns finding dicts shaped for codescan.CodeFinding.

Lockfiles (exact versions) are preferred; a bare package.json is used only as a
fallback and its range-stripped versions are flagged as approximate. Network is
required — errors are explicit, and successful partial results are retained.
"""

from __future__ import annotations

import concurrent.futures
import json
import os
import re
import urllib.error
import urllib.request

from .models import severity_rank
from dataclasses import dataclass

OSV_BATCH = "https://api.osv.dev/v1/querybatch"
OSV_VULN = "https://api.osv.dev/v1/vulns/"
USER_AGENT = "celsius/1.1 (+authorized dependency audit)"
TIMEOUT = 15
MAX_DEPS = 800           # cap queries on huge lockfiles
MAX_DETAIL_FETCH = 80    # cap per-vuln detail lookups
MAX_DETAIL_WORKERS = 8
MAX_QUERY_PAGES = 10     # bound follow-up pages for each dependency query

_SKIP_DIRS = {".git", "node_modules", "venv", ".venv", "__pycache__", "dist",
              "build", ".mypy_cache", ".pytest_cache", "vendor", ".idea", ".tox"}

_SEV = {"CRITICAL": "CRITICAL", "HIGH": "HIGH", "MODERATE": "MEDIUM",
        "MEDIUM": "MEDIUM", "LOW": "LOW", "MODERATE/LOW": "LOW"}


@dataclass(frozen=True)
class Dep:
    ecosystem: str   # OSV ecosystem: npm | PyPI | Packagist | RubyGems | Go | crates.io
    name: str
    version: str
    manifest: str    # relative path
    approximate: bool = False


# ---- version helpers ----------------------------------------------------------

def _clean(v: str) -> str:
    v = (v or "").strip().lstrip("vV=^~> <")
    v = v.split(",")[0].strip()
    m = re.match(r"\d+(?:\.\d+)*(?:[-+.][\w.]+)?", v)
    return m.group(0) if m else ""


# ---- manifest parsers ---------------------------------------------------------

def _parse_package_lock(path: str, rel: str) -> list[Dep]:
    out: list[Dep] = []
    try:
        data = json.load(open(path, encoding="utf-8"))
    except (OSError, ValueError):
        return out
    pkgs = data.get("packages")
    if isinstance(pkgs, dict):  # lockfile v2/v3
        for key, meta in pkgs.items():
            if not key or "node_modules/" not in key + "/":
                continue
            name = key.split("node_modules/")[-1]
            ver = (meta or {}).get("version")
            if name and ver:
                out.append(Dep("npm", name, ver, rel))
    def walk(deps):  # lockfile v1
        for name, meta in (deps or {}).items():
            ver = (meta or {}).get("version")
            if name and ver:
                out.append(Dep("npm", name, ver, rel))
            walk((meta or {}).get("dependencies"))
    if not pkgs:
        walk(data.get("dependencies"))
    return out


def _parse_package_json(path: str, rel: str) -> list[Dep]:
    out: list[Dep] = []
    try:
        data = json.load(open(path, encoding="utf-8"))
    except (OSError, ValueError):
        return out
    for section in ("dependencies", "devDependencies", "optionalDependencies"):
        for name, rng in (data.get(section) or {}).items():
            ver = _clean(rng)
            if name and ver and not str(rng).startswith(("http", "git", "file", "link", "workspace")):
                out.append(Dep("npm", name, ver, rel, approximate=True))
    return out


def _parse_requirements(path: str, rel: str) -> list[Dep]:
    out: list[Dep] = []
    try:
        lines = open(path, encoding="utf-8").read().splitlines()
    except OSError:
        return out
    for ln in lines:
        ln = ln.split("#")[0].strip()
        if not ln or ln.startswith("-") or "://" in ln:
            continue
        m = re.match(r"([A-Za-z0-9._-]+)\s*(\[[^\]]+\])?\s*([=~!<>]=?)\s*([\w.]+)", ln)
        if m:
            out.append(Dep("PyPI", m.group(1), _clean(m.group(4)), rel,
                           approximate=m.group(3) != "=="))
    return out


def _parse_pipfile_lock(path: str, rel: str) -> list[Dep]:
    out: list[Dep] = []
    try:
        data = json.load(open(path, encoding="utf-8"))
    except (OSError, ValueError):
        return out
    for section in ("default", "develop"):
        for name, meta in (data.get(section) or {}).items():
            ver = _clean((meta or {}).get("version", ""))
            if name and ver:
                out.append(Dep("PyPI", name, ver, rel))
    return out


def _parse_poetry_lock(path: str, rel: str) -> list[Dep]:
    out: list[Dep] = []
    try:
        text = open(path, encoding="utf-8").read()
    except OSError:
        return out
    for block in re.split(r"\[\[package\]\]", text)[1:]:
        nm = re.search(r'name\s*=\s*"([^"]+)"', block)
        vr = re.search(r'version\s*=\s*"([^"]+)"', block)
        if nm and vr:
            out.append(Dep("PyPI", nm.group(1), _clean(vr.group(1)), rel))
    return out


def _parse_composer_lock(path: str, rel: str) -> list[Dep]:
    out: list[Dep] = []
    try:
        data = json.load(open(path, encoding="utf-8"))
    except (OSError, ValueError):
        return out
    for section in ("packages", "packages-dev"):
        for pkg in (data.get(section) or []):
            name, ver = pkg.get("name"), _clean(pkg.get("version", ""))
            if name and ver:
                out.append(Dep("Packagist", name, ver, rel))
    return out


def _parse_gemfile_lock(path: str, rel: str) -> list[Dep]:
    out: list[Dep] = []
    try:
        lines = open(path, encoding="utf-8").read().splitlines()
    except OSError:
        return out
    in_specs = False
    for ln in lines:
        if re.match(r"\s*specs:\s*$", ln):
            in_specs = True
            continue
        if in_specs:
            m = re.match(r"\s{4}([A-Za-z0-9._-]+) \(([\w.]+)\)\s*$", ln)
            if m:
                out.append(Dep("RubyGems", m.group(1), _clean(m.group(2)), rel))
            elif ln and not ln.startswith(" "):
                in_specs = False
    return out


def _parse_go_mod(path: str, rel: str) -> list[Dep]:
    out: list[Dep] = []
    try:
        text = open(path, encoding="utf-8").read()
    except OSError:
        return out
    for m in re.finditer(r"^\s*(?:require\s+)?([\w./-]+\.[\w./-]+)\s+v([\w.\-+]+)",
                         text, re.M):
        ver = m.group(2)
        if "// indirect" not in m.group(0):
            out.append(Dep("Go", m.group(1), _clean("v" + ver), rel))
    return out


def _parse_cargo_lock(path: str, rel: str) -> list[Dep]:
    out: list[Dep] = []
    try:
        text = open(path, encoding="utf-8").read()
    except OSError:
        return out
    for block in re.split(r"\[\[package\]\]", text)[1:]:
        nm = re.search(r'name\s*=\s*"([^"]+)"', block)
        vr = re.search(r'version\s*=\s*"([^"]+)"', block)
        if nm and vr:
            out.append(Dep("crates.io", nm.group(1), _clean(vr.group(1)), rel))
    return out


# filename -> (parser, is_lockfile). Lockfiles win over loose manifests in a dir.
_MANIFESTS = [
    ("package-lock.json", _parse_package_lock, True),
    ("npm-shrinkwrap.json", _parse_package_lock, True),
    ("package.json", _parse_package_json, False),
    ("Pipfile.lock", _parse_pipfile_lock, True),
    ("poetry.lock", _parse_poetry_lock, True),
    ("requirements.txt", _parse_requirements, False),
    ("composer.lock", _parse_composer_lock, True),
    ("Gemfile.lock", _parse_gemfile_lock, True),
    ("go.mod", _parse_go_mod, False),
    ("Cargo.lock", _parse_cargo_lock, True),
]


def discover_deps(root: str) -> list[Dep]:
    """Find and parse dependency manifests under `root`. In each directory a
    lockfile suppresses the looser package.json/requirements.txt for npm/PyPI."""
    deps: dict[tuple, Dep] = {}
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        present = set(filenames)
        has_npm_lock = bool(present & {"package-lock.json", "npm-shrinkwrap.json"})
        has_py_lock = bool(present & {"Pipfile.lock", "poetry.lock"})
        for fname, parser, _is_lock in _MANIFESTS:
            if fname not in present:
                continue
            if fname == "package.json" and has_npm_lock:
                continue
            if fname == "requirements.txt" and has_py_lock:
                continue
            path = os.path.join(dirpath, fname)
            rel = os.path.relpath(path, root)
            for d in parser(path, rel):
                if d.name and d.version:
                    deps.setdefault((d.ecosystem, d.name, d.version), d)
            if len(deps) >= MAX_DEPS:
                return list(deps.values())[:MAX_DEPS]
    return list(deps.values())


# ---- OSV.dev queries ----------------------------------------------------------

def _post(url: str, payload: dict) -> dict:
    body = json.dumps(payload).encode()
    req = urllib.request.Request(url, data=body,
                                 headers={"User-Agent": USER_AGENT,
                                          "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
        return json.loads(resp.read().decode())


def _get(url: str) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
        return json.loads(resp.read().decode())


def _severity_of(vuln: dict) -> str:
    ds = (vuln.get("database_specific") or {}).get("severity")
    if ds and ds.upper() in _SEV:
        return _SEV[ds.upper()]
    for sev in vuln.get("severity") or []:
        score = str(sev.get("score", ""))
        m = re.search(r"/([\d.]+)$", score) or re.search(r"\b(\d+\.\d+)\b", score)
        if m:
            f = float(m.group(1))
            return ("CRITICAL" if f >= 9 else "HIGH" if f >= 7
                    else "MEDIUM" if f >= 4 else "LOW")
    return "MEDIUM"


def _fixed_versions(vuln: dict, name: str) -> list[str]:
    fixes: list[str] = []
    for aff in vuln.get("affected") or []:
        if (aff.get("package") or {}).get("name") != name:
            continue
        for rng in aff.get("ranges") or []:
            for ev in rng.get("events") or []:
                if ev.get("fixed"):
                    fixes.append(ev["fixed"])
    return sorted(set(fixes))




def scan_dependencies(root: str) -> tuple[list[dict], list[str]]:
    """Return (finding_dicts, errors). Finding dicts match codescan.CodeFinding."""
    root = os.path.abspath(root)
    if os.path.isfile(root):
        root = os.path.dirname(root)
    return audit_deps(discover_deps(root))


def audit_deps(deps: list[Dep]) -> tuple[list[dict], list[str]]:
    """Query OSV.dev for a list of Deps and return (finding_dicts, errors).

    Shared by manifest scanning (scan_dependencies) and client-side library
    auditing — anything that can name (ecosystem, package, version)."""
    if not deps:
        return [], []

    queries = [{"version": d.version, "package": {"name": d.name, "ecosystem": d.ecosystem}}
               for d in deps]
    vuln_ids_per_dep: list[list[str]] = [[] for _ in deps]
    query_issues: list[list[str]] = [[] for _ in deps]
    errors: list[str] = []

    def dep_label(d: Dep) -> str:
        return f"{d.ecosystem}:{d.name}@{d.version}"

    def add_result(index: int, result: dict) -> None:
        for vuln in result.get("vulns") or []:
            vid = vuln.get("id")
            if vid and vid not in vuln_ids_per_dep[index]:
                vuln_ids_per_dep[index].append(vid)

    def page_issue(index: int, issue: str, detail: str) -> None:
        query_issues[index].append(issue)
        errors.append(f"sca: OSV pagination for {dep_label(deps[index])}: {detail}; "
                      "results are incomplete")

    # Batch chunks are independent: a later failure must not discard earlier hits.
    for start in range(0, len(queries), 100):
        chunk = queries[start:start + 100]
        end = start + len(chunk)
        try:
            res = _post(OSV_BATCH, {"queries": chunk})
        except (urllib.error.URLError, OSError, ValueError) as e:
            errors.append(f"sca: OSV query failed for batch dependencies {start + 1}-{end} "
                          f"({e}); successful dependency results were retained")
            continue
        if not isinstance(res, dict) or not isinstance(res.get("results"), list):
            errors.append(f"sca: OSV query returned no valid results for batch dependencies "
                          f"{start + 1}-{end}; those dependencies were not assessed")
            continue
        results = res.get("results") or []
        if len(results) < len(chunk):
            errors.append(f"sca: OSV query returned {len(results)}/{len(chunk)} results for "
                          f"batch dependencies {start + 1}-{end}; missing results were not assessed")
        if len(results) > len(chunk):
            errors.append(f"sca: OSV query returned extra results for batch dependencies "
                          f"{start + 1}-{end}; extra results were ignored")

        for i, initial in enumerate(results[:len(chunk)]):
            index = start + i
            if not isinstance(initial, dict):
                page_issue(index, "query result missing", "invalid initial result")
                continue
            current = initial
            pages = 1
            seen_tokens: set[str] = set()
            while True:
                add_result(index, current)
                token = current.get("next_page_token") or ""
                if not token:
                    break
                if not isinstance(token, str):
                    page_issue(index, "invalid page token", "invalid next_page_token")
                    break
                if pages >= MAX_QUERY_PAGES:
                    page_issue(index, "page cap reached",
                               f"page cap {MAX_QUERY_PAGES} reached")
                    break
                if token in seen_tokens:
                    page_issue(index, "repeated page token", "repeated next_page_token")
                    break
                seen_tokens.add(token)
                page_query = dict(queries[index])
                page_query["page_token"] = token
                try:
                    page_res = _post(OSV_BATCH, {"queries": [page_query]})
                except (urllib.error.URLError, OSError, ValueError) as e:
                    page_issue(index, "later page failed",
                               f"page {pages + 1} failed ({e}); earlier results were retained")
                    break
                page_results = (page_res.get("results") or []) if isinstance(page_res, dict) else []
                if not page_results or not isinstance(page_results[0], dict):
                    page_issue(index, "later page missing",
                               f"page {pages + 1} returned no valid result")
                    break
                current = page_results[0]
                pages += 1

    unique_ids: list[str] = []
    seen_ids: set[str] = set()
    for ids in vuln_ids_per_dep:
        for vid in ids:
            if vid not in seen_ids:
                seen_ids.add(vid)
                unique_ids.append(vid)

    selected_ids = unique_ids[:MAX_DETAIL_FETCH]
    capped_ids = unique_ids[MAX_DETAIL_FETCH:]
    capped = set(capped_ids)
    if capped_ids:
        shown = ", ".join(capped_ids[:5])
        remaining = len(capped_ids) - 5
        suffix = f" (+{remaining} more)" if remaining > 0 else ""
        errors.append(f"sca: {len(capped_ids)} advisories not detailed "
                      f"(cap {MAX_DETAIL_FETCH}): {shown}{suffix}")

    details: dict[str, dict] = {}
    failed_details: set[str] = set()
    missing_details: set[str] = set()

    def fetch_detail(vid: str):
        try:
            return vid, _get(OSV_VULN + vid), None
        except (urllib.error.URLError, OSError, ValueError) as e:
            return vid, None, e

    if selected_ids:
        workers = min(MAX_DETAIL_WORKERS, len(selected_ids))
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
            for vid, data, error in ex.map(fetch_detail, selected_ids):
                if error is not None:
                    failed_details.add(vid)
                    errors.append(f"sca: OSV advisory detail failed for {vid} ({error}); "
                                  "affected findings are incomplete")
                elif not isinstance(data, dict) or not data:
                    missing_details.add(vid)
                    errors.append(f"sca: OSV advisory detail missing for {vid}; "
                                  "affected findings are incomplete")
                else:
                    details[vid] = data

    def compact_ids(ids: list[str]) -> str:
        shown = ", ".join(ids[:3])
        return shown + (f" (+{len(ids) - 3} more)" if len(ids) > 3 else "")

    findings: list[dict] = []
    for index, (d, ids) in enumerate(zip(deps, vuln_ids_per_dep)):
        if not ids:
            continue
        vulns = [details[i] for i in ids if i in details]
        sev = max((_severity_of(v) for v in vulns), default="MEDIUM",
                  key=lambda s: severity_rank(s))
        labels: list[str] = []
        for vid in ids:
            vuln = details.get(vid, {})
            cve = next((a for a in (vuln.get("aliases") or [])
                        if isinstance(a, str) and a.startswith("CVE-")), None)
            label = cve or vid
            if label not in labels:
                labels.append(label)
        fixed = sorted({fv for v in vulns for fv in _fixed_versions(v, d.name)})
        summary = next((v.get("summary") or v.get("details", "")[:120]
                        for v in vulns if v.get("summary") or v.get("details")), "")
        approx = " (version approximate — from a range, not a lockfile)" if d.approximate else ""
        rec = (f"Upgrade {d.name} to {', '.join(fixed)} or later."
               if fixed else f"Upgrade {d.name} to a patched release (see advisory).")

        status: list[str] = []
        if query_issues[index]:
            issues = list(dict.fromkeys(query_issues[index]))
            status.append(f"query incomplete ({', '.join(issues)})")
        failed = [vid for vid in ids if vid in failed_details]
        capped_for_dep = [vid for vid in ids if vid in capped]
        missing = [vid for vid in ids
                   if vid not in details and vid not in failed_details and vid not in capped]
        if failed:
            status.append(f"detail failed: {compact_ids(failed)}")
        if capped_for_dep:
            status.append(f"details not fetched (cap): {compact_ids(capped_for_dep)}")
        if missing:
            status.append(f"details missing: {compact_ids(missing)}")
        if status or query_issues[index]:
            rec += " Review all listed advisory IDs manually; OSV results or details are incomplete."

        evidence = f"{d.ecosystem}: {', '.join(labels[:6])}" + approx
        if status:
            evidence += " — " + "; ".join(status)
        if summary:
            evidence += f" — {summary}"
        findings.append({
            "title": f"Vulnerable dependency: {d.name}@{d.version} "
                     f"({len(ids)} known {'vulnerability' if len(ids) == 1 else 'vulnerabilities'})",
            "severity": sev, "category": "dependency",
            "file": d.manifest, "line": 0,
            "rule_id": labels[0] if labels else "OSV",
            "evidence": evidence[:300],
            "recommendation": rec,
        })
    return findings, errors
