"""API discovery: OpenAPI/Swagger documents and GraphQL introspection.

These are safe-active checks: we request a small set of well-known doc paths and
send one benign GraphQL introspection query. Nothing is mutated.

Beyond *finding* an API we also map its risk surface — read-only and heuristic:

  * GraphQL introspection is parsed for its query/mutation FIELDS, and field
    names/arguments are matched against patterns that commonly indicate
    arbitrary file read / path traversal (e.g. ``getFile(name)``) or SSRF
    (e.g. ``getWebsiteSeoScore(url)``). These are flagged for manual
    verification — we never invoke the operations.
  * Discovered endpoint paths (OpenAPI + anything the crawler surfaced) are
    scanned for object-identifier patterns (``/users/{id}``, ``/orders/42``)
    that are the classic place broken object-level authorization (BOLA/IDOR,
    OWASP API #1) lives. We list them as a surface to test by hand — confirming
    BOLA needs two identities and is out of scope for passive recon.
"""

from __future__ import annotations

import json
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request

from ..models import Finding, Severity

USER_AGENT = "celsius/0.5 (+authorized security testing)"
TIMEOUT = 8

_OPENAPI_PATHS = [
    "/openapi.json", "/swagger.json", "/v2/api-docs", "/v3/api-docs",
    "/swagger/v1/swagger.json", "/api-docs", "/api/swagger.json",
    "/.well-known/openapi.json", "/swagger/ui", "/api/v1/openapi.json",
]
_GRAPHQL_PATHS = ["/graphql", "/api/graphql", "/v1/graphql", "/query"]

# Field-level introspection: roots + their fields and argument names. Falls back
# gracefully if a server allows type introspection but strips field details.
_INTROSPECTION = json.dumps({"query":
    "{__schema{queryType{name fields{name args{name}}}"
    "mutationType{name fields{name args{name}}}types{name}}}"})

# Heuristics over GraphQL field + argument names. A match is a *candidate*, not a
# confirmed bug — we surface it for manual verification, never invoke it.
_RISK_FILE = re.compile(
    r"file|attachment|document|download|template|content|invoice|report|avatar|"
    r"image|photo|asset|path|filename|backup|log", re.I)
_RISK_SSRF = re.compile(
    r"url|uri|link|website|fetch|proxy|webhook|callback|redirect|screenshot|"
    r"render|seo|preview|import|crawl|remote", re.I)

# Object-identifier patterns in endpoint paths -> classic BOLA/IDOR surface.
_ID_CONCRETE = re.compile(r"/[A-Za-z][\w-]*/(\d+)(?=[/?#]|$)")          # /users/42
_ID_TEMPLATE = re.compile(r"\{[^}]*(?:id|key|uuid|guid|no|num|slug)[^}]*\}", re.I)  # /users/{userId}
_ID_COLON = re.compile(r"/:[\w]*(?:id|key)\b", re.I)                    # /users/:id


def _get(url: str, insecure: bool, auth=None) -> tuple[int, str]:
    ctx = ssl.create_default_context()
    if insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    hdrs = auth.merge({"User-Agent": USER_AGENT}) if auth else {"User-Agent": USER_AGENT}
    req = urllib.request.Request(url, headers=hdrs)
    with urllib.request.urlopen(req, timeout=TIMEOUT, context=ctx) as resp:
        return resp.status, resp.read(400_000).decode("utf-8", errors="replace")


def _post_json(url: str, body: str, insecure: bool, auth=None) -> tuple[int, str]:
    ctx = ssl.create_default_context()
    if insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    base = {"User-Agent": USER_AGENT, "Content-Type": "application/json"}
    hdrs = auth.merge(base) if auth else base
    req = urllib.request.Request(url, data=body.encode(), headers=hdrs, method="POST")
    with urllib.request.urlopen(req, timeout=TIMEOUT, context=ctx) as resp:
        return resp.status, resp.read(400_000).decode("utf-8", errors="replace")


# ---- GraphQL schema analysis --------------------------------------------------

def _parse_operations(schema: dict) -> list[dict]:
    """Flatten the query/mutation root fields into [{name, kind, args:[...]}]."""
    ops: list[dict] = []
    for root, kind in (("queryType", "query"), ("mutationType", "mutation")):
        node = schema.get(root) or {}
        for f in (node.get("fields") or []):
            ops.append({
                "name": f.get("name", ""),
                "kind": kind,
                "args": [a.get("name", "") for a in (f.get("args") or [])],
            })
    return ops


def _graphql_risky(ops: list[dict], url: str) -> list[Finding]:
    """Flag query/mutation fields whose name or args suggest file read / SSRF."""
    findings: list[Finding] = []
    for op in ops:
        haystack = " ".join([op["name"], *op["args"]])
        sig = f'{op["name"]}({", ".join(op["args"])})'
        if op["args"] and _RISK_FILE.search(haystack):
            findings.append(Finding(
                title=f"GraphQL field may allow arbitrary file read: {op['name']}",
                severity=Severity.MEDIUM, category="api-discovery",
                description=(f"The {op['kind']} field `{sig}` at {url} takes a name/path "
                             "argument and returns content — a common arbitrary-file-read / "
                             "path-traversal pattern. Not invoked by this scan."),
                recommendation=("Verify manually (authorized targets only): request the field "
                                "with a traversal payload and confirm files outside the intended "
                                "directory are returned. Constrain inputs to an allow-list."),
                evidence=sig,
            ))
        elif op["args"] and _RISK_SSRF.search(haystack):
            findings.append(Finding(
                title=f"GraphQL field may allow SSRF: {op['name']}",
                severity=Severity.LOW, category="api-discovery",
                description=(f"The {op['kind']} field `{sig}` at {url} takes a URL/host argument "
                             "and appears to fetch it server-side — a common SSRF pattern. "
                             "Not invoked by this scan."),
                recommendation=("Verify manually: point the argument at an internal/metadata host "
                                "and confirm the server fetches it. Restrict outbound fetches."),
                evidence=sig,
            ))
    return findings


# ---- BOLA / IDOR surface ------------------------------------------------------

def _bola_candidates(paths: list[str]) -> list[str]:
    """Endpoint paths carrying an object identifier — where BOLA/IDOR lives."""
    out: list[str] = []
    seen: set[str] = set()
    for p in paths:
        if not p:
            continue
        # normalise to just the path component
        path = urllib.parse.urlparse(p).path if "://" in p else p
        if not path or "/" not in path:
            continue
        if _ID_TEMPLATE.search(path) or _ID_COLON.search(path) or _ID_CONCRETE.search(path):
            # collapse concrete ids so /users/1 and /users/2 don't both list
            key = _ID_CONCRETE.sub(lambda m: m.group(0).replace(m.group(1), "{id}"), path)
            if key not in seen:
                seen.add(key)
                out.append(key)
    return out


def _bola_finding(candidates: list[str]) -> list[Finding]:
    if not candidates:
        return []
    shown = candidates[:20]
    more = f" (+{len(candidates) - len(shown)} more)" if len(candidates) > len(shown) else ""
    return [Finding(
        title=f"Object-level authorization (BOLA/IDOR) surface: {len(candidates)} endpoint(s)",
        severity=Severity.LOW, category="api-discovery",
        description=("These endpoints reference objects by identifier — the classic place for "
                     "broken object-level authorization (OWASP API #1): a low-privilege user "
                     f"reading or modifying another user's objects.{more}"),
        recommendation=("Test by hand (authorized only): authenticate as one user and request "
                        "another user's object id; if it succeeds, object-level authz is missing. "
                        "Enforce per-object ownership checks on every such route."),
        evidence="\n".join(shown),
    )]


# ---- public entrypoint --------------------------------------------------------

def discover(base_url: str, *, insecure: bool = False, auth=None,
             extra_endpoints: list[str] | None = None
             ) -> tuple[dict, list[Finding], list[str]]:
    """Returns (info, findings, errors). info has 'openapi', 'graphql', 'endpoints'.

    `extra_endpoints` (e.g. URLs the crawler surfaced) are folded into the
    BOLA/IDOR surface analysis alongside any OpenAPI paths discovered here.
    """
    findings: list[Finding] = []
    errors: list[str] = []
    info: dict = {"openapi": None, "graphql": None, "endpoints": []}
    base = base_url.rstrip("/")
    parsed = urllib.parse.urlparse(base)
    root = f"{parsed.scheme}://{parsed.netloc}"

    # OpenAPI / Swagger
    for path in _OPENAPI_PATHS:
        url = root + path
        try:
            status, body = _get(url, insecure, auth)
        except (urllib.error.URLError, ssl.SSLError, OSError, ValueError):
            continue
        if status != 200:
            continue
        try:
            doc = json.loads(body)
        except json.JSONDecodeError:
            continue
        if isinstance(doc, dict) and ("openapi" in doc or "swagger" in doc):
            paths = list((doc.get("paths") or {}).keys())
            info["openapi"] = {"url": url, "paths": paths[:200],
                               "title": (doc.get("info") or {}).get("title", "")}
            info["endpoints"].extend(paths)
            findings.append(Finding(
                title="OpenAPI/Swagger document exposed",
                severity=Severity.LOW, category="api-discovery",
                description=f"An API specification is publicly readable at {url} "
                            f"({len(paths)} paths). It maps the API attack surface.",
                recommendation="Restrict API docs to authenticated users in production.",
                evidence=url,
            ))
            break

    # GraphQL introspection
    for path in _GRAPHQL_PATHS:
        url = root + path
        try:
            status, body = _post_json(url, _INTROSPECTION, insecure, auth)
        except (urllib.error.URLError, ssl.SSLError, OSError, ValueError):
            continue
        if status == 200 and "__schema" in body and '"types"' in body:
            try:
                schema = json.loads(body)["data"]["__schema"]
            except (json.JSONDecodeError, KeyError, TypeError):
                continue
            n = len(schema.get("types") or [])
            ops = _parse_operations(schema)
            info["graphql"] = {"url": url, "types": n,
                               "operations": [f'{o["name"]}({",".join(o["args"])})' for o in ops]}
            findings.append(Finding(
                title="GraphQL introspection enabled",
                severity=Severity.MEDIUM, category="api-discovery",
                description=f"GraphQL introspection is enabled at {url} "
                            f"({n} types, {len(ops)} root operations), exposing the full schema.",
                recommendation="Disable introspection in production GraphQL servers.",
                evidence=url,
            ))
            findings.extend(_graphql_risky(ops, url))
            break

    # BOLA / IDOR surface — over OpenAPI paths + crawler-surfaced endpoints
    surface = list(info["endpoints"]) + list(extra_endpoints or [])
    findings.extend(_bola_finding(_bola_candidates(surface)))

    return info, findings, errors
