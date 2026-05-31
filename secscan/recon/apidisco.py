"""API discovery: OpenAPI/Swagger documents and GraphQL introspection.

These are safe-active checks: we request a small set of well-known doc paths and
send one benign GraphQL introspection query. Nothing is mutated.
"""

from __future__ import annotations

import json
import ssl
import urllib.error
import urllib.parse
import urllib.request

from ..models import Finding, Severity

USER_AGENT = "secscan/0.5 (+authorized security testing)"
TIMEOUT = 8

_OPENAPI_PATHS = [
    "/openapi.json", "/swagger.json", "/v2/api-docs", "/v3/api-docs",
    "/swagger/v1/swagger.json", "/api-docs", "/api/swagger.json",
    "/.well-known/openapi.json", "/swagger/ui", "/api/v1/openapi.json",
]
_GRAPHQL_PATHS = ["/graphql", "/api/graphql", "/v1/graphql", "/query"]
_INTROSPECTION = json.dumps({"query": "{__schema{queryType{name} types{name}}}"})


def _get(url: str, insecure: bool) -> tuple[int, str]:
    ctx = ssl.create_default_context()
    if insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=TIMEOUT, context=ctx) as resp:
        return resp.status, resp.read(400_000).decode("utf-8", errors="replace")


def _post_json(url: str, body: str, insecure: bool) -> tuple[int, str]:
    ctx = ssl.create_default_context()
    if insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, data=body.encode(),
                                 headers={"User-Agent": USER_AGENT,
                                          "Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=TIMEOUT, context=ctx) as resp:
        return resp.status, resp.read(400_000).decode("utf-8", errors="replace")


def discover(base_url: str, *, insecure: bool = False
             ) -> tuple[dict, list[Finding], list[str]]:
    """Returns (info, findings, errors). info has 'openapi', 'graphql', 'endpoints'."""
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
            status, body = _get(url, insecure)
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
            status, body = _post_json(url, _INTROSPECTION, insecure)
        except (urllib.error.URLError, ssl.SSLError, OSError, ValueError):
            continue
        if status == 200 and "__schema" in body and '"types"' in body:
            try:
                n = len(json.loads(body)["data"]["__schema"]["types"])
            except (json.JSONDecodeError, KeyError, TypeError):
                n = 0
            info["graphql"] = {"url": url, "types": n}
            findings.append(Finding(
                title="GraphQL introspection enabled",
                severity=Severity.MEDIUM, category="api-discovery",
                description=f"GraphQL introspection is enabled at {url} "
                            f"({n} types), exposing the full schema to attackers.",
                recommendation="Disable introspection in production GraphQL servers.",
                evidence=url,
            ))
            break

    return info, findings, errors
