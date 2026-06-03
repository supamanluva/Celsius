"""Curated list of *authorized* vulnerable test targets.

These are deliberately-insecure applications published by their vendors for the
explicit purpose of practising security testing — scanning and (within their
terms) exploiting them is legal. They make good smoke-tests for celsius itself
and a safe place to learn, instead of pointing the tool at systems you do not
own or have written permission to test.

The web UI and CLI surface this list so a user who needs a lawful target has one
to hand. Always read each site's own terms; "authorized" here means the vendor
publishes it for testing, not that anything goes.
"""

from __future__ import annotations

# Each entry: name, url, stack, focus (what it teaches / which bug classes live
# there). `group` buckets related sites in the UI.
TEST_SITES: list[dict] = [
    # ---- Invicti test sites (testinvicti.com family) -------------------------
    {
        "group": "Invicti", "name": "testinvicti.com", "url": "http://testinvicti.com/",
        "stack": "IIS · ASP.NET",
        "focus": "Landing site for Invicti's deliberately-vulnerable demo family; "
                 "links out to the per-stack apps below. Classic web bugs (XSS, SQLi).",
    },
    {
        "group": "Invicti", "name": "php.testinvicti.com", "url": "http://php.testinvicti.com/",
        "stack": "PHP",
        "focus": "PHP web app — SQL injection, reflected/stored XSS, file inclusion.",
    },
    {
        "group": "Invicti", "name": "aspnet.testinvicti.com", "url": "http://aspnet.testinvicti.com/",
        "stack": "ASP.NET · IIS",
        "focus": "ASP.NET web app — injection, XSS, and .NET-specific issues "
                 "(viewstate, trace, verbose errors).",
    },
    {
        "group": "Invicti", "name": "angular.testinvicti.com", "url": "http://angular.testinvicti.com/",
        "stack": "Angular (SPA)",
        "focus": "Single-page front-end — DOM-based XSS, client-side routing/secret "
                 "exposure, and the API calls behind a JS app.",
    },
    {
        "group": "Invicti", "name": "python.testinvicti.com", "url": "http://python.testinvicti.com/",
        "stack": "Python",
        "focus": "Python web app — injection, template/SSTI, and framework "
                 "misconfiguration practice.",
    },
    {
        "group": "Invicti", "name": "rest.testinvicti.com", "url": "http://rest.testinvicti.com/",
        "stack": "REST API",
        "focus": "\"Invicti Vulnerable REST API\" — testing scanners against a "
                 "documented REST surface (params, auth, injection).",
    },
    {
        "group": "Invicti", "name": "graphql.testinvicti.com", "url": "http://graphql.testinvicti.com/graphql",
        "stack": "GraphQL",
        "focus": "GraphQL endpoint with introspection enabled; schema exposes risky "
                 "fields like getFile (arbitrary file read / path traversal) and "
                 "getWebsiteSeoScore (SSRF).",
    },
    {
        "group": "Invicti", "name": "vulnapi.testinvicti.com", "url": "http://vulnapi.testinvicti.com/",
        "stack": "REST API · OWASP API Top 10",
        "focus": "\"Invicti Vulnerable API\" showcasing the OWASP API Security Top 10 "
                 "(2023): BOLA/IDOR, broken authentication, excessive data exposure "
                 "(it even documents static bearer tokens to start from).",
    },

    # ---- VulnWeb (Acunetix, now part of Invicti) -----------------------------
    {
        "group": "VulnWeb", "name": "testphp.vulnweb.com", "url": "http://testphp.vulnweb.com/",
        "stack": "Apache · PHP · MySQL",
        "focus": "The classic Acunetix target — SQL injection and XSS in a small "
                 "PHP shop (artists.php?artist=, listproducts.php?cat=).",
    },
    {
        "group": "VulnWeb", "name": "testasp.vulnweb.com", "url": "http://testasp.vulnweb.com/",
        "stack": "IIS · Classic ASP · MS SQL Server",
        "focus": "Classic ASP app — SQLi and XSS against a legacy Microsoft stack.",
    },
    {
        "group": "VulnWeb", "name": "testaspnet.vulnweb.com", "url": "http://testaspnet.vulnweb.com/",
        "stack": "IIS · ASP.NET · MS SQL Server",
        "focus": "ASP.NET version of the VulnWeb app — injection and XSS with "
                 ".NET error/trace behaviour.",
    },
    {
        "group": "VulnWeb", "name": "testhtml5.vulnweb.com", "url": "http://testhtml5.vulnweb.com/",
        "stack": "Nginx · Python/Flask · CouchDB",
        "focus": "HTML5/REST front-end over a NoSQL (CouchDB) backend — REST and "
                 "NoSQL-injection practice.",
    },

    # ---- Pentest-Ground (Pentest-Tools.com) ----------------------------------
    # Openly scannable, no auth; every target is destroyed and redeployed every
    # 30 minutes to keep a clean vulnerable state. Note the non-standard ports.
    {
        "group": "Pentest-Ground", "name": "DVWA", "url": "https://pentest-ground.com:4280",
        "stack": "PHP web app · port 4280",
        "focus": "Damn Vulnerable Web Application — the classic CSRF / XSS / SQL "
                 "injection trainer, with selectable difficulty levels.",
    },
    {
        "group": "Pentest-Ground", "name": "DVGA", "url": "https://pentest-ground.com:5013",
        "stack": "GraphQL · port 5013",
        "focus": "Damn Vulnerable GraphQL Application — command injection, XSS and "
                 "SQLi via GraphQL, plus introspection/batching abuse.",
    },
    {
        "group": "Pentest-Ground", "name": "RestFlaw", "url": "https://pentest-ground.com:9000",
        "stack": "REST API · port 9000",
        "focus": "Vulnerable REST API — SQL injection, code injection and XXE "
                 "through API parameters and XML bodies.",
    },
    {
        "group": "Pentest-Ground", "name": "ShadowLogic",
        "url": "https://pentest-ground.com:7001/console/login/LoginForm.jsp",
        "stack": "Oracle WebLogic · port 7001",
        "focus": "WebLogic admin console vulnerable to CVE-2023-21839 — "
                 "unauthenticated remote code execution.",
    },
    {
        "group": "Pentest-Ground", "name": "CipherHeart", "url": "pentest-ground.com:6379",
        "stack": "Redis · port 6379",
        "focus": "Exposed Redis vulnerable to CVE-2022-0543 (Lua sandbox escape → "
                 "RCE). A network-service target — scan with the port/nmap option.",
    },
    {
        "group": "Pentest-Ground", "name": "GuardianLeaks", "url": "https://pentest-ground.com:81",
        "stack": "Web app · port 81",
        "focus": "Web application carrying XSS, SSRF and code-injection flaws.",
    },
]

NOTE = ("Authorized targets only. These apps are published by their vendors "
        "(Invicti / Acunetix / Pentest-Tools.com) as deliberately-vulnerable "
        "practice targets — Pentest-Ground resets every 30 min and is openly "
        "scannable. Never point celsius at a system you don't own or have "
        "written permission to test.")


def groups() -> list[dict]:
    """TEST_SITES bucketed by `group`, preserving order: [{name, sites:[...]}]."""
    order: list[str] = []
    by: dict[str, list[dict]] = {}
    for s in TEST_SITES:
        g = s["group"]
        if g not in by:
            by[g] = []
            order.append(g)
        by[g].append(s)
    return [{"name": g, "sites": by[g]} for g in order]
