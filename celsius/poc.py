"""Proof-of-concept / reproduction generator (TEXT ONLY).

Given a Finding or CVE, produces step-by-step reproduction instructions and
references that a tester can follow manually to demonstrate the issue. It does
NOT execute anything and emits no weaponized payloads — only benign,
non-destructive verification steps suitable for an authorized-test report.
"""

from __future__ import annotations

from typing import Optional

from .models import CVE, Finding


def _box(title: str, steps: list[str], refs: Optional[list[str]] = None,
         note: str = "") -> dict:
    return {"title": title, "steps": steps, "references": refs or [], "note": note}


# ---- per-category reproduction templates for header/web findings -------------

def poc_for_finding(finding: Finding, target_url: str = "<URL>") -> dict:
    cat = finding.category
    url = target_url or "<URL>"

    if cat == "csp":
        return _box(
            "Demonstrate weak/missing Content-Security-Policy",
            [
                f"1. Fetch the response headers:   curl -sI {url}",
                "2. Confirm there is no Content-Security-Policy header, or that it "
                "contains 'unsafe-inline'/'*'.",
                "3. In a test page you control, embed an inline <script>alert(document.domain)</script> "
                "to show that, absent CSP, injected inline script would execute. Use a harmless alert "
                "marker — do NOT exfiltrate data.",
                "4. Document the missing/weak directive as the root cause that raises XSS impact.",
            ],
            ["https://developer.mozilla.org/docs/Web/HTTP/CSP",
             "https://content-security-policy.com/"],
            note="Non-destructive: only proves the policy gap; no real payload delivered.",
        )

    if cat == "headers" and "HSTS" in finding.title:
        return _box(
            "Demonstrate missing HSTS",
            [
                f"1. curl -sI {url} | grep -i strict-transport-security   (expect: no output)",
                "2. From a network position, show an http:// request is not auto-upgraded "
                "(e.g. open the http:// URL and observe no redirect/STS enforcement).",
                "3. Conclude a downgrade/MITM window exists on first or subsequent visits.",
            ],
            ["https://developer.mozilla.org/docs/Web/HTTP/Headers/Strict-Transport-Security"],
            note="Observation only.",
        )

    if cat == "headers" and "clickjack" in finding.title.lower():
        return _box(
            "Demonstrate clickjacking exposure",
            [
                f"1. curl -sI {url} | grep -iE 'x-frame-options|frame-ancestors'   (expect: none)",
                f"2. Create a local test.html containing:  <iframe src=\"{url}\" width=800 height=600></iframe>",
                "3. Open test.html locally; if the target renders inside the frame, framing is allowed.",
            ],
            ["https://owasp.org/www-community/attacks/Clickjacking"],
            note="Uses a local frame you control; no interaction with real users.",
        )

    if cat in ("info-disclosure",):
        return _box(
            "Demonstrate version/information disclosure",
            [
                f"1. curl -sI {url}",
                "2. Record the Server / X-Powered-By value revealing the exact product+version.",
                "3. Map that version to known CVEs (see the CVE section of this report).",
            ],
            ["https://owasp.org/www-project-web-security-testing-guide/"],
            note="Read-only.",
        )

    if cat == "cookies":
        return _box(
            "Demonstrate insecure cookie flags",
            [
                f"1. curl -sI {url} | grep -i set-cookie",
                "2. Note the absence of Secure and/or HttpOnly attributes.",
                "3. Explain impact: HttpOnly absent -> readable via document.cookie (XSS theft); "
                "Secure absent -> sent over plaintext http.",
            ],
            ["https://owasp.org/www-community/controls/SecureCookieAttribute"],
            note="Header inspection only.",
        )

    if cat == "exposed-secret":
        return _box(
            "Verify an exposed secret (handle carefully)",
            [
                "1. Locate the credential in the served front-end asset noted in 'evidence'.",
                "2. Treat it as live: do NOT use it against production. If you must confirm validity "
                "in scope, make a single minimal read-only API call and stop.",
                "3. Report it as exposed and require rotation regardless of validity.",
            ],
            ["https://cwe.mitre.org/data/definitions/798.html"],
            note="Confirm existence by inspection; avoid using the key beyond a minimal in-scope check.",
        )

    if cat == "nuclei":
        return _box(
            f"Reproduce the nuclei finding: {finding.title}",
            [
                "1. Re-run only this template against the in-scope target:",
                f"   nuclei -target {url} -id <template-id>",
                "2. Inspect 'matched-at' in the output to see the exact request/response that fired.",
                "3. Manually replay that single request with curl to confirm, then document.",
            ],
            ["https://docs.projectdiscovery.io/tools/nuclei/overview"],
            note="Replays one benign matcher request; review the template before running.",
        )

    # generic fallback
    return _box(
        f"Reproduce: {finding.title}",
        [
            f"1. Inspect {url} relevant to '{finding.category}'.",
            f"2. Confirm the condition described: {finding.description[:200]}",
            "3. Capture the request/response as evidence.",
        ],
        note="Manual verification.",
    )


# ---- CVE reproduction (point to authoritative advisories, no weaponization) --

def poc_for_cve(cve: CVE, service_label: str = "") -> dict:
    svc = service_label or cve.affects or "the detected service"
    poc_urls = cve.poc_refs() if hasattr(cve, "poc_refs") else []
    refs = poc_urls + [cve.url, f"https://www.cve.org/CVERecord?id={cve.id}"]
    box = _box(
        f"Confirm exposure to {cve.id} ({svc})",
        [
            f"1. Confirm the running version: it falls within the affected range for {cve.id} "
            f"(see Affects: {cve.affects}).",
            "2. Verify reachability of the vulnerable component/feature (e.g. for a module-specific "
            "bug, confirm that module/config path is actually in use).",
            f"3. Review the authoritative advisory for the documented trigger conditions: {cve.url}",
            "4. If a public, vendor-sanctioned PoC exists (linked from the NVD references), reproduce "
            "it ONLY against your in-scope test system and prefer the non-destructive variant "
            "(e.g. trigger a detectable but harmless effect rather than full exploitation).",
            "5. Capture the version banner + the advisory match as the evidence chain; remediate by "
            "upgrading to the fixed version.",
        ],
        refs,
        note="This tool intentionally does not generate exploit payloads. Use the vendor/advisory "
             "PoC under your authorization, non-destructively, against test systems only. "
             "Tip: enable --cve-verify to auto-confirm with a non-destructive nuclei template.",
    )
    return box
