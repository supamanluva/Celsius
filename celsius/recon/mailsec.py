"""E-mail security assessment via DNS-over-HTTPS (fully passive).

Assesses a domain's e-mail security without contacting the target's mail server:
MX, SPF, DKIM (selector probing), DMARC, MTA-STS (DNS record + policy file over
HTTPS), TLS-RPT, BIMI and DNSSEC. Returns (info, findings, errors); the plugin
layer stores info in ScanResult.recon['mailsec'] and findings in result.findings.

All traffic goes to a public DoH resolver and (for MTA-STS) to the domain's own
published policy URL — nothing is sent to the mail server, no packets to port 25.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request

from ..models import Finding, Severity

DOH_URL = "https://dns.google/resolve"
USER_AGENT = "celsius/1.1 (+authorized email-security check)"
TIMEOUT = 8

# Common DKIM selectors (cannot be enumerated via DNS — we probe known names).
COMMON_SELECTORS = [
    "selector1", "selector2",          # Microsoft 365
    "google",                          # Google Workspace
    "k1", "k2",                        # Mailchimp/Mandrill et al.
    "s1", "s2", "default", "dkim", "mail", "smtp", "mx",
    "mandrill", "mxvault", "dkim1", "key1", "fm1", "fm2", "fm3",  # Fastmail
    "scph0", "sig1", "zoho",
]

# Known mail-provider patterns in MX -> readable name (drives selector guessing + fix text).
_PROVIDERS = [
    ("protection.outlook.com", "Microsoft 365 / Exchange Online", ["selector1", "selector2"]),
    ("outlook.com", "Microsoft 365", ["selector1", "selector2"]),
    ("google.com", "Google Workspace", ["google"]),
    ("googlemail.com", "Google Workspace", ["google"]),
    ("mimecast.com", "Mimecast", []),
    ("pphosted.com", "Proofpoint", []),
    ("proofpoint.com", "Proofpoint", []),
    ("messagelabs.com", "Symantec.cloud", []),
    ("zoho.com", "Zoho Mail", ["zoho"]),
    ("fastmail.com", "Fastmail", ["fm1", "fm2", "fm3"]),
]


# ---- DoH helpers --------------------------------------------------------------

def _query(name: str, rtype: str) -> tuple[int, bool, list[str]]:
    """Return (status, ad_flag, [values]). ad_flag = DNSSEC-authenticated answer."""
    params = urllib.parse.urlencode({"name": name, "type": rtype})
    req = urllib.request.Request(f"{DOH_URL}?{params}", headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            data = json.loads(resp.read().decode())
    except (urllib.error.URLError, OSError, json.JSONDecodeError):
        return (-1, False, [])
    vals = [a.get("data", "").strip() for a in (data.get("Answer") or []) if a.get("data")]
    return (data.get("Status", -1), bool(data.get("AD")), vals)


def _txt(name: str) -> tuple[bool, list[str]]:
    """TXT query, normalised: strips the quotes DoH wraps strings in and joins
    multi-string records into one value. Returns (ad_flag, [strings])."""
    _status, ad, raw = _query(name, "TXT")
    out: list[str] = []
    for v in raw:
        if v.startswith('"'):
            # one TXT record may be split: "part1" "part2" -> concatenate
            parts = [p for p in v.split('"') if p and not p.isspace()]
            out.append("".join(parts))
        else:
            out.append(v)
    return ad, out


# ---- analysis -----------------------------------------------------------------

def _provider(mx: list[str]) -> tuple[str, list[str]]:
    """Guess provider + provider-specific DKIM selectors from MX hosts."""
    joined = " ".join(mx).lower()
    for needle, name, selectors in _PROVIDERS:
        if needle in joined:
            return name, selectors
    return "", []


def _check_spf(domain: str) -> dict:
    _ad, txts = _txt(domain)
    spf = next((t for t in txts if t.lower().startswith("v=spf1")), None)
    if not spf:
        return {"key": "spf", "label": "SPF", "status": "bad", "value": "",
                "detail": "No SPF record — sender addresses can be spoofed.",
                "fix": f'Add a TXT record on {domain}:  "v=spf1 include:<your-provider> -all"'}
    tail = spf.split()[-1].lower()
    if tail == "-all":
        return {"key": "spf", "label": "SPF", "status": "ok", "value": spf,
                "detail": "Hard fail (-all) — strict.", "fix": ""}
    if tail == "~all":
        return {"key": "spf", "label": "SPF", "status": "warn", "value": spf,
                "detail": "Softfail (~all) — lets failing checks through.",
                "fix": "Tighten the end of the SPF record from ~all to -all once you have verified "
                       "that all legitimate senders are covered."}
    return {"key": "spf", "label": "SPF", "status": "bad", "value": spf,
            "detail": f"Missing fail mechanism ('{tail}') — provides no spoofing protection.",
            "fix": "End the SPF record with -all (or at least ~all)."}


def _check_dmarc(domain: str) -> dict:
    _ad, txts = _txt(f"_dmarc.{domain}")
    rec = next((t for t in txts if t.lower().startswith("v=dmarc1")), None)
    fix_add = (f'Add a TXT record on _dmarc.{domain}:  '
               f'"v=DMARC1; p=reject; rua=mailto:dmarc@{domain}; pct=100"')
    if not rec:
        return {"key": "dmarc", "label": "DMARC", "status": "bad", "value": "",
                "detail": "No DMARC policy — recipients have no instruction on how to handle spoofing.",
                "fix": fix_add}
    tags = {k.strip().lower(): v.strip() for k, _, v in
            (p.partition("=") for p in rec.split(";") if "=" in p)}
    p = tags.get("p", "none").lower()
    has_rua = "rua" in tags
    detail = f"p={p}" + ("" if has_rua else "; no rua= (missing aggregate reporting)")
    if p == "reject":
        status = "ok"
        fix = "" if has_rua else f"Add rua=mailto:dmarc@{domain} for aggregate reports."
    elif p == "quarantine":
        status = "warn"
        fix = "Raise to p=reject once the reports look clean."
    else:  # none
        status = "bad"
        fix = "p=none provides no enforcement — raise to p=quarantine and then p=reject."
    return {"key": "dmarc", "label": "DMARC", "status": status, "value": rec,
            "detail": detail, "fix": fix}


def _dkim_has_key(txts: list[str]) -> bool:
    """True only if a selector publishes a *non-empty* public key. An empty
    ``p=`` is a revocation/null record (RFC 6376), not a usable signing key."""
    for t in txts:
        low = t.lower()
        if "v=dkim1" not in low and "k=rsa" not in low and "k=ed25519" not in low and "p=" not in low:
            continue
        tags = {k.strip().lower(): v.strip() for k, _, v in
                (seg.partition("=") for seg in t.split(";") if "=" in seg)}
        if tags.get("p", ""):   # non-empty public key
            return True
    return False


def _check_dkim(domain: str, provider_selectors: list[str]) -> dict:
    selectors = list(dict.fromkeys(provider_selectors + COMMON_SELECTORS))
    found = []
    for sel in selectors:
        _ad, txts = _txt(f"{sel}._domainkey.{domain}")
        if _dkim_has_key(txts):
            found.append(sel)
        if len(found) >= 3:
            break
    if found:
        return {"key": "dkim", "label": "DKIM", "status": "ok",
                "value": ", ".join(found),
                "detail": f"Published key found (selector: {', '.join(found)}).", "fix": ""}
    return {"key": "dkim", "label": "DKIM", "status": "warn", "value": "",
            "detail": "No DKIM key found on common selectors (may use a custom selector name).",
            "fix": "Confirm DKIM signing is enabled at your mail provider and that the selector is "
                   "published as <selector>._domainkey." + domain + "."}


def _check_mta_sts(domain: str) -> dict:
    _ad, txts = _txt(f"_mta-sts.{domain}")
    rec = next((t for t in txts if t.lower().startswith("v=stsv1")), None)
    fix_add = (f"Publish MTA-STS: a TXT record on _mta-sts.{domain} (\"v=STSv1; id=<changes on update>\") "
               f"+ a policy file at https://mta-sts.{domain}/.well-known/mta-sts.txt with mode: enforce.")
    if not rec:
        return {"key": "mta_sts", "label": "MTA-STS", "status": "warn", "value": "",
                "detail": "Missing — inbound mail can be downgraded to an unprotected connection (MITM).",
                "fix": fix_add}
    # Fetch the policy file (public, standardised URL — still passive).
    mode = ""
    try:
        url = f"https://mta-sts.{domain}/.well-known/mta-sts.txt"
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            policy = resp.read(8192).decode("utf-8", "replace")
        for line in policy.splitlines():
            if line.lower().startswith("mode:"):
                mode = line.split(":", 1)[1].strip().lower()
    except (urllib.error.URLError, OSError, ValueError):
        return {"key": "mta_sts", "label": "MTA-STS", "status": "warn", "value": rec,
                "detail": "DNS record exists but the policy file could not be fetched.",
                "fix": f"Make sure https://mta-sts.{domain}/.well-known/mta-sts.txt "
                       f"responds with a valid certificate."}
    if mode == "enforce":
        return {"key": "mta_sts", "label": "MTA-STS", "status": "ok", "value": f"mode={mode}",
                "detail": "Active in enforce mode.", "fix": ""}
    return {"key": "mta_sts", "label": "MTA-STS", "status": "warn", "value": f"mode={mode or '?'}",
            "detail": f"Policy in '{mode or 'unknown'}' mode — not enforced yet.",
            "fix": "Set mode: enforce in the policy file once you have verified the mx list is correct."}


def _check_tls_rpt(domain: str) -> dict:
    _ad, txts = _txt(f"_smtp._tls.{domain}")
    rec = next((t for t in txts if t.lower().startswith("v=tlsrptv1")), None)
    if rec:
        return {"key": "tls_rpt", "label": "TLS-RPT", "status": "ok", "value": rec,
                "detail": "Reporting of TLS problems is enabled.", "fix": ""}
    return {"key": "tls_rpt", "label": "TLS-RPT", "status": "info", "value": "",
            "detail": "Missing — you receive no reports about failed TLS on mail delivery.",
            "fix": f'Add a TXT record on _smtp._tls.{domain}:  "v=TLSRPTv1; rua=mailto:tlsrpt@{domain}"'}


def _check_dnssec(domain: str, mx_ad: bool) -> dict:
    status_code, _ad, ds = _query(domain, "DS")
    if ds or mx_ad:
        return {"key": "dnssec", "label": "DNSSEC", "status": "ok",
                "value": "DS published" if ds else "authenticated answers",
                "detail": "DNSSEC is active — DNS answers cannot be spoofed.", "fix": ""}
    return {"key": "dnssec", "label": "DNSSEC", "status": "warn", "value": "",
            "detail": "No DS record — DNS for the domain is not signed.",
            "fix": "Enable DNSSEC at your DNS operator/registrar and publish the DS record."}


def _check_bimi(domain: str, dmarc_ok: bool) -> dict:
    _ad, txts = _txt(f"default._bimi.{domain}")
    rec = next((t for t in txts if t.lower().startswith("v=bimi1")), None)
    if rec:
        return {"key": "bimi", "label": "BIMI", "status": "ok", "value": rec,
                "detail": "BIMI record published (brand logo in the inbox).", "fix": ""}
    return {"key": "bimi", "label": "BIMI", "status": "info", "value": "",
            "detail": "Missing (optional; requires DMARC p=reject/quarantine"
                      + ("" if dmarc_ok else " — fix DMARC first") + ").",
            "fix": "Optional: publish a BIMI record + optional VMC certificate for a logo in the inbox."}


_GRADE = [(95, "A+"), (85, "A"), (75, "B"), (60, "C"), (40, "D"), (0, "F")]
# Weight per check (sums to 100). info checks (tls_rpt, bimi) weigh lightly.
_WEIGHTS = {"spf": 22, "dkim": 18, "dmarc": 25, "mta_sts": 12, "tls_rpt": 6,
            "dnssec": 12, "bimi": 5}
_STATUS_SCORE = {"ok": 1.0, "warn": 0.4, "info": 0.5, "bad": 0.0}

_SEVERITY = {"bad": Severity.HIGH, "warn": Severity.LOW, "info": Severity.INFO, "ok": None}


def analyze(domain: str) -> tuple[dict, list[Finding], list[str]]:
    """Run all email-security checks for `domain`. Passive (DoH + policy URL)."""
    domain = domain.strip().lower().rstrip(".")
    errors: list[str] = []

    status_code, mx_ad, mx_raw = _query(domain, "MX")
    if status_code == -1:
        return ({"domain": domain, "checks": [], "mx": [], "grade": "?", "score": 0},
                [], [f"mailsec: DNS lookup failed for {domain}"])
    # MX data looks like "10 mail.example.com." -> take the hostname.
    mx_hosts = [v.split()[-1].rstrip(".") for v in mx_raw if v.split()]
    provider, prov_selectors = _provider(mx_hosts)

    checks = [
        _check_spf(domain),
        _check_dkim(domain, prov_selectors),
        _check_dmarc(domain),
        _check_mta_sts(domain),
        _check_tls_rpt(domain),
        _check_dnssec(domain, mx_ad),
    ]
    dmarc_ok = any(c["key"] == "dmarc" and c["status"] == "ok" for c in checks)
    checks.append(_check_bimi(domain, dmarc_ok))

    # score / grade
    total = sum(_WEIGHTS.values())
    earned = sum(_WEIGHTS.get(c["key"], 0) * _STATUS_SCORE.get(c["status"], 0) for c in checks)
    score = round(100 * earned / total) if total else 0
    grade = next(g for thr, g in _GRADE if score >= thr)

    info = {
        "domain": domain,
        "mx": mx_hosts,
        "provider": provider,
        "checks": checks,
        "score": score,
        "grade": grade,
    }

    # findings (one per non-ok check), with the exact fix + which mail server it applies to
    findings: list[Finding] = []
    mx_note = (f" Applies to the mail server: {', '.join(mx_hosts)}"
               f"{f' ({provider})' if provider else ''}." if mx_hosts else "")
    for c in checks:
        sev = _SEVERITY.get(c["status"])
        if sev is None:
            continue
        findings.append(Finding(
            title=f"E-mail: {c['label']} — {c['detail'].split('—')[0].strip().rstrip('.')}",
            severity=sev, category="mailsec",
            description=c["detail"] + mx_note,
            recommendation=c["fix"],
            evidence=(c["value"] or "")[:300],
        ))
    return info, findings, errors


def summarize(info: dict) -> str:
    if not info.get("checks"):
        return ""
    bad = [c["label"] for c in info["checks"] if c["status"] in ("bad", "warn")]
    head = f"Mail security {info.get('grade', '?')} ({info.get('score', 0)}/100)"
    return head + (f" — to fix: {', '.join(bad)}" if bad else " — no issues")
