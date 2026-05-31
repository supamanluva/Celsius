"""TLS / certificate analysis (stdlib ssl only).

We do a verifying handshake first (so cert problems surface as findings), then a
non-verifying handshake to read the negotiated protocol/cipher and cert details,
and finally probe whether legacy TLS versions are still accepted.
"""

from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone
from typing import Optional

from ..models import Finding, Severity

TIMEOUT = 8


def _connect(host: str, port: int, context: ssl.SSLContext):
    raw = socket.create_connection((host, port), timeout=TIMEOUT)
    return context.wrap_socket(raw, server_hostname=host)


def analyze(host: str, port: int = 443) -> tuple[dict, list[Finding], list[str]]:
    """Returns (tls_info, findings, errors)."""
    findings: list[Finding] = []
    errors: list[str] = []
    info: dict = {"host": host, "port": port}

    # 1) verifying handshake — surfaces expiry / self-signed / hostname mismatch
    verify_ctx = ssl.create_default_context()
    cert: Optional[dict] = None
    try:
        with _connect(host, port, verify_ctx) as s:
            cert = s.getpeercert()
            info["protocol"] = s.version()
            info["cipher"] = s.cipher()[0] if s.cipher() else None
            info["verified"] = True
    except ssl.SSLCertVerificationError as e:
        info["verified"] = False
        reason = str(getattr(e, "verify_message", "") or e).lower()
        sev = Severity.HIGH
        if "expired" in reason:
            title = "TLS certificate expired"
        elif "self signed" in reason or "self-signed" in reason:
            title = "Self-signed TLS certificate"
        elif "hostname mismatch" in reason or "doesn't match" in reason:
            title = "TLS certificate hostname mismatch"
        else:
            title = "TLS certificate not trusted"
        findings.append(Finding(
            title=title, severity=sev, category="tls",
            description=f"Certificate validation failed: {reason}",
            recommendation="Install a valid, trusted certificate matching the hostname.",
            evidence=reason[:160],
        ))
    except (ssl.SSLError, socket.timeout, socket.gaierror, OSError) as e:
        errors.append(f"TLS connect failed for {host}:{port}: {e}")
        return info, findings, errors

    # 2) non-verifying handshake to read protocol/cipher/cert even if untrusted
    noverify = ssl.create_default_context()
    noverify.check_hostname = False
    noverify.verify_mode = ssl.CERT_NONE
    try:
        with _connect(host, port, noverify) as s:
            info.setdefault("protocol", s.version())
            if s.cipher():
                info.setdefault("cipher", s.cipher()[0])
            if cert is None:
                cert = s.getpeercert()  # empty under CERT_NONE, but harmless
    except (ssl.SSLError, OSError):
        pass

    # 3) certificate detail / expiry (when we have a parsed cert)
    if cert:
        info["subject"] = _name(cert.get("subject"))
        info["issuer"] = _name(cert.get("issuer"))
        not_after = cert.get("notAfter")
        sans = [v for k, v in cert.get("subjectAltName", []) if k == "DNS"]
        info["san"] = sans[:20]
        if not_after:
            info["not_after"] = not_after
            days = _days_until(not_after)
            info["days_to_expiry"] = days
            if days is not None and 0 <= days <= 21:
                findings.append(Finding(
                    title=f"TLS certificate expiring soon ({days}d)",
                    severity=Severity.MEDIUM, category="tls",
                    description=f"The certificate expires on {not_after}.",
                    recommendation="Renew/automate certificate renewal (e.g. ACME).",
                ))

    # 4) protocol weakness from the negotiated version
    proto = info.get("protocol") or ""
    if proto in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
        findings.append(Finding(
            title=f"Weak TLS protocol negotiated: {proto}",
            severity=Severity.MEDIUM, category="tls",
            description=f"The server negotiated {proto}, which is deprecated.",
            recommendation="Disable TLS < 1.2; prefer TLS 1.3.",
        ))

    # 5) actively probe whether legacy TLS 1.0/1.1 are still accepted
    legacy = _probe_legacy(host, port)
    if legacy:
        info["legacy_accepted"] = legacy
        findings.append(Finding(
            title=f"Legacy TLS accepted: {', '.join(legacy)}",
            severity=Severity.MEDIUM, category="tls",
            description="The server still accepts deprecated TLS versions.",
            recommendation="Disable TLS 1.0/1.1 at the server/load balancer.",
        ))

    return info, findings, errors


def _probe_legacy(host: str, port: int) -> list[str]:
    accepted = []
    versions = []
    if hasattr(ssl, "TLSVersion"):
        versions = [("TLSv1", ssl.TLSVersion.TLSv1), ("TLSv1.1", ssl.TLSVersion.TLSv1_1)]
    for label, ver in versions:
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = ver
            ctx.maximum_version = ver
            with _connect(host, port, ctx):
                accepted.append(label)
        except (ssl.SSLError, OSError, ValueError):
            continue
    return accepted


def _name(seq) -> str:
    if not seq:
        return ""
    parts = []
    for rdn in seq:
        for k, v in rdn:
            if k in ("commonName", "organizationName"):
                parts.append(v)
    return ", ".join(parts)


def _days_until(not_after: str) -> Optional[int]:
    try:
        epoch = ssl.cert_time_to_seconds(not_after)
        exp = datetime.fromtimestamp(epoch, tz=timezone.utc)
        return (exp - datetime.now(timezone.utc)).days
    except (ValueError, OSError):
        return None
