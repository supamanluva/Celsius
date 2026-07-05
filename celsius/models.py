"""Shared data structures used across scanner modules and the reporter."""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Optional


# Canonical severity ordering — the single source of truth. Everything that ranks
# or sorts by severity goes through Severity.rank or severity_rank(), never a
# private copy of this dict.
_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


class Severity(str, Enum):
    """Ordered severity buckets, aligned with CVSS qualitative ratings."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def rank(self) -> int:
        return _RANK[self.value]

    @classmethod
    def from_cvss(cls, score: Optional[float]) -> "Severity":
        if score is None:
            return cls.INFO
        if score >= 9.0:
            return cls.CRITICAL
        if score >= 7.0:
            return cls.HIGH
        if score >= 4.0:
            return cls.MEDIUM
        if score > 0.0:
            return cls.LOW
        return cls.INFO


def severity_rank(sev) -> int:
    """Rank for a Severity or its string value (case-insensitive); unknown -> 0.

    Call sites work with both: Finding.severity is a Severity, but serialized
    scans carry plain strings. This is the one accessor for both, so the ordering
    lives in exactly one place (_RANK)."""
    if isinstance(sev, Severity):
        return sev.rank
    return _RANK.get(str(sev).upper(), 0)


@dataclass
class Service:
    """A detected service / software product with an optional version."""

    name: str                      # e.g. "nginx", "OpenSSH"
    version: Optional[str] = None  # e.g. "1.29.6"
    port: Optional[int] = None
    protocol: Optional[str] = None  # "tcp" / "udp"
    product: Optional[str] = None   # vendor product string from nmap, if any
    source: str = ""                # "http-header", "nmap", ...
    extra: dict[str, Any] = field(default_factory=dict)

    def label(self) -> str:
        v = f" {self.version}" if self.version else ""
        p = f" (port {self.port}/{self.protocol})" if self.port else ""
        return f"{self.name}{v}{p}"


@dataclass
class CVE:
    """A known vulnerability affecting a detected service version."""

    id: str
    severity: Severity
    cvss: Optional[float]
    description: str
    url: str
    published: Optional[str] = None
    affects: str = ""  # human-readable label, e.g. "nginx 1.29.8 (port 443/tcp)"
    product: str = ""  # structured mapping back to the detected service, so CVEs
    version: str = ""  # can be grouped/filtered/exported per component without
    port: Optional[int] = None  # re-parsing the `affects` string
    references: list[dict[str, Any]] = field(default_factory=list)  # PoC/exploit refs
    verified: bool = False  # confirmed via nuclei template against the live target
    confidence: str = "firm"  # "firm" | "weak" — weak = over-broad NVD match (no
                              # version range) or distro-backported package; not a
                              # confident hit and excluded from the headline severity
    caveat: str = ""          # why a match is weak / how to confirm it
    exploitability: dict[str, Any] = field(default_factory=dict)  # M4: verdict/signals/howto

    def poc_refs(self) -> list[str]:
        """URLs of public exploits / PoCs (NVD-tagged 'Exploit' or known PoC hosts)."""
        return [r["url"] for r in self.references if r.get("poc")]

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d


@dataclass
class Finding:
    """A non-CVE issue: a missing/weak header, a nuclei hit, a misconfig."""

    title: str
    severity: Severity
    category: str            # "headers", "csp", "nuclei", "tls", "ai-hypothesis", ...
    description: str = ""
    recommendation: str = ""
    evidence: str = ""
    confidence: str = ""     # "high"/"medium"/"low" — used by AI hypotheses
    exploitability: dict[str, Any] = field(default_factory=dict)  # M4: verdict/signals/howto

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d


@dataclass
class ScanResult:
    """Everything we learned about one target."""

    target: str
    url: Optional[str] = None
    ip: Optional[str] = None
    services: list[Service] = field(default_factory=list)
    cves: list[CVE] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    recon: dict[str, Any] = field(default_factory=dict)  # dns/tls/tech/subdomains
    chains: list[dict[str, Any]] = field(default_factory=list)   # M6: exploit chains
    coverage: dict[str, Any] = field(default_factory=dict)       # M6: completeness critic
    started_at: str = ""
    finished_at: str = ""
    # Populated by the engine after the result is persisted (the store's row id);
    # runtime-only, so it is intentionally not part of to_dict().
    scan_id: Optional[str] = None

    def add_finding(self, f: Finding) -> None:
        self.findings.append(f)

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "url": self.url,
            "ip": self.ip,
            "services": [asdict(s) for s in self.services],
            "cves": [c.to_dict() for c in self.cves],
            "findings": [f.to_dict() for f in self.findings],
            "errors": self.errors,
            "recon": self.recon,
            "chains": self.chains,
            "coverage": self.coverage,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
        }

    def all_severities_sorted(self) -> list[Severity]:
        # Weak (low-confidence) CVEs and AI hypotheses ("leads, not facts") are
        # reported but excluded from the headline severity / exit code, so an
        # unconfirmed match can't flip the whole result to CRITICAL.
        sev = {c.severity for c in self.cves if c.confidence != "weak"} \
            | {f.severity for f in self.findings if f.category != "ai-hypothesis"}
        return sorted(sev, key=lambda s: s.rank, reverse=True)
