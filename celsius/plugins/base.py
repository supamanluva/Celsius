"""Plugin base types and registry."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, IntEnum
from typing import TYPE_CHECKING, Callable, Optional

if TYPE_CHECKING:
    from ..audit import AuditLog
    from ..config import ScanConfig
    from ..http_analysis import HttpResult
    from ..models import ScanResult
    from ..scope import Scope
    from ..targets import Target


class Phase(IntEnum):
    """Plugins run in ascending phase order."""
    RECON = 1     # discover hosts/ports/services/endpoints
    DETECT = 2    # find weaknesses on what recon surfaced
    ENRICH = 3    # add CVEs, EPSS/KEV, exploitability, correlation


class Mode(str, Enum):
    """Least-intrusive mode a plugin needs to run.

    PASSIVE      — ordinary HTTP a browser would make + third-party lookups.
    SAFE_ACTIVE  — scanners/probes (nmap, nuclei) with benign, non-destructive payloads.
    EXPLOIT      — lab-mode active exploitation (guardrailed; future).
    """
    PASSIVE = "passive"
    SAFE_ACTIVE = "safe-active"
    EXPLOIT = "exploit"

    @property
    def rank(self) -> int:
        return {"passive": 0, "safe-active": 1, "exploit": 2}[self.value]


@dataclass
class ScanContext:
    """Shared state threaded through every plugin in a single scan."""
    config: "ScanConfig"
    target: "Target"
    result: "ScanResult"
    scope: "Scope"
    audit: "AuditLog"
    log: Callable[[str], None] = lambda _m: None
    http_result: Optional["HttpResult"] = None
    data: dict = field(default_factory=dict)


class Plugin:
    """Base class for checks. Subclass and set the class attributes."""
    id: str = "plugin"
    title: str = "plugin"
    phase: Phase = Phase.DETECT
    mode: Mode = Mode.PASSIVE
    category: str = "general"

    def enabled(self, ctx: ScanContext) -> bool:
        """Whether this plugin should run for this scan (config toggles)."""
        return True

    def run(self, ctx: ScanContext) -> None:
        """Perform the check; mutate ctx.result. Must not raise on target errors —
        append to ctx.result.errors instead."""
        raise NotImplementedError


_REGISTRY: list[Plugin] = []


def register(cls: type[Plugin]) -> type[Plugin]:
    """Class decorator: instantiate and register a plugin."""
    _REGISTRY.append(cls())
    return cls


def all_plugins() -> list[Plugin]:
    """Registered plugins in execution order (phase, then registration order)."""
    return sorted(_REGISTRY, key=lambda p: p.phase)
