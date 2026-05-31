"""Optional redaction before sending content to an external LLM.

DEFAULT OFF — per project decision, full context is sent so the model finds
everything, and findings go to the asset owner to fix/rotate. When enabled (for
sensitive engagements / third-party code), secrets are replaced with typed
placeholders so the model can still reason about "a secret here" without seeing
its value. Either way we return a manifest of what was (or would be) sensitive,
which the audit log records.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .. import secrets as secret_rules


@dataclass
class RedactionResult:
    text: str
    enabled: bool
    manifest: list[dict] = field(default_factory=list)  # [{rule_id, redacted, count}]

    @property
    def n_sensitive(self) -> int:
        return sum(m["count"] for m in self.manifest)


def redact(text: str, *, enabled: bool = False) -> RedactionResult:
    """Scan for secrets; mask them only if `enabled`. Always builds a manifest."""
    matches = secret_rules.scan_text(text)
    counts: dict[str, dict] = {}
    out = text
    for sm in matches:
        key = sm.rule_id
        counts.setdefault(key, {"rule_id": key, "redacted": sm.redacted, "count": 0})
        counts[key]["count"] += 1
        if enabled:
            placeholder = f"<{sm.rule_id.upper().replace('-', '_')}>"
            out = out.replace(sm.match, placeholder)
    return RedactionResult(text=out, enabled=enabled, manifest=list(counts.values()))
