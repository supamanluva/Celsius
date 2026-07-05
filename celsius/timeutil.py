"""Timestamp helpers — one home for "what time is it, formatted".

Two formats, on purpose: ISO-8601 for machine-readable records (the audit log and
stored scans) and a compact human-readable form for report/UI display. Keeping
both here means no module re-derives `datetime.now(timezone.utc)...` on its own.
"""

from __future__ import annotations

from datetime import datetime, timezone


def utcnow_iso() -> str:
    """UTC now, ISO-8601 (e.g. ``2026-07-05T12:00:00+00:00``) — logs / storage."""
    return datetime.now(timezone.utc).isoformat()


def utcnow_display() -> str:
    """UTC now, compact human form (e.g. ``2026-07-05 12:00:00Z``) — reports/UI."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")
