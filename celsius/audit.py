"""Append-only audit log.

Records scan lifecycle and every active (safe-active/exploit) probe, so there is
always an accountable trail of what celsius did against a target. JSON Lines,
one event per line, never rewritten.
"""

from __future__ import annotations

import json
import os
import threading
from datetime import datetime, timezone
from typing import Optional

DEFAULT_PATH = os.path.expanduser("~/.local/share/celsius/audit.log")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class AuditLog:
    def __init__(self, path: str = DEFAULT_PATH, scan_id: str = ""):
        self.path = path
        self.scan_id = scan_id
        self._lock = threading.Lock()
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
        except OSError:
            pass

    def event(self, kind: str, **fields) -> None:
        rec = {"ts": _now(), "scan_id": self.scan_id, "event": kind}
        rec.update(fields)
        line = json.dumps(rec, default=str)
        with self._lock:
            try:
                with open(self.path, "a") as fh:
                    fh.write(line + "\n")
            except OSError:
                pass  # auditing must never break a scan

    # convenience wrappers
    def scan_start(self, target: str, modes: list[str]) -> None:
        self.event("scan_start", target=target, modes=modes)

    def scan_end(self, target: str, findings: int, cves: int) -> None:
        self.event("scan_end", target=target, findings=findings, cves=cves)

    def active_probe(self, plugin: str, target: str, mode: str, detail: str = "") -> None:
        self.event("active_probe", plugin=plugin, target=target, mode=mode, detail=detail)

    def skipped(self, plugin: str, target: str, reason: str) -> None:
        self.event("skipped", plugin=plugin, target=target, reason=reason)


def read_recent(path: str = DEFAULT_PATH, limit: int = 200) -> list[dict]:
    if not os.path.exists(path):
        return []
    out: list[dict] = []
    try:
        with open(path) as fh:
            for line in fh:
                line = line.strip()
                if line:
                    try:
                        out.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
    except OSError:
        return []
    return out[-limit:]
