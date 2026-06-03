"""SQLite persistence for scans and findings (local-first).

Stores the full scan result as JSON for fidelity, plus a normalized `findings`
table for history/trend queries. Enables scan history and (later) temporal diff.
"""

from __future__ import annotations

import json
import os
import sqlite3
import uuid
from datetime import datetime, timezone
from typing import Optional

DEFAULT_DB = os.path.expanduser("~/.local/share/celsius/celsius.db")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id          TEXT PRIMARY KEY,
    target      TEXT NOT NULL,
    url         TEXT,
    ip          TEXT,
    started_at  TEXT,
    finished_at TEXT,
    created_at  TEXT NOT NULL,
    n_findings  INTEGER DEFAULT 0,
    n_cves      INTEGER DEFAULT 0,
    worst       TEXT,
    result_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS findings (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id   TEXT NOT NULL,
    kind      TEXT NOT NULL,          -- 'cve' | 'finding'
    severity  TEXT,
    title     TEXT,
    category  TEXT,
    ident     TEXT,                   -- CVE id or finding key
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target);
"""

_SEV_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class Store:
    def __init__(self, path: str = DEFAULT_DB):
        self.path = path
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
        except OSError:
            pass
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    def save_scan(self, result_dict: dict) -> str:
        scan_id = uuid.uuid4().hex[:12]
        cves = result_dict.get("cves", [])
        findings = result_dict.get("findings", [])
        worst = _worst_severity(cves, findings)
        self._conn.execute(
            "INSERT INTO scans (id, target, url, ip, started_at, finished_at, "
            "created_at, n_findings, n_cves, worst, result_json) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (scan_id, result_dict.get("target", ""), result_dict.get("url"),
             result_dict.get("ip"), result_dict.get("started_at"),
             result_dict.get("finished_at"), _now(), len(findings), len(cves),
             worst, json.dumps(result_dict)),
        )
        rows = []
        for c in cves:
            rows.append((scan_id, "cve", c.get("severity"), c.get("id"),
                         "cve", c.get("id")))
        for f in findings:
            rows.append((scan_id, "finding", f.get("severity"), f.get("title"),
                         f.get("category"), f.get("title")))
        self._conn.executemany(
            "INSERT INTO findings (scan_id, kind, severity, title, category, ident) "
            "VALUES (?,?,?,?,?,?)", rows)
        self._conn.commit()
        return scan_id

    def list_scans(self, target: Optional[str] = None, limit: int = 100) -> list[dict]:
        if target:
            cur = self._conn.execute(
                "SELECT id,target,url,ip,started_at,finished_at,n_findings,n_cves,worst "
                "FROM scans WHERE target=? ORDER BY created_at DESC LIMIT ?",
                (target, limit))
        else:
            cur = self._conn.execute(
                "SELECT id,target,url,ip,started_at,finished_at,n_findings,n_cves,worst "
                "FROM scans ORDER BY created_at DESC LIMIT ?", (limit,))
        return [dict(r) for r in cur.fetchall()]

    def get_scan(self, scan_id: str) -> Optional[dict]:
        cur = self._conn.execute("SELECT result_json FROM scans WHERE id=?", (scan_id,))
        row = cur.fetchone()
        return json.loads(row["result_json"]) if row else None

    def scans_for_domain(self, domain: str) -> list[dict]:
        """Latest stored scan (full result) per host for `domain` + its subdomains."""
        domain = domain.strip().lower().rstrip(".")
        if not domain:
            return []
        cur = self._conn.execute(
            "SELECT target, url, result_json FROM scans ORDER BY created_at DESC")
        seen: set[str] = set()
        out: list[dict] = []
        for row in cur.fetchall():
            host = _host_of(row["url"] or row["target"] or "")
            if not host or host in seen:
                continue
            if host == domain or host.endswith("." + domain):
                seen.add(host)
                try:
                    out.append(json.loads(row["result_json"]))
                except (json.JSONDecodeError, TypeError):
                    continue
        return out

    def close(self) -> None:
        self._conn.close()


def _host_of(target: str) -> str:
    """Bare hostname from a URL/target string (no scheme, userinfo, path, port)."""
    t = (target or "").strip().lower()
    if "://" in t:
        t = t.split("://", 1)[1]
    t = t.split("/")[0].split("@")[-1]
    if t.startswith("["):                 # IPv6 literal
        return t.split("]")[0].lstrip("[")
    return t.split(":")[0]


def _worst_severity(cves: list[dict], findings: list[dict]) -> str:
    # Low-confidence CVEs (over-broad NVD match or distro-backported package) are
    # reported but must not drive the headline severity — otherwise an unconfirmed
    # legacy CVE makes every box look CRITICAL.
    firm_cves = [c for c in cves if c.get("confidence", "firm") != "weak"]
    worst, rank = "INFO", -1
    for item in list(firm_cves) + list(findings):
        s = item.get("severity", "INFO")
        if _SEV_RANK.get(s, 0) > rank:
            worst, rank = s, _SEV_RANK.get(s, 0)
    return worst if (firm_cves or findings) else "NONE"
