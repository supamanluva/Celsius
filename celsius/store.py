"""SQLite persistence for scans and findings (local-first).

Stores the full scan result as JSON for fidelity, plus a normalized `findings`
table for history/trend queries. Enables scan history and (later) temporal diff.
"""

from __future__ import annotations

import json
import os
import sqlite3
import uuid
from typing import Optional

from . import grade
from .models import severity_rank
from .timeutil import utcnow_iso as _now

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
        # Lightweight migration: grade/score are stored at save time so the
        # history list can show them without re-parsing 50 result_json blobs.
        cols = {r[1] for r in self._conn.execute("PRAGMA table_info(scans)")}
        if "grade" not in cols:
            self._conn.execute("ALTER TABLE scans ADD COLUMN grade TEXT")
            self._conn.execute("ALTER TABLE scans ADD COLUMN score INTEGER")
        self._conn.commit()

    def save_scan(self, result_dict: dict) -> str:
        scan_id = uuid.uuid4().hex[:12]
        cves = result_dict.get("cves", [])
        findings = result_dict.get("findings", [])
        worst = _worst_severity(cves, findings)
        assessment = grade.assess(result_dict)
        self._conn.execute(
            "INSERT INTO scans (id, target, url, ip, started_at, finished_at, "
            "created_at, n_findings, n_cves, worst, grade, score, result_json) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (scan_id, result_dict.get("target", ""), result_dict.get("url"),
             result_dict.get("ip"), result_dict.get("started_at"),
             result_dict.get("finished_at"), _now(), len(findings), len(cves),
             worst, assessment["grade"], assessment["score"],
             json.dumps(result_dict)),
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

    def list_scans(self, target: Optional[str] = None, limit: int = 100,
                   offset: int = 0, exact: bool = False) -> list[dict]:
        """History rows, newest first. `target` filters case-insensitively by
        substring (LIKE with escaped wildcards, so a literal '%' in the query
        can't widen the match); `exact=True` keeps the old whole-string match
        (used by the temporal diff, which must compare the same target)."""
        cols = ("id,target,url,ip,started_at,finished_at,n_findings,n_cves,"
                "worst,grade,score")
        if target and exact:
            cur = self._conn.execute(
                f"SELECT {cols} FROM scans WHERE target=? "
                "ORDER BY created_at DESC LIMIT ? OFFSET ?",
                (target, limit, offset))
        elif target:
            pat = "%" + _escape_like(target.lower()) + "%"
            cur = self._conn.execute(
                f"SELECT {cols} FROM scans WHERE lower(target) LIKE ? ESCAPE '\\' "
                "ORDER BY created_at DESC LIMIT ? OFFSET ?",
                (pat, limit, offset))
        else:
            cur = self._conn.execute(
                f"SELECT {cols} FROM scans ORDER BY created_at DESC LIMIT ? OFFSET ?",
                (limit, offset))
        return [dict(r) for r in cur.fetchall()]

    def delete_scan(self, scan_id: str) -> bool:
        """Remove one scan (and its findings rows) from history. False if absent."""
        cur = self._conn.execute("DELETE FROM scans WHERE id=?", (scan_id,))
        if cur.rowcount:
            self._conn.execute("DELETE FROM findings WHERE scan_id=?", (scan_id,))
            self._conn.commit()
            return True
        return False

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


def _escape_like(s: str) -> str:
    """Escape LIKE wildcards so user input matches literally (ESCAPE '\\')."""
    return s.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


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
    # AI hypotheses are explicit "leads, not facts" — also kept out of the
    # headline so an unverified guess can't flip the box to CRITICAL.
    firm_cves = [c for c in cves if c.get("confidence", "firm") != "weak"]
    real_findings = [f for f in findings if f.get("category") != "ai-hypothesis"]
    worst, rank = "INFO", -1
    for item in list(firm_cves) + list(real_findings):
        s = item.get("severity", "INFO")
        if severity_rank(s) > rank:
            worst, rank = s, severity_rank(s)
    return worst if (firm_cves or real_findings) else "NONE"
