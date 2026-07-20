"""CVE verification via nuclei templates (A).

Given the CVEs found by version detection, run the matching nuclei CVE templates
(`-id <CVE>`) against the authorized target to CONFIRM which ones actually fire.
nuclei's CVE templates are written to be non-destructive — they detect/confirm a
vulnerable code path, they do not weaponize it — which is exactly the responsible
"demonstrate the hole" check.

This is a SAFE-ACTIVE operation: it sends real probes, so it is gated by the
engine's mode/scope rules.
"""

from __future__ import annotations

import json
import subprocess

from . import nuclei_scan


def verify_cves(url: str, cve_ids: list[str], *, timeout: int = 300
                ) -> tuple[set[str], list[dict], list[str]]:
    """Run nuclei restricted to the given CVE template ids.

    Returns (confirmed_ids, hit_details, errors). Only CVEs whose template exists
    AND fires against the target are returned as confirmed.
    """
    errors: list[str] = []
    path = nuclei_scan.nuclei_path()
    if not path:
        return set(), [], ["nuclei not installed — cannot verify CVEs"]
    if not cve_ids:
        return set(), [], []
    if not nuclei_scan.templates_installed():
        ok, msg = nuclei_scan.update_templates(path)
        if not ok:
            return set(), [], [f"nuclei templates unavailable: {msg}"]

    # nuclei matches CVE templates by id; pass all ids in one run.
    cmd = [path, "-target", url, "-jsonl", "-silent", "-disable-update-check"]
    for cid in cve_ids:
        cmd += ["-id", cid]

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        return set(), [], [f"nuclei CVE verification timed out after {timeout}s"]

    confirmed: set[str] = set()
    hits: list[dict] = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        tid = (obj.get("template-id") or "").upper()
        if tid.startswith("CVE-"):
            confirmed.add(tid)
            hits.append({"cve": tid, "matched_at": obj.get("matched-at", ""),
                         "name": (obj.get("info") or {}).get("name", "")})
    return confirmed, hits, errors
