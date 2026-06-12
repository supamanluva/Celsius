"""Typosquat / lookalike-domain detection.

Active scanning can't see the domains *impersonating* you. This generates the
lookalike permutations attackers actually register for phishing — character
omission/transposition/repetition, homoglyphs (o->0, l->1, rn->m, …), hyphen
insertion, vowel swaps, and TLD swaps — then checks which ones are LIVE (resolve
to an IP), flagging mail-capable ones (MX present) as the highest phishing risk.

Passive: only DNS lookups of the generated names; nothing is sent to your domain
or to the lookalikes themselves. Stdlib-only (reuses the DoH resolver in recon.dns).
"""

from __future__ import annotations

import concurrent.futures
from typing import Callable, Optional

from .recon import dns as dns_mod

_TLDS = ["com", "net", "org", "co", "io", "info", "biz", "online", "site", "app",
         "xyz", "cc", "dev", "me", "shop", "store", "live", "email", "support", "login"]

# DNS-valid single-character look-alikes (letters/digits only).
_HOMO = {
    "o": ["0"], "0": ["o"], "l": ["1", "i"], "i": ["l", "1"], "1": ["l", "i"],
    "e": ["3"], "3": ["e"], "a": ["4"], "4": ["a"], "s": ["5"], "5": ["s"],
    "b": ["8"], "8": ["b"], "g": ["9"], "9": ["g"], "t": ["7"], "7": ["t"],
    "z": ["2"], "2": ["z"],
}
_BIGRAM = [("rn", "m"), ("m", "rn"), ("vv", "w"), ("w", "vv"), ("cl", "d"), ("nn", "m")]
_VOWELS = "aeiou"
_VALID = set("abcdefghijklmnopqrstuvwxyz0123456789-")


def registrable(domain: str) -> tuple[str, str]:
    """Naive split into (name, tld) using the last two labels — good enough for
    common gTLDs (ccTLD second-levels like co.uk are out of scope for v1)."""
    d = domain.strip().lower().rstrip(".")
    labels = d.split(".")
    if len(labels) >= 2:
        return labels[-2], labels[-1]
    return d, ""


def _valid_label(name: str) -> bool:
    return (0 < len(name) <= 63 and set(name) <= _VALID
            and not name.startswith("-") and not name.endswith("-"))


def _name_variants(name: str) -> set[str]:
    out: set[str] = set()
    n = len(name)
    # omission
    for i in range(n):
        out.add(name[:i] + name[i + 1:])
    # transposition (swap adjacent)
    for i in range(n - 1):
        out.add(name[:i] + name[i + 1] + name[i] + name[i + 2:])
    # repetition (double a char)
    for i in range(n):
        out.add(name[:i] + name[i] + name[i:])
    # single-char homoglyph
    for i, ch in enumerate(name):
        for sub in _HOMO.get(ch, []):
            out.add(name[:i] + sub + name[i + 1:])
    # bigram homoglyphs (rn<->m, vv<->w, …)
    for a, b in _BIGRAM:
        idx = name.find(a)
        while idx != -1:
            out.add(name[:idx] + b + name[idx + len(a):])
            idx = name.find(a, idx + 1)
    # hyphen insertion
    if n >= 4:
        for i in range(1, n):
            out.add(name[:i] + "-" + name[i:])
    # vowel swap
    for i, ch in enumerate(name):
        if ch in _VOWELS:
            for v in _VOWELS:
                if v != ch:
                    out.add(name[:i] + v + name[i + 1:])
    out.discard(name)
    return {v for v in out if _valid_label(v)}


def generate(domain: str, *, max_candidates: int = 1000) -> list[str]:
    """All lookalike domains for `domain` — permuted names on the same TLD, plus
    the original name on common other TLDs. Excludes the input domain."""
    name, tld = registrable(domain)
    cands: set[str] = set()
    for v in _name_variants(name):
        if tld:
            cands.add(f"{v}.{tld}")
    for t in _TLDS:                      # TLD swap (same name)
        if t != tld:
            cands.add(f"{name}.{t}")
    cands.discard(f"{name}.{tld}")
    return sorted(cands)[:max_candidates]


def check_live(domain: str, *, mail: bool = True) -> Optional[dict]:
    """Return {domain, ip, mail} if the lookalike resolves, else None."""
    addrs = dns_mod._query(domain, "A") or dns_mod._query(domain, "AAAA")
    if not addrs:
        return None
    res = {"domain": domain, "ip": addrs[0]}
    if mail:
        res["mail"] = bool(dns_mod._query(domain, "MX"))
    return res


def scan(domain: str, *, max_candidates: int = 1000, workers: int = 16,
         mail: bool = True, log: Callable[[str], None] = lambda _m: None) -> list[dict]:
    """Generate lookalikes and return the ones that are LIVE (resolve), mail-capable
    first. Concurrency is bounded; each lookup is a single DNS query."""
    cands = generate(domain, max_candidates=max_candidates)
    log(f"typosquat: checking {len(cands)} lookalike(s) for {domain} ...")
    live: list[dict] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        for r in ex.map(lambda d: check_live(d, mail=mail), cands):
            if r:
                live.append(r)
    live.sort(key=lambda r: (not r.get("mail"), r["domain"]))   # mail-capable first
    return live
