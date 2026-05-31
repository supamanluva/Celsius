"""Authorization scope: which targets may be scanned, and in which modes.

A scope.yml gates everything. Without one we fall back to a *permissive* scope
that allows passive + safe-active (but never exploit) for any target — the CLI
authorization prompt / web checkbox still applies. This keeps the local
single-user flow friction-free while making lab-mode exploitation opt-in and
explicit.

YAML is parsed with a tiny built-in reader if PyYAML is absent (stdlib-only core).
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from typing import Optional

from .plugins.base import Mode


@dataclass
class Scope:
    targets: dict[str, set[str]] = field(default_factory=dict)  # host -> {modes}
    exclusions: list[str] = field(default_factory=list)
    rate_limit_rps: int = 10
    permissive: bool = False
    authorized_by: str = ""

    @classmethod
    def permissive_default(cls) -> "Scope":
        return cls(permissive=True, rate_limit_rps=10)

    @classmethod
    def load(cls, path: str) -> "Scope":
        data = _read_yaml(path)
        targets: dict[str, set[str]] = {}
        for entry in data.get("targets", []) or []:
            if isinstance(entry, str):
                targets[entry.lower()] = {Mode.PASSIVE.value, Mode.SAFE_ACTIVE.value}
            elif isinstance(entry, dict):
                host = str(entry.get("host", "")).lower()
                if not host:
                    continue
                modes = entry.get("modes") or [Mode.PASSIVE.value]
                targets[host] = {str(m) for m in modes}
        return cls(
            targets=targets,
            exclusions=[str(x).lower() for x in (data.get("exclusions") or [])],
            rate_limit_rps=int(data.get("rate_limit_rps", 10)),
            authorized_by=str(data.get("authorized_by", "")),
        )

    def is_excluded(self, host: str) -> bool:
        host = (host or "").lower()
        return any(fnmatch.fnmatch(host, pat) for pat in self.exclusions)

    def allows(self, host: str, mode: Mode) -> bool:
        host = (host or "").lower()
        if self.is_excluded(host):
            return False
        if self.permissive:
            # everything except exploit is allowed without an explicit listing
            return mode.rank <= Mode.SAFE_ACTIVE.rank
        allowed = self.targets.get(host)
        if allowed is None:
            # try suffix/wildcard host matches
            for h, modes in self.targets.items():
                if fnmatch.fnmatch(host, h) or host == h:
                    allowed = modes
                    break
        if not allowed:
            return False
        return mode.value in allowed

    def reason(self, host: str, mode: Mode) -> str:
        if self.is_excluded(host):
            return f"{host} is excluded by scope"
        if self.permissive and mode == Mode.EXPLOIT:
            return "exploit mode requires an explicit scope.yml entry"
        if not self.permissive and host.lower() not in self.targets:
            return f"{host} is not listed in scope.yml"
        return f"mode '{mode.value}' not permitted for {host}"


# ---- minimal YAML reader (subset) --------------------------------------------

def _read_yaml(path: str) -> dict:
    try:
        import yaml  # type: ignore
        with open(path) as fh:
            return yaml.safe_load(fh) or {}
    except ImportError:
        with open(path) as fh:
            return _mini_yaml(fh.read())


def _mini_yaml(text: str) -> dict:
    """Parse the small subset of YAML used by scope.yml (keys, lists, host/modes).

    Supports: top-level key: value, key: with a list of '- item' or '- key: ...'
    dicts (one level), and inline [a, b] lists. Not a general YAML parser.
    """
    root: dict = {}
    lines = [ln.rstrip() for ln in text.splitlines()
             if ln.strip() and not ln.strip().startswith("#")]
    i = 0
    while i < len(lines):
        line = lines[i]
        indent = len(line) - len(line.lstrip())
        if indent == 0 and ":" in line:
            key, _, val = line.partition(":")
            key = key.strip()
            val = val.strip()
            if val:
                root[key] = _scalar_or_inline_list(val)
                i += 1
            else:
                items, i = _read_block(lines, i + 1, indent)
                root[key] = items
        else:
            i += 1
    return root


def _read_block(lines, i, parent_indent):
    items: list = []
    while i < len(lines):
        line = lines[i]
        indent = len(line) - len(line.lstrip())
        if indent <= parent_indent:
            break
        stripped = line.strip()
        if stripped.startswith("- "):
            rest = stripped[2:].strip()
            if ":" in rest and not rest.startswith("["):
                # dict item, possibly with following indented keys
                d: dict = {}
                k, _, v = rest.partition(":")
                d[k.strip()] = _scalar_or_inline_list(v.strip()) if v.strip() else None
                j = i + 1
                while j < len(lines):
                    l2 = lines[j]
                    ind2 = len(l2) - len(l2.lstrip())
                    if ind2 <= indent or l2.strip().startswith("- "):
                        break
                    k2, _, v2 = l2.strip().partition(":")
                    d[k2.strip()] = _scalar_or_inline_list(v2.strip())
                    j += 1
                items.append(d)
                i = j
            else:
                items.append(_scalar_or_inline_list(rest))
                i += 1
        else:
            i += 1
    return items, i


def _scalar_or_inline_list(v: str):
    if v.startswith("[") and v.endswith("]"):
        inner = v[1:-1].strip()
        return [x.strip().strip("'\"") for x in inner.split(",") if x.strip()]
    return v.strip().strip("'\"")


def load_scope(path: Optional[str]) -> Scope:
    if not path:
        return Scope.permissive_default()
    return Scope.load(path)
