"""nmap wrapper for port + service/version detection.

Runs `nmap -sV` with XML output and parses out open ports and the detected
service name/product/version for each. With ``os_detect`` it also adds nmap OS
detection (``-O``) and parses the OS/device fingerprint (type, vendor, family) —
useful for identifying routers/firewalls/embedded devices. ``-O`` needs raw
sockets, so it is only added when running as root; otherwise the service scan
proceeds and a note is recorded.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import socket
import subprocess
import time
import xml.etree.ElementTree as ET
from dataclasses import asdict
from pathlib import Path
from typing import Optional

from .logsetup import get_logger
from .models import Service

_log = get_logger("nmap")

# Port state is an IP-level property, so scanning N hostnames that resolve to the
# same IP (e.g. a domain + its subdomains behind one server) re-runs nmap for an
# identical result. Cache parsed results per (IP, port-spec) and reuse them.
_CACHE_DIR = Path(os.path.expanduser("~/.cache/celsius/portscan"))
_CACHE_TTL = 6 * 3600


def _resolve(host: str) -> Optional[str]:
    try:
        return socket.gethostbyname(host)
    except (socket.gaierror, OSError):
        return None


def _cache_file(key: str) -> Path:
    return _CACHE_DIR / (hashlib.sha256(key.encode()).hexdigest() + ".json")


def _cache_get(key: str) -> Optional[dict]:
    f = _cache_file(key)
    try:
        if not f.exists() or (time.time() - f.stat().st_mtime) > _CACHE_TTL:
            return None
        data = json.loads(f.read_text())
        data["_age"] = int(time.time() - f.stat().st_mtime)
        return data
    except (OSError, json.JSONDecodeError):
        return None


def _cache_put(key: str, services: list[Service], os_info: dict) -> None:
    try:
        _CACHE_DIR.mkdir(parents=True, exist_ok=True)
        _cache_file(key).write_text(json.dumps(
            {"services": [asdict(s) for s in services], "os_info": os_info}))
    except OSError:
        pass


class NmapNotInstalled(RuntimeError):
    pass


def nmap_path() -> Optional[str]:
    return shutil.which("nmap")


def is_available() -> bool:
    return nmap_path() is not None


def _is_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0


def scan(
    host: str,
    *,
    top_ports: int = 100,
    ports: Optional[str] = None,
    timeout: int = 300,
    os_detect: bool = False,
    extra_args: Optional[list[str]] = None,
    resolved_ip: Optional[str] = None,
) -> tuple[list[Service], dict, list[str]]:
    """Run nmap service/version detection. Returns (services, os_info, errors).

    `ports` (e.g. "80,443,8080" or "1-1000") overrides `top_ports` if given.
    `os_detect` adds OS/device fingerprinting (`-O`); requires root, otherwise it
    is skipped with a note and `os_info` is empty.

    Results are cached per resolved IP + port-spec, so scanning several hostnames
    that share an IP only runs nmap once. Pass `resolved_ip` to reuse an
    already-resolved address (else it resolves `host` itself).
    """
    errors: list[str] = []
    path = nmap_path()
    if not path:
        raise NmapNotInstalled("nmap is not installed or not on PATH")

    # IP-level cache: reuse a recent scan of the same address.
    ip = resolved_ip or _resolve(host)
    cache_key = f"{ip}|{ports or 'top' + str(top_ports)}|os={int(bool(os_detect))}" if ip else None
    if cache_key:
        hit = _cache_get(cache_key)
        if hit is not None:
            services = [Service(**s) for s in hit.get("services", [])]
            note = (f"port scan reused from a recent scan of {ip} "
                    f"(shared by this host; cached {hit['_age']}s ago)")
            return services, hit.get("os_info") or {}, [note]

    cmd = [path, "-sV", "-Pn", "-T4", "-oX", "-"]
    if os_detect:
        if _is_root():
            # -O = OS detection; --osscan-guess pushes nmap to report close
            # matches even when confidence is below the default threshold.
            cmd += ["-O", "--osscan-guess"]
        else:
            errors.append(
                "OS detection (-O) requires root — run with sudo; "
                "skipping OS scan (service/version scan continues)"
            )
            os_detect = False
    if ports:
        cmd += ["-p", ports]
    else:
        cmd += ["--top-ports", str(top_ports)]
    if extra_args:
        cmd += extra_args
    cmd.append(host)

    _log.debug("running: %s", " ".join(cmd))
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, check=False
        )
    except subprocess.TimeoutExpired:
        _log.warning("nmap timed out after %ss scanning %s", timeout, host)
        return [], {}, [f"nmap timed out after {timeout}s scanning {host}"]
    except FileNotFoundError:
        raise NmapNotInstalled("nmap binary disappeared")

    _log.debug("nmap exit=%s, stdout=%d bytes", proc.returncode, len(proc.stdout))
    if proc.stderr.strip():
        _log.debug("nmap stderr: %s", proc.stderr.strip())
    if proc.returncode != 0 and not proc.stdout.strip():
        _log.warning("nmap failed (exit %s): %s", proc.returncode, proc.stderr.strip()[:300])
        return [], {}, [f"nmap failed (exit {proc.returncode}): {proc.stderr.strip()[:300]}"]

    try:
        root = ET.fromstring(proc.stdout)
    except ET.ParseError as e:
        return [], {}, [f"could not parse nmap XML: {e}"]

    services = _parse_xml(root)
    os_info = _parse_os(root) if os_detect else {}
    if cache_key:
        _cache_put(cache_key, services, os_info)
    return services, os_info, errors


def _parse_xml(root: ET.Element) -> list[Service]:
    services: list[Service] = []
    for host in root.findall("host"):
        for port in host.findall("./ports/port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            portid = port.get("portid")
            protocol = port.get("protocol")
            svc = port.find("service")
            if svc is None:
                services.append(Service(
                    name="unknown",
                    port=int(portid) if portid else None,
                    protocol=protocol,
                    source="nmap",
                ))
                continue

            name = svc.get("name") or "unknown"
            product = svc.get("product")
            version = svc.get("version")
            extrainfo = svc.get("extrainfo")
            # Prefer the product name (e.g. "nginx", "OpenSSH") for CVE matching.
            display_name = product or name
            services.append(Service(
                name=display_name,
                version=version,
                port=int(portid) if portid else None,
                protocol=protocol,
                product=product,
                source="nmap",
                extra={
                    "service": name,
                    "extrainfo": extrainfo or "",
                    "ostype": svc.get("ostype") or "",
                },
            ))
    return services


def _parse_os(root: ET.Element) -> dict:
    """Parse nmap's <os> block into a structured device/OS fingerprint.

    Returns {} when nmap reported no OS match. Each match carries the device
    `type` (e.g. router/firewall/WAP/general purpose) and `vendor`, which is what
    answers "what router/device is this?".
    """
    matches: list[dict] = []
    device_types: list[str] = []
    vendors: list[str] = []

    for host in root.findall("host"):
        os_el = host.find("os")
        if os_el is None:
            continue
        for osmatch in os_el.findall("osmatch"):
            cls = osmatch.find("osclass")
            entry = {
                "name": osmatch.get("name") or "",
                "accuracy": int(osmatch.get("accuracy") or 0),
                "type": cls.get("type") if cls is not None else None,
                "vendor": cls.get("vendor") if cls is not None else None,
                "osfamily": cls.get("osfamily") if cls is not None else None,
                "osgen": cls.get("osgen") if cls is not None else None,
                "cpe": [c.text for c in (cls.findall("cpe") if cls is not None else []) if c.text],
            }
            matches.append(entry)
            if entry["type"] and entry["type"] not in device_types:
                device_types.append(entry["type"])
            if entry["vendor"] and entry["vendor"] not in vendors:
                vendors.append(entry["vendor"])

    if not matches:
        return {}

    # nmap emits matches already sorted by accuracy; surface the best one.
    matches.sort(key=lambda m: m["accuracy"], reverse=True)
    return {
        "best_match": matches[0]["name"],
        "best_accuracy": matches[0]["accuracy"],
        "device_types": device_types,
        "vendors": vendors,
        "matches": matches[:8],
    }
