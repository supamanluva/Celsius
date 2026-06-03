"""nmap wrapper for port + service/version detection.

Runs `nmap -sV` with XML output and parses out open ports and the detected
service name/product/version for each. With ``os_detect`` it also adds nmap OS
detection (``-O``) and parses the OS/device fingerprint (type, vendor, family) —
useful for identifying routers/firewalls/embedded devices. ``-O`` needs raw
sockets, so it is only added when running as root; otherwise the service scan
proceeds and a note is recorded.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import xml.etree.ElementTree as ET
from typing import Optional

from .logsetup import get_logger
from .models import Service

_log = get_logger("nmap")


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
) -> tuple[list[Service], dict, list[str]]:
    """Run nmap service/version detection. Returns (services, os_info, errors).

    `ports` (e.g. "80,443,8080" or "1-1000") overrides `top_ports` if given.
    `os_detect` adds OS/device fingerprinting (`-O`); requires root, otherwise it
    is skipped with a note and `os_info` is empty.
    """
    errors: list[str] = []
    path = nmap_path()
    if not path:
        raise NmapNotInstalled("nmap is not installed or not on PATH")

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
                    name=f"unknown",
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
