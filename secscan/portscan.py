"""nmap wrapper for port + service/version detection.

Runs `nmap -sV` with XML output and parses out open ports and the detected
service name/product/version for each.
"""

from __future__ import annotations

import shutil
import subprocess
import xml.etree.ElementTree as ET
from typing import Optional

from .models import Service


class NmapNotInstalled(RuntimeError):
    pass


def nmap_path() -> Optional[str]:
    return shutil.which("nmap")


def is_available() -> bool:
    return nmap_path() is not None


def scan(
    host: str,
    *,
    top_ports: int = 100,
    ports: Optional[str] = None,
    timeout: int = 300,
    extra_args: Optional[list[str]] = None,
) -> tuple[list[Service], list[str]]:
    """Run nmap service/version detection. Returns (services, errors).

    `ports` (e.g. "80,443,8080" or "1-1000") overrides `top_ports` if given.
    """
    errors: list[str] = []
    path = nmap_path()
    if not path:
        raise NmapNotInstalled("nmap is not installed or not on PATH")

    cmd = [path, "-sV", "-Pn", "-T4", "-oX", "-"]
    if ports:
        cmd += ["-p", ports]
    else:
        cmd += ["--top-ports", str(top_ports)]
    if extra_args:
        cmd += extra_args
    cmd.append(host)

    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, check=False
        )
    except subprocess.TimeoutExpired:
        return [], [f"nmap timed out after {timeout}s scanning {host}"]
    except FileNotFoundError:
        raise NmapNotInstalled("nmap binary disappeared")

    if proc.returncode != 0 and not proc.stdout.strip():
        return [], [f"nmap failed (exit {proc.returncode}): {proc.stderr.strip()[:300]}"]

    try:
        services = _parse_xml(proc.stdout)
    except ET.ParseError as e:
        return [], [f"could not parse nmap XML: {e}"]

    return services, errors


def _parse_xml(xml_text: str) -> list[Service]:
    services: list[Service] = []
    root = ET.fromstring(xml_text)
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
