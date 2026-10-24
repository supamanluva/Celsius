"""Installer checks that never use sudo, install packages, or access the network."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "install.sh"

_STUB = """#!/usr/bin/env bash
set -euo pipefail
printf '%s' "${0##*/}" >> "$CELSIUS_TEST_LOG"
printf ' %s' "$@" >> "$CELSIUS_TEST_LOG"
printf '\\n' >> "$CELSIUS_TEST_LOG"
if [[ "${0##*/}" == "uv" && "${1:-}" == "sync" ]]; then
    mkdir -p .venv/bin
    for tool in celsius playwright python; do
        cp "$CELSIUS_TEST_STUB" ".venv/bin/$tool"
    done
fi
"""


def _checksum(archive: Path, sums: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["bash", "-c", 'source "$1"; verify_checksum "$2" "$3"',
         "bash", str(INSTALLER), str(archive), str(sums)],
        text=True, capture_output=True, timeout=10, check=False,
    )


def test_install_help():
    proc = subprocess.run(
        [str(INSTALLER), "--help"], cwd=ROOT,
        text=True, capture_output=True, timeout=10, check=False,
    )
    assert proc.returncode == 0, proc.stderr
    assert "Usage: ./install.sh" in proc.stdout
    assert "Nmap, Nuclei" in proc.stdout
    assert "Do not run as root" in proc.stdout


def test_install_checksum_verification():
    with tempfile.TemporaryDirectory(prefix="celsius-checksum-test-") as temp:
        archive = Path(temp) / "tool.tar.gz"
        sums = Path(temp) / "checksums.txt"
        archive.write_bytes(b"celsius installer test\n")
        digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        sums.write_text(f"{digest}  {archive.name}\n", encoding="utf-8")

        good = _checksum(archive, sums)
        assert good.returncode == 0, good.stderr

        archive.write_bytes(b"tampered\n")
        bad = _checksum(archive, sums)
        assert bad.returncode != 0
        assert "SHA-256 verification failed" in bad.stderr


def test_install_full_flow_with_mocks():
    if sys.platform != "linux":
        return

    with tempfile.TemporaryDirectory(prefix="celsius-install-test-") as temp:
        base = Path(temp)
        project = base / "project"
        home = base / "home"
        fake_bin = base / "bin"
        project.mkdir()
        home.mkdir()
        fake_bin.mkdir()
        script = project / "install.sh"
        shutil.copy2(INSTALLER, script)
        (project / "pyproject.toml").touch()
        (project / "uv.lock").touch()

        log = base / "commands.log"
        log.touch()
        stub = fake_bin / "tool-stub"
        stub.write_text(_STUB, encoding="utf-8")
        stub.chmod(0o755)
        for name in ("apt-get", "sudo", "uv", "nmap", "nuclei", "gitleaks",
                     "semgrep", "trufflehog", "curl"):
            (fake_bin / name).symlink_to(stub)

        env = os.environ.copy()
        env.update({
            "HOME": str(home),
            "PATH": str(fake_bin) + os.pathsep + env.get("PATH", ""),
            "CELSIUS_TEST_LOG": str(log),
            "CELSIUS_TEST_STUB": str(stub),
        })
        proc = subprocess.run(
            [str(script)], cwd=project, env=env,
            text=True, capture_output=True, timeout=30, check=False,
        )
        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert "Installation complete." in proc.stdout

        commands = log.read_text(encoding="utf-8").splitlines()
        playwright = project / ".venv" / "bin" / "playwright"
        assert commands == [
            "sudo -v",
            "sudo apt-get update",
            "sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y "
            "--no-install-recommends ca-certificates curl unzip python3 python3-venv",
            "uv python install 3.12",
            "uv sync --frozen --extra web --extra dynamic --no-dev --python 3.12",
            f"sudo {playwright} install-deps chromium",
            "playwright install chromium",
            "nuclei -update-templates",
            "celsius --version",
            "nmap --version",
            "nuclei -version",
            "gitleaks version",
            "semgrep --version",
            "trufflehog --version",
            "python -",
        ]


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items())
           if k.startswith("test_") and callable(v)]
    failed = 0
    for fn in fns:
        try:
            fn()
            print(f"PASS {fn.__name__}")
        except AssertionError as e:
            failed += 1
            print(f"FAIL {fn.__name__}: {e}")
    print(f"\n{len(fns) - failed}/{len(fns)} passed")
    sys.exit(1 if failed else 0)
