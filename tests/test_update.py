"""Safe updater integration tests using temporary local Git remotes."""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
UPDATER = ROOT / "update.sh"


def _environment() -> dict[str, str]:
    env = os.environ.copy()
    env.update({
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_TERMINAL_PROMPT": "0",
    })
    return env


def _git(cwd: Path, *args: object) -> str:
    proc = subprocess.run(
        ["git", "-C", str(cwd), *(str(arg) for arg in args)],
        text=True, capture_output=True, timeout=20, check=False, env=_environment(),
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    return proc.stdout.strip()


def _commit(repo: Path, message: str) -> None:
    _git(repo, "add", ".")
    _git(repo, "-c", "user.name=Celsius Tests",
         "-c", "user.email=celsius@example.invalid", "commit", "-m", message)


def _push(repo: Path) -> None:
    _git(repo, "push", "origin", "main")


def _updater(repo: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [str(repo / "update.sh")], cwd=repo,
        text=True, capture_output=True, timeout=30, check=False, env=_environment(),
    )


def _fixture(base: Path) -> tuple[Path, Path]:
    remote = base / "remote.git"
    publisher = base / "publisher"
    checkout = base / "checkout"
    publisher.mkdir()
    _git(base, "init", "--bare", "--initial-branch=main", remote)
    _git(publisher, "init", "--initial-branch=main")
    shutil.copy2(UPDATER, publisher / "update.sh")
    (publisher / "README.md").write_text("version one\n", encoding="utf-8")
    (publisher / "pyproject.toml").write_text("version = 1\n", encoding="utf-8")
    (publisher / ".gitignore").write_text(".venv/\n", encoding="utf-8")
    _commit(publisher, "initial")
    _git(publisher, "remote", "add", "origin", remote)
    _git(publisher, "push", "--set-upstream", "origin", "main")
    _git(base, "clone", remote, checkout)
    return publisher, checkout


def test_update_help():
    proc = subprocess.run(
        [str(UPDATER), "--help"], cwd=ROOT,
        text=True, capture_output=True, timeout=10, check=False,
    )
    assert proc.returncode == 0, proc.stderr
    assert "Usage: ./update.sh" in proc.stdout
    assert "fast-forward-only" in proc.stdout
    assert "never commits or pushes" in proc.stdout


def test_update_workflow_and_local_work_guards():
    if shutil.which("git") is None:
        return

    with tempfile.TemporaryDirectory(prefix="celsius-update-test-") as temp:
        publisher, checkout = _fixture(Path(temp))

        result = _updater(checkout)
        assert result.returncode == 0, result.stderr
        assert "up to date" in result.stdout

        ignored = checkout / ".venv"
        ignored.mkdir()
        (ignored / "runtime-data").write_text("keep this\n", encoding="utf-8")
        (publisher / "README.md").write_text("version two\n", encoding="utf-8")
        _commit(publisher, "code update")
        _push(publisher)
        result = _updater(checkout)
        assert result.returncode == 0, result.stderr
        assert "Updated to" in result.stdout
        assert (checkout / "README.md").read_text(encoding="utf-8") == "version two\n"
        assert (ignored / "runtime-data").is_file()

        (publisher / "pyproject.toml").write_text("version = 2\n", encoding="utf-8")
        _commit(publisher, "runtime update")
        _push(publisher)
        (checkout / "README.md").write_text("uncommitted local work\n", encoding="utf-8")
        head = _git(checkout, "rev-parse", "HEAD")
        result = _updater(checkout)
        assert result.returncode != 0
        assert "uncommitted or untracked" in result.stderr
        assert _git(checkout, "rev-parse", "HEAD") == head
        assert (checkout / "README.md").read_text(encoding="utf-8") == "uncommitted local work\n"

        _git(checkout, "restore", "README.md")
        result = _updater(checkout)
        assert result.returncode == 0, result.stderr
        assert "Runtime files changed" in result.stdout
        assert "./install.sh" in result.stdout
        assert "./kill.sh && ./run.sh" in result.stdout

        (checkout / "collision.txt").write_text("keep local file\n", encoding="utf-8")
        (publisher / "collision.txt").write_text("upstream file\n", encoding="utf-8")
        _commit(publisher, "add collision")
        _push(publisher)
        head = _git(checkout, "rev-parse", "HEAD")
        result = _updater(checkout)
        assert result.returncode != 0
        assert "uncommitted or untracked" in result.stderr
        assert _git(checkout, "rev-parse", "HEAD") == head
        assert (checkout / "collision.txt").read_text(encoding="utf-8") == "keep local file\n"

        (checkout / "collision.txt").unlink()
        result = _updater(checkout)
        assert result.returncode == 0, result.stderr
        assert (checkout / "collision.txt").read_text(encoding="utf-8") == "upstream file\n"

        (checkout / "local.txt").write_text("local commit\n", encoding="utf-8")
        _commit(checkout, "local commit")
        head = _git(checkout, "rev-parse", "HEAD")
        result = _updater(checkout)
        assert result.returncode == 0, result.stderr
        assert "ahead" in result.stdout
        assert _git(checkout, "rev-parse", "HEAD") == head

        (publisher / "README.md").write_text("diverged upstream\n", encoding="utf-8")
        _commit(publisher, "diverge")
        _push(publisher)
        result = _updater(checkout)
        assert result.returncode != 0
        assert "diverged" in result.stderr
        assert _git(checkout, "rev-parse", "HEAD") == head
        assert (checkout / "local.txt").read_text(encoding="utf-8") == "local commit\n"

        _git(checkout, "remote", "set-url", "origin", checkout.parent / "missing.git")
        result = _updater(checkout)
        assert result.returncode != 0
        assert "fetch failed" in result.stderr
        assert _git(checkout, "rev-parse", "HEAD") == head


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
