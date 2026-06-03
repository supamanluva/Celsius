"""Guard: pyproject.toml version must match celsius.__version__.

uv_build requires a static [project] version, but the source tree runs
uninstalled (CI does `python -m celsius --version`), so celsius/__init__.py
stays the runtime source of truth. This test fails loudly if the two drift.

Stdlib-only: run directly (`python tests/test_packaging.py`) or under pytest.
"""

from __future__ import annotations

import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from celsius import __version__  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _pyproject_version() -> str:
    path = os.path.join(ROOT, "pyproject.toml")
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    # Match the [project] `version = "..."` line (tomllib only landed in 3.11).
    m = re.search(r'(?m)^\s*version\s*=\s*"([^"]+)"', text)
    assert m, "no version field found in pyproject.toml"
    return m.group(1)


def test_pyproject_matches_dunder_version():
    proj = _pyproject_version()
    assert proj == __version__, (
        f"version drift: pyproject.toml={proj!r} vs "
        f"celsius.__version__={__version__!r} — bump both."
    )


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
