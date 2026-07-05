"""Pytest-only test isolation for the stdlib-style test suite.

The tests here deliberately monkeypatch module-level callables directly
(e.g. ``mon.reeval.reevaluate = fake``, or ``P.subprocess.run = fake`` reaching a
stdlib module through a celsius reference) instead of using a fixture, so that
each file also runs standalone as ``python tests/test_x.py`` with no pytest
dependency — the CI "stdlib-only" guarantee. Standalone runs get isolation for
free: one process per file.

Under a single shared pytest session that isolation disappears, and a test that
reassigns e.g. ``reeval.reevaluate`` (and never restores it) leaks into every
later test that calls the real function. This autouse fixture restores any
module-level attribute a test reassigned, giving pytest runs the same per-test
isolation the standalone runners get. It only loads under pytest, so it does not
affect the standalone ``python tests/test_x.py`` path.

Coverage: every already-imported ``celsius.*`` module, plus the specific stdlib
modules the suite patches through a celsius reference (``subprocess``/``socket``/
``time``/``urllib.request``) — otherwise a patch like ``P.subprocess.run = fake``
would leak into a later subprocess-using test and pass it on fake data.
"""

import sys

import pytest

# stdlib modules the suite monkeypatches via a celsius reference (portscan's
# subprocess, crawler's time/urllib, subdomain enum's socket). Snapshotted so
# those reassignments are restored too, not just celsius.* ones.
_EXTRA_MODULES = ("subprocess", "socket", "time", "urllib.request")


def _tracked_modules():
    for name, mod in list(sys.modules.items()):
        if getattr(mod, "__dict__", None) is None:
            continue
        if name.startswith("celsius") or name in _EXTRA_MODULES:
            yield name, mod


@pytest.fixture(autouse=True)
def _restore_module_state():
    # Shallow-snapshot each tracked module's __dict__ before the test.
    snapshots = {name: dict(mod.__dict__) for name, mod in _tracked_modules()}
    yield
    # Restore attributes the test reassigned to a different object. The pollution
    # in this suite is always reassignment of an existing module-level callable,
    # so restoring changed keys is sufficient (and safer than deleting keys that
    # a lazy import may have legitimately added).
    for name, saved in snapshots.items():
        mod = sys.modules.get(name)
        if mod is None:
            continue
        current = mod.__dict__
        for key, original in saved.items():
            if current.get(key, original) is not original:
                current[key] = original
