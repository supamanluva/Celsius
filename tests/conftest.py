"""Pytest-only test isolation for the stdlib-style test suite.

The tests here deliberately monkeypatch module-level callables directly
(e.g. ``mon.reeval.reevaluate = fake``) instead of using a fixture, so that
each file also runs standalone as ``python tests/test_x.py`` with no pytest
dependency — the CI "stdlib-only" guarantee. Standalone runs get isolation for
free: one process per file.

Under a single shared pytest session that isolation disappears, and a test that
reassigns ``reeval.reevaluate`` (and never restores it) leaks into every later
test that calls the real function. This autouse fixture restores any module-level
attribute a test reassigned, giving pytest runs the same per-test isolation the
standalone runners get. It only loads under pytest, so it does not affect the
standalone ``python tests/test_x.py`` path.
"""

import sys

import pytest


@pytest.fixture(autouse=True)
def _restore_celsius_module_state():
    # Shallow-snapshot the __dict__ of every already-imported celsius.* module.
    snapshots = {
        name: dict(mod.__dict__)
        for name, mod in list(sys.modules.items())
        if name.startswith("celsius") and getattr(mod, "__dict__", None) is not None
    }
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
