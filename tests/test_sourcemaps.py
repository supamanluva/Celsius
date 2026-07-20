"""Tests for source-map recovery and the secret scan over recovered source.

scan_recovered() is network-free (it scans an in-memory dict), and is pinned
here because it must scan in "frontend" context: JWTs carrying an `exp` claim
in recovered browser source are short-lived session tokens and downgrade to
LOW, not MEDIUM. Stdlib-only: run directly (`python tests/test_sourcemaps.py`)
or under pytest.
"""

from __future__ import annotations

import base64
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from celsius.models import Severity  # noqa: E402
from celsius.recon import sourcemaps as sm  # noqa: E402


def _jwt(payload: dict) -> str:
    """Build an unsigned JWT-shaped token (header.payload.sig) for testing."""
    def seg(obj) -> str:
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip("=")
    # The signature segment must be non-repetitive or _PLACEHOLDER rejects the token.
    return f"{seg({'alg': 'HS256', 'typ': 'JWT'})}.{seg(payload)}.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJVadQssw5c"


def test_recovered_jwt_with_exp_downgrades_to_low():
    token = _jwt({"sub": "user1", "exp": 1893456000})
    findings = sm.scan_recovered({"app.js": f'const token = "{token}";'})
    jwt_hits = [f for f in findings if "JWT" in f.title or "token" in f.title.lower()]
    assert jwt_hits, "JWT in recovered source must be reported"
    assert all(f.severity == Severity.LOW for f in jwt_hits)


def test_recovered_jwt_without_exp_stays_medium():
    token = _jwt({"sub": "user1"})
    findings = sm.scan_recovered({"app.js": f'const token = "{token}";'})
    jwt_hits = [f for f in findings if "JWT" in f.title or "token" in f.title.lower()]
    assert jwt_hits
    assert all(f.severity == Severity.MEDIUM for f in jwt_hits)


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
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
