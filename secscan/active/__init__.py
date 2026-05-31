"""Lab-mode active verification (EXPLOIT mode).

Non-destructive checks that CONFIRM or REFUTE a suspected vulnerability against an
explicitly authorized lab target. Every check is benign (unique markers, a single
quote, canary redirects, read-only reads); nothing is mutated or exfiltrated.

Gated by a layered safety harness (see harness.py): lab-mode flag + scope.yml
EXPLOIT entry + per-run attestation + dry-run preview + kill-switch + rate cap +
full audit of every request.
"""
