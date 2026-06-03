"""On-disk cache for LLM responses + a rough token/cost guard.

Identical (provider, model, prompt) requests return instantly and for free.
The budget guard is a soft cap: it estimates tokens (~4 chars/token) and refuses
to send once a per-run ceiling is exceeded, so an AI pass can't run away.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path
from typing import Optional

CACHE_DIR = Path(os.path.expanduser("~/.cache/celsius/ai"))
CACHE_TTL = 7 * 24 * 3600


def _key(provider: str, model: str, payload: str) -> str:
    h = hashlib.sha256(f"{provider}|{model}|{payload}".encode()).hexdigest()
    return h


def get(provider: str, model: str, payload: str) -> Optional[str]:
    f = CACHE_DIR / (_key(provider, model, payload) + ".txt")
    if not f.exists():
        return None
    try:
        if (time.time() - f.stat().st_mtime) > CACHE_TTL:
            return None
        return f.read_text()
    except OSError:
        return None


def put(provider: str, model: str, payload: str, response: str) -> None:
    try:
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        (CACHE_DIR / (_key(provider, model, payload) + ".txt")).write_text(response)
    except OSError:
        pass


def estimate_tokens(text: str) -> int:
    return max(1, len(text) // 4)


class Budget:
    """Soft per-run token ceiling. spent() accumulates est. input+output tokens."""

    def __init__(self, max_tokens: int = 200_000):
        self.max_tokens = max_tokens
        self._spent = 0

    def can_spend(self, est: int) -> bool:
        return (self._spent + est) <= self.max_tokens

    def add(self, est: int) -> None:
        self._spent += est

    def spent(self) -> int:
        return self._spent
