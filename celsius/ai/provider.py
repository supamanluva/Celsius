"""LLM provider abstraction + concrete providers (stdlib HTTP only).

Providers:
  deepseek   OpenAI-compatible chat API at api.deepseek.com (default)
  openai     OpenAI chat API
  local      Ollama / any OpenAI-compatible server (default localhost:11434)
  anthropic  Anthropic Messages API
  mock       deterministic, offline — for tests and dry runs

Selection: get_provider(name, model=..., api_key=..., base_url=...). API keys fall
back to env vars (DEEPSEEK_API_KEY / OPENAI_API_KEY / ANTHROPIC_API_KEY).
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Optional


class AIError(RuntimeError):
    pass


@dataclass
class Message:
    role: str   # "system" | "user" | "assistant"
    content: str


class LLMProvider:
    name = "base"
    default_model = ""

    def __init__(self, model: Optional[str] = None, api_key: Optional[str] = None,
                 base_url: Optional[str] = None, timeout: int = 120):
        self.model = model or self.default_model
        self.api_key = api_key
        self.base_url = base_url
        self.timeout = timeout

    def available(self) -> tuple[bool, str]:
        """(usable, reason-if-not). Default: needs an API key."""
        if not self.api_key:
            return False, f"no API key (set {self._env_var()})"
        return True, ""

    def _env_var(self) -> str:
        return f"{self.name.upper()}_API_KEY"

    def complete(self, messages: list[Message], *, json_mode: bool = False,
                 temperature: float = 0.2, max_tokens: int = 4096) -> str:
        raise NotImplementedError


# ---- HTTP helper --------------------------------------------------------------

def _post_json(url: str, payload: dict, headers: dict, timeout: int) -> dict:
    data = json.dumps(payload).encode()
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        body = ""
        try:
            body = e.read().decode()[:400]
        except Exception:
            pass
        raise AIError(f"HTTP {e.code} from {url}: {body}")
    except (urllib.error.URLError, OSError) as e:
        raise AIError(f"request to {url} failed: {e}")
    except json.JSONDecodeError as e:
        raise AIError(f"invalid JSON from {url}: {e}")


# ---- OpenAI-compatible (OpenAI, DeepSeek, Ollama) -----------------------------

class OpenAICompatProvider(LLMProvider):
    name = "openai-compat"
    default_model = "gpt-4o-mini"
    default_base_url = "https://api.openai.com/v1"
    supports_json_mode = True

    def __init__(self, **kw):
        super().__init__(**kw)
        if not self.base_url:
            self.base_url = self.default_base_url

    def complete(self, messages, *, json_mode=False, temperature=0.2, max_tokens=4096) -> str:
        payload = {
            "model": self.model,
            "messages": [{"role": m.role, "content": m.content} for m in messages],
            "temperature": temperature,
            "max_tokens": max_tokens,
            "stream": False,
        }
        if json_mode and self.supports_json_mode:
            payload["response_format"] = {"type": "json_object"}
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        data = _post_json(f"{self.base_url}/chat/completions", payload, headers, self.timeout)
        try:
            return data["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError):
            raise AIError(f"unexpected response shape: {json.dumps(data)[:300]}")


class DeepSeekProvider(OpenAICompatProvider):
    name = "deepseek"
    default_model = "deepseek-chat"
    default_base_url = "https://api.deepseek.com"

    def _env_var(self) -> str:
        return "DEEPSEEK_API_KEY"


class OpenAIProvider(OpenAICompatProvider):
    name = "openai"
    default_model = "gpt-4o-mini"
    default_base_url = "https://api.openai.com/v1"


class LocalProvider(OpenAICompatProvider):
    """Ollama / llama.cpp — OpenAI-compatible. Nothing leaves the machine."""
    name = "local"
    default_model = "llama3.1"
    default_base_url = "http://localhost:11434/v1"
    supports_json_mode = False  # many local servers ignore response_format

    def available(self) -> tuple[bool, str]:
        return True, ""  # no API key needed; assume a local server is running

    def _env_var(self) -> str:
        return "LOCAL_LLM_KEY"


# ---- Anthropic ----------------------------------------------------------------

class AnthropicProvider(LLMProvider):
    name = "anthropic"
    default_model = "claude-sonnet-4-6"
    base = "https://api.anthropic.com/v1/messages"

    def complete(self, messages, *, json_mode=False, temperature=0.2, max_tokens=4096) -> str:
        system = " ".join(m.content for m in messages if m.role == "system")
        convo = [{"role": m.role, "content": m.content}
                 for m in messages if m.role in ("user", "assistant")]
        payload = {"model": self.model, "max_tokens": max_tokens,
                   "temperature": temperature, "messages": convo}
        if system:
            payload["system"] = system + (
                "\nRespond with a single valid JSON object and nothing else." if json_mode else "")
        headers = {
            "Content-Type": "application/json",
            "x-api-key": self.api_key or "",
            "anthropic-version": "2023-06-01",
        }
        data = _post_json(self.base, payload, headers, self.timeout)
        try:
            return "".join(blk.get("text", "") for blk in data["content"])
        except (KeyError, TypeError):
            raise AIError(f"unexpected response shape: {json.dumps(data)[:300]}")


# ---- Mock (offline, deterministic) -------------------------------------------

class MockProvider(LLMProvider):
    name = "mock"
    default_model = "mock-1"

    def __init__(self, canned: Optional[str] = None, **kw):
        super().__init__(**kw)
        self._canned = canned

    def available(self) -> tuple[bool, str]:
        return True, ""

    def complete(self, messages, *, json_mode=False, temperature=0.2, max_tokens=4096) -> str:
        if self._canned is not None:
            return self._canned
        # Echo a minimal, schema-shaped JSON so analyze code paths can be tested
        # without a live API.
        user = next((m.content for m in reversed(messages) if m.role == "user"), "")
        marker = "code" if "SOURCE" in user or "file" in user.lower() else "triage"
        if marker == "code":
            return json.dumps({"findings": [{
                "title": "Mock: potential injection",
                "severity": "MEDIUM", "confidence": "low",
                "file": "unknown", "line": 0,
                "description": "Mock provider output (no live model).",
                "verification": "Manually review the flagged sink.",
            }]})
        return json.dumps({
            "summary": "Mock triage summary (no live model configured).",
            "prioritized": [], "likely_false_positives": [], "hypotheses": [],
        })


# ---- factory ------------------------------------------------------------------

_PROVIDERS = {
    "deepseek": DeepSeekProvider,
    "openai": OpenAIProvider,
    "local": LocalProvider,
    "anthropic": AnthropicProvider,
    "mock": MockProvider,
}

_ENV_KEYS = {
    "deepseek": "DEEPSEEK_API_KEY",
    "openai": "OPENAI_API_KEY",
    "anthropic": "ANTHROPIC_API_KEY",
}


def available_providers() -> list[str]:
    return list(_PROVIDERS)


def get_provider(name: str = "deepseek", *, model: Optional[str] = None,
                 api_key: Optional[str] = None, base_url: Optional[str] = None,
                 timeout: int = 120) -> LLMProvider:
    name = (name or "deepseek").lower()
    cls = _PROVIDERS.get(name)
    if cls is None:
        raise AIError(f"unknown AI provider '{name}'. Options: {', '.join(_PROVIDERS)}")
    if api_key is None and name in _ENV_KEYS:
        api_key = os.environ.get(_ENV_KEYS[name])
    _validate_base_url(base_url, name)
    return cls(model=model, api_key=api_key, base_url=base_url, timeout=timeout)


def _validate_base_url(base_url: Optional[str], provider: str) -> None:
    """A user-supplied base_url receives the full prompt (scan findings, source,
    detected secrets) plus the Authorization bearer key. Require https:// so a
    typo'd or hostile http endpoint can't silently exfiltrate that data; allow
    plain http only for an explicitly local server."""
    if not base_url:
        return
    from urllib.parse import urlparse
    u = urlparse(base_url.strip())
    if u.scheme not in ("http", "https"):
        raise AIError(f"invalid AI base_url scheme '{u.scheme or '?'}' — use https://")
    host = (u.hostname or "").lower()
    is_local = host in ("localhost", "127.0.0.1", "::1") or provider == "local"
    if u.scheme == "http" and not is_local:
        raise AIError(
            "refusing to send scan data + API key over plain http to a non-local "
            f"AI endpoint ({host or base_url!r}); use https:// (or the 'local' provider).")
