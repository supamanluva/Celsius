"""AI layer: provider-agnostic LLM access for analysis tasks.

DeepSeek is the default provider, behind an abstraction so OpenAI/Anthropic/local
models are drop-in. Privacy: secret redaction before send is **default ON** —
secrets are masked to typed placeholders (covering the active loop's live response
bodies / tool evidence, not just the scan summary) so values don't egress to the
provider; `--ai-no-redact` opts out on a target you own. Every external send is
logged with the masking state and a sensitive-content count.
"""

from .provider import (  # noqa: F401
    AIError,
    LLMProvider,
    Message,
    available_providers,
    get_provider,
)
