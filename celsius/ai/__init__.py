"""AI layer: provider-agnostic LLM access for analysis tasks.

DeepSeek is the default provider, behind an abstraction so OpenAI/Anthropic/local
models are drop-in. Privacy: redaction before send is OPTIONAL and default OFF —
the goal is maximum detection, and findings go to the asset owner to remediate
(see plan.md §4 and the redaction toggle). Every external send is logged.
"""

from .provider import (  # noqa: F401
    AIError,
    LLMProvider,
    Message,
    available_providers,
    get_provider,
)
