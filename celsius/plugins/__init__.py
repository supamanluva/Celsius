"""Plugin system for celsius checks.

A check is a Plugin with metadata (id, phase, required mode). The engine builds a
ScanContext, then runs the registered plugins in phase order, skipping any whose
required mode is not permitted by scope/config. Plugins mutate the shared
ScanResult on the context.

Import `celsius.plugins.builtin` to register the built-in checks.
"""

from .base import (  # noqa: F401
    Mode,
    Phase,
    Plugin,
    ScanContext,
    all_plugins,
    register,
)
