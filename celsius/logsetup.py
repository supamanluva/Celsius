"""Central logging setup: a persistent rotating file log plus a level-controlled
console (stderr) stream, shared by the CLI and the web app.

Every scan is always traced to ``~/.local/share/celsius/scan.log`` regardless of
whether stderr is a TTY, so there is a durable record of what ran and what
errored. Console verbosity is controlled by ``-v/--verbose`` and ``--debug``;
``--quiet`` silences everything below ERROR. The file always captures DEBUG.

Use ``get_logger("nmap")`` etc. in modules to emit detail (commands, subprocess
stderr) that lands in the file log and, at -v/--debug, on the console too.
"""

from __future__ import annotations

import logging
import logging.handlers
import os
import sys
from typing import Optional

LOGGER_NAME = "celsius"
DEFAULT_LOG_FILE = os.path.expanduser("~/.local/share/celsius/scan.log")

_configured = False

_PREFIX = {
    logging.DEBUG: "[d]",
    logging.INFO: "[*]",
    logging.WARNING: "[!]",
    logging.ERROR: "[!]",
    logging.CRITICAL: "[!]",
}


class _ConsoleFormatter(logging.Formatter):
    """Terminal-friendly: a short level prefix, plus the child name in debug."""

    def __init__(self, show_source: bool = False):
        super().__init__()
        self.show_source = show_source

    def format(self, record: logging.LogRecord) -> str:
        prefix = _PREFIX.get(record.levelno, "[*]")
        msg = record.getMessage()
        if self.show_source and record.name != LOGGER_NAME:
            child = record.name.split(".", 1)[-1]
            msg = f"{child}: {msg}"
        return f"{prefix} {msg}"


def setup_logging(
    *,
    verbose: bool = False,
    debug: bool = False,
    quiet: bool = False,
    log_file: Optional[str] = None,
) -> logging.Logger:
    """Configure the ``celsius`` logger once. Idempotent: later calls return the
    existing logger without adding duplicate handlers."""
    global _configured
    logger = logging.getLogger(LOGGER_NAME)
    logger.setLevel(logging.DEBUG)  # handlers do the filtering
    logger.propagate = False
    if _configured:
        return logger

    # Always-on rotating file handler (independent of TTY).
    path = log_file or DEFAULT_LOG_FILE
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        fh = logging.handlers.RotatingFileHandler(
            path, maxBytes=2_000_000, backupCount=3, encoding="utf-8"
        )
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(logging.Formatter(
            "%(asctime)s %(levelname)-7s %(name)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        ))
        logger.addHandler(fh)
    except OSError:
        pass  # logging must never break a scan

    # Console handler on stderr.
    ch = logging.StreamHandler(sys.stderr)
    if quiet:
        ch.setLevel(logging.ERROR)
    elif debug:
        ch.setLevel(logging.DEBUG)
    elif verbose:
        ch.setLevel(logging.INFO)
    else:
        # Default mirrors the old behaviour: progress on a TTY, quiet when piped.
        ch.setLevel(logging.INFO if sys.stderr.isatty() else logging.WARNING)
    ch.setFormatter(_ConsoleFormatter(show_source=debug))
    logger.addHandler(ch)

    _configured = True
    logger.debug("logging initialised (file=%s)", path)
    return logger


def get_logger(name: Optional[str] = None) -> logging.Logger:
    """Return the shared logger, or a named child (``celsius.<name>``)."""
    base = logging.getLogger(LOGGER_NAME)
    return base.getChild(name) if name else base
