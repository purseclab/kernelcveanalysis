"""
core.log — Structured logging for syzploit.

Provides a ``console`` (rich.Console) and ``debug_print`` helper
shared across all modules.
"""

from __future__ import annotations

import sys

from rich.console import Console

console = Console(stderr=True)


def debug_print(module: str, msg: str, *, enabled: bool = True) -> None:
    """Print a bracketed debug message to stderr."""
    if enabled:
        print(f"[DEBUG:{module}] {msg}", file=sys.stderr)
