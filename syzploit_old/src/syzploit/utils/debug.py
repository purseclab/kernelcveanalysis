"""
Debug logging helpers shared across syzploit subpackages.
"""

import sys


def debug_print(module: str, msg: str, enabled: bool = True) -> None:
    """
    Print a debug message to stderr if enabled.

    Args:
        module: Name of the module (e.g. "Synthesizer", "PDDLGenerator")
        msg: The debug message
        enabled: Whether to actually print
    """
    if enabled:
        print(f"[DEBUG:{module}] {msg}", file=sys.stderr)
