"""
core.log — Structured logging for syzploit.

Provides a ``console`` (rich.Console) and ``debug_print`` helper
shared across all modules.  When ``enable_file_logging()`` is called,
ALL console output is tee'd to a log file in the work directory.
"""

from __future__ import annotations

import io
import sys
from pathlib import Path
from typing import Optional

from rich.console import Console


class _TeeFile:
    """Write to both a file and the original stream."""

    def __init__(self, stream, logfile):
        self._stream = stream
        self._logfile = logfile

    def write(self, data):
        self._stream.write(data)
        try:
            self._logfile.write(data)
            self._logfile.flush()
        except Exception:
            pass
        return len(data)

    def flush(self):
        self._stream.flush()
        try:
            self._logfile.flush()
        except Exception:
            pass

    def fileno(self):
        return self._stream.fileno()

    def isatty(self):
        return self._stream.isatty()

    def __getattr__(self, name):
        return getattr(self._stream, name)


console = Console(stderr=True)

# File handle kept alive for the duration of the process
_log_file_handle: Optional[io.TextIOWrapper] = None
_log_console: Optional[Console] = None


def enable_file_logging(work_dir: str) -> Path:
    """Start capturing ALL console output to ``<work_dir>/output.log``.

    Must be called early — before any tools run.  Tee's stderr
    (where Rich writes) and stdout so both console output and
    subprocess output are captured.
    """
    global console, _log_file_handle, _log_console

    log_path = Path(work_dir) / "output.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    _log_file_handle = open(log_path, "a", encoding="utf-8")

    # Tee stderr (Rich console writes here) and stdout
    sys.stderr = _TeeFile(sys.stderr, _log_file_handle)
    sys.stdout = _TeeFile(sys.stdout, _log_file_handle)

    # Recreate the console so it picks up the new stderr
    console = Console(stderr=True)

    return log_path


def debug_print(module: str, msg: str, *, enabled: bool = True) -> None:
    """Print a bracketed debug message to stderr."""
    if enabled:
        print(f"[DEBUG:{module}] {msg}", file=sys.stderr)
