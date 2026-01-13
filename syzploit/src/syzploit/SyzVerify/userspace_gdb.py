"""
Userspace GDB Python instrumentation for SyzVerify.

Responsibilities:
- Attach to a userspace gdbserver (e.g., :2345) and set breakpoints.
- Record function entry/exit events and selected syscalls.
- Optionally watch memory reads/writes for selected buffers.
- Provide a `us_export_results` command to dump collected events to JSON.

Usage inside GDB:
  (gdb) source /path/to/userspace_gdb.py
  (gdb) us_init /tmp/userspace_results.json
  (gdb) break main
  (gdb) continue
  ...
  (gdb) us_export_results  # writes JSON to configured path

Note: Keep dependencies minimal; rely on GDB Python API only.
"""

import gdb
import json
import time
from typing import Any, Dict, List, Optional


class _UserspaceEventLog:
    def __init__(self) -> None:
        self.events: List[Dict[str, Any]] = []
        self.output_path: Optional[str] = None

    def set_output(self, path: str) -> None:
        self.output_path = path

    def add(self, kind: str, **kwargs: Any) -> None:
        ev = {
            "ts": time.time(),
            "kind": kind,
        }
        ev.update(kwargs)
        self.events.append(ev)

    def export(self) -> str:
        data = {
            "userspace": {
                "events": self.events,
            }
        }
        s = json.dumps(data)
        if self.output_path:
            try:
                with open(self.output_path, "w") as f:
                    f.write(s)
            except Exception as e:
                gdb.write(f"[userspace_gdb] Failed to write results: {e}\n")
        return s


_log = _UserspaceEventLog()
_monitor_mode: bool = True

def _enable_logging_to_file(path: str) -> None:
    try:
        gdb.execute(f"set logging file {path}")
        gdb.execute("set logging overwrite on")
        gdb.execute("set logging enabled on")
        gdb.execute("set pagination off")
        try:
            gdb.execute("set timestamps on")
        except gdb.error:
            pass
        gdb.write(f"[userspace_gdb] GDB console logging -> {path}\n")
    except gdb.error as e:
        gdb.write(f"[userspace_gdb] Failed to enable logging: {e}\n")


def _safe_selected_frame() -> Optional[gdb.Frame]:
    try:
        return gdb.selected_frame()
    except gdb.error:
        return None


def _frame_info() -> Dict[str, Any]:
    f = _safe_selected_frame()
    if not f:
        return {"func": None, "pc": None}
    func = None
    try:
        func = f.name()
    except gdb.error:
        func = None
    pc = None
    try:
        pc = f.pc()
    except gdb.error:
        pc = None
    return {"func": func, "pc": pc}


class _FnEnterBreakpoint(gdb.Breakpoint):
    def __init__(self, spec: str) -> None:
        super().__init__(spec, internal=False)
        self.silent = True

    def stop(self) -> bool:
        info = _frame_info()
        _log.add("fn_enter", **info)
        return False  # continue unless user wants to interact


class _FnExitCatch(gdb.FinishBreakpoint):
    def __init__(self) -> None:
        super().__init__(internal=True)
        self.silent = True

    def stop(self) -> bool:
        info = _frame_info()
        # Try to get return value if available
        retval_str = None
        try:
            if hasattr(self, "retval") and self.retval is not None:
                retval_str = str(self.retval)
        except Exception:
            retval_str = None
        _log.add("fn_exit", **info, retval=retval_str)
        return False


class _SyscallBreakpoint(gdb.Breakpoint):
    def __init__(self, spec: str) -> None:
        super().__init__(spec, internal=False)
        self.silent = True

    def stop(self) -> bool:
        info = _frame_info()
        _log.add("syscall", **info)
        # Set a finish breakpoint to catch return
        try:
            _FnExitCatch()
        except gdb.error:
            pass
        return False


class UsInitCmd(gdb.Command):
    """
    us_init <output_json_path>
    Configure output file path and install default instrumentation:
    - Break at `main` entry
    - Trace common syscalls in libc wrappers if symbols are available
    """

    def __init__(self) -> None:
        super().__init__("us_init", gdb.COMMAND_USER)

    def invoke(self, arg: str, from_tty: bool) -> None:
        parts = arg.split()
        path = parts[0].strip() if parts else ""
        mode = parts[1].strip() if len(parts) > 1 else "monitor"
        if path:
            _log.set_output(path)
            gdb.write(f"[userspace_gdb] Output path: {path}\n")
        else:
            gdb.write("[userspace_gdb] No output path provided; will return JSON only.\n")
        # Also enable GDB console logging to a sibling .log file
        if path:
            _enable_logging_to_file(path + ".log")

        global _monitor_mode
        _monitor_mode = (mode.lower() == "monitor")

        if _monitor_mode:
            # Monitor mode: avoid breakpoints; keep non-stop off for remote compatibility
            try:
                gdb.execute("set non-stop off")
            except gdb.error:
                pass
            gdb.write("[userspace_gdb] Monitor mode enabled (no explicit breakpoints).\n")
        else:
            gdb.write("[userspace_gdb] Breakpoint mode disabled by default; pass non-monitor to enable.\n")


class UsExportResultsCmd(gdb.Command):
    """
    us_export_results
    Export the collected userspace events to the configured JSON path
    (or return the JSON string if no path was set).
    """

    def __init__(self) -> None:
        super().__init__("us_export_results", gdb.COMMAND_USER)

    def invoke(self, arg: str, from_tty: bool) -> None:
        s = _log.export()
        gdb.write("[userspace_gdb] Exported userspace results.\n")
        if not _log.output_path:
            gdb.write(s + "\n")


class UsMaybeContinueCmd(gdb.Command):
    """
    us_maybe_continue
    Attempt to continue execution; ignore errors if the program is not running.
    """

    def __init__(self) -> None:
        super().__init__("us_maybe_continue", gdb.COMMAND_USER)

    def invoke(self, arg: str, from_tty: bool) -> None:
        try:
            gdb.execute("continue")
        except gdb.error as e:
            gdb.write(f"[userspace_gdb] continue skipped: {e}\n")


class UsTryBreakCmd(gdb.Command):
    """
    us_try_break <spec>
    Try to set a breakpoint; ignore errors if symbol not found or target not ready.
    """

    def __init__(self) -> None:
        super().__init__("us_try_break", gdb.COMMAND_USER)

    def invoke(self, arg: str, from_tty: bool) -> None:
        spec = arg.strip()
        if not spec:
            gdb.write("[userspace_gdb] usage: us_try_break <spec>\n")
            return
        try:
            _ = gdb.Breakpoint(spec, internal=False)
        except gdb.error as e:
            gdb.write(f"[userspace_gdb] break '{spec}' skipped: {e}\n")


def _on_stop_handler(event: Any) -> None:
    # Generic stop logger that auto-continues
    info = _frame_info()
    _log.add("stop", **info)
    # Auto-continue in monitor mode to avoid interactive halts
    if _monitor_mode:
        try:
            gdb.execute("continue")
        except gdb.error:
            pass


# Register commands on import
UsInitCmd()
UsExportResultsCmd()
UsMaybeContinueCmd()
UsTryBreakCmd()
gdb.events.stop.connect(_on_stop_handler)
