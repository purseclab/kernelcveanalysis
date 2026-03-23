"""
infra.gdb — GDB integration for kernel debugging and tracing.

Provides GDB attachment, breakpoint management, and kernel tracing
helpers used by dynamic analysis and feasibility checking.

The approach mirrors syzploit_old's proven method:
  1. Resolve function names → addresses using kallsyms (avoiding the need
     for a local vmlinux with debug symbols).
  2. Generate a GDB Python script that sets breakpoints at raw addresses,
     auto-continues on each hit, and exports an events JSON.
  3. Generate a GDB commands file that loads vmlinux (if available) or
     sets architecture, connects to the remote stub, sources the Python
     script, and runs ``continue``.
  4. Run ``gdb-multiarch -batch -nx -x commands.txt`` as a subprocess.
  5. Parse the JSON events file to determine which functions were hit.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import signal
import subprocess
import tempfile
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ..core.log import console


# ── Kallsyms helpers ──────────────────────────────────────────────────


def _resolve_from_nm(
    functions: List[str],
    vmlinux_path: str,
    text_only: bool = False,
) -> Dict[str, int]:
    """Resolve kernel function names to addresses via ``nm`` on vmlinux.

    This finds **static** (``t``-type) symbols that ``/proc/kallsyms``
    typically hides, such as ``__dst_negative_advice`` or
    ``sk_dst_reset``.
    """
    _TEXT_TYPES = frozenset("TtWw")
    wanted = set(functions)
    result: Dict[str, int] = {}
    for nm_cmd in ("nm", "aarch64-linux-gnu-nm", "aarch64-linux-android-nm"):
        try:
            cp = subprocess.run(
                [nm_cmd, vmlinux_path],
                capture_output=True, text=True, timeout=120,
            )
            if cp.returncode != 0 or not cp.stdout:
                continue
            for line in cp.stdout.splitlines():
                parts = line.split(None, 2)
                if len(parts) < 3:
                    continue
                addr_str, _sym_type, sym_name = parts
                sym_name = sym_name.split()[0]
                if sym_name in wanted:
                    if text_only and _sym_type not in _TEXT_TYPES:
                        continue
                    try:
                        addr = int(addr_str, 16)
                        if addr != 0:
                            result[sym_name] = addr
                    except ValueError:
                        continue
            break  # nm succeeded — don't try other prefixes
        except Exception:
            continue
    return result


def _resolve_functions_from_kallsyms(
    functions: List[str],
    kallsyms_path: Optional[str],
    vmlinux_path: Optional[str] = None,
    text_only: bool = False,
) -> Dict[str, int]:
    """Resolve kernel function names to addresses using kallsyms + vmlinux.

    First checks the *kallsyms_path* file, then falls through to
    ``nm`` on *vmlinux_path* for any symbols still missing.  This is
    critical for static functions (``t``-type) like
    ``__dst_negative_advice`` that are absent from ``/proc/kallsyms``
    but present in the vmlinux ELF.

    If *text_only* is True, only symbols with type ``T``, ``t``, or ``W``
    (text/code/weak) are returned — data symbols (``D``, ``d``, ``B``,
    ``b``, ``R``, ``r``, ``A``) are skipped.  This is important for
    GDB breakpoint targets, which must be executable code addresses.

    Returns ``{function_name: address}`` for functions found.
    Skips entries with zero addresses (kptr_restrict still active).
    """
    _TEXT_TYPES = frozenset("TtWw")
    name_to_addr: Dict[str, int] = {}
    wanted = set(functions)

    # ── Pass 1: kallsyms ──────────────────────────────────────────
    if kallsyms_path and Path(kallsyms_path).is_file():
        try:
            with open(kallsyms_path) as f:
                for line in f:
                    parts = line.strip().split(None, 2)
                    if len(parts) < 3:
                        continue
                    addr_str, sym_type, sym_name = parts[0], parts[1], parts[2]
                    # Some kallsyms lines have a module suffix like "[binder_linux]"
                    sym_name = sym_name.split()[0]
                    if sym_name in wanted:
                        if text_only and sym_type not in _TEXT_TYPES:
                            continue
                        addr = int(addr_str, 16)
                        if addr != 0:
                            name_to_addr[sym_name] = addr
        except Exception:
            pass

    # ── Pass 2: vmlinux nm (for any still-missing symbols) ────────
    still_missing = wanted - set(name_to_addr)
    if still_missing and vmlinux_path and Path(vmlinux_path).is_file():
        nm_resolved = _resolve_from_nm(list(still_missing), vmlinux_path, text_only=text_only)
        if nm_resolved:
            name_to_addr.update(nm_resolved)
            console.print(
                f"  [dim]Resolved {len(nm_resolved)} additional symbol(s) "
                f"from vmlinux: {list(nm_resolved.keys())}[/]"
            )

    return name_to_addr


# ── GDB script generation ────────────────────────────────────────────

# Default hardware breakpoint limits by architecture.
# ARM64 CPUs typically have 4-6 HW breakpoint registers; use 4 as the
# safe lower bound.  x86_64 has 4 HW debug registers.
_DEFAULT_MAX_HW_BPS: Dict[str, int] = {
    "arm64": 4,
    "aarch64": 4,
    "x86_64": 4,
    "x86": 4,
}

# SOFTWARE breakpoints are preferred once kernel is booted under KVM/QEMU.
# They are unlimited (no hardware debug register constraint) and work
# reliably once the MMU is active.
#
# *** IMPORTANT (March 2026 fix): Under KVM, software breakpoints
# (gdb.BP_BREAKPOINT / "break *0xaddr") do NOT reliably fire for
# kernel addresses.  KVM executes the vCPU natively via debug
# registers, bypassing QEMU's software patching.  Hardware breakpoints
# ("hbreak *0xaddr" / gdb.BP_HARDWARE_BREAKPOINT) use the CPU debug
# registers and DO work under KVM.
#
# Strategy:
#   1. Install the first <HW_LIMIT> breakpoints as HARDWARE (hbreak)
#   2. Install remaining breakpoints as SOFTWARE (best-effort)
#   3. Use gdb.events.stop handler for event recording (reliable
#      across all breakpoint types — this is syzploit_old's approach)
_USE_SOFTWARE_BREAKPOINTS: bool = False  # HW breakpoints required on KVM/QEMU


def _generate_gdb_python_script(
    function_addrs: Dict[str, int],
    events_file: str,
    arch: str = "arm64",
    max_hw_breakpoints: Optional[int] = None,
    use_software_breakpoints: bool = False,
    name_only_functions: Optional[List[str]] = None,
) -> str:
    """Generate a GDB Python script that sets breakpoints and auto-continues.

    Supports both address-based and name-based breakpoints.  Name-based
    breakpoints (when addresses are unknown) use ``break <func_name>``
    which requires either vmlinux symbols or ``set breakpoint pending on``.

    Parameters
    ----------
    function_addrs : dict
        {function_name: address} for address-resolved breakpoints.
    name_only_functions : list, optional
        Function names without addresses (will use ``break <name>``).
    use_software_breakpoints : bool
        If True, prefer software breakpoints (``break``) over hardware
        (``hbreak``).  Software BPs are more portable but may not fire
        under KVM for kernel addresses.
    """
    hw_limit = max_hw_breakpoints or _DEFAULT_MAX_HW_BPS.get(arch, 4)
    name_only = name_only_functions or []

    bp_entries = json.dumps(
        {name: hex(addr) for name, addr in function_addrs.items()}
    )
    name_only_json = json.dumps(name_only)

    # Build the reverse map addr->name for stop handler lookup
    addr_to_name = json.dumps(
        {hex(addr): name for name, addr in function_addrs.items()}
    )

    # Choose breakpoint command based on preference
    bp_hw_cmd = "break" if use_software_breakpoints else "hbreak"
    bp_sw_cmd = "break"

    return f'''# Auto-generated GDB Python script for kernel path verification
# Generated by syzploit -- do not edit
#
# Breakpoint commands: {bp_hw_cmd} (primary), {bp_sw_cmd} (overflow)
# Supports both address-based (*0xaddr) and name-based breakpoints.

import gdb
import json
import time
import atexit

_events_file = "{events_file}"
_bp_map = {bp_entries}  # name -> hex_addr (address-resolved)
_name_only = {name_only_json}  # function names without addresses
_addr_to_name = {addr_to_name}  # hex_addr -> name (for stop handler)
_name_bp_numbers = {{}}  # gdb_bp_number -> func_name (for name-based BPs)
_all_monitored = set(list(_bp_map.keys()) + _name_only)
_hits = {{}}  # name -> hit_count
_start_time = time.time()
_last_export = time.time()
_EXPORT_INTERVAL = 15  # seconds between periodic exports
_BP_THROTTLE_MAX = 200  # auto-disable BP after this many hits
_HW_LIMIT = {hw_limit}
_hw_installed = 0
_sw_installed = 0
_USE_SW = {use_software_breakpoints}  # prefer software breakpoints

# Allow pending breakpoints (defers resolution if needed)
gdb.execute("set breakpoint pending on", to_string=True)


# -- Results export (triple redundancy: atexit + on-exit + periodic) --

def _save_results():
    """Export hit results as JSON."""
    try:
        data = {{
            "functions_hit": {{k: v for k, v in _hits.items() if v > 0}},
            "functions_missed": [
                k for k in _all_monitored if _hits.get(k, 0) == 0
            ],
            "total_hits": sum(_hits.values()),
            "elapsed": time.time() - _start_time,
            "hw_breakpoints": _hw_installed,
            "sw_breakpoints": _sw_installed,
        }}
        with open(_events_file, "w") as f:
            json.dump(data, f, indent=2)
        gdb.write(
            f"[SYZPLOIT] Results saved: {{len(data['functions_hit'])}} "
            f"function(s) hit, {{data['total_hits']}} total hits\\n"
        )
    except Exception as e:
        gdb.write(f"[SYZPLOIT] Failed to save results: {{e}}\\n")

atexit.register(_save_results)

# Also save on inferior exit
def _on_exit(event):
    gdb.write("[SYZPLOIT] Inferior exited, saving results...\\n")
    _save_results()

try:
    gdb.events.exited.connect(_on_exit)
except Exception:
    pass  # Some GDB versions don't support this


# -- Stop event handler --
#
# This handler fires on EVERY stop (breakpoint, signal, step, etc.).
# It checks the stopped PC against:
#   1. The addr_to_name map (address-resolved breakpoints)
#   2. The name_bp_numbers map (name-based breakpoints by BP number)
#   3. GDB breakpoint objects as fallback (resolves name-based BPs)

def _on_stop(event):
    """Handle stop events - record breakpoint hits."""
    global _last_export
    try:
        pc = int(gdb.parse_and_eval("$pc"))
    except Exception:
        return

    pc_hex = hex(pc)
    func_name = _addr_to_name.get(pc_hex)

    # Fallback: check if this stop is from a name-based breakpoint
    if not func_name:
        # Check if GDB's BreakpointEvent tells us which BP fired
        if hasattr(event, 'breakpoints'):
            for bp in event.breakpoints:
                if bp.number in _name_bp_numbers:
                    func_name = _name_bp_numbers[bp.number]
                    # Cache the resolved address for future lookups
                    _addr_to_name[pc_hex] = func_name
                    break
        # Last resort: scan our BP list
        if not func_name:
            for bp in (gdb.breakpoints() or []):
                if not bp.hit_count:
                    continue
                if bp.number in _name_bp_numbers:
                    # Check if this BP's resolved address matches PC
                    try:
                        if bp.location:
                            loc = bp.location.replace("*", "").strip()
                            bp_addr = int(loc, 16) if loc.startswith("0x") else None
                            if bp_addr and bp_addr == pc:
                                func_name = _name_bp_numbers[bp.number]
                                _addr_to_name[pc_hex] = func_name
                                break
                    except (ValueError, AttributeError):
                        pass

    if func_name:
        count = _hits.get(func_name, 0) + 1
        _hits[func_name] = count
        elapsed = time.time() - _start_time
        gdb.write(
            f"[SYZPLOIT] HIT: {{func_name}} "
            f"(count={{count}}, t={{elapsed:.1f}}s)\\n"
        )

        # Auto-throttle: delete BP after too many hits
        if count >= _BP_THROTTLE_MAX:
            gdb.write(
                f"[SYZPLOIT] Throttle: disabling {{func_name}} "
                f"after {{count}} hits\\n"
            )
            for bp in gdb.breakpoints() or []:
                try:
                    if bp.location and (pc_hex in bp.location or
                       func_name in (bp.location or "")):
                        bp.enabled = False
                        break
                except Exception:
                    continue

        # Periodic export (in case GDB crashes or gets killed)
        now = time.time()
        if now - _last_export >= _EXPORT_INTERVAL:
            _save_results()
            _last_export = now

gdb.events.stop.connect(_on_stop)
gdb.write("[SYZPLOIT] Stop handler registered\\n")


# -- Install breakpoints ---------------------------------------------------

_total_requested = len(_bp_map) + len(_name_only)
gdb.write(f"[SYZPLOIT] Installing {{_total_requested}} breakpoint(s) "
          f"({{len(_bp_map)}} by address, {{len(_name_only)}} by name, "
          f"HW limit: {{_HW_LIMIT}}, prefer_sw={{_USE_SW}})...\\n")

# -- Phase 1: Address-based breakpoints --
for _name in list(_bp_map.keys()):
    _addr_hex = _bp_map[_name]
    try:
        if not _USE_SW and _hw_installed < _HW_LIMIT:
            gdb.execute(f"hbreak *{{_addr_hex}}", to_string=True)
            _hw_installed += 1
            gdb.write(f"[SYZPLOIT] HW BP: {{_name}} at *{{_addr_hex}} "
                       f"({{_hw_installed}}/{{_HW_LIMIT}})\\n")
        else:
            gdb.execute(f"break *{{_addr_hex}}", to_string=True)
            _sw_installed += 1
            gdb.write(f"[SYZPLOIT] SW BP: {{_name}} at *{{_addr_hex}}\\n")
    except gdb.error as _e:
        err = str(_e).lower()
        if "hardware breakpoint" in err or "breakpoints/watchpoints" in err:
            try:
                gdb.execute(f"break *{{_addr_hex}}", to_string=True)
                _sw_installed += 1
                gdb.write(f"[SYZPLOIT] SW BP (HW fallback): {{_name}} "
                           f"at *{{_addr_hex}}\\n")
            except gdb.error as _e2:
                gdb.write(f"[SYZPLOIT] BP FAIL: {{_name}}: {{_e2}}\\n")
        else:
            gdb.write(f"[SYZPLOIT] BP FAIL: {{_name}} at {{_addr_hex}}: "
                       f"{{_e}}\\n")

# -- Phase 2: Name-based breakpoints (no address, resolved by GDB) --
for _fn in _name_only:
    try:
        if not _USE_SW and _hw_installed < _HW_LIMIT:
            gdb.execute(f"hbreak {{_fn}}", to_string=True)
            _hw_installed += 1
            _kind = "HW"
        else:
            gdb.execute(f"break {{_fn}}", to_string=True)
            _sw_installed += 1
            _kind = "SW"
        # Record the BP number → function name mapping for stop handler
        for _bp in (gdb.breakpoints() or []):
            if _bp.location and _fn in _bp.location:
                _name_bp_numbers[_bp.number] = _fn
                # If GDB resolved an address, add it to addr_to_name too
                try:
                    _loc = _bp.location.replace("*", "").strip()
                    if _loc.startswith("0x"):
                        _addr_to_name[_loc] = _fn
                except Exception:
                    pass
                break
        gdb.write(f"[SYZPLOIT] {{_kind}} Name BP: {{_fn}} (pending OK)\\n")
    except gdb.error as _e:
        if not _USE_SW and "hardware breakpoint" in str(_e).lower():
            try:
                gdb.execute(f"break {{_fn}}", to_string=True)
                _sw_installed += 1
                for _bp in (gdb.breakpoints() or []):
                    if _bp.location and _fn in _bp.location:
                        _name_bp_numbers[_bp.number] = _fn
                        break
                gdb.write(f"[SYZPLOIT] SW Name BP (HW fallback): {{_fn}}\\n")
            except gdb.error as _e2:
                gdb.write(f"[SYZPLOIT] Name BP FAIL: {{_fn}}: {{_e2}}\\n")
        else:
            gdb.write(f"[SYZPLOIT] Name BP FAIL: {{_fn}}: {{_e}}\\n")

gdb.write(f"[SYZPLOIT] Installed: {{_hw_installed}} HW + {{_sw_installed}} SW "
          f"= {{_hw_installed + _sw_installed}} total breakpoint(s)\\n")
gdb.write("[SYZPLOIT] Kernel will continue — stop handler will record hits\\n")

# Save initial state before continue (in case of early crash)
_save_results()
'''


def _generate_gdb_commands_file(
    gdb_host: str,
    gdb_port: int,
    script_path: str,
    vmlinux_path: Optional[str] = None,
    arch: str = "arm64",
    log_file: Optional[str] = None,
) -> str:
    """Generate a GDB commands file for batch-mode execution.

    The commands:
    1. Load vmlinux with ``file`` (if available — gives arch + symbols)
    2. Set architecture AFTER connecting (avoids mismatch with stub)
    3. Connect to the remote GDB stub
    4. Source the Python monitoring script
    5. ``continue`` (the script's breakpoints fire and auto-continue)
    6. On exit, disconnect and quit
    """
    lines: list[str] = []

    # Load vmlinux FIRST if available — this auto-detects architecture
    # and provides symbol names, avoiding manual arch mismatch issues.
    has_vmlinux = vmlinux_path and Path(vmlinux_path).is_file()
    if has_vmlinux:
        lines.append(f"file {vmlinux_path}")

    # Pagination and confirmation off for batch mode
    lines.append("set pagination off")
    lines.append("set confirm off")
    lines.append("set tcp connect-timeout 30")
    lines.append("set breakpoint pending on")

    # Logging
    if log_file:
        lines.append(f"set logging file {log_file}")
        lines.append("set logging overwrite on")
        lines.append("set logging enabled on")

    # Connect to the kernel GDB stub.
    # Use a Python retry loop to handle the 'vMustReplyEmpty' protocol
    # error that occurs when a prior raw-socket GDB continue (from
    # _send_gdb_continue) left the stub in an inconsistent state.
    lines.append("python")
    lines.append("import time as _t")
    lines.append("_connected = False")
    lines.append("for _attempt in range(5):")
    lines.append("    try:")
    lines.append(f'        gdb.execute("target remote {gdb_host}:{gdb_port}")')
    lines.append("        _connected = True")
    lines.append("        break")
    lines.append("    except gdb.error as _e:")
    lines.append("        _emsg = str(_e)")
    lines.append('        if "vMustReplyEmpty" in _emsg or "unexpectedly" in _emsg or ("Packet too long" in _emsg and "Ignoring" not in _emsg):')
    lines.append(f'            gdb.write(f"[SYZPLOIT] Connection attempt {{_attempt+1}} got protocol error, retrying...\\n")')
    lines.append("            try:")
    lines.append('                gdb.execute("disconnect", to_string=True)')
    lines.append("            except Exception:")
    lines.append("                pass")
    lines.append("            _t.sleep(2)")
    lines.append("            continue")
    lines.append('        elif "Connection refused" in _emsg or "timed out" in _emsg:')
    lines.append(f'            gdb.write(f"[SYZPLOIT] Connection attempt {{_attempt+1}} failed: {{_e}}, retrying...\\n")')
    lines.append("            _t.sleep(3)")
    lines.append("            continue")
    lines.append("        else:")
    lines.append('            raise')
    lines.append("if not _connected:")
    lines.append(f'    gdb.write("[SYZPLOIT] Failed to connect after 5 attempts, exiting\\n")')
    lines.append('    gdb.execute("quit")')
    lines.append("end")

    # Set architecture AFTER connecting — avoids the "Selected
    # architecture aarch64 is not compatible with reported target
    # architecture i386:x86-64" error and the subsequent "Truncated
    # register 55 in remote 'g' packet" crash.  Only force-set when
    # vmlinux isn't providing arch info already.
    if not has_vmlinux:
        if arch in ("arm64", "aarch64"):
            lines.append("set architecture aarch64")
        elif arch in ("x86_64", "x86"):
            lines.append("set architecture i386:x86-64")

    # Source the Python instrumentation script
    lines.append(f"source {script_path}")

    # Continue — the Python script's custom breakpoint classes handle
    # auto-continue by returning False from stop().  GDB stays in the
    # continue state until interrupted (SIGINT from stop_monitoring)
    # or the remote disconnects (VM shutdown/crash).
    # We use a Python loop (like syzploit_old's syz_safe_continue) for
    # error recovery — if the connection drops and reconnects, or if
    # GDB gets interrupted, the loop retries continue.
    lines.append("python")
    lines.append("import time")
    lines.append("_stop_count = 0")
    lines.append("_max_stops = 100000")
    lines.append("while _stop_count < _max_stops:")
    lines.append("    try:")
    lines.append('        gdb.execute("continue")')
    lines.append("        _stop_count += 1")
    lines.append("    except gdb.error as e:")
    lines.append('        err = str(e).lower()')
    lines.append("        if 'not running' in err or 'not being run' in err:")
    lines.append("            time.sleep(1)")
    lines.append("            continue")
    lines.append("        if 'connection closed' in err or 'remote' in err:")
    lines.append('            gdb.write(f"[SYZPLOIT] Connection lost: {e}\\n")')
    lines.append("            break")
    # Handle ARM64 hardware breakpoint limit exceeded: progressively
    # delete breakpoints from the end (lowest priority) and retry.
    lines.append("        if 'hardware breakpoint' in err or 'breakpoints/watchpoints' in err or 'command aborted' in err:")
    lines.append('            gdb.write(f"[SYZPLOIT] HW breakpoint limit hit, removing excess...\\n")')
    lines.append("            _all_bps = sorted(gdb.breakpoints() or [], key=lambda b: b.number, reverse=True)")
    lines.append("            if _all_bps:")
    lines.append("                _victim = _all_bps[0]")
    lines.append('                gdb.write(f"[SYZPLOIT]  deleting BP#{_victim.number}\\n")')
    lines.append("                _victim.delete()")
    lines.append("                continue  # retry continue with fewer BPs")
    lines.append("            else:")
    lines.append('                gdb.write("[SYZPLOIT] No breakpoints left to remove\\n")')
    lines.append("                break")
    lines.append('        gdb.write(f"[SYZPLOIT] Continue error: {e}\\n")')
    lines.append("        break")
    lines.append("    except KeyboardInterrupt:")
    lines.append("        break")
    lines.append("end")

    # Graceful exit
    lines.append("disconnect")
    lines.append("quit")

    return "\n".join(lines) + "\n"


# ── GDB binary detection ─────────────────────────────────────────────

def _find_gdb_binary(arch: str = "arm64") -> str:
    """Find an appropriate GDB binary for the target architecture."""
    if arch in ("arm64", "aarch64"):
        candidates = ["gdb-multiarch", "aarch64-linux-gnu-gdb", "gdb"]
    else:
        candidates = ["gdb", "gdb-multiarch"]

    for name in candidates:
        if shutil.which(name):
            return name

    return "gdb-multiarch"  # fallback; will error if not installed


# ── Main controller ───────────────────────────────────────────────────

class GDBController:
    """
    Control GDB via subprocess for kernel path verification.

    The design mirrors syzploit_old's approach:
    - Generate a GDB Python script with breakpoints
    - Run GDB in batch mode as a background subprocess
    - Parse the exported JSON events file after stopping

    Unlike the previous approach, this works WITHOUT vmlinux by
    resolving function names to addresses via kallsyms BEFORE
    starting GDB.
    """

    def __init__(
        self,
        gdb_binary: Optional[str] = None,
        vmlinux: Optional[str] = None,
        arch: str = "arm64",
    ) -> None:
        self.gdb_binary = gdb_binary or _find_gdb_binary(arch)
        self.vmlinux = vmlinux
        self.arch = arch
        self._process: Optional[subprocess.Popen] = None
        self._work_dir: Optional[str] = None
        self._events_file: Optional[str] = None
        self._function_names: List[str] = []
        self._monitor_script_dir: Optional[str] = None

    def attach(self, host: str = "localhost", port: int = 1234) -> bool:
        """Quick connectivity check — attach and immediately detach."""
        cmd = [self.gdb_binary]
        if self.vmlinux and Path(self.vmlinux).is_file():
            cmd.append(self.vmlinux)
        cmd += [
            "-ex", f"target remote {host}:{port}",
            "-ex", "set pagination off",
            "-batch",
        ]
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=30
            )
            return result.returncode == 0
        except Exception:
            return False

    # ── Background monitoring ─────────────────────────────────────────

    def start_monitoring(
        self,
        functions: List[str],
        *,
        host: str = "localhost",
        port: int = 1234,
        kallsyms_path: Optional[str] = None,
        custom_script_dir: Optional[str] = None,
    ) -> bool:
        """Start GDB as a background process monitoring kernel breakpoints.

        1. Resolve *functions* → addresses using *kallsyms_path*.
        2. Generate a GDB Python script with auto-continue breakpoints.
        3. Generate a GDB commands file.
        4. Launch ``gdb-multiarch -batch -nx -x commands.txt`` in the
           background.

        If *custom_script_dir* is provided, use the pre-generated
        ExploitMonitor scripts from that directory instead of the
        default basic hit/miss script.  The directory must contain
        ``exploit_monitor.py`` and ``monitor_commands.gdb``.  This
        enables richer monitoring: heap tracking, state snapshots,
        phase detection, and pre/post condition evaluation.

        The kernel keeps running — breakpoints fire and GDB auto-continues.
        Call :meth:`stop_monitoring` after the reproducer finishes to
        read the results.

        Returns True if GDB was started successfully.
        """
        if self._process is not None:
            console.print("  [yellow]GDB monitor already running[/]")
            return True

        self._function_names = list(functions)
        self._monitor_script_dir = custom_script_dir

        # ── If a pre-generated ExploitMonitor script dir is provided,
        #    use it directly instead of generating the basic hit/miss script.
        if custom_script_dir:
            _csd = Path(custom_script_dir)
            _custom_cmds = _csd / "monitor_commands.gdb"
            _custom_script = _csd / "exploit_monitor.py"
            if _custom_cmds.is_file() and _custom_script.is_file():
                console.print(
                    f"  [dim]Using ExploitMonitor script from "
                    f"{custom_script_dir}[/]"
                )
                # The ExploitMonitor events file lives alongside the script
                self._work_dir = str(_csd)
                self._events_file = str(_csd / "monitor_events.json")

                # Patch the commands file: fix target remote host:port and
                # inject vmlinux if the original didn't include it.
                _cmds_text = _custom_cmds.read_text()
                _cmds_text = re.sub(
                    r"target remote \S+:\d+",
                    f"target remote {host}:{port}",
                    _cmds_text,
                )
                # Inject "file <vmlinux>" before "target remote" if absent
                if self.vmlinux and Path(self.vmlinux).is_file():
                    if not re.search(r"^file\s+", _cmds_text, re.MULTILINE):
                        _cmds_text = re.sub(
                            r"(target remote\s)",
                            f"file {self.vmlinux}\n\\1",
                            _cmds_text,
                            count=1,
                        )
                        # Remove manual "set architecture" — vmlinux provides it
                        _cmds_text = re.sub(
                            r"set architecture \S+\n", "", _cmds_text
                        )
                _patched_cmds = _csd / "monitor_commands_patched.gdb"
                _patched_cmds.write_text(_cmds_text)
                commands_path = str(_patched_cmds)
                try:
                    self._process = subprocess.Popen(
                        [self.gdb_binary, "-q", "-nx", "-x", commands_path],
                        stdin=subprocess.DEVNULL,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                    )
                    # Wait up to 10s for GDB to initialize (remote ARM64 is slow)
                    for _wait in range(5):
                        time.sleep(2)
                        if self._process.poll() is not None:
                            break
                    if self._process.poll() is not None:
                        out = self._process.stdout.read().decode(
                            errors="replace"
                        ) if self._process.stdout else ""
                        console.print(
                            f"  [yellow]GDB (custom) exited early "
                            f"(rc={self._process.returncode}): "
                            f"{out[:2000]}[/]"
                        )
                        self._process = None
                        return False
                    console.print(
                        "  [dim]GDB ExploitMonitor started (heap tracking + "
                        "state snapshots active)[/]"
                    )
                    return True
                except FileNotFoundError:
                    console.print(
                        f"  [red]GDB binary not found: {self.gdb_binary}[/]"
                    )
                    self._process = None
                    return False
                except Exception as exc:
                    console.print(
                        f"  [yellow]GDB (custom) start failed: {exc}[/]"
                    )
                    self._process = None
                    return False
            else:
                console.print(
                    f"  [dim]Custom script dir missing files, "
                    f"falling back to basic monitoring[/]"
                )

        # ── Resolve function names → addresses ────────────────────────
        resolved = _resolve_functions_from_kallsyms(
            functions, kallsyms_path, vmlinux_path=self.vmlinux,
        )
        if not resolved:
            # Try using function names directly (works if vmlinux is loaded)
            if self.vmlinux and Path(self.vmlinux).is_file():
                console.print(
                    "  [dim]No kallsyms addresses — will use vmlinux "
                    "symbol names for breakpoints[/]"
                )
                # Use name-based breakpoints (GDB resolves via vmlinux)
                resolved = {fn: 0 for fn in functions}
            else:
                # Last resort: use function names directly as breakpoints.
                # The QEMU GDB stub sometimes resolves kernel symbols even
                # without vmlinux, especially if the kernel was compiled
                # with debug info.  If not, GDB will simply skip the
                # unresolvable breakpoints ("pending on").
                console.print(
                    "  [dim]No kallsyms addresses and no vmlinux — "
                    "trying name-based breakpoints (may be pending)[/]"
                )
                resolved = {fn: 0 for fn in functions}

        found_names = [n for n in functions if n in resolved]
        missed_names = [n for n in functions if n not in resolved]
        if missed_names:
            console.print(
                f"  [dim]Resolved {len(found_names)}/{len(functions)} "
                f"functions. Missing: {missed_names}[/]"
            )

        # Re-order resolved to match the caller's priority order
        # (_resolve_functions_from_kallsyms returns in kallsyms file order,
        #  but the caller lists functions highest-priority first)
        resolved_ordered: Dict[str, int] = {}
        for fn in functions:
            if fn in resolved:
                resolved_ordered[fn] = resolved[fn]
        resolved = resolved_ordered

        # Only use entries with actual addresses (skip the 0-address
        # placeholder for name-based breakpoints handled differently)
        addr_map = {n: a for n, a in resolved.items() if a != 0}
        name_only = [n for n, a in resolved.items() if a == 0]

        # Prefer software breakpoints — more portable than hardware BPs
        # and work well with QEMU's GDB stub in most configurations.
        use_sw = _USE_SOFTWARE_BREAKPOINTS
        max_hw = _DEFAULT_MAX_HW_BPS.get(self.arch, 4)
        total = len(addr_map) + len(name_only)
        if use_sw:
            console.print(
                f"  [dim]Breakpoint strategy: {total} SW (software) total[/]"
            )
        else:
            console.print(
                f"  [dim]Breakpoint strategy: {min(total, max_hw)} HW "
                f"(KVM-reliable) + {max(0, total - max_hw)} SW (best-effort) "
                f"= {total} total[/]"
            )

        # ── Create working directory for temp files ───────────────────
        self._work_dir = tempfile.mkdtemp(prefix="syzploit_gdb_")
        self._events_file = os.path.join(self._work_dir, "events.json")
        script_path = os.path.join(self._work_dir, "monitor.py")
        commands_path = os.path.join(self._work_dir, "commands.gdb")
        log_path = os.path.join(self._work_dir, "gdb_output.log")

        # ── Generate the Python script ────────────────────────────────
        # Both address-based and name-only breakpoints are handled in the
        # script itself (unified stop handler for both types).
        script_content = _generate_gdb_python_script(
            addr_map, self._events_file, self.arch,
            use_software_breakpoints=use_sw,
            name_only_functions=name_only,
        )

        with open(script_path, "w") as f:
            f.write(script_content)

        # ── Generate the commands file ────────────────────────────────
        commands_content = _generate_gdb_commands_file(
            gdb_host=host,
            gdb_port=port,
            script_path=script_path,
            vmlinux_path=self.vmlinux,
            arch=self.arch,
            log_file=log_path,
        )
        with open(commands_path, "w") as f:
            f.write(commands_content)

        # ── Launch GDB ────────────────────────────────────────────────
        # NOTE: Do NOT use -batch.  In batch mode GDB may exit after
        # the first auto-continue breakpoint cycle.  syzploit_old used
        # `gdb -q` (no -batch) so GDB stays alive, blocking on the
        # `continue` command until we SIGINT it from stop_monitoring().
        console.print(
            f"  [dim]GDB command: {self.gdb_binary} -q -nx "
            f"-x {commands_path}[/]"
        )
        try:
            self._process = subprocess.Popen(
                [self.gdb_binary, "-q", "-nx", "-x", commands_path],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )
            # Give GDB time to connect, load vmlinux, source monitor
            # script, install all breakpoints, and start continue loop.
            # Remote ARM64 GDB is slow — 5s is often not enough.
            # Poll for readiness by checking if GDB is still alive
            # after initial setup (10s total, check every 2s).
            for _wait in range(5):
                time.sleep(2)
                if self._process.poll() is not None:
                    break  # GDB exited — handle below
            if self._process.poll() is not None:
                # GDB exited already
                out = self._process.stdout.read().decode(errors="replace") if self._process.stdout else ""
                console.print(
                    f"  [yellow]GDB exited early "
                    f"(rc={self._process.returncode}): "
                    f"{out[:2000]}[/]"
                )
                self._process = None
                return False
            console.print(
                f"  [dim]GDB monitor started with {len(addr_map) + len(name_only)} "
                f"breakpoint(s) ({len(addr_map)} by address, "
                f"{len(name_only)} by name)[/]"
            )
            return True
        except FileNotFoundError:
            console.print(
                f"  [red]GDB binary not found: {self.gdb_binary}. "
                f"Install gdb-multiarch.[/]"
            )
            self._process = None
            return False
        except Exception as exc:
            console.print(f"  [yellow]GDB monitor start failed: {exc}[/]")
            self._process = None
            return False

    def stop_monitoring(self) -> Dict[str, bool]:
        """Stop GDB and return ``{function_name: was_hit}`` from the events file.

        Sends SIGINT to interrupt GDB's ``continue`` loop, waits for it to
        run the atexit handler that writes the events JSON, then parses
        the file.

        The GDB script uses custom Breakpoint subclasses that also write
        periodic exports, so even if atexit doesn't fire, we should have
        partial results from the last periodic save.
        """
        if self._process is None:
            return {}

        gdb_stdout = ""

        try:
            # Send SIGINT to interrupt the Python continue loop inside GDB.
            # This causes the KeyboardInterrupt handler to break the loop,
            # then GDB runs atexit handlers (which call _save_results).
            self._process.send_signal(signal.SIGINT)
            time.sleep(3)  # Give atexit handler time to write JSON

            # Send another SIGINT in case the first was caught by GDB itself
            # and not forwarded to the Python script
            try:
                if self._process.poll() is None:
                    self._process.send_signal(signal.SIGINT)
                    time.sleep(2)
            except Exception:
                pass

            # Now terminate
            if self._process.poll() is None:
                self._process.terminate()
            try:
                out_bytes, _ = self._process.communicate(timeout=15)
                gdb_stdout = out_bytes.decode(errors="replace") if out_bytes else ""
            except subprocess.TimeoutExpired:
                self._process.kill()
                out_bytes, _ = self._process.communicate(timeout=5)
                gdb_stdout = out_bytes.decode(errors="replace") if out_bytes else ""
        except Exception as exc:
            console.print(f"  [yellow]GDB monitor stop error: {exc}[/]")
            try:
                self._process.kill()
                out_bytes, _ = self._process.communicate(timeout=5)
                gdb_stdout = out_bytes.decode(errors="replace") if out_bytes else ""
            except Exception:
                pass

        self._process = None

        # Log GDB output for debugging
        if gdb_stdout:
            console.print(
                f"  [dim]GDB output ({len(gdb_stdout)} bytes): "
                f"{gdb_stdout[:400]}[/]"
            )

        # ── Parse the events JSON file ────────────────────────────────
        hits: Dict[str, bool] = {fn: False for fn in self._function_names}

        if self._events_file and Path(self._events_file).is_file():
            try:
                with open(self._events_file) as f:
                    data = json.load(f)
                # Support both formats:
                # - Basic monitor: {"functions_hit": {name: count, ...}}
                # - ExploitMonitor: {"bp_hits": {name: count, ...}}
                funcs_hit = data.get("functions_hit") or data.get("bp_hits") or {}
                for fn in self._function_names:
                    if fn in funcs_hit and funcs_hit[fn] > 0:
                        hits[fn] = True
                total = data.get("total_hits") or sum(funcs_hit.values())
                console.print(
                    f"  [dim]Events file: {len(funcs_hit)} function(s) hit, "
                    f"{total} total[/]"
                )
            except Exception as exc:
                console.print(
                    f"  [yellow]Could not parse events file: {exc}[/]"
                )
        else:
            # Fallback: parse GDB stdout for "[SYZPLOIT] HIT:" or
            # "[MONITOR] HIT:" lines (both formats)
            console.print(
                "  [dim]No events file — parsing GDB stdout for hits[/]"
            )
            for line in gdb_stdout.splitlines():
                m = re.search(r"\[(?:SYZPLOIT|MONITOR)\] HIT: (\S+)", line)
                if m:
                    fn_name = m.group(1)
                    if fn_name in hits:
                        hits[fn_name] = True

        # Clean up temp files — but NOT the custom script dir (it belongs
        # to the caller and contains results we still need to parse)
        if self._work_dir and not self._monitor_script_dir:
            try:
                import shutil as _shutil
                _shutil.rmtree(self._work_dir, ignore_errors=True)
            except Exception:
                pass
        self._work_dir = None

        return hits

    # ── Legacy / simple methods ───────────────────────────────────────

    def set_breakpoints_and_run(
        self,
        functions: List[str],
        *,
        host: str = "localhost",
        port: int = 1234,
        timeout: int = 60,
        kallsyms_path: Optional[str] = None,
    ) -> Dict[str, bool]:
        """One-shot: set breakpoints, continue, collect results.

        Blocking call that runs for *timeout* seconds.
        """
        ok = self.start_monitoring(
            functions, host=host, port=port,
            kallsyms_path=kallsyms_path,
        )
        if not ok:
            return {fn: False for fn in functions}

        # Let GDB run for the timeout duration
        time.sleep(timeout)

        return self.stop_monitoring()

    def run_gdb_script(
        self,
        script_path: str,
        *,
        host: str = "localhost",
        port: int = 1234,
        timeout: int = 120,
    ) -> Tuple[int, str]:
        """Execute a GDB Python script against a remote target."""
        cmd = [self.gdb_binary]
        if self.vmlinux and Path(self.vmlinux).is_file():
            cmd.append(self.vmlinux)
        cmd += [
            "-ex", f"target remote {host}:{port}",
            "-x", script_path,
            "-batch",
        ]
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout
            )
            return result.returncode, result.stdout + result.stderr
        except subprocess.TimeoutExpired:
            return -1, "GDB script timed out"
        except Exception as exc:
            return -1, str(exc)

    # ── Crash-site analysis ───────────────────────────────────────────

    def capture_crash_state(
        self,
        *,
        host: str = "localhost",
        port: int = 1234,
    ) -> Dict[str, Any]:
        """Connect to a halted kernel and capture diagnostic state.

        After an exploit causes a kernel panic/OOPS, the QEMU GDB stub
        halts the CPU.  This method connects, captures registers and
        backtrace, then disconnects.  Returns a dict with:
          - registers: dict of register name → hex value
          - backtrace: formatted backtrace string
          - crash_function: function name at crash site (if vmlinux loaded)
          - crash_address: program counter value
          - stack_dump: raw stack bytes (hex)
        """
        result: Dict[str, Any] = {
            "registers": {},
            "backtrace": "",
            "crash_function": "",
            "crash_address": "",
            "stack_dump": "",
        }

        # Build a GDB commands file that captures state
        work_dir = tempfile.mkdtemp(prefix="syzploit_gdb_crash_")
        state_file = os.path.join(work_dir, "crash_state.json")
        script_path = os.path.join(work_dir, "crash_capture.py")
        commands_path = os.path.join(work_dir, "commands.gdb")

        capture_script = f'''# Crash state capture script — generated by syzploit
import gdb
import json

state = {{"registers": {{}}, "backtrace": "", "crash_function": "", "crash_address": "", "stack_dump": ""}}

try:
    # Capture registers
    reg_output = gdb.execute("info registers", to_string=True)
    state["registers_raw"] = reg_output
    for line in reg_output.strip().splitlines():
        parts = line.split()
        if len(parts) >= 2:
            state["registers"][parts[0]] = parts[1]

    # Get program counter
    try:
        pc = gdb.execute("print/x $pc", to_string=True)
        state["crash_address"] = pc.strip().split("=")[-1].strip() if "=" in pc else pc.strip()
    except Exception:
        pass

    # Capture backtrace
    try:
        bt = gdb.execute("bt 20", to_string=True)
        state["backtrace"] = bt
        # Extract crash function from first frame
        lines = bt.strip().splitlines()
        if lines:
            import re
            m = re.search(r"in\\s+(\\S+)", lines[0])
            if m:
                state["crash_function"] = m.group(1)
            elif "??" not in lines[0]:
                # Try extracting from format "#0 function_name ..."
                m2 = re.search(r"#0\\s+(?:0x[0-9a-f]+\\s+in\\s+)?(\\S+)", lines[0])
                if m2:
                    state["crash_function"] = m2.group(1)
    except Exception:
        pass

    # Stack dump (16 words around SP)
    try:
        if "$sp" in reg_output or "sp" in state["registers"]:
            stack = gdb.execute("x/16gx $sp", to_string=True)
            state["stack_dump"] = stack
    except Exception:
        pass

except Exception as e:
    state["error"] = str(e)

with open("{state_file}", "w") as f:
    json.dump(state, f, indent=2)

gdb.write("[SYZPLOIT] Crash state captured\\n")
'''

        with open(script_path, "w") as f:
            f.write(capture_script)

        # Build commands file
        lines: list[str] = []
        # Load vmlinux FIRST for auto architecture detection
        has_vmlinux = self.vmlinux and Path(self.vmlinux).is_file()
        if has_vmlinux:
            lines.append(f"file {self.vmlinux}")
        lines.append("set pagination off")
        lines.append("set confirm off")
        lines.append("set tcp connect-timeout 15")
        lines.append(f"target remote {host}:{port}")
        # Set architecture AFTER connecting, only when no vmlinux
        if not has_vmlinux:
            if self.arch in ("arm64", "aarch64"):
                lines.append("set architecture aarch64")
            elif self.arch in ("x86_64", "x86"):
                lines.append("set architecture i386:x86-64")
        lines.append(f"source {script_path}")
        lines.append("disconnect")
        lines.append("quit")

        with open(commands_path, "w") as f:
            f.write("\n".join(lines) + "\n")

        # Run GDB
        try:
            proc = subprocess.run(
                [self.gdb_binary, "-batch", "-nx", "-x", commands_path],
                capture_output=True, text=True, timeout=30,
            )
        except Exception as exc:
            console.print(f"  [yellow]Crash capture failed: {exc}[/]")
            return result

        # Parse results
        if Path(state_file).is_file():
            try:
                with open(state_file) as f:
                    data = json.load(f)
                result["registers"] = data.get("registers", {})
                result["backtrace"] = data.get("backtrace", "")
                result["crash_function"] = data.get("crash_function", "")
                result["crash_address"] = data.get("crash_address", "")
                result["stack_dump"] = data.get("stack_dump", "")
            except Exception:
                pass

        # Clean up
        try:
            import shutil as _shutil
            _shutil.rmtree(work_dir, ignore_errors=True)
        except Exception:
            pass

        return result


# ══════════════════════════════════════════════════════════════════════
# Interactive GDB Session
# ══════════════════════════════════════════════════════════════════════

# Path to the analysis script that registers syz-* commands.
_ANALYSIS_SCRIPT = str(
    Path(__file__).with_name("gdb_analysis_script.py")
)


class InteractiveGDB:
    """Persistent interactive GDB session for ad-hoc kernel exploration.

    Unlike :class:`GDBController` which runs GDB in batch mode with
    pre-generated scripts, ``InteractiveGDB`` keeps a GDB subprocess
    alive with stdin/stdout pipes so the caller can send arbitrary
    commands and read their output.

    On connect it automatically:
    - Loads vmlinux (if provided) for symbol resolution
    - Connects to the QEMU GDB stub
    - Sources the ``gdb_analysis_script.py`` which registers the
      ``syz-*`` family of custom analysis commands

    The LLM agent interacts with this via ``tool_gdb_command`` in
    ``source_tools.py``.  A command allow-list prevents accidental
    damage, but all standard inspection / stepping commands are
    permitted.

    Thread-safety: each ``execute()`` call is serialized by a lock.
    """

    # Commands that are allowed without restrictions
    _ALLOWED_PREFIXES = (
        # Inspection
        "info ", "show ", "print ", "p ", "p/", "x/", "display ",
        "whatis ", "ptype ", "explore ",
        # Navigation / stepping
        "bt", "backtrace", "frame ", "up", "down",
        "stepi", "si", "nexti", "ni", "step", "next",
        "finish", "continue", "c", "until ",
        "thread ", "inferior ",
        # Breakpoints
        "break ", "b ", "hbreak ", "tbreak ",
        "watch ", "rwatch ", "awatch ",
        "delete ", "disable ", "enable ", "clear ",
        "condition ",
        # Memory
        "disassemble ", "disas ",
        "find ", "mem ",
        "dump ", "restore ",
        "set ", "call ",
        # Custom analysis
        "syz-",
        # Misc safe commands
        "list ", "l ", "where", "maintenance ",
        "help",
    )

    # Commands that are explicitly blocked
    _BLOCKED_PATTERNS = (
        "shell", "!",
        "target ", "remote ",
        "file ", "exec-file ", "symbol-file ",
        "add-inferior",
        "monitor quit", "monitor system_reset",
        "quit", "q",
        "disconnect",
        "python exec", "python import os",
        "source /",  # block sourcing arbitrary files
    )

    def __init__(
        self,
        *,
        gdb_binary: Optional[str] = None,
        vmlinux: Optional[str] = None,
        arch: str = "arm64",
        host: str = "localhost",
        port: int = 1234,
        ssh_host: Optional[str] = None,
        ssh_port: int = 22,
        setup_tunnel: bool = False,
        transcript_path: Optional[str] = None,
    ) -> None:
        self.gdb_binary = gdb_binary or _find_gdb_binary(arch)
        self.vmlinux = vmlinux
        self.arch = arch
        self.host = host
        self.port = port
        self.ssh_host = ssh_host
        self.ssh_port = ssh_port
        self.setup_tunnel = setup_tunnel
        self._transcript_path = transcript_path
        self._transcript_file: Optional[Any] = None

        self._process: Optional[subprocess.Popen] = None
        self._tunnel_proc: Optional[subprocess.Popen] = None
        self._actual_port: int = port
        self._lock = threading.Lock()
        self._connected = False
        self._sentinel_counter = 0
        self._last_raw_output = ""

    # ── Lifecycle ─────────────────────────────────────────────────────

    def connect(self) -> bool:
        """Start GDB, connect to the remote stub, load analysis helpers.

        Returns True on success. Idempotent — if already connected,
        returns True immediately.
        """
        if self._connected and self._process and self._process.poll() is None:
            return True

        # Close stale session
        if self._process is not None:
            self.close()

        # Set up SSH tunnel if needed
        self._actual_port = self.port
        if self.setup_tunnel and self.ssh_host:
            local_port = 11234 + (self.port % 1000)
            # Check if the port is already in use (e.g. from a prior
            # collect_target_info step).  If so, reuse it.
            import socket as _socket
            _port_in_use = False
            try:
                with _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM) as _s:
                    _s.settimeout(1)
                    _s.connect(("127.0.0.1", local_port))
                    _port_in_use = True
            except (ConnectionRefusedError, OSError):
                pass

            if _port_in_use:
                console.print(
                    f"  [dim]InteractiveGDB: reusing existing tunnel "
                    f"on localhost:{local_port}[/]"
                )
                self._actual_port = local_port
            else:
                console.print(
                    f"  [dim]InteractiveGDB: SSH tunnel "
                    f"localhost:{local_port} → {self.ssh_host}:{self.port}[/]"
                )
                self._tunnel_proc = subprocess.Popen(
                    [
                        "ssh", "-o", "StrictHostKeyChecking=no",
                        "-N", "-L",
                        f"{local_port}:localhost:{self.port}",
                        *(["-p", str(self.ssh_port)] if self.ssh_port != 22 else []),
                        self.ssh_host,
                    ],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                time.sleep(2)
                self._actual_port = local_port

        # Launch GDB
        cmd = [self.gdb_binary, "-q", "-nx"]
        console.print(
            f"  [dim]InteractiveGDB: launching {self.gdb_binary}[/]"
        )
        try:
            self._process = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                bufsize=1,  # line-buffered (requires text mode)
                text=True,
                encoding="utf-8",
                errors="replace",
            )
        except FileNotFoundError:
            console.print(
                f"  [red]GDB binary not found: {self.gdb_binary}[/]"
            )
            return False

        # Drain the initial GDB banner
        self._drain_until_ready(timeout=10)

        # Basic setup
        self._raw_send("set pagination off")
        self._raw_send("set confirm off")
        self._raw_send("set tcp connect-timeout 15")
        self._raw_send("set breakpoint pending on")

        # Open transcript log for user inspection
        if self._transcript_path and self._transcript_file is None:
            try:
                from datetime import datetime, timezone
                self._transcript_file = open(self._transcript_path, "a")  # noqa: SIM115
                self._transcript_file.write(
                    f"\n{'='*72}\n"
                    f"GDB transcript started at "
                    f"{datetime.now(timezone.utc).isoformat()}\n"
                    f"{'='*72}\n\n"
                )
                self._transcript_file.flush()
                console.print(
                    f"  [dim]InteractiveGDB: transcript → "
                    f"{self._transcript_path}[/]"
                )
            except Exception as exc:
                console.print(
                    f"  [dim]InteractiveGDB: transcript open failed: {exc}[/]"
                )
                self._transcript_file = None

        # Load vmlinux
        if self.vmlinux and Path(self.vmlinux).is_file():
            out = self._raw_send(f"file {self.vmlinux}")
            console.print(f"  [dim]InteractiveGDB: loaded vmlinux[/]")

        # Connect to remote stub — with retry logic.
        # GDB output can be garbled with pipe I/O, so we check multiple
        # success indicators: "Remote debugging" (canonical), "0x"
        # (GDB prints current PC on connect), "using" (from "...using
        # localhost:PORT").
        connect_cmd = f"target remote {self.host}:{self._actual_port}"
        for _conn_attempt in range(3):
            out = self._raw_send(connect_cmd, timeout=30)
            if out is None:
                out = ""

            # If _raw_send returned empty, the sentinel may not have been
            # echoed yet because GDB was busy with the remote-protocol
            # handshake.  Do a longer extra drain to pick up late output.
            if not out.strip():
                time.sleep(5)
                extra_lines: list[str] = []
                for _ in range(40):
                    line = self._read_line(timeout=0.5)
                    if line is None:
                        break
                    extra_lines.append(line)
                if extra_lines:
                    out = "\n".join(extra_lines)

            # Still empty — GDB might be connected but output was lost.
            # Probe with a simple command.
            if not out.strip():
                probe_early = self._raw_send("print 1+1", timeout=10)
                if probe_early and ("$" in probe_early or "= " in probe_early):
                    console.print(
                        f"  [dim]InteractiveGDB: connected (empty connect "
                        f"output but probe succeeded)[/]"
                    )
                    self._connected = True
                    break

            # Check for successful connection indicators
            _connected_ok = (
                "Remote debugging" in out
                or "Remote" in out
                or "0x" in out
                or "in ??" in out
                or "using" in out
                # GDB warnings that appear only when connected
                or "Ignoring packet error" in out
                or "unrecognized item" in out
                or "warning:" in out
            )
            # Check for known transient errors — be specific to avoid
            # matching harmless warnings like "Ignoring packet error"
            _transient = (
                "vMustReplyEmpty" in out
                or "unexpectedly" in out
                or ("Packet too long" in out and "Ignoring" not in out)
            )

            if _connected_ok and not _transient:
                console.print(
                    f"  [dim]InteractiveGDB: connected to "
                    f"{self.host}:{self._actual_port}[/]"
                )
                self._connected = True
                break
            elif _transient:
                console.print(
                    f"  [dim]InteractiveGDB: transient error "
                    f"(attempt {_conn_attempt + 1}/3), retrying…[/]"
                )
                time.sleep(2)
                self._raw_send("disconnect", timeout=5)
                time.sleep(1)
                continue
            else:
                # Output might be garbled — try probing to see if we're
                # actually connected despite garbled output.
                probe = self._raw_send("info target", timeout=15)
                if probe and ("Remote" in probe or "serial" in probe or "0x" in probe):
                    console.print(
                        f"  [dim]InteractiveGDB: connected (verified "
                        f"via probe)[/]"
                    )
                    self._connected = True
                    break
                # Second probe with a simpler command
                probe2 = self._raw_send("print 1+1", timeout=10)
                if probe2 and ("$" in probe2 or "= " in probe2):
                    console.print(
                        f"  [dim]InteractiveGDB: connected (verified "
                        f"via probe2)[/]"
                    )
                    self._connected = True
                    break
                console.print(
                    f"  [dim]InteractiveGDB: connect unclear "
                    f"(attempt {_conn_attempt + 1}/3): "
                    f"{out[:200]}[/]"
                )
                if _conn_attempt < 2:
                    time.sleep(2)
                    self._raw_send("disconnect", timeout=5)
                    time.sleep(1)
                    continue

        if not self._connected:
            console.print(
                f"  [yellow]InteractiveGDB: connect failed after "
                f"3 attempts: {(out or '')[:200]}[/]"
            )
            return False

        # Set architecture if no vmlinux
        if not (self.vmlinux and Path(self.vmlinux).is_file()):
            if self.arch in ("arm64", "aarch64"):
                self._raw_send("set architecture aarch64")
            elif self.arch in ("x86_64", "x86"):
                self._raw_send("set architecture i386:x86-64")

        # Verify the target is actually usable — sometimes `target remote`
        # succeeds but the kernel disconnects immediately (e.g. QEMU GDB
        # stub was in "running, no debugger" state from a prior continue).
        probe = self._raw_send("info target", timeout=10)
        if probe and "not being run" in probe:
            # Target disconnected — try reconnecting.  This happens when
            # a prior boot-phase continue released the GDB stub.
            console.print(
                "  [dim]InteractiveGDB: target disconnected, reconnecting…[/]"
            )
            reconnect_out = self._raw_send(
                f"target remote {self.host}:{self._actual_port}",
                timeout=30,
            )
            if reconnect_out and ("not being run" in reconnect_out or "Connection refused" in reconnect_out):
                console.print(
                    f"  [yellow]InteractiveGDB: reconnect failed: "
                    f"{reconnect_out[:200]}[/]"
                )

        # Source analysis helpers
        if Path(_ANALYSIS_SCRIPT).is_file():
            out = self._raw_send(f"source {_ANALYSIS_SCRIPT}", timeout=10)
            console.print(
                f"  [dim]InteractiveGDB: analysis helpers loaded[/]"
            )

        return True

    def close(self) -> None:
        """Disconnect and terminate GDB."""
        # Close transcript first
        if self._transcript_file is not None:
            try:
                from datetime import datetime, timezone
                self._transcript_file.write(
                    f"\n{'='*72}\n"
                    f"GDB transcript ended at "
                    f"{datetime.now(timezone.utc).isoformat()}\n"
                    f"{'='*72}\n"
                )
                self._transcript_file.close()
            except Exception:
                pass
            self._transcript_file = None

        if self._process is not None:
            try:
                if self._process.poll() is None:
                    self._process.stdin.write("disconnect\nquit\n")
                    self._process.stdin.flush()
                    try:
                        self._process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        self._process.terminate()
                        self._process.wait(timeout=3)
            except Exception:
                try:
                    self._process.kill()
                except Exception:
                    pass
            self._process = None

        if self._tunnel_proc is not None:
            try:
                self._tunnel_proc.terminate()
                self._tunnel_proc.wait(timeout=3)
            except Exception:
                try:
                    self._tunnel_proc.kill()
                except Exception:
                    pass
            self._tunnel_proc = None

        self._connected = False

    @property
    def is_connected(self) -> bool:
        return (
            self._connected
            and self._process is not None
            and self._process.poll() is None
        )

    # ── Transcript logging ────────────────────────────────────────────

    def _log_transcript(self, command: str, output: str) -> None:
        """Append a command+output entry to the transcript file."""
        if self._transcript_file is None:
            return
        try:
            from datetime import datetime, timezone
            ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
            self._transcript_file.write(
                f"[{ts}] >>> {command}\n{output}\n\n"
            )
            self._transcript_file.flush()
        except Exception:
            pass

    # ── Public command interface ──────────────────────────────────────

    def execute(
        self, command: str, *, timeout: int = 30
    ) -> str:
        """Send a command to GDB and return its output.

        Validates the command against the allow/block lists.
        Output is truncated to ~8000 characters.

        For ``continue`` commands: sends an interrupt (Ctrl-C) after the
        timeout to stop the inferior and collect the stop reason. This
        prevents the sentinel from being blocked indefinitely.

        Raises ValueError for blocked commands.
        Raises RuntimeError if the session is not connected.
        """
        command = command.strip()
        if not command:
            return ""

        # Validate command
        error = self._validate_command(command)
        if error:
            raise ValueError(error)

        if not self.is_connected:
            raise RuntimeError(
                "GDB session is not connected. "
                "Call connect() first or use gdb_session action='start'."
            )

        # For `continue` (without &): GDB blocks until a breakpoint hit
        # or interrupt.  The sentinel echo after `continue` won't be
        # processed until the inferior stops.  Handle this by:
        # 1. Sending `continue` WITHOUT the sentinel
        # 2. Reading output until a stop reason or timeout
        # 3. Sending interrupt (Ctrl-C) if timeout
        _is_continue = command in ("continue", "c") or command.startswith("continue ")
        if _is_continue and "&" not in command:
            return self._execute_continue(command, timeout=timeout)

        with self._lock:
            self._last_raw_output = ""
            result = self._raw_send(command, timeout=timeout)
            if result is None:
                self._log_transcript(command, "[timeout]")
                return "[timeout] GDB did not respond within the time limit"
            if len(result) > 8000:
                result = result[:7800] + f"\n\n... (truncated, {len(result)} total chars)"
            raw_for_log = self._last_raw_output or result
            self._log_transcript(command, raw_for_log)
            return result

    def _execute_continue(self, command: str, *, timeout: int = 30) -> str:
        """Handle `continue` specially — it blocks until inferior stops.

        Sends the continue command, waits for a breakpoint hit or
        timeout.  If timeout, sends Ctrl-C to halt the inferior and
        returns whatever stop reason GDB reports.
        """
        import signal

        with self._lock:
            if self._process is None or self._process.poll() is not None:
                return "[error] GDB process is not running"

            # Send continue without sentinel
            try:
                self._process.stdin.write(f"{command}\n")
                self._process.stdin.flush()
            except (BrokenPipeError, OSError):
                return "[error] broken pipe"

            # Read output until we see a stop reason or timeout
            output_parts = []
            deadline = time.monotonic() + timeout
            stopped = False

            while time.monotonic() < deadline:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                line = self._read_line(timeout=min(remaining, 2.0))
                if line is None:
                    continue
                output_parts.append(line)
                # Check for stop indicators
                stripped = line.strip()
                if any(ind in stripped for ind in (
                    "Breakpoint ", "Hardware watchpoint",
                    "Program received signal", "stopped",
                    "Thread ", "Switching to ",
                    "(gdb)", "SIGINT", "SIGTRAP",
                )):
                    # Read a few more lines (GDB often outputs multi-line stop info)
                    for _ in range(5):
                        extra = self._read_line(timeout=1.0)
                        if extra:
                            output_parts.append(extra)
                            if "(gdb)" in extra:
                                break
                    stopped = True
                    break

            if not stopped:
                # Interrupt the remote target.  For `target remote`, we
                # need to send a raw Ctrl-C (0x03) to the GDB process's
                # stdin AND use SIGINT, because GDB translates SIGINT to
                # a GDB-RSP break packet for the remote stub.
                try:
                    # Method 1: Write interrupt byte directly to stdin
                    self._process.stdin.write("\x03")
                    self._process.stdin.flush()
                except Exception:
                    pass
                try:
                    # Method 2: Also send SIGINT to GDB process
                    self._process.send_signal(signal.SIGINT)
                except Exception:
                    pass
                # Read the interrupt response
                for _ in range(15):
                    line = self._read_line(timeout=2.0)
                    if line:
                        output_parts.append(line)
                        if "(gdb)" in line:
                            break

            raw = "\n".join(output_parts)
            self._last_raw_output = raw
            result = self._clean_output(raw, command)
            self._log_transcript(command, raw)

            if len(result) > 8000:
                result = result[:7800] + f"\n... (truncated, {len(result)} total)"
            return result

    def set_breakpoint(
        self, location: str, *, hardware: bool = False, temporary: bool = False,
    ) -> str:
        """Set a breakpoint at the given location.

        *location* can be a function name, ``*0xaddr``, or ``file:line``.
        Uses software breakpoints by default — the interactive session
        connects after kernel boot, so GDB can patch instructions
        directly.  Use ``hardware=True`` only if SW BPs don't fire.
        """
        if temporary:
            prefix = "thbreak" if hardware else "tbreak"
        else:
            prefix = "hbreak" if hardware else "break"
        return self.execute(f"{prefix} {location}")

    def set_breakpoint_at_address(self, addr: int, *, hardware: bool = False) -> str:
        """Set a breakpoint at a raw address."""
        return self.set_breakpoint(f"*{hex(addr)}", hardware=hardware)

    def remove_all_breakpoints(self) -> str:
        """Delete all breakpoints."""
        return self.execute("delete breakpoints")

    def continue_execution(self) -> str:
        """Resume execution (non-blocking — returns after continue starts)."""
        return self.execute("continue", timeout=5)

    def step_instruction(self) -> str:
        """Execute one machine instruction."""
        return self.execute("stepi")

    def get_backtrace(self, depth: int = 20) -> str:
        """Get backtrace."""
        return self.execute(f"bt {depth}")

    def get_registers(self) -> str:
        """Get all registers."""
        return self.execute("info registers")

    def read_memory(self, addr: int, count: int = 16, fmt: str = "gx") -> str:
        """Read memory in GDB x/ format."""
        count = min(count, 256)
        return self.execute(f"x/{count}{fmt} {hex(addr)}")

    def get_vuln_state(self) -> str:
        """Run the comprehensive syz-vuln-state analysis."""
        return self.execute("syz-vuln-state", timeout=30)

    def check_uaf(self, addr: int) -> str:
        """Check if an address shows UAF indicators."""
        return self.execute(f"syz-uaf-check {hex(addr)}")

    def check_oob(self, addr: int, size: int) -> str:
        """Check for OOB around an allocation."""
        return self.execute(f"syz-oob-check {hex(addr)} {size}")

    def check_cred(self) -> str:
        """Inspect current cred struct."""
        return self.execute("syz-cred-check")

    # ── Command Validation ────────────────────────────────────────────

    def _validate_command(self, command: str) -> Optional[str]:
        """Return an error message if the command is blocked, else None."""
        cmd_lower = command.lower().strip()

        # Check blocked patterns first
        for blocked in self._BLOCKED_PATTERNS:
            if cmd_lower.startswith(blocked):
                return (
                    f"Command '{command}' is blocked for safety. "
                    f"Blocked pattern: '{blocked}'"
                )

        # Empty command is fine (GDB repeats last)
        if not cmd_lower:
            return None

        # Check if it matches any allowed prefix
        for prefix in self._ALLOWED_PREFIXES:
            if cmd_lower.startswith(prefix):
                return None

        # Some single-word commands are allowed
        _ALLOWED_EXACT = {
            "bt", "backtrace", "where", "continue", "c",
            "stepi", "si", "nexti", "ni", "step", "next",
            "finish", "up", "down", "help",
        }
        if cmd_lower in _ALLOWED_EXACT:
            return None

        return (
            f"Command '{command}' is not in the allowed command set. "
            f"Allowed: inspection (info/print/x), stepping (stepi/nexti/step), "
            f"breakpoints (break/hbreak/delete), memory (x/), "
            f"and syz-* analysis commands."
        )

    # ── Low-level I/O ─────────────────────────────────────────────────

    def _raw_send(
        self, command: str, *, timeout: int = 15,
    ) -> Optional[str]:
        """Send a command via stdin and collect output until the GDB prompt.

        Uses a unique echo sentinel so we know exactly when output ends.
        Returns None on timeout.
        """
        if self._process is None or self._process.poll() is not None:
            return None

        self._sentinel_counter += 1
        sentinel = f"__SYZPLOIT_DONE_{self._sentinel_counter}__"

        # Send the command, then echo the sentinel
        payload = f"{command}\necho {sentinel}\\n\n"
        try:
            self._process.stdin.write(payload)
            self._process.stdin.flush()
        except (BrokenPipeError, OSError):
            return None

        # Read until sentinel appears
        output_parts: list[str] = []
        deadline = time.monotonic() + timeout

        while time.monotonic() < deadline:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break

            line = self._read_line(timeout=min(remaining, 2.0))
            if line is None:
                # No output within 2s — check if process is still alive
                if self._process and self._process.poll() is not None:
                    break
                continue

            if sentinel in line:
                break
            output_parts.append(line)

        raw = "\n".join(output_parts)
        # Keep raw output for transcript logging
        self._last_raw_output = raw
        # Strip the echo of the command itself and GDB prompts
        result = self._clean_output(raw, command)
        return result

    def _read_line(self, timeout: float = 1.0) -> Optional[str]:
        """Read one line from GDB stdout with a timeout.

        Uses a background thread to avoid blocking forever on readline().
        Subprocess is in text mode (encoding='utf-8') so readline()
        returns str directly.
        """
        if self._process is None or self._process.stdout is None:
            return None

        result: list[Optional[str]] = [None]

        def _reader():
            try:
                result[0] = self._process.stdout.readline()
            except Exception:
                pass

        t = threading.Thread(target=_reader, daemon=True)
        t.start()
        t.join(timeout=timeout)

        if result[0] is None:
            return None

        return result[0].rstrip("\n\r")

    def _drain_until_ready(self, timeout: int = 10) -> str:
        """Drain GDB output until quiet (initial banner)."""
        self._sentinel_counter += 1
        sentinel = f"__SYZPLOIT_DONE_{self._sentinel_counter}__"

        try:
            self._process.stdin.write(f"echo {sentinel}\\n\n")
            self._process.stdin.flush()
        except (BrokenPipeError, OSError):
            return ""

        parts: list[str] = []
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            line = self._read_line(timeout=1.0)
            if line is None:
                continue
            if sentinel in line:
                break
            parts.append(line)

        return "\n".join(parts)

    @staticmethod
    def _clean_output(raw: str, command: str) -> str:
        """Remove GDB prompt noise and command echo from output."""
        lines = raw.split("\n")
        cleaned: list[str] = []
        for line in lines:
            # Skip the echo of our command
            stripped = line.strip()
            if stripped == command.strip():
                continue
            # Skip bare GDB prompts
            if stripped in ("(gdb)", "(gdb) "):
                continue
            # Strip leading "(gdb) " from lines
            if line.startswith("(gdb) "):
                line = line[6:]
            cleaned.append(line)
        return "\n".join(cleaned).strip()
