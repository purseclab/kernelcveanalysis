"""
analysis.crash_parser — Parse kernel crash logs (KASAN, UBSAN, generic oops).

Extracts structured ``CrashReport`` from raw dmesg / crash log text.
This is a pure-parsing module with no LLM calls.
"""

from __future__ import annotations

import re
from typing import List, Optional, Tuple

from ..core.models import Arch, CrashFrame, CrashReport, VulnType

# ── Known unimportant / infrastructure stack functions ────────────────

UNIMPORTANT_STACK_FUNCTIONS: set[str] = {
    "kasan_report", "kasan_check_range", "__kasan_check_read",
    "__kasan_check_write", "check_memory_region", "kasan_save_stack",
    "kasan_set_track", "kasan_save_free_info", "kasan_save_alloc_info",
    "__asan_load1", "__asan_load2", "__asan_load4", "__asan_load8",
    "__asan_store1", "__asan_store2", "__asan_store4", "__asan_store8",
    "print_report", "print_address_description", "kasan_report_invalid_free",
    "kunit_try_catch_run", "kunit_generic_run_threadfn_adapter",
    "__ubsan_handle_out_of_bounds", "__ubsan_handle_shift_out_of_bounds",
    "__ubsan_handle_load_invalid_value",
    "dump_stack", "show_stack", "panic", "oops_enter", "oops_exit",
    "die", "__die", "do_trap", "do_error_trap",
    "kmalloc", "kfree", "kmem_cache_alloc", "kmem_cache_free",
    "slab_alloc", "slab_free", "__slab_alloc", "__slab_free",
    "alloc_pages", "__alloc_pages",
    "entry_SYSCALL_64", "do_syscall_64", "__x64_sys_",
    "el0_svc", "el0_svc_handler", "invoke_syscall",
}


def parse_crash_log(raw: str) -> CrashReport:
    """
    Parse a raw kernel crash log into a structured ``CrashReport``.

    Handles:
    - KASAN reports (slab-use-after-free, slab-out-of-bounds, etc.)
    - UBSAN reports
    - KMSAN reports
    - Generic kernel oops / BUG / panic
    """
    report = CrashReport(raw_log=raw)

    # ── Detect crash type ─────────────────────────────────────────────
    bug_match = re.search(
        r"BUG:\s*(KASAN|UBSAN|KMSAN):\s*([^\n]+?)\s+in\s+(\S+)", raw
    )
    if bug_match:
        sanitizer = bug_match.group(1)
        detail = bug_match.group(2).strip()
        func = bug_match.group(3).strip()
        report.crash_type = f"{sanitizer}: {detail}"
        report.corrupted_function = func
        report.bug_type = _classify_vuln_type(sanitizer, detail)
    else:
        # Generic oops
        oops = re.search(r"(kernel BUG|BUG:|Oops|kernel panic)", raw, re.IGNORECASE)
        if oops:
            report.crash_type = oops.group(0)

    # ── Access info ───────────────────────────────────────────────────
    acc = re.search(r"(Read|Write) of size (\d+) at addr ([0-9a-fA-Fx]+)", raw)
    if acc:
        report.access_type = acc.group(1).lower()
        report.access_size = int(acc.group(2))
        report.access_address = acc.group(3)

    # ── Slab cache / object size ──────────────────────────────────────
    slab_m = re.search(
        r"(?:in cache|Allocated in|cache)\s+['\"]?(\S+?)['\"]?\s", raw
    )
    if slab_m:
        report.slab_cache = slab_m.group(1)

    obj_m = re.search(r"object size[:\s]+(\d+)", raw, re.IGNORECASE)
    if obj_m:
        report.object_size = int(obj_m.group(1))

    # ── Stack traces ──────────────────────────────────────────────────
    report.stack_frames = _parse_stack_section(raw, "Call Trace")
    if not report.stack_frames:
        report.stack_frames = _parse_stack_section(raw, "call trace")
    report.alloc_frames = _parse_stack_section(raw, "Allocated by")
    report.free_frames = _parse_stack_section(raw, "Freed by")

    # ── Architecture detection ────────────────────────────────────────
    if re.search(r"aarch64|arm64|goldfish|cuttlefish", raw, re.IGNORECASE):
        report.arch = Arch.ARM64
    elif re.search(r"x86_64|amd64", raw, re.IGNORECASE):
        report.arch = Arch.X86_64

    # ── Kernel version ────────────────────────────────────────────────
    ver_m = re.search(r"Linux version (\S+)", raw)
    if ver_m:
        report.kernel_version = ver_m.group(1)

    return report


# ── Internal helpers ──────────────────────────────────────────────────


def _classify_vuln_type(sanitizer: str, detail: str) -> VulnType:
    d = detail.lower()
    if "use-after-free" in d or "uaf" in d:
        return VulnType.UAF
    if "out-of-bounds" in d:
        return VulnType.OOB_WRITE if "write" in d else VulnType.OOB_READ
    if "double-free" in d:
        return VulnType.DOUBLE_FREE
    if "null" in d:
        return VulnType.NULL_DEREF
    if "uninit" in d:
        return VulnType.USE_BEFORE_INIT
    if sanitizer == "UBSAN":
        if "shift" in d or "overflow" in d:
            return VulnType.INTEGER_OVERFLOW
    return VulnType.UNKNOWN


def _parse_stack_section(raw: str, header: str) -> List[CrashFrame]:
    """Extract stack frames from a section starting with *header*."""
    pattern = re.compile(
        rf"^\s*{re.escape(header)}.*?$\n((?:\s+.*\n)*)",
        re.MULTILINE | re.IGNORECASE,
    )
    m = pattern.search(raw)
    if not m:
        return []
    return _parse_frames(m.group(1))


def _parse_frames(block: str) -> List[CrashFrame]:
    """Parse individual frames from a stack-trace block."""
    frames: List[CrashFrame] = []
    # Pattern: optional [ ] address, function_name+offset/size [module]
    frame_re = re.compile(
        r"(?:\[<[0-9a-fA-F]+>\]\s*)?"
        r"(?:\?\s*)?"
        r"(\w[\w.]+)"                     # function name
        r"(?:\+0x([0-9a-fA-F]+))?"        # +offset
        r"(?:/0x[0-9a-fA-F]+)?"           # /size
        r"(?:\s+\[(\S+)\])?"              # [module]
        r"(?:\s+(\S+:\d+))?"              # file:line
    )
    for line in block.splitlines():
        line = line.strip()
        if not line:
            continue
        m = frame_re.search(line)
        if m:
            func = m.group(1)
            # Skip infrastructure functions
            if func in UNIMPORTANT_STACK_FUNCTIONS:
                continue
            file_line = m.group(4)
            file_name = None
            line_num = None
            if file_line and ":" in file_line:
                parts = file_line.rsplit(":", 1)
                file_name = parts[0]
                try:
                    line_num = int(parts[1])
                except ValueError:
                    pass
            frames.append(
                CrashFrame(
                    function=func,
                    offset=m.group(2),
                    module=m.group(3),
                    file=file_name,
                    line=line_num,
                )
            )
    return frames


def filter_important_frames(frames: List[CrashFrame]) -> List[CrashFrame]:
    """Remove infrastructure / sanitizer frames, keeping only meaningful ones."""
    return [f for f in frames if f.function not in UNIMPORTANT_STACK_FUNCTIONS]
