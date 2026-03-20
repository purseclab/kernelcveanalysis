"""
GDB Python analysis script — sourced by GDB during interactive sessions.

This script is NOT executed directly by Python.  It is loaded inside a
running GDB session via ``source <path>``.  When sourced, it registers
a set of custom GDB commands (prefixed ``syz-``) that the LLM agent
can invoke through the interactive GDB tool.

Custom commands provided:
  syz-uaf-check <ptr>           Check if a pointer looks like a freed SLUB object
  syz-oob-check <ptr> <size>    Check for SLUB redzone corruption around an allocation
  syz-kasan-check <ptr>         Read KASAN shadow byte(s) for an address
  syz-heap-dump <ptr> <n>       Dump N words from a heap pointer and classify
  syz-cred-check [task_ptr]     Inspect current task's cred struct (UID/GID/caps)
  syz-slab-info <ptr>           Show slab page metadata for a pointer
  syz-task-info [task_ptr]      Display current task_struct fields
  syz-vuln-state                Comprehensive snapshot: regs + bt + heap + cred
  syz-mem-diff <ptr> <size>     Snapshot memory region for later comparison
  syz-mem-compare <ptr> <size>  Compare memory region with previous snapshot
  syz-breakpoint-summary        List all breakpoints and their hit counts
  syz-stack-vars                Show local variables and frame info
"""

# This entire file is meant to be source'd inside GDB.  The top-level
# code after the class definitions runs at source-time and prints a
# banner so the interactive session knows analysis helpers are loaded.

import gdb  # type: ignore[import-unresolved]
import json
import re
import traceback


# ── Utility helpers ───────────────────────────────────────────────────

def _safe_eval(expr):
    """Evaluate a GDB expression, returning None on failure."""
    try:
        return gdb.parse_and_eval(expr)
    except gdb.error:
        return None


def _safe_exec(cmd):
    """Execute a GDB command and return its output string."""
    try:
        return gdb.execute(cmd, to_string=True)
    except gdb.error as e:
        return f"[error] {e}"


def _detect_arch():
    """Detect target architecture from GDB."""
    try:
        arch_str = gdb.execute("show architecture", to_string=True)
        if "aarch64" in arch_str:
            return "arm64"
        elif "x86-64" in arch_str or "i386:x86-64" in arch_str:
            return "x86_64"
    except gdb.error:
        pass
    return "unknown"


def _get_current_task(arch):
    """Try to get the current task_struct pointer."""
    if arch == "arm64":
        # sp_el0 holds current task_struct on ARM64 Linux
        val = _safe_eval("$sp_el0")
        if val is not None:
            addr = int(val) & 0xFFFFFFFFFFFFFFFF
            if addr > 0xFFFF000000000000:
                return addr
    elif arch == "x86_64":
        # per-cpu current_task via gs_base
        val = _safe_eval("$gs_base")
        if val is not None:
            addr = int(val) & 0xFFFFFFFFFFFFFFFF
            if addr > 0xFFFF000000000000:
                return addr
    return None


def _read_mem_bytes(addr, size):
    """Read raw bytes from inferior memory. Returns bytes or None."""
    try:
        inf = gdb.selected_inferior()
        return bytes(inf.read_memory(addr, size))
    except (gdb.MemoryError, gdb.error):
        return None


def _read_u32(addr):
    """Read a 32-bit unsigned from memory."""
    data = _read_mem_bytes(addr, 4)
    if data is None:
        return None
    return int.from_bytes(data, byteorder="little")


def _read_u64(addr):
    """Read a 64-bit unsigned from memory."""
    data = _read_mem_bytes(addr, 8)
    if data is None:
        return None
    return int.from_bytes(data, byteorder="little")


# ── SLUB poison / redzone constants ──────────────────────────────────

SLUB_RED_INACTIVE = 0xBB  # Redzone byte for inactive objects
SLUB_RED_ACTIVE = 0xCC    # Redzone byte for active objects (some kernels)
SLUB_POISON_FREE = 0x6B   # Poison byte after kfree()
SLUB_POISON_INUSE = 0x5A  # End-of-object marker
KASAN_SHADOW_OFFSET_ARM64 = 0xDFFF200000000000  # Common for 48-bit VA
KASAN_SHADOW_SCALE = 3  # shadow = (addr >> 3) + offset

# KASAN shadow byte meanings
KASAN_SHADOW_MEANINGS = {
    0x00: "valid (accessible)",
    0xFF: "freed (KASAN generic)",
    0xFE: "freed (RCU)",
    0xFD: "freed (quarantine)",
    0xFB: "out-of-bounds (global)",
    0xFC: "redzone (stack)",
    0xFA: "use-after-scope",
    0xF8: "out-of-bounds (alloc)",
    0xF5: "use-after-free",
    0xF1: "stack left redzone",
    0xF2: "stack mid redzone",
    0xF3: "stack right redzone",
}

# ── Memory snapshots for diff ────────────────────────────────────────
_memory_snapshots = {}  # key = hex(ptr) -> bytes


# ══════════════════════════════════════════════════════════════════════
# Custom GDB Commands
# ══════════════════════════════════════════════════════════════════════


class SyzUafCheck(gdb.Command):
    """syz-uaf-check <ptr> — Check if a pointer looks like a freed SLUB object.

    Reads 64 bytes from the pointer and checks for SLUB poison patterns
    (0x6b fill after kfree).  Also tries KASAN shadow byte analysis.
    """

    def __init__(self):
        super().__init__("syz-uaf-check", gdb.COMMAND_DATA)

    def invoke(self, arg, from_tty):
        args = gdb.string_to_argv(arg)
        if not args:
            gdb.write("Usage: syz-uaf-check <address>\n")
            return

        try:
            ptr = int(args[0], 0)
        except ValueError:
            gdb.write(f"Invalid address: {args[0]}\n")
            return

        gdb.write(f"\n=== UAF Check: {hex(ptr)} ===\n")

        # Read 64 bytes from the object
        data = _read_mem_bytes(ptr, 64)
        if data is None:
            gdb.write(f"  Cannot read memory at {hex(ptr)} (unmapped/faulted)\n")
            gdb.write("  RESULT: memory inaccessible — likely freed or invalid\n")
            return

        # Check for SLUB poison pattern (0x6b fill)
        poison_count = sum(1 for b in data if b == SLUB_POISON_FREE)
        poison_pct = poison_count / len(data) * 100

        gdb.write(f"  First 64 bytes: {data[:32].hex()} ...\n")
        gdb.write(f"  Poison bytes (0x6b): {poison_count}/64 ({poison_pct:.0f}%)\n")

        if poison_pct > 60:
            gdb.write("  ** LIKELY FREED (UAF): majority of bytes are SLUB poison (0x6b) **\n")
        elif poison_pct > 20:
            gdb.write("  ** POSSIBLY FREED: significant poison byte presence **\n")
        else:
            gdb.write("  Object does NOT appear to have SLUB poison fill — likely alive or reclaimed\n")

        # Check first 8 bytes — if it looks like a freelist pointer
        first_qword = int.from_bytes(data[:8], "little")
        if first_qword == 0 or (first_qword > 0xFFFF000000000000 and first_qword < 0xFFFFFFFFFFFFFFFF):
            gdb.write(f"  First qword: {hex(first_qword)} — could be SLUB freelist next ptr\n")

        # Try KASAN shadow byte
        _check_kasan_at(ptr)

        gdb.write("\n")


class SyzOobCheck(gdb.Command):
    """syz-oob-check <ptr> <size> — Check for SLUB redzone corruption.

    Reads bytes before and after an allocation to look for redzone
    corruption indicating an out-of-bounds write.
    """

    def __init__(self):
        super().__init__("syz-oob-check", gdb.COMMAND_DATA)

    def invoke(self, arg, from_tty):
        args = gdb.string_to_argv(arg)
        if len(args) < 2:
            gdb.write("Usage: syz-oob-check <address> <object_size>\n")
            return

        try:
            ptr = int(args[0], 0)
            size = int(args[1], 0)
        except ValueError:
            gdb.write(f"Invalid arguments: {args}\n")
            return

        gdb.write(f"\n=== OOB Check: {hex(ptr)} size={size} ===\n")

        # Check redzone BEFORE the object (16 bytes)
        pre_data = _read_mem_bytes(ptr - 16, 16)
        if pre_data:
            non_rz = sum(1 for b in pre_data if b != SLUB_RED_INACTIVE)
            gdb.write(f"  Pre-redzone  (ptr-16): {pre_data.hex()}\n")
            if non_rz > 4:
                gdb.write("  ** PRE-REDZONE CORRUPTED: possible underflow write **\n")
            else:
                gdb.write("  Pre-redzone looks intact\n")
        else:
            gdb.write("  Cannot read pre-redzone memory\n")

        # Check redzone AFTER the object (16 bytes)
        post_data = _read_mem_bytes(ptr + size, 16)
        if post_data:
            non_rz = sum(1 for b in post_data if b != SLUB_RED_INACTIVE)
            gdb.write(f"  Post-redzone (ptr+{size}): {post_data.hex()}\n")
            if non_rz > 4:
                gdb.write("  ** POST-REDZONE CORRUPTED: possible overflow write (OOB) **\n")
            else:
                gdb.write("  Post-redzone looks intact\n")
        else:
            gdb.write("  Cannot read post-redzone memory\n")

        # KASAN
        _check_kasan_at(ptr)
        _check_kasan_at(ptr + size)

        gdb.write("\n")


class SyzKasanCheck(gdb.Command):
    """syz-kasan-check <ptr> — Read KASAN shadow byte(s) for an address."""

    def __init__(self):
        super().__init__("syz-kasan-check", gdb.COMMAND_DATA)

    def invoke(self, arg, from_tty):
        args = gdb.string_to_argv(arg)
        if not args:
            gdb.write("Usage: syz-kasan-check <address>\n")
            return

        try:
            ptr = int(args[0], 0)
        except ValueError:
            gdb.write(f"Invalid address: {args[0]}\n")
            return

        gdb.write(f"\n=== KASAN Shadow Check: {hex(ptr)} ===\n")
        _check_kasan_at(ptr)
        gdb.write("\n")


def _check_kasan_at(ptr):
    """Check KASAN shadow byte for a given pointer (helper)."""
    # Try multiple known shadow offsets
    offsets = [
        ("48-bit VA", 0xDFFF200000000000),
        ("39-bit VA", 0xFFFFFC0000000000),
    ]
    for label, shadow_offset in offsets:
        shadow_addr = (ptr >> KASAN_SHADOW_SCALE) + shadow_offset
        shadow_byte = _read_mem_bytes(shadow_addr, 1)
        if shadow_byte is not None:
            val = shadow_byte[0]
            meaning = KASAN_SHADOW_MEANINGS.get(val, f"partial valid ({val} bytes)" if 1 <= val <= 7 else "unknown")
            gdb.write(f"  KASAN ({label}): shadow@{hex(shadow_addr)} = 0x{val:02x} — {meaning}\n")
            if val == 0xFF or val == 0xFD or val == 0xF5:
                gdb.write("  ** KASAN confirms: USE-AFTER-FREE **\n")
            elif val == 0xFB or val == 0xF8:
                gdb.write("  ** KASAN confirms: OUT-OF-BOUNDS **\n")
            return
    gdb.write(f"  KASAN: shadow memory not readable (KASAN may not be enabled)\n")


class SyzHeapDump(gdb.Command):
    """syz-heap-dump <ptr> <n> — Dump N 8-byte words from a heap pointer."""

    def __init__(self):
        super().__init__("syz-heap-dump", gdb.COMMAND_DATA)

    def invoke(self, arg, from_tty):
        args = gdb.string_to_argv(arg)
        if len(args) < 1:
            gdb.write("Usage: syz-heap-dump <address> [num_words=16]\n")
            return

        try:
            ptr = int(args[0], 0)
            n = int(args[1], 0) if len(args) > 1 else 16
        except ValueError:
            gdb.write(f"Invalid arguments: {args}\n")
            return

        n = min(n, 128)  # cap at 128 words
        gdb.write(f"\n=== Heap Dump: {hex(ptr)} ({n} words) ===\n")
        output = _safe_exec(f"x/{n}gx {hex(ptr)}")
        gdb.write(output)

        # Quick classification
        data = _read_mem_bytes(ptr, min(n * 8, 512))
        if data:
            poison_pct = sum(1 for b in data if b == SLUB_POISON_FREE) / len(data) * 100
            zero_pct = sum(1 for b in data if b == 0) / len(data) * 100
            if poison_pct > 50:
                gdb.write(f"  Classification: SLUB POISON (freed object, {poison_pct:.0f}% 0x6b)\n")
            elif zero_pct > 80:
                gdb.write(f"  Classification: ZEROED (kzalloc or cleared, {zero_pct:.0f}% zero)\n")
            else:
                gdb.write(f"  Classification: IN-USE data (poison={poison_pct:.0f}%, zero={zero_pct:.0f}%)\n")
        gdb.write("\n")


class SyzCredCheck(gdb.Command):
    """syz-cred-check [task_ptr] — Inspect current task's cred struct."""

    def __init__(self):
        super().__init__("syz-cred-check", gdb.COMMAND_DATA)

    def invoke(self, arg, from_tty):
        args = gdb.string_to_argv(arg)
        arch = _detect_arch()

        if args:
            try:
                task_addr = int(args[0], 0)
            except ValueError:
                gdb.write(f"Invalid task address: {args[0]}\n")
                return
        else:
            task_addr = _get_current_task(arch)
            if task_addr is None:
                gdb.write("Cannot determine current task_struct address\n")
                return

        gdb.write(f"\n=== Cred Check: task_struct @ {hex(task_addr)} ===\n")

        # Try common cred offsets for different kernel versions
        # task_struct->cred varies by kernel version
        cred_offsets = [0x678, 0x6a8, 0x6c0, 0x6e0, 0x740, 0x750, 0x660, 0x698]

        for cred_off in cred_offsets:
            cred_ptr = _read_u64(task_addr + cred_off)
            if cred_ptr is None:
                continue
            if not (0xFFFF000000000000 < cred_ptr < 0xFFFFFFFFFFFFFFFF):
                continue

            # cred struct layout (simplified):
            #   +0:  atomic_t usage
            #   +4:  kuid_t uid
            #   +8:  kgid_t gid
            #   +12: kuid_t suid
            #   +16: ksgid_t sgid
            #   +20: kuid_t euid
            #   +24: kgid_t egid
            uid = _read_u32(cred_ptr + 4)
            gid = _read_u32(cred_ptr + 8)
            euid = _read_u32(cred_ptr + 20)
            egid = _read_u32(cred_ptr + 24)

            if uid is not None and uid < 100000:
                gdb.write(f"  cred offset: {hex(cred_off)} → cred @ {hex(cred_ptr)}\n")
                gdb.write(f"  uid={uid}  gid={gid}  euid={euid}  egid={egid}\n")
                if uid == 0 and euid == 0:
                    gdb.write("  ** RUNNING AS ROOT (uid=0, euid=0) **\n")
                elif uid == 0 or euid == 0:
                    gdb.write("  ** PARTIAL ROOT (uid or euid is 0) **\n")

                # Check capabilities
                # cap_inheritable at +40, cap_permitted at +48, cap_effective at +56
                cap_eff = _read_u64(cred_ptr + 56)
                if cap_eff is not None:
                    gdb.write(f"  cap_effective: {hex(cap_eff)}\n")
                    if cap_eff == 0x3FFFFFFFFF or cap_eff == 0x1FFFFFFFFFF:
                        gdb.write("  ** FULL CAPABILITIES **\n")
                gdb.write("\n")
                return

        gdb.write("  Could not find valid cred pointer at known offsets\n\n")


class SyzSlabInfo(gdb.Command):
    """syz-slab-info <ptr> — Show slab/page metadata for a pointer."""

    def __init__(self):
        super().__init__("syz-slab-info", gdb.COMMAND_DATA)

    def invoke(self, arg, from_tty):
        args = gdb.string_to_argv(arg)
        if not args:
            gdb.write("Usage: syz-slab-info <address>\n")
            return

        try:
            ptr = int(args[0], 0)
        except ValueError:
            gdb.write(f"Invalid address: {args[0]}\n")
            return

        gdb.write(f"\n=== Slab Info: {hex(ptr)} ===\n")

        # Page-aligned address (4KB pages)
        page_addr = ptr & ~0xFFF
        gdb.write(f"  Page-aligned: {hex(page_addr)}\n")
        gdb.write(f"  Offset in page: {ptr - page_addr}\n")

        # Dump the object neighbourhood
        # Show 3 words before and 8 words at the pointer
        gdb.write("  Memory at pointer:\n")
        gdb.write(_safe_exec(f"x/8gx {hex(ptr)}"))

        # Check if SLUB freelist pointer (first qword)
        first = _read_u64(ptr)
        if first is not None:
            if first == 0:
                gdb.write("  First qword = NULL (end of freelist or zeroed field)\n")
            elif 0xFFFF000000000000 < first < 0xFFFFFFFFFFFFFFFF:
                gdb.write(f"  First qword = {hex(first)} — looks like a kernel pointer (freelist next?)\n")

        gdb.write("\n")


class SyzTaskInfo(gdb.Command):
    """syz-task-info [task_ptr] — Display current task_struct fields."""

    def __init__(self):
        super().__init__("syz-task-info", gdb.COMMAND_DATA)

    def invoke(self, arg, from_tty):
        args = gdb.string_to_argv(arg)
        arch = _detect_arch()

        if args:
            try:
                task_addr = int(args[0], 0)
            except ValueError:
                gdb.write(f"Invalid address: {args[0]}\n")
                return
        else:
            task_addr = _get_current_task(arch)
            if task_addr is None:
                gdb.write("Cannot determine current task_struct\n")
                return

        gdb.write(f"\n=== Task Info: {hex(task_addr)} ===\n")

        # task_struct->comm is typically at offset 0x678..0x850 depending
        # on kernel version.  Try reading with GDB's type system if vmlinux
        # is loaded, otherwise try common offsets.
        try:
            # If vmlinux with debug info is loaded:
            task_val = gdb.Value(task_addr).cast(
                gdb.lookup_type("struct task_struct").pointer()
            )
            gdb.write(f"  comm: {task_val['comm'].string()}\n")
            gdb.write(f"  pid: {int(task_val['pid'])}\n")
            gdb.write(f"  tgid: {int(task_val['tgid'])}\n")
            gdb.write(f"  state: {int(task_val['__state'])}\n")
            gdb.write(f"  flags: {hex(int(task_val['flags']))}\n")
        except (gdb.error, RuntimeError):
            # No debug info — dump raw fields at common offsets
            gdb.write("  (no debug info — using heuristic offsets)\n")

            # Common task_struct offsets (5.10 ARM64):
            #   pid: ~0x568-0x570
            #   comm: ~0x680-0x690 (16 bytes string)
            pid_offsets = [0x568, 0x570, 0x578, 0x590, 0x598]
            for off in pid_offsets:
                pid = _read_u32(task_addr + off)
                if pid is not None and 0 < pid < 65536:
                    gdb.write(f"  pid (offset {hex(off)}): {pid}\n")
                    break

            # Read comm string — look for ASCII at common offsets
            comm_offsets = [0x680, 0x690, 0x6a0, 0x6b0, 0x6d0, 0x750, 0x760]
            for off in comm_offsets:
                data = _read_mem_bytes(task_addr + off, 16)
                if data:
                    # Check if it looks like an ASCII string
                    try:
                        text = data.split(b'\x00')[0].decode('ascii')
                        if len(text) >= 2 and text.isprintable():
                            gdb.write(f"  comm (offset {hex(off)}): \"{text}\"\n")
                            break
                    except (UnicodeDecodeError, ValueError):
                        continue

        # Registers for current context
        gdb.write("  Current registers:\n")
        if arch == "arm64":
            for reg in ["pc", "sp", "x0", "x1", "x29", "x30"]:
                val = _safe_eval(f"${reg}")
                if val is not None:
                    gdb.write(f"    {reg} = {hex(int(val) & 0xFFFFFFFFFFFFFFFF)}\n")
        else:
            for reg in ["rip", "rsp", "rdi", "rsi", "rbp"]:
                val = _safe_eval(f"${reg}")
                if val is not None:
                    gdb.write(f"    {reg} = {hex(int(val) & 0xFFFFFFFFFFFFFFFF)}\n")

        gdb.write("\n")


class SyzVulnState(gdb.Command):
    """syz-vuln-state — Comprehensive vulnerability analysis snapshot."""

    def __init__(self):
        super().__init__("syz-vuln-state", gdb.COMMAND_DATA)

    def invoke(self, arg, from_tty):
        arch = _detect_arch()

        gdb.write("\n" + "=" * 60 + "\n")
        gdb.write("  VULNERABILITY STATE SNAPSHOT\n")
        gdb.write("=" * 60 + "\n")

        # 1. Registers
        gdb.write("\n[REGISTERS]\n")
        gdb.write(_safe_exec("info registers"))

        # 2. Backtrace
        gdb.write("\n[BACKTRACE]\n")
        gdb.write(_safe_exec("bt 25"))

        # 3. Stack dump
        gdb.write("\n[STACK (16 words at SP)]\n")
        gdb.write(_safe_exec("x/16gx $sp"))

        # 4. Current thread info
        gdb.write("\n[THREAD]\n")
        gdb.write(_safe_exec("info threads"))

        # 5. Credential check
        gdb.write("\n[CREDENTIALS]\n")
        task_addr = _get_current_task(arch)
        if task_addr:
            gdb.write(f"  task_struct @ {hex(task_addr)}\n")
            # Inline cred check
            cred_offsets = [0x678, 0x6a8, 0x6c0, 0x6e0, 0x740]
            found = False
            for cred_off in cred_offsets:
                cred_ptr = _read_u64(task_addr + cred_off)
                if cred_ptr and 0xFFFF000000000000 < cred_ptr < 0xFFFFFFFFFFFFFFFF:
                    uid = _read_u32(cred_ptr + 4)
                    euid = _read_u32(cred_ptr + 20)
                    if uid is not None and uid < 100000:
                        gdb.write(f"  cred @ {hex(cred_ptr)} (offset={hex(cred_off)})\n")
                        gdb.write(f"  uid={uid}  euid={euid}\n")
                        if uid == 0:
                            gdb.write("  ** ROOT **\n")
                        found = True
                        break
            if not found:
                gdb.write("  Could not locate cred struct\n")
        else:
            gdb.write("  Could not identify current task_struct\n")

        # 6. Breakpoints
        gdb.write("\n[BREAKPOINTS]\n")
        gdb.write(_safe_exec("info breakpoints"))

        gdb.write("\n" + "=" * 60 + "\n\n")


class SyzMemDiff(gdb.Command):
    """syz-mem-diff <ptr> <size> — Snapshot memory for later comparison."""

    def __init__(self):
        super().__init__("syz-mem-diff", gdb.COMMAND_DATA)

    def invoke(self, arg, from_tty):
        args = gdb.string_to_argv(arg)
        if len(args) < 2:
            gdb.write("Usage: syz-mem-diff <address> <size>\n")
            return

        try:
            ptr = int(args[0], 0)
            size = int(args[1], 0)
        except ValueError:
            gdb.write(f"Invalid arguments: {args}\n")
            return

        size = min(size, 4096)
        data = _read_mem_bytes(ptr, size)
        if data is None:
            gdb.write(f"Cannot read {size} bytes at {hex(ptr)}\n")
            return

        key = hex(ptr)
        _memory_snapshots[key] = data
        gdb.write(f"Snapshot saved: {size} bytes at {key}\n")
        gdb.write(f"Use 'syz-mem-compare {key} {size}' after the operation to see changes\n\n")


class SyzMemCompare(gdb.Command):
    """syz-mem-compare <ptr> <size> — Compare memory with saved snapshot."""

    def __init__(self):
        super().__init__("syz-mem-compare", gdb.COMMAND_DATA)

    def invoke(self, arg, from_tty):
        args = gdb.string_to_argv(arg)
        if len(args) < 2:
            gdb.write("Usage: syz-mem-compare <address> <size>\n")
            return

        try:
            ptr = int(args[0], 0)
            size = int(args[1], 0)
        except ValueError:
            gdb.write(f"Invalid arguments: {args}\n")
            return

        key = hex(ptr)
        if key not in _memory_snapshots:
            gdb.write(f"No snapshot saved for {key} — use syz-mem-diff first\n")
            return

        old_data = _memory_snapshots[key]
        size = min(size, len(old_data))
        new_data = _read_mem_bytes(ptr, size)
        if new_data is None:
            gdb.write(f"Cannot read {size} bytes at {hex(ptr)}\n")
            return

        gdb.write(f"\n=== Memory Compare: {key} ({size} bytes) ===\n")
        diffs = 0
        for i in range(size):
            if old_data[i] != new_data[i]:
                diffs += 1
                if diffs <= 64:
                    gdb.write(f"  offset +{i:#06x}: {old_data[i]:#04x} → {new_data[i]:#04x}\n")

        if diffs == 0:
            gdb.write("  NO CHANGES\n")
        else:
            gdb.write(f"\n  Total changed bytes: {diffs}/{size}\n")
            if diffs > 64:
                gdb.write(f"  (showing first 64 diffs)\n")
        gdb.write("\n")


class SyzBreakpointSummary(gdb.Command):
    """syz-breakpoint-summary — Enhanced breakpoint info with hit counts."""

    def __init__(self):
        super().__init__("syz-breakpoint-summary", gdb.COMMAND_DATA)

    def invoke(self, arg, from_tty):
        gdb.write("\n=== Breakpoint Summary ===\n")
        bp_info = _safe_exec("info breakpoints")
        gdb.write(bp_info)

        # Count by type
        hw_count = bp_info.count("hw breakpoint")
        sw_count = bp_info.count("breakpoint") - hw_count
        wp_count = bp_info.count("watchpoint")
        gdb.write(f"\n  HW breakpoints: {hw_count}  SW breakpoints: {sw_count}  Watchpoints: {wp_count}\n\n")


class SyzStackVars(gdb.Command):
    """syz-stack-vars — Show local variables and frame info."""

    def __init__(self):
        super().__init__("syz-stack-vars", gdb.COMMAND_DATA)

    def invoke(self, arg, from_tty):
        gdb.write("\n=== Stack Frame & Variables ===\n")

        # Frame info
        gdb.write("[Frame]\n")
        gdb.write(_safe_exec("info frame"))

        # Try locals
        gdb.write("\n[Local Variables]\n")
        locals_out = _safe_exec("info locals")
        if "No locals" in locals_out or "No symbol" in locals_out:
            gdb.write("  (no debug info available for this frame)\n")
            # Fall back to raw stack dump
            gdb.write("\n[Stack (raw, 12 words from SP)]\n")
            gdb.write(_safe_exec("x/12gx $sp"))
        else:
            gdb.write(locals_out)

        # Args
        gdb.write("\n[Function Arguments]\n")
        args_out = _safe_exec("info args")
        if "No arguments" in args_out or "No symbol" in args_out:
            arch = _detect_arch()
            if arch == "arm64":
                gdb.write("  (using register ABI — args in x0-x7)\n")
                for i in range(8):
                    val = _safe_eval(f"$x{i}")
                    if val is not None:
                        gdb.write(f"    x{i} = {hex(int(val) & 0xFFFFFFFFFFFFFFFF)}\n")
            elif arch == "x86_64":
                gdb.write("  (using register ABI — args in rdi,rsi,rdx,rcx,r8,r9)\n")
                for reg in ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]:
                    val = _safe_eval(f"${reg}")
                    if val is not None:
                        gdb.write(f"    {reg} = {hex(int(val) & 0xFFFFFFFFFFFFFFFF)}\n")
        else:
            gdb.write(args_out)

        gdb.write("\n")


# ══════════════════════════════════════════════════════════════════════
# Registration — runs when GDB sources this file
# ══════════════════════════════════════════════════════════════════════

SyzUafCheck()
SyzOobCheck()
SyzKasanCheck()
SyzHeapDump()
SyzCredCheck()
SyzSlabInfo()
SyzTaskInfo()
SyzVulnState()
SyzMemDiff()
SyzMemCompare()
SyzBreakpointSummary()
SyzStackVars()

gdb.write("\n")
gdb.write("=" * 50 + "\n")
gdb.write("  syzploit analysis commands loaded\n")
gdb.write("=" * 50 + "\n")
gdb.write("  Available commands:\n")
gdb.write("    syz-uaf-check <ptr>         — Check for use-after-free\n")
gdb.write("    syz-oob-check <ptr> <size>   — Check for out-of-bounds\n")
gdb.write("    syz-kasan-check <ptr>        — Read KASAN shadow bytes\n")
gdb.write("    syz-heap-dump <ptr> [n]      — Dump heap memory words\n")
gdb.write("    syz-cred-check [task_ptr]    — Inspect cred struct (UID/caps)\n")
gdb.write("    syz-slab-info <ptr>          — Show slab metadata for pointer\n")
gdb.write("    syz-task-info [task_ptr]     — Show task_struct fields\n")
gdb.write("    syz-vuln-state               — Full vulnerability snapshot\n")
gdb.write("    syz-mem-diff <ptr> <size>    — Snapshot memory region\n")
gdb.write("    syz-mem-compare <ptr> <size> — Compare with snapshot\n")
gdb.write("    syz-breakpoint-summary       — Enhanced breakpoint listing\n")
gdb.write("    syz-stack-vars               — Stack frame & variables\n")
gdb.write("=" * 50 + "\n\n")
