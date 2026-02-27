"""
btf_offsets.py — Extract struct field offsets from vmlinux BTF data.

BTF (BPF Type Format) is embedded in vmlinux and provides precise
struct layouts for the *exact* kernel build, eliminating the need for
hardcoded offset tables.

Extraction strategies (tried in order):
1. ``pahole`` — the standard tool, most reliable.
2. ``bpftool btf dump`` — alternative, available on many systems.
3. Fallback to the hardcoded ``struct_offsets.py`` database.

Usage::

    offsets = query_btf_offsets(
        vmlinux_path="/path/to/vmlinux",
        structs=["cred", "task_struct", "msg_msg"],
    )
    # offsets = {"cred": {"uid": 4, "gid": 8, ...}, ...}
"""

import json
import os
import re
import shutil
import subprocess
from typing import Dict, List, Optional, Tuple

# Try to import the hardcoded fallback
try:
    from ..SyzAnalyze.struct_offsets import get_offset, STRUCT_OFFSETS
    _HAVE_FALLBACK = True
except ImportError:
    _HAVE_FALLBACK = False

# Exploit-relevant structs and fields for selective extraction
EXPLOIT_STRUCTS = {
    "cred": ["uid", "gid", "euid", "egid", "suid", "sgid", "fsuid", "fsgid",
             "securebits", "cap_inheritable", "cap_permitted", "cap_effective"],
    "task_struct": ["cred", "real_cred", "comm", "pid", "tgid", "tasks",
                    "mm", "active_mm", "fs", "files", "nsproxy"],
    "msg_msg": ["m_list", "m_type", "m_ts", "next", "security"],
    "pipe_buffer": ["page", "offset", "len", "ops", "flags"],
    "pipe_inode_info": ["bufs", "nrbufs", "ring_size", "head", "tail"],
    "tty_struct": ["magic", "ops", "driver", "ldisc", "count", "kref"],
    "seq_operations": ["start", "stop", "next", "show"],
    "sk_buff": ["head", "data", "tail", "end", "len", "data_len", "sk"],
    "file": ["f_op", "f_count", "f_flags", "f_mode", "f_pos", "private_data"],
}


def _run_pahole(vmlinux: str, struct_name: str) -> Optional[str]:
    """Run pahole to dump a struct's layout. Returns stdout or None."""
    pahole = shutil.which("pahole")
    if not pahole:
        return None
    try:
        result = subprocess.run(
            [pahole, "-C", struct_name, vmlinux],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout
    except Exception:
        pass
    return None


def _run_bpftool(vmlinux: str, struct_name: str) -> Optional[str]:
    """Run bpftool btf dump to get struct info. Returns stdout or None."""
    bpftool = shutil.which("bpftool")
    if not bpftool:
        return None
    try:
        # bpftool btf dump file <vmlinux> format c | grep -A200 "struct name {"
        result = subprocess.run(
            [bpftool, "btf", "dump", "file", vmlinux, "format", "c"],
            capture_output=True, text=True, timeout=60,
        )
        if result.returncode == 0:
            return result.stdout
    except Exception:
        pass
    return None


def _parse_pahole_output(output: str) -> Dict[str, int]:
    """Parse pahole output to extract field name -> byte offset.

    Pahole format example::

        struct cred {
            atomic_t                   usage;        /*     0     4 */
            kuid_t                     uid;          /*     4     4 */
            ...
        };
    """
    offsets: Dict[str, int] = {}
    # Match: <type> <name>; /* <offset> <size> */
    # Also handles:  <type> <name>[N]; /* <offset> <size> */
    pat = re.compile(
        r"^\s+\S.*?\s+(\w+)(?:\[\d+\])?;\s*/\*\s+(\d+)\s+\d+"
    )
    for line in output.splitlines():
        m = pat.match(line)
        if m:
            field_name = m.group(1)
            offset = int(m.group(2))
            offsets[field_name] = offset
    return offsets


def _parse_bpftool_c_output(output: str, struct_name: str) -> Dict[str, int]:
    """Parse bpftool C format output for a specific struct.

    The C format doesn't include offsets directly, so we'd need to
    compute them from types and alignment — expensive and fragile.
    For now, this only works if pahole-style comments are present.
    """
    # Look for the struct block
    pattern = re.compile(
        rf"struct\s+{re.escape(struct_name)}\s*\{{(.*?)\}};",
        re.DOTALL,
    )
    m = pattern.search(output)
    if not m:
        return {}
    # bpftool C output doesn't include offset comments in most versions
    # Fall back to empty
    return {}


def query_btf_offsets(
    vmlinux_path: str,
    structs: Optional[List[str]] = None,
    kernel_version: Optional[str] = None,
    logger=None,
) -> Dict[str, Dict[str, int]]:
    """Query struct field offsets from vmlinux BTF data.

    Tries ``pahole`` first, then ``bpftool``, then falls back to the
    hardcoded database in ``struct_offsets.py``.

    Args:
        vmlinux_path: Path to the vmlinux ELF with BTF.
        structs: Struct names to query.  If None, queries all
            exploit-relevant structs from EXPLOIT_STRUCTS.
        kernel_version: Kernel version string for fallback lookup.
        logger: Optional logging callback.

    Returns:
        ``{struct_name: {field_name: byte_offset, ...}, ...}``
    """
    def log(msg):
        if logger:
            logger(msg)
        else:
            print(f"[BTF] {msg}")

    if structs is None:
        structs = list(EXPLOIT_STRUCTS.keys())

    result: Dict[str, Dict[str, int]] = {}

    # Check vmlinux exists
    vmlinux_exists = vmlinux_path and os.path.isfile(vmlinux_path)

    if vmlinux_exists:
        # Strategy 1: pahole
        pahole_available = shutil.which("pahole") is not None
        if pahole_available:
            log(f"Using pahole to extract BTF offsets from {vmlinux_path}")
            for sname in structs:
                output = _run_pahole(vmlinux_path, sname)
                if output:
                    offsets = _parse_pahole_output(output)
                    if offsets:
                        # Filter to only exploit-relevant fields if specified
                        if sname in EXPLOIT_STRUCTS:
                            relevant = EXPLOIT_STRUCTS[sname]
                            offsets = {k: v for k, v in offsets.items()
                                       if k in relevant}
                        result[sname] = offsets
                        log(f"  {sname}: {len(offsets)} fields from pahole")
            if result:
                return result

        # Strategy 2: bpftool
        bpftool_available = shutil.which("bpftool") is not None
        if bpftool_available:
            log("Trying bpftool btf dump...")
            bpf_output = _run_bpftool(vmlinux_path, "")
            if bpf_output:
                for sname in structs:
                    offsets = _parse_bpftool_c_output(bpf_output, sname)
                    if offsets:
                        result[sname] = offsets
                        log(f"  {sname}: {len(offsets)} fields from bpftool")
            if result:
                return result

        log("No BTF tools available (install dwarves for pahole)")
    else:
        log(f"vmlinux not found: {vmlinux_path}")

    # Strategy 3: Fallback to hardcoded struct_offsets.py
    if _HAVE_FALLBACK and kernel_version:
        log(f"Falling back to hardcoded offsets for kernel {kernel_version}")
        for sname in structs:
            offsets = {}
            fields = EXPLOIT_STRUCTS.get(sname, [])
            for field in fields:
                val = get_offset(sname, field, kernel_version)
                if val is not None:
                    offsets[field] = val
            if offsets:
                result[sname] = offsets
                log(f"  {sname}: {len(offsets)} fields (hardcoded)")
    elif not _HAVE_FALLBACK:
        log("No fallback offsets available (struct_offsets.py not importable)")

    return result


def generate_btf_defines(
    offsets: Dict[str, Dict[str, int]],
) -> str:
    """Convert offset dict to C ``#define`` block.

    Example output::

        // BTF-derived struct offsets
        #define OFFSET_CRED_UID 4
        #define OFFSET_CRED_GID 8
        ...
    """
    lines = ["// BTF-derived struct offsets (auto-generated)"]
    for struct_name in sorted(offsets):
        lines.append(f"// --- {struct_name} ---")
        for field, off in sorted(offsets[struct_name].items(), key=lambda x: x[1]):
            macro = f"OFFSET_{struct_name.upper()}_{field.upper()}"
            lines.append(f"#define {macro} 0x{off:x}")
    return "\n".join(lines)
