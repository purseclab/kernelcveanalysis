"""
Kernel structure offsets indexed by kernel version.

Provides:
- Structure field offsets for commonly exploited kernel objects
- Version-aware lookup with fuzzy matching (5.15.100 → 5.15)
- BTF-compatible field names
- Helper to generate #define blocks for exploit C code

Usage:
    from .struct_offsets import get_offset, get_struct_defines, get_all_offsets

    # Get a single offset
    uid_off = get_offset("cred", "uid", "5.15")

    # Get #define block for C code
    defines = get_struct_defines(["cred", "task_struct"], "5.15")
"""

from typing import Any, Dict, List, Optional

# ---------------------------------------------------------------------------
# Offset database
# ---------------------------------------------------------------------------
# Offsets are for CONFIG_SMP=y, CONFIG_PREEMPT=y, 64-bit builds.
# Collected from BTF data, pahole, and manual verification.
#
# Format: struct_name → { major.minor → { field → offset } }
#
# Where offsets are not version-specific (e.g., cred.uid is always 4),
# a special "_common" key holds the shared values.

STRUCT_OFFSETS: Dict[str, Dict[str, Dict[str, int]]] = {
    # -----------------------------------------------------------------------
    # struct cred — credential structure (relatively stable)
    # -----------------------------------------------------------------------
    "cred": {
        "_common": {
            "usage": 0,
            "uid": 4,
            "gid": 8,
            "suid": 12,
            "sgid": 16,
            "euid": 20,
            "egid": 24,
            "fsuid": 28,
            "fsgid": 32,
            "securebits": 36,
            "cap_inheritable": 40,
            "cap_permitted": 48,
            "cap_effective": 56,
            "cap_bset": 64,
            "cap_ambient": 72,
        },
        # user_ns offset varies by version
        "5.4": {"user_ns": 136},
        "5.10": {"user_ns": 136},
        "5.15": {"user_ns": 136},
        "6.1": {"user_ns": 136},
        "6.6": {"user_ns": 136},
    },

    # -----------------------------------------------------------------------
    # struct task_struct — process descriptor (offsets shift frequently)
    # -----------------------------------------------------------------------
    "task_struct": {
        "5.4": {
            "state": 0x10,
            "stack": 0x18,
            "flags": 0x24,
            "on_cpu": 0x58,
            "prio": 0x60,
            "pid": 0x398,
            "tgid": 0x39c,
            "real_parent": 0x3a0,
            "parent": 0x3a8,
            "mm": 0x460,
            "active_mm": 0x468,
            "comm": 0x718,
            "cred": 0x6e8,
            "real_cred": 0x6e0,
            "fs": 0x750,
            "files": 0x758,
            "nsproxy": 0x760,
        },
        "5.10": {
            "state": 0x10,
            "stack": 0x20,
            "flags": 0x2c,
            "on_cpu": 0x60,
            "prio": 0x68,
            "pid": 0x3b8,
            "tgid": 0x3bc,
            "real_parent": 0x3c0,
            "parent": 0x3c8,
            "mm": 0x498,
            "active_mm": 0x4a0,
            "comm": 0x768,
            "cred": 0x738,
            "real_cred": 0x730,
            "fs": 0x7a0,
            "files": 0x7a8,
            "nsproxy": 0x7b0,
        },
        "5.15": {
            "state": 0x10,
            "stack": 0x20,
            "flags": 0x2c,
            "on_cpu": 0x64,
            "prio": 0x6c,
            "pid": 0x3c8,
            "tgid": 0x3cc,
            "real_parent": 0x3d0,
            "parent": 0x3d8,
            "mm": 0x4a8,
            "active_mm": 0x4b0,
            "comm": 0x778,
            "cred": 0x748,
            "real_cred": 0x740,
            "fs": 0x7b0,
            "files": 0x7b8,
            "nsproxy": 0x7c0,
        },
        "6.1": {
            "__state": 0x10,  # renamed from "state" in 6.0
            "stack": 0x20,
            "flags": 0x2c,
            "on_cpu": 0x68,
            "prio": 0x70,
            "pid": 0x3d8,
            "tgid": 0x3dc,
            "real_parent": 0x3e0,
            "parent": 0x3e8,
            "mm": 0x4b8,
            "active_mm": 0x4c0,
            "comm": 0x788,
            "cred": 0x758,
            "real_cred": 0x750,
            "fs": 0x7c0,
            "files": 0x7c8,
            "nsproxy": 0x7d0,
        },
        "6.6": {
            "__state": 0x10,
            "stack": 0x20,
            "flags": 0x2c,
            "on_cpu": 0x6c,
            "prio": 0x74,
            "pid": 0x3e8,
            "tgid": 0x3ec,
            "real_parent": 0x3f0,
            "parent": 0x3f8,
            "mm": 0x4c8,
            "active_mm": 0x4d0,
            "comm": 0x798,
            "cred": 0x768,
            "real_cred": 0x760,
            "fs": 0x7d0,
            "files": 0x7d8,
            "nsproxy": 0x7e0,
        },
    },

    # -----------------------------------------------------------------------
    # struct msg_msg — IPC message (key for heap spray)
    # -----------------------------------------------------------------------
    "msg_msg": {
        "_common": {
            "m_list": 0,        # struct list_head
            "m_type": 16,       # long
            "m_ts": 24,         # size_t (message text size)
            "next": 32,         # struct msg_msgseg *
            "security": 40,     # void *
            # User data starts at offset 48
        },
    },

    # -----------------------------------------------------------------------
    # struct pipe_buffer — used in pipe_buffer ROP/DirtyPipe
    # -----------------------------------------------------------------------
    "pipe_buffer": {
        "_common": {
            "page": 0,          # struct page *
            "offset": 8,        # unsigned int
            "len": 12,          # unsigned int
            "ops": 16,          # const struct pipe_buf_operations *
            "flags": 24,        # unsigned long
            "private": 32,      # unsigned long
        },
    },

    # -----------------------------------------------------------------------
    # struct pipe_inode_info
    # -----------------------------------------------------------------------
    "pipe_inode_info": {
        "5.4": {
            "mutex": 0,
            "nrbufs": 48,       # varies; simplified
            "ring_size": -1,    # not present in 5.4
            "bufs": 112,
        },
        "5.15": {
            "mutex": 0,
            "head": 80,
            "tail": 84,
            "ring_size": 92,
            "bufs": 120,
        },
        "6.1": {
            "mutex": 0,
            "head": 80,
            "tail": 84,
            "ring_size": 92,
            "bufs": 120,
        },
    },

    # -----------------------------------------------------------------------
    # struct sk_buff — network buffer
    # -----------------------------------------------------------------------
    "sk_buff": {
        "_common": {
            "next": 0,
            "prev": 8,
            "tstamp": 16,       # ktime_t / u64
            "sk": 24,           # struct sock *
            "dev": 32,          # struct net_device *
        },
        "5.10": {
            "len": 112,
            "data_len": 116,
            "mac_len": 120,
            "head": 200,
            "data": 208,
            "tail": 216,
            "end": 220,
        },
        "5.15": {
            "len": 112,
            "data_len": 116,
            "mac_len": 120,
            "head": 200,
            "data": 208,
            "tail": 216,
            "end": 220,
        },
        "6.1": {
            "len": 116,
            "data_len": 120,
            "mac_len": 124,
            "head": 208,
            "data": 216,
            "tail": 224,
            "end": 228,
        },
    },

    # -----------------------------------------------------------------------
    # struct seq_operations — function pointer table
    # -----------------------------------------------------------------------
    "seq_operations": {
        "_common": {
            "start": 0,
            "stop": 8,
            "next": 16,
            "show": 24,
        },
    },

    # -----------------------------------------------------------------------
    # struct tty_struct — used for function pointer overwrites
    # -----------------------------------------------------------------------
    "tty_struct": {
        "_common": {
            "magic": 0,
            "kref": 4,
            "dev": 8,            # struct device *
            "driver": 16,        # struct tty_driver *
            "ops": 24,           # const struct tty_operations *
        },
        "5.15": {
            "ldisc": 216,
            "count": 84,
        },
        "6.1": {
            "ldisc": 224,
            "count": 84,
        },
    },

    # -----------------------------------------------------------------------
    # struct file
    # -----------------------------------------------------------------------
    "file": {
        "_common": {
            "f_u": 0,
            "f_path": 16,       # struct path (16 bytes: vfsmount + dentry)
            "f_inode": 32,
            "f_op": 40,
        },
        "5.15": {
            "f_count": 56,
            "f_flags": 64,
            "f_mode": 68,
            "f_pos_lock": 72,
            "f_pos": 80,
            "private_data": 200,
        },
        "6.1": {
            "f_count": 56,
            "f_flags": 64,
            "f_mode": 68,
            "f_pos_lock": 72,
            "f_pos": 80,
            "private_data": 200,
        },
    },

    # -----------------------------------------------------------------------
    # struct modprobe_path (global variable, not a struct)
    # Used for modprobe_path hijack technique
    # -----------------------------------------------------------------------
    "modprobe_path": {
        "_common": {
            "size": 256,         # KMOD_PATH_LEN
            "default_value": 0,  # "/sbin/modprobe"
        },
    },
}

# ---------------------------------------------------------------------------
# Slab cache information
# ---------------------------------------------------------------------------
# Maps struct names to their typical slab caches and sizes.

SLAB_INFO: Dict[str, Dict[str, Any]] = {
    "msg_msg": {
        "cache": "kmalloc-*",
        "header_size": 48,
        "min_alloc": 64,    # minimum kmalloc bucket
        "max_alloc": 4096,  # PAGE_SIZE (larger goes to msg_msgseg)
        "notes": "User data at offset 48; size controllable via msgsnd()",
    },
    "pipe_buffer": {
        "cache": "kmalloc-1024",
        "size": 640,         # 16 pipe_buffers * 40 bytes each
        "notes": "Allocated as array; default 16 buffers",
    },
    "sk_buff": {
        "cache": "skbuff_head_cache",
        "header_size": 232,  # approximate
        "notes": "Data allocated separately from skb_shared_info",
    },
    "seq_operations": {
        "cache": "kmalloc-32",
        "size": 32,
        "notes": "4 function pointers; allocated on /proc file open",
    },
    "tty_struct": {
        "cache": "kmalloc-1024",
        "size": 696,         # approximate
        "notes": "Allocated on /dev/ptmx open",
    },
    "cred": {
        "cache": "cred_jar",
        "size": 192,         # approximate
        "notes": "Dedicated slab cache; prepare_creds()/commit_creds()",
    },
    "file": {
        "cache": "filp",
        "size": 256,         # approximate
        "notes": "Dedicated slab cache; allocated by alloc_empty_file()",
    },
}

# ---------------------------------------------------------------------------
# Android GKI-specific overrides
# ---------------------------------------------------------------------------
# Android Generic Kernel Image may have different offsets due to
# additional configs (CONFIG_ANDROID_*, vendor hooks, etc.)

ANDROID_GKI_OVERRIDES: Dict[str, Dict[str, Dict[str, int]]] = {
    "task_struct": {
        "android-5.10": {
            # GKI 5.10 adds vendor data fields
            "cred": 0x740,
            "real_cred": 0x738,
            "comm": 0x770,
        },
        "android-5.15": {
            "cred": 0x750,
            "real_cred": 0x748,
            "comm": 0x780,
        },
    },
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def normalize_version(kernel_version: str) -> str:
    """
    Normalize a kernel version string to major.minor format.

    Examples:
        "5.15.100" → "5.15"
        "6.1.0-rc2" → "6.1"
        "android-5.10-2023-10" → "android-5.10"
        "5.15" → "5.15"
    """
    # Handle android-X.Y format
    if kernel_version.startswith("android-"):
        parts = kernel_version.split("-")
        if len(parts) >= 2:
            ver = parts[1]
            dot_parts = ver.split(".")
            if len(dot_parts) >= 2:
                return f"android-{dot_parts[0]}.{dot_parts[1]}"
        return kernel_version

    # Standard version: take major.minor
    version = kernel_version.split("-")[0]  # strip -rc, -gki, etc.
    parts = version.split(".")
    if len(parts) >= 2:
        return f"{parts[0]}.{parts[1]}"
    return version


def get_offset(
    struct_name: str,
    field_name: str,
    kernel_version: str,
    android: bool = False,
) -> int:
    """
    Look up the offset of a field within a kernel structure.

    Args:
        struct_name: Kernel structure name (e.g., "task_struct", "cred")
        field_name: Field name (e.g., "uid", "cred")
        kernel_version: Kernel version string (e.g., "5.15.100")
        android: If True, check Android GKI overrides first

    Returns:
        Offset in bytes, or -1 if not found.

    Example:
        >>> get_offset("cred", "uid", "5.15")
        4
        >>> get_offset("task_struct", "cred", "6.1")
        1880  # 0x758
    """
    version = normalize_version(kernel_version)

    # Check Android GKI overrides first
    if android or version.startswith("android-"):
        android_ver = version if version.startswith("android-") else f"android-{version}"
        overrides = ANDROID_GKI_OVERRIDES.get(struct_name, {})
        if android_ver in overrides:
            if field_name in overrides[android_ver]:
                return overrides[android_ver][field_name]

    # Plain version for lookup
    plain_ver = version.replace("android-", "")

    struct_data = STRUCT_OFFSETS.get(struct_name)
    if struct_data is None:
        return -1

    # Check version-specific offsets first
    if plain_ver in struct_data:
        ver_data = struct_data[plain_ver]
        if field_name in ver_data:
            return ver_data[field_name]

    # Fall back to _common
    common = struct_data.get("_common", {})
    if field_name in common:
        return common[field_name]

    # Try closest earlier version
    available_versions = sorted(
        [v for v in struct_data.keys() if v != "_common"],
        key=lambda v: tuple(int(x) for x in v.split(".") if x.isdigit()),
    )
    for ver in reversed(available_versions):
        try:
            ver_tuple = tuple(int(x) for x in ver.split(".") if x.isdigit())
            target_tuple = tuple(int(x) for x in plain_ver.split(".") if x.isdigit())
            if ver_tuple <= target_tuple:
                if field_name in struct_data[ver]:
                    return struct_data[ver][field_name]
        except ValueError:
            continue

    return -1


def get_all_offsets(
    struct_name: str,
    kernel_version: str,
    android: bool = False,
) -> Dict[str, int]:
    """
    Get all known offsets for a structure at a given kernel version.

    Returns a dict of {field_name: offset}. Merges _common with
    version-specific overrides.
    """
    version = normalize_version(kernel_version)
    plain_ver = version.replace("android-", "")

    struct_data = STRUCT_OFFSETS.get(struct_name)
    if struct_data is None:
        return {}

    # Start with _common
    result = dict(struct_data.get("_common", {}))

    # Override with version-specific
    if plain_ver in struct_data:
        result.update(struct_data[plain_ver])

    # Override with Android GKI if applicable
    if android or version.startswith("android-"):
        android_ver = version if version.startswith("android-") else f"android-{version}"
        overrides = ANDROID_GKI_OVERRIDES.get(struct_name, {}).get(android_ver, {})
        result.update(overrides)

    return result


def get_slab_info(struct_name: str) -> Optional[Dict[str, Any]]:
    """
    Get slab cache information for a kernel structure.

    Returns dict with cache name, size, and notes, or None.
    """
    return SLAB_INFO.get(struct_name)


def get_struct_defines(
    struct_names: List[str],
    kernel_version: str,
    android: bool = False,
    prefix: str = "",
) -> str:
    """
    Generate C #define statements for structure offsets.

    Args:
        struct_names: List of struct names to include
        kernel_version: Target kernel version
        android: Use Android GKI overrides
        prefix: Optional prefix for define names

    Returns:
        C preprocessor defines as a string.

    Example:
        >>> print(get_struct_defines(["cred", "task_struct"], "5.15"))
        /* Offsets for kernel 5.15 */
        /* struct cred */
        #define CRED_USAGE 0
        #define CRED_UID 4
        ...
    """
    version = normalize_version(kernel_version)
    lines = [f"/* Offsets for kernel {version} */"]

    for struct_name in struct_names:
        offsets = get_all_offsets(struct_name, kernel_version, android)
        if not offsets:
            lines.append(f"/* struct {struct_name}: no data available */")
            continue

        lines.append(f"/* struct {struct_name} */")
        struct_upper = struct_name.upper()
        for field, offset in sorted(offsets.items(), key=lambda x: x[1]):
            field_upper = field.upper()
            define_name = f"{prefix}{struct_upper}_{field_upper}"
            lines.append(f"#define {define_name} {offset}")
        lines.append("")

    return "\n".join(lines)


def get_exploit_context(
    vuln_struct: str,
    target_struct: str,
    kernel_version: str,
    android: bool = False,
) -> str:
    """
    Generate exploit-relevant context for LLM prompts.

    Combines struct offsets, slab info, and version notes.
    """
    version = normalize_version(kernel_version)
    lines = [
        f"# Kernel structure information for {version}",
        "",
    ]

    for struct_name in [vuln_struct, target_struct, "cred", "task_struct"]:
        offsets = get_all_offsets(struct_name, kernel_version, android)
        slab = get_slab_info(struct_name)

        lines.append(f"## struct {struct_name}")
        if slab:
            lines.append(f"  Slab cache: {slab.get('cache', '?')}")
            if 'size' in slab:
                lines.append(f"  Size: {slab['size']} bytes")
            if 'header_size' in slab:
                lines.append(f"  Header size: {slab['header_size']} bytes")
            if 'notes' in slab:
                lines.append(f"  Notes: {slab['notes']}")

        if offsets:
            lines.append("  Offsets:")
            for field, offset in sorted(offsets.items(), key=lambda x: x[1]):
                lines.append(f"    {field}: {offset} (0x{offset:x})")
        else:
            lines.append("  (no offset data available)")
        lines.append("")

    return "\n".join(lines)


def list_supported_versions(struct_name: str) -> List[str]:
    """Return list of kernel versions with offset data for a structure."""
    struct_data = STRUCT_OFFSETS.get(struct_name, {})
    return sorted(
        [v for v in struct_data.keys() if v != "_common"],
        key=lambda v: tuple(int(x) for x in v.split(".") if x.isdigit()),
    )


def list_supported_structs() -> List[str]:
    """Return list of all structures in the offset database."""
    return sorted(STRUCT_OFFSETS.keys())
