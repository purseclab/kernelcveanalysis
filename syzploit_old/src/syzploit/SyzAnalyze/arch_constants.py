"""
Architecture-specific constants for PoC adaptation across platforms.

Provides:
- Syscall number mappings per architecture (x86_64, arm64)
- Syscall name normalization (e.g., open→openat on arm64)
- Register name mappings
- IOCTL encoding helpers
- Architecture detection from crash reports

Usage:
    from .arch_constants import translate_syscall_nr, get_register_name, SYSCALL_NR

    # Translate syscall number between architectures
    arm64_nr = translate_syscall_nr("write", "x86_64", "arm64")

    # Get equivalent register name
    reg = get_register_name("rdi", "arm64")  # → "x0"
"""

from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Syscall number tables
# ---------------------------------------------------------------------------
# Sources:
#   x86_64: arch/x86/entry/syscalls/syscall_64.tbl
#   arm64:  include/uapi/asm-generic/unistd.h

SYSCALL_NR: Dict[str, Dict[str, int]] = {
    "x86_64": {
        # File I/O
        "read": 0,
        "write": 1,
        "open": 2,
        "close": 3,
        "stat": 4,
        "fstat": 5,
        "lstat": 6,
        "poll": 7,
        "lseek": 8,
        "mmap": 9,
        "mprotect": 10,
        "munmap": 11,
        "brk": 12,
        "ioctl": 16,
        "pread64": 17,
        "pwrite64": 18,
        "readv": 19,
        "writev": 20,
        "access": 21,
        "pipe": 22,
        "dup": 32,
        "dup2": 33,
        "fcntl": 72,
        "flock": 73,
        "fsync": 74,
        "openat": 257,
        "mkdirat": 258,
        "fstatat": 262,
        "unlinkat": 263,
        "renameat": 264,
        "readlinkat": 267,
        "pipe2": 293,
        "dup3": 292,
        # Process
        "fork": 57,
        "vfork": 58,
        "execve": 59,
        "exit": 60,
        "wait4": 61,
        "kill": 62,
        "clone": 56,
        "getpid": 39,
        "getuid": 102,
        "getgid": 104,
        "geteuid": 107,
        "getegid": 108,
        "setuid": 105,
        "setgid": 106,
        "setreuid": 113,
        "setregid": 114,
        "prctl": 157,
        "clone3": 435,
        # Memory
        "madvise": 28,
        "mremap": 25,
        "msync": 26,
        "mincore": 27,
        "shmget": 29,
        "shmat": 30,
        "shmctl": 31,
        "mlock": 149,
        "munlock": 150,
        "process_vm_readv": 310,
        "process_vm_writev": 311,
        "userfaultfd": 323,
        # IPC
        "msgget": 68,
        "msgsnd": 69,
        "msgrcv": 70,
        "msgctl": 71,
        "semget": 64,
        "semop": 65,
        "semctl": 66,
        # Network
        "socket": 41,
        "connect": 42,
        "accept": 43,
        "sendto": 44,
        "recvfrom": 45,
        "sendmsg": 46,
        "recvmsg": 47,
        "bind": 49,
        "listen": 50,
        "socketpair": 53,
        "setsockopt": 54,
        "getsockopt": 55,
        "accept4": 288,
        # Signal
        "rt_sigaction": 13,
        "rt_sigprocmask": 14,
        "rt_sigreturn": 15,
        "sigaltstack": 131,
        # Epoll / select
        "select": 23,
        "epoll_create": 213,
        "epoll_ctl": 233,
        "epoll_wait": 232,
        "epoll_create1": 291,
        "epoll_pwait": 281,
        # Timer
        "nanosleep": 35,
        "getitimer": 36,
        "setitimer": 38,
        "timer_create": 222,
        "timer_settime": 223,
        "timer_gettime": 224,
        "timer_delete": 226,
        "clock_gettime": 228,
        "clock_nanosleep": 230,
        "timerfd_create": 283,
        "timerfd_settime": 286,
        # Futex
        "futex": 202,
        "futex_waitv": 449,
        # io_uring
        "io_uring_setup": 425,
        "io_uring_enter": 426,
        "io_uring_register": 427,
        # Namespace
        "unshare": 272,
        "setns": 308,
        # Misc
        "mount": 165,
        "umount2": 166,
        "pivot_root": 155,
        "syslog": 103,
        "ptrace": 101,
        "keyctl": 250,
        "add_key": 248,
        "request_key": 249,
        "bpf": 321,
        "seccomp": 317,
        "perf_event_open": 298,
        "splice": 275,
        "tee": 276,
        "vmsplice": 278,
        "sendfile": 40,
    },
    "arm64": {
        # File I/O — arm64 uses *at variants; no plain open/stat/access
        "read": 63,
        "write": 64,
        "close": 57,
        "fstat": 80,
        "lseek": 62,
        "mmap": 222,
        "mprotect": 226,
        "munmap": 215,
        "brk": 214,
        "ioctl": 29,
        "pread64": 67,
        "pwrite64": 68,
        "readv": 65,
        "writev": 66,
        "pipe2": 59,
        "dup": 23,
        "dup3": 24,
        "fcntl": 25,
        "flock": 32,
        "fsync": 82,
        "openat": 56,
        "mkdirat": 34,
        "fstatat": 79,
        "unlinkat": 35,
        "renameat": 38,
        "readlinkat": 78,
        "ppoll": 73,
        # Process
        "execve": 221,
        "exit": 93,
        "exit_group": 94,
        "wait4": 260,
        "kill": 129,
        "clone": 220,
        "getpid": 172,
        "getuid": 174,
        "getgid": 176,
        "geteuid": 175,
        "getegid": 177,
        "setuid": 146,
        "setgid": 144,
        "setreuid": 145,
        "setregid": 143,
        "prctl": 167,
        "clone3": 435,
        # Memory
        "madvise": 233,
        "mremap": 216,
        "msync": 227,
        "mincore": 232,
        "shmget": 194,
        "shmat": 196,
        "shmctl": 195,
        "mlock": 228,
        "munlock": 229,
        "process_vm_readv": 270,
        "process_vm_writev": 271,
        "userfaultfd": 282,
        # IPC
        "msgget": 186,
        "msgsnd": 189,
        "msgrcv": 188,
        "msgctl": 187,
        "semget": 190,
        "semop": 193,
        "semctl": 191,
        # Network
        "socket": 198,
        "connect": 203,
        "accept": 202,
        "sendto": 206,
        "recvfrom": 207,
        "sendmsg": 211,
        "recvmsg": 212,
        "bind": 200,
        "listen": 201,
        "socketpair": 199,
        "setsockopt": 208,
        "getsockopt": 209,
        "accept4": 242,
        # Signal
        "rt_sigaction": 134,
        "rt_sigprocmask": 135,
        "rt_sigreturn": 139,
        "sigaltstack": 132,
        # Epoll / select
        "pselect6": 72,
        "epoll_create1": 20,
        "epoll_ctl": 21,
        "epoll_pwait": 22,
        # Timer
        "nanosleep": 101,
        "getitimer": 102,
        "setitimer": 103,
        "timer_create": 107,
        "timer_settime": 110,
        "timer_gettime": 108,
        "timer_delete": 111,
        "clock_gettime": 113,
        "clock_nanosleep": 115,
        "timerfd_create": 85,
        "timerfd_settime": 86,
        # Futex
        "futex": 98,
        "futex_waitv": 449,
        # io_uring
        "io_uring_setup": 425,
        "io_uring_enter": 426,
        "io_uring_register": 427,
        # Namespace
        "unshare": 97,
        "setns": 268,
        # Misc
        "mount": 40,
        "umount2": 39,
        "pivot_root": 41,
        "syslog": 116,
        "ptrace": 117,
        "keyctl": 219,
        "add_key": 217,
        "request_key": 218,
        "bpf": 280,
        "seccomp": 277,
        "perf_event_open": 241,
        "splice": 76,
        "tee": 77,
        "vmsplice": 75,
        "sendfile": 71,
    },
}

# ---------------------------------------------------------------------------
# Syscall name equivalences across architectures
# ---------------------------------------------------------------------------
# arm64 drops legacy calls; map old names to modern equivalents.

SYSCALL_ALIASES: Dict[str, Dict[str, str]] = {
    "arm64": {
        "open": "openat",
        "stat": "fstatat",
        "lstat": "fstatat",
        "access": "faccessat",
        "pipe": "pipe2",
        "dup2": "dup3",
        "fork": "clone",
        "vfork": "clone",
        "epoll_create": "epoll_create1",
        "epoll_wait": "epoll_pwait",
        "select": "pselect6",
        "poll": "ppoll",
    },
}

# ---------------------------------------------------------------------------
# Register mappings
# ---------------------------------------------------------------------------
# Maps x86_64 register names to arm64 equivalents (argument order is the same,
# just different names).

REGISTER_MAP: Dict[str, Dict[str, str]] = {
    "x86_64_to_arm64": {
        # Arguments (System V ABI → AAPCS64)
        "rdi": "x0",
        "rsi": "x1",
        "rdx": "x2",
        "rcx": "x3",
        "r8": "x4",
        "r9": "x5",
        # Return
        "rax": "x0",
        # Stack / frame
        "rsp": "sp",
        "rbp": "x29",
        # Instruction pointer
        "rip": "pc",
        # Link register (x86 has no LR; arm64 does)
        "": "x30",
    },
    "arm64_to_x86_64": {
        "x0": "rdi",
        "x1": "rsi",
        "x2": "rdx",
        "x3": "rcx",
        "x4": "r8",
        "x5": "r9",
        "sp": "rsp",
        "x29": "rbp",
        "pc": "rip",
        "x30": "",  # No direct equivalent
    },
}

# Syscall-specific argument register (the syscall number register)
SYSCALL_NR_REGISTER: Dict[str, str] = {
    "x86_64": "rax",
    "arm64": "x8",
}

# ---------------------------------------------------------------------------
# IOCTL encoding helpers
# ---------------------------------------------------------------------------
# Linux IOCTL encoding: _IOC(dir, type, nr, size)
#   dir:  2 bits (bits 30-31)
#   size: 14 bits (bits 16-29)
#   type: 8 bits (bits 8-15)
#   nr:   8 bits (bits 0-7)

_IOC_NRBITS = 8
_IOC_TYPEBITS = 8
_IOC_SIZEBITS = 14
_IOC_DIRBITS = 2

_IOC_NRSHIFT = 0
_IOC_TYPESHIFT = _IOC_NRSHIFT + _IOC_NRBITS
_IOC_SIZESHIFT = _IOC_TYPESHIFT + _IOC_TYPEBITS
_IOC_DIRSHIFT = _IOC_SIZESHIFT + _IOC_SIZEBITS

_IOC_NONE = 0
_IOC_WRITE = 1
_IOC_READ = 2


def ioc(direction: int, typ: int, nr: int, size: int) -> int:
    """Encode a Linux IOCTL request number."""
    return (
        (direction << _IOC_DIRSHIFT)
        | (typ << _IOC_TYPESHIFT)
        | (nr << _IOC_NRSHIFT)
        | (size << _IOC_SIZESHIFT)
    )


def ioc_decode(code: int) -> Dict[str, int]:
    """Decode a Linux IOCTL request number into its components."""
    return {
        "direction": (code >> _IOC_DIRSHIFT) & ((1 << _IOC_DIRBITS) - 1),
        "type": (code >> _IOC_TYPESHIFT) & ((1 << _IOC_TYPEBITS) - 1),
        "nr": (code >> _IOC_NRSHIFT) & ((1 << _IOC_NRBITS) - 1),
        "size": (code >> _IOC_SIZESHIFT) & ((1 << _IOC_SIZEBITS) - 1),
    }


def io(typ: int, nr: int) -> int:
    """_IO(type, nr) — no data transfer."""
    return ioc(_IOC_NONE, typ, nr, 0)


def ior(typ: int, nr: int, size: int) -> int:
    """_IOR(type, nr, size) — read from device."""
    return ioc(_IOC_READ, typ, nr, size)


def iow(typ: int, nr: int, size: int) -> int:
    """_IOW(type, nr, size) — write to device."""
    return ioc(_IOC_WRITE, typ, nr, size)


def iowr(typ: int, nr: int, size: int) -> int:
    """_IOWR(type, nr, size) — read + write."""
    return ioc(_IOC_READ | _IOC_WRITE, typ, nr, size)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def translate_syscall_nr(
    syscall_name: str,
    from_arch: str,
    to_arch: str,
) -> int:
    """
    Translate a syscall by name from one architecture to another.

    Handles aliasing (e.g., open→openat on arm64).
    Returns -1 if the syscall is not found on the target architecture.

    Example:
        >>> translate_syscall_nr("write", "x86_64", "arm64")
        64
        >>> translate_syscall_nr("open", "x86_64", "arm64")
        56  # aliased to openat
    """
    # Resolve aliases on the target architecture
    aliases = SYSCALL_ALIASES.get(to_arch, {})
    resolved_name = aliases.get(syscall_name, syscall_name)

    target_table = SYSCALL_NR.get(to_arch, {})
    return target_table.get(resolved_name, -1)


def get_syscall_name(nr: int, arch: str) -> Optional[str]:
    """
    Look up a syscall name by its number on the given architecture.

    Returns None if no matching syscall is found.
    """
    table = SYSCALL_NR.get(arch, {})
    for name, num in table.items():
        if num == nr:
            return name
    return None


def get_register_name(reg: str, target_arch: str) -> str:
    """
    Map a register name to the equivalent on the target architecture.

    Falls back to returning the input unchanged if no mapping exists.
    """
    reg = reg.lower()
    # Determine direction
    if target_arch == "arm64":
        mapping = REGISTER_MAP.get("x86_64_to_arm64", {})
    elif target_arch == "x86_64":
        mapping = REGISTER_MAP.get("arm64_to_x86_64", {})
    else:
        return reg
    return mapping.get(reg, reg)


def detect_arch_from_crash(crash_text: str) -> Optional[str]:
    """
    Detect architecture from a kernel crash report.

    Looks for register dumps and architecture-specific keywords.
    """
    # x86_64 indicators
    x86_markers = ["RIP:", "RSP:", "RBP:", "RAX:", "RBX:", "RCX:", "RDX:"]
    # arm64 indicators
    arm64_markers = ["pc :", "lr :", "sp :", "x0 :", "x29:", "x30:"]

    x86_score = sum(1 for m in x86_markers if m in crash_text)
    arm64_score = sum(1 for m in arm64_markers if m in crash_text)

    if x86_score > arm64_score:
        return "x86_64"
    elif arm64_score > x86_score:
        return "arm64"
    return None


def list_arch_differences(syscall_name: str) -> Dict[str, Any]:
    """
    Return a summary of how a syscall differs between architectures.

    Useful for LLM prompts when adapting PoCs.
    """
    result = {
        "name": syscall_name,
        "numbers": {},
        "aliases": {},
        "notes": [],
    }
    for arch in SYSCALL_NR:
        tbl = SYSCALL_NR[arch]
        aliases = SYSCALL_ALIASES.get(arch, {})
        if syscall_name in tbl:
            result["numbers"][arch] = tbl[syscall_name]
        elif syscall_name in aliases:
            alias = aliases[syscall_name]
            result["aliases"][arch] = alias
            if alias in tbl:
                result["numbers"][arch] = tbl[alias]
            result["notes"].append(
                f"{arch}: '{syscall_name}' is not available; use '{alias}' (nr={tbl.get(alias, '?')})"
            )
        else:
            result["notes"].append(f"{arch}: '{syscall_name}' not found")

    return result


def get_adaptation_context(
    from_arch: str, to_arch: str, syscall_names: List[str]
) -> str:
    """
    Generate a human-readable adaptation context string for LLM prompts.

    Summarises syscall number changes, aliased calls, and register mappings.
    """
    lines = [
        f"# Architecture adaptation: {from_arch} → {to_arch}",
        "",
        "## Syscall number changes:",
    ]

    for name in sorted(set(syscall_names)):
        info = list_arch_differences(name)
        from_nr = info["numbers"].get(from_arch, "N/A")
        to_nr = info["numbers"].get(to_arch, "N/A")
        alias = info["aliases"].get(to_arch, "")
        line = f"  {name}: {from_arch}={from_nr} → {to_arch}={to_nr}"
        if alias:
            line += f"  (aliased to '{alias}')"
        lines.append(line)

    if from_arch == "x86_64" and to_arch == "arm64":
        lines += [
            "",
            "## Important notes for x86_64 → arm64:",
            "  - arm64 has NO open(), stat(), access(), pipe(), dup2(), fork(), vfork()",
            "  - Use openat(), fstatat(), faccessat(), pipe2(), dup3(), clone() instead",
            "  - Syscall NR register: rax → x8",
            "  - Argument registers: rdi,rsi,rdx,rcx,r8,r9 → x0,x1,x2,x3,x4,x5",
            "  - Return register: rax → x0",
            "  - arm64 has no 32-bit compat syscall gate by default",
        ]
    elif from_arch == "arm64" and to_arch == "x86_64":
        lines += [
            "",
            "## Important notes for arm64 → x86_64:",
            "  - x86_64 supports both legacy and *at syscalls",
            "  - Syscall NR register: x8 → rax",
            "  - Argument registers: x0-x5 → rdi,rsi,rdx,rcx,r8,r9",
        ]

    return "\n".join(lines)
