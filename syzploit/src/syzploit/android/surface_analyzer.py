"""
android.surface_analyzer — Android attack surface analysis.

Enumerates accessible attack surfaces from a given SELinux context
(e.g. untrusted_app, system_server) by parsing SELinux policy,
device node permissions, and binder service registrations.

This helps the exploit agent understand what kernel interfaces are
reachable from a given Android process context.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set


# ═════════════════════════════════════════════════════════════════════
# Known kernel attack surfaces on Android
# ═════════════════════════════════════════════════════════════════════

_KERNEL_ATTACK_SURFACES: Dict[str, Dict[str, Any]] = {
    "binder": {
        "device": "/dev/binder",
        "description": "Android IPC mechanism. Main attack surface for untrusted apps.",
        "selinux_class": "binder",
        "syscalls": ["ioctl"],
        "cves": [
            "CVE-2023-20938",
            "CVE-2023-21255",
            "CVE-2020-0041",
            "CVE-2019-2215",
        ],
        "reachable_from": ["untrusted_app", "system_server", "priv_app"],
    },
    "hwbinder": {
        "device": "/dev/hwbinder",
        "description": "Hardware binder for HAL communication.",
        "selinux_class": "hwbinder",
        "syscalls": ["ioctl"],
        "cves": [],
        "reachable_from": ["system_server", "hal_*"],
    },
    "ashmem": {
        "device": "/dev/ashmem",
        "description": "Android shared memory (legacy, replaced by memfd).",
        "selinux_class": "chr_file",
        "syscalls": ["ioctl", "mmap"],
        "cves": [],
        "reachable_from": ["untrusted_app", "system_server"],
    },
    "ion": {
        "device": "/dev/ion",
        "description": "ION memory allocator (deprecated in 5.x, replaced by DMA-BUF).",
        "selinux_class": "chr_file",
        "syscalls": ["ioctl"],
        "cves": ["CVE-2020-0069", "CVE-2019-2025"],
        "reachable_from": ["untrusted_app"],
    },
    "gpu_mali": {
        "device": "/dev/mali0",
        "description": "ARM Mali GPU driver.",
        "selinux_class": "chr_file",
        "syscalls": ["ioctl", "mmap"],
        "cves": [
            "CVE-2023-26083",
            "CVE-2023-4211",
            "CVE-2022-46395",
        ],
        "reachable_from": ["untrusted_app", "gpu_service"],
    },
    "gpu_adreno": {
        "device": "/dev/kgsl-3d0",
        "description": "Qualcomm Adreno GPU driver.",
        "selinux_class": "chr_file",
        "syscalls": ["ioctl", "mmap"],
        "cves": ["CVE-2023-33106", "CVE-2023-33107"],
        "reachable_from": ["untrusted_app", "gpu_service"],
    },
    "io_uring": {
        "device": None,
        "description": "io_uring async I/O (restricted/disabled on most Android 13+).",
        "selinux_class": "anon_inode",
        "syscalls": ["io_uring_setup", "io_uring_enter", "io_uring_register"],
        "cves": [
            "CVE-2023-2598",
            "CVE-2022-29582",
            "CVE-2021-41073",
        ],
        "reachable_from": [],  # Typically blocked by seccomp on Android 13+
    },
    "pipe": {
        "device": None,
        "description": "Pipe/FIFO buffer — used for dirty pipe + pipe_buffer corruption.",
        "selinux_class": "fifo_file",
        "syscalls": ["pipe", "pipe2", "splice", "read", "write"],
        "cves": ["CVE-2022-0847"],  # Dirty Pipe
        "reachable_from": ["untrusted_app", "system_server"],
    },
    "epoll": {
        "device": None,
        "description": "epoll event notification — used for race timing in exploits.",
        "selinux_class": "anon_inode",
        "syscalls": ["epoll_create", "epoll_ctl", "epoll_wait"],
        "cves": [],
        "reachable_from": ["untrusted_app", "system_server"],
    },
    "socket_netlink": {
        "device": None,
        "description": "Netlink sockets for kernel<->userspace communication.",
        "selinux_class": "netlink_socket",
        "syscalls": ["socket", "bind", "sendmsg", "recvmsg"],
        "cves": [],
        "reachable_from": ["system_server"],  # Usually blocked for apps
    },
    "usb_gadget": {
        "device": "/dev/usb-ffs/",
        "description": "USB gadget/ConfigFS — physical access vector.",
        "selinux_class": "chr_file",
        "syscalls": ["ioctl", "read", "write"],
        "cves": [],
        "reachable_from": [],  # Requires physical access
    },
}

# ═════════════════════════════════════════════════════════════════════
# SELinux context → allowed syscalls (from Android seccomp policy)
# ═════════════════════════════════════════════════════════════════════

_SECCOMP_ALLOWED: Dict[str, Set[str]] = {
    "untrusted_app": {
        "read", "write", "open", "close", "stat", "fstat", "lstat",
        "poll", "lseek", "mmap", "mprotect", "munmap", "brk",
        "ioctl", "pipe", "pipe2", "dup", "dup2", "dup3",
        "socket", "connect", "sendto", "recvfrom", "sendmsg", "recvmsg",
        "bind", "listen", "accept4", "getsockopt", "setsockopt",
        "clone", "fork", "vfork", "execve", "exit", "exit_group",
        "futex", "epoll_create1", "epoll_ctl", "epoll_pwait",
        "timerfd_create", "timerfd_settime", "timerfd_gettime",
        "eventfd2", "signalfd4", "prctl", "madvise",
        "getuid", "geteuid", "getgid", "getegid",
        "getpid", "getppid", "gettid",
        "sched_setaffinity", "sched_getaffinity",
        "splice", "tee",
        # Note: io_uring_* are BLOCKED on Android 13+
    },
    "system_server": {
        # system_server has a broader seccomp policy
        "read", "write", "open", "close", "stat", "fstat", "lstat",
        "poll", "lseek", "mmap", "mprotect", "munmap", "brk",
        "ioctl", "pipe", "pipe2",
        "socket", "connect", "sendto", "recvfrom", "sendmsg", "recvmsg",
        "bind", "listen", "accept4",
        "clone", "fork", "vfork", "execve",
        "futex", "epoll_create1", "epoll_ctl", "epoll_pwait",
        "timerfd_create", "timerfd_settime",
        "eventfd2", "prctl", "madvise",
        "getuid", "geteuid", "getgid", "getegid",
        "sched_setaffinity", "sched_getaffinity",
        "splice", "tee",
        "keyctl", "add_key", "request_key",
        "bpf",  # Some BPF access for system_server
    },
}


class AttackSurfaceAnalyzer:
    """Analyze Android kernel attack surface from a given context."""

    def __init__(self) -> None:
        self._surfaces = _KERNEL_ATTACK_SURFACES
        self._seccomp = _SECCOMP_ALLOWED

    def get_reachable_surfaces(
        self,
        selinux_context: str = "untrusted_app",
    ) -> List[Dict[str, Any]]:
        """Return kernel attack surfaces reachable from given context."""
        results = []
        for name, surface in self._surfaces.items():
            reachable = surface.get("reachable_from", [])
            # Check direct match or wildcard match
            if any(
                ctx == selinux_context or
                (ctx.endswith("*") and selinux_context.startswith(ctx[:-1]))
                for ctx in reachable
            ):
                results.append({"name": name, **surface})
        return results

    def get_surface_info(self, name: str) -> Optional[Dict[str, Any]]:
        """Get detailed info about a specific attack surface."""
        return self._surfaces.get(name)

    def get_allowed_syscalls(
        self,
        selinux_context: str = "untrusted_app",
    ) -> Set[str]:
        """Return syscalls allowed by seccomp for the given context."""
        return self._seccomp.get(selinux_context, set())

    def check_exploit_feasibility(
        self,
        *,
        required_syscalls: List[str],
        required_surfaces: List[str],
        selinux_context: str = "untrusted_app",
    ) -> Dict[str, Any]:
        """Check if an exploit's requirements are satisfiable.

        Returns a report with:
          - blocked_syscalls: syscalls needed but not allowed
          - unreachable_surfaces: surfaces needed but not accessible
          - feasible: True if all requirements met
          - notes: additional context
        """
        allowed = self.get_allowed_syscalls(selinux_context)
        reachable = {s["name"] for s in self.get_reachable_surfaces(selinux_context)}

        blocked = [s for s in required_syscalls if s not in allowed]
        unreachable = [s for s in required_surfaces if s not in reachable]

        notes = []
        if "io_uring_setup" in required_syscalls:
            notes.append(
                "io_uring is blocked by seccomp on Android 13+. "
                "Exploit must avoid io_uring or target Android < 13."
            )
        if "bpf" in required_syscalls and selinux_context == "untrusted_app":
            notes.append(
                "BPF syscall is typically blocked for untrusted apps. "
                "Consider system_server context instead."
            )

        return {
            "feasible": len(blocked) == 0 and len(unreachable) == 0,
            "blocked_syscalls": blocked,
            "unreachable_surfaces": unreachable,
            "allowed_syscall_count": len(allowed),
            "reachable_surface_count": len(reachable),
            "notes": notes,
        }

    def find_cve_surfaces(self, cve_id: str) -> List[Dict[str, Any]]:
        """Find attack surfaces associated with a CVE."""
        results = []
        for name, surface in self._surfaces.items():
            if cve_id in surface.get("cves", []):
                results.append({"name": name, **surface})
        return results

    def format_for_prompt(
        self,
        selinux_context: str = "untrusted_app",
    ) -> str:
        """Format reachable attack surface info for an LLM prompt."""
        reachable = self.get_reachable_surfaces(selinux_context)
        allowed = self.get_allowed_syscalls(selinux_context)

        parts = [
            f"# Android Attack Surface Analysis",
            f"## Context: {selinux_context}",
            f"## Allowed syscalls: {len(allowed)}",
            "",
            "## Reachable Kernel Attack Surfaces:",
        ]

        for surface in reachable:
            name = surface["name"]
            parts.append(f"\n### {name}")
            parts.append(f"Description: {surface['description']}")
            if surface.get("device"):
                parts.append(f"Device node: {surface['device']}")
            parts.append(f"Syscalls: {', '.join(surface['syscalls'])}")
            if surface.get("cves"):
                parts.append(f"Known CVEs: {', '.join(surface['cves'])}")

        # Check what's blocked
        blocked_surfaces = []
        for name, surface in self._surfaces.items():
            if not any(
                ctx == selinux_context or
                (ctx.endswith("*") and selinux_context.startswith(ctx[:-1]))
                for ctx in surface.get("reachable_from", [])
            ):
                blocked_surfaces.append(name)

        if blocked_surfaces:
            parts.append(f"\n## Unreachable surfaces: {', '.join(blocked_surfaces)}")

        return "\n".join(parts)

    def parse_selinux_policy(self, policy_text: str) -> Dict[str, List[str]]:
        """Parse SELinux allow rules to find accessible device types.

        Expects output from `sesearch --allow -s <domain>` or raw policy text.
        Returns dict mapping target types to allowed permissions.
        """
        rules: Dict[str, List[str]] = {}
        # Match: allow source_t target_t:class { perms };
        pattern = re.compile(
            r"allow\s+\S+\s+(\S+):(\S+)\s+\{([^}]+)\}"
        )
        for match in pattern.finditer(policy_text):
            target = match.group(1)
            _class = match.group(2)
            perms = match.group(3).strip().split()
            key = f"{target}:{_class}"
            rules.setdefault(key, []).extend(perms)
        return rules
