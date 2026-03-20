"""
analysis.kernel_config — Kernel configuration analysis for exploitation.

Pulls /proc/config.gz or a config file from the target and analyses
which mitigations and exploitation-relevant features are enabled.
"""

from __future__ import annotations

import gzip
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from ..core.log import console


# ── Mitigation definitions ────────────────────────────────────────────

@dataclass
class MitigationInfo:
    """Describes a kernel mitigation / hardening option."""

    config_key: str
    name: str
    description: str
    impact: str  # How it affects exploitation
    severity: str  # "high", "medium", "low" — how much it blocks exploits


# All known exploitation-relevant kernel config options
_MITIGATIONS: List[MitigationInfo] = [
    # Slab hardening
    MitigationInfo(
        "CONFIG_SLAB_FREELIST_HARDENED", "Freelist Hardening",
        "XORs slab freelist pointers with a per-cache random value",
        "Blocks freelist pointer overwrite attacks; makes UAF corruption detectable via BUG_ON",
        "high",
    ),
    MitigationInfo(
        "CONFIG_SLAB_FREELIST_RANDOM", "Freelist Randomization",
        "Randomizes the order of objects within slab pages",
        "Reduces reliability of heap sprays that depend on predictable object layout",
        "medium",
    ),
    MitigationInfo(
        "CONFIG_INIT_ON_FREE_DEFAULT_ON", "Zero on Free",
        "Zeros freed slab objects automatically",
        "Destroys dangling data in UAF objects; spray must re-fill with controlled content",
        "high",
    ),
    MitigationInfo(
        "CONFIG_INIT_ON_ALLOC_DEFAULT_ON", "Zero on Alloc",
        "Zeros newly allocated slab objects",
        "Prevents info leaks from uninitialized heap memory; less impact on UAF exploits",
        "medium",
    ),
    # CFI / control flow
    MitigationInfo(
        "CONFIG_CFI_CLANG", "Clang CFI",
        "Control Flow Integrity via Clang's -fsanitize=cfi",
        "Blocks indirect call hijacking (fake vtable / ops table attacks). "
        "JOP/ROP-style pivots through function pointers will trigger a CFI violation",
        "high",
    ),
    MitigationInfo(
        "CONFIG_CFI_PERMISSIVE", "CFI Permissive",
        "CFI violations are logged but not enforced",
        "CFI is present but not blocking — exploits may still work with warnings in dmesg",
        "low",
    ),
    MitigationInfo(
        "CONFIG_SHADOW_CALL_STACK", "Shadow Call Stack (SCS)",
        "Protects return addresses on a separate shadow stack (arm64)",
        "Blocks ROP chains that overwrite return addresses on the kernel stack",
        "high",
    ),
    # KASLR / randomization
    MitigationInfo(
        "CONFIG_RANDOMIZE_BASE", "KASLR",
        "Randomizes kernel base address at boot",
        "Requires KASLR bypass (info leak) before using absolute kernel addresses",
        "high",
    ),
    MitigationInfo(
        "CONFIG_RANDOMIZE_MODULE_REGION_FULL", "Module ASLR",
        "Randomizes loadable module memory region",
        "Module addresses unpredictable; affects exploits targeting module code",
        "medium",
    ),
    # Sanitizers (debug — usually not in production)
    MitigationInfo(
        "CONFIG_KASAN", "KASAN",
        "Kernel Address Sanitizer — detects UAF, OOB, etc at runtime",
        "Will detect and report the vulnerability immediately, likely killing the exploit process. "
        "Good for crash confirmation but blocks reliable exploitation",
        "high",
    ),
    MitigationInfo(
        "CONFIG_KASAN_GENERIC", "KASAN Generic",
        "Generic (software) KASAN mode — high overhead",
        "Same as KASAN but with full shadow memory; very likely to catch heap corruption",
        "high",
    ),
    MitigationInfo(
        "CONFIG_KASAN_SW_TAGS", "KASAN SW Tags",
        "Software tag-based KASAN (arm64) — lower overhead than generic",
        "May miss some accesses but still catches most UAF/OOB",
        "medium",
    ),
    MitigationInfo(
        "CONFIG_KASAN_HW_TAGS", "KASAN HW Tags (MTE)",
        "Hardware tag-based KASAN using ARM MTE",
        "Low overhead but probabilistic — 1/16 chance of missing tag mismatch",
        "medium",
    ),
    MitigationInfo(
        "CONFIG_UBSAN", "UBSAN",
        "Undefined Behavior Sanitizer",
        "Catches integer overflows, alignment issues, etc. May interfere with integer overflow exploits",
        "low",
    ),
    # Userfaultfd control
    MitigationInfo(
        "CONFIG_USERFAULTFD", "Userfaultfd",
        "Enables userfaultfd syscall",
        "If ENABLED, allows page-fault-based heap spray timing control (powerful for UAF races). "
        "If disabled, must use alternative timing (FUSE, signals)",
        "medium",
    ),
    # User namespaces
    MitigationInfo(
        "CONFIG_USER_NS", "User Namespaces",
        "Allows unprivileged user namespace creation",
        "If ENABLED, allows unprivileged access to kernel functionality "
        "normally requiring CAP_SYS_ADMIN (e.g. mount, nftables)",
        "medium",
    ),
    # SELinux
    MitigationInfo(
        "CONFIG_SECURITY_SELINUX", "SELinux",
        "SELinux mandatory access control",
        "Blocks many syscall-based attack paths (ioctl, socket, open). "
        "Exploit must either work within domain policy or disable SELinux post-exploitation",
        "high",
    ),
    # Seccomp
    MitigationInfo(
        "CONFIG_SECCOMP", "Seccomp",
        "Seccomp syscall filtering",
        "On Android, apps run under seccomp-bpf filters that block many syscalls. "
        "Exploit must use only allowed syscalls or escape seccomp first",
        "high",
    ),
    # Static user mode helper
    MitigationInfo(
        "CONFIG_STATIC_USERMODEHELPER", "Static Usermode Helper",
        "Pins modprobe_path / core_pattern to a fixed binary",
        "Blocks modprobe_path overwrite technique for code execution. "
        "Must use alternative priv-esc (cred overwrite, task walk)",
        "medium",
    ),
    # Stack protector
    MitigationInfo(
        "CONFIG_STACKPROTECTOR", "Stack Protector",
        "Stack canary protection",
        "Blocks stack buffer overflow exploitation; does not affect heap vulnerabilities",
        "medium",
    ),
    MitigationInfo(
        "CONFIG_STACKPROTECTOR_STRONG", "Stack Protector Strong",
        "Strong stack canary — protects more functions",
        "More comprehensive stack protection",
        "medium",
    ),
    # Page table isolation
    MitigationInfo(
        "CONFIG_PAGE_TABLE_ISOLATION", "KPTI",
        "Kernel Page Table Isolation (Meltdown mitigation)",
        "Does not directly block most kernel exploits but prevents some "
        "Meltdown-style physmap reads",
        "low",
    ),
    # Hardened usercopy
    MitigationInfo(
        "CONFIG_HARDENED_USERCOPY", "Hardened Usercopy",
        "Validates copy_to/from_user against slab boundaries",
        "Blocks OOB read/write via usercopy functions; does not "
        "affect direct pointer corruption",
        "medium",
    ),
    # GCC plugins
    MitigationInfo(
        "CONFIG_GCC_PLUGIN_STRUCTLEAK", "Structleak",
        "Auto-initialize stack variables",
        "Prevents info leaks from uninitialized stack memory",
        "low",
    ),
    MitigationInfo(
        "CONFIG_GCC_PLUGIN_RANDSTRUCT", "Randstruct",
        "Randomize struct field layout",
        "Makes struct offset assumptions unreliable; requires per-build offset resolution",
        "high",
    ),
]

# Build lookup dict
_MITIGATION_MAP: Dict[str, MitigationInfo] = {m.config_key: m for m in _MITIGATIONS}


@dataclass
class KernelConfigAnalysis:
    """Result of kernel config analysis."""

    config_source: str = ""  # "/proc/config.gz", "local file", etc.
    total_options: int = 0

    # Categorized mitigations
    active_mitigations: List[Dict[str, str]] = field(default_factory=list)
    inactive_mitigations: List[Dict[str, str]] = field(default_factory=list)
    unknown_mitigations: List[Dict[str, str]] = field(default_factory=list)

    # Exploitation-relevant features (enabled / disabled)
    features: Dict[str, bool] = field(default_factory=dict)

    # Raw config values for exploitation-relevant keys
    raw_values: Dict[str, str] = field(default_factory=dict)

    # Overall assessment
    hardening_level: str = "unknown"  # "minimal", "moderate", "hardened", "debug"
    exploitation_notes: List[str] = field(default_factory=list)

    def summary(self) -> str:
        lines = [
            f"=== Kernel Config Analysis ===",
            f"  Source: {self.config_source}",
            f"  Total options: {self.total_options}",
            f"  Hardening level: {self.hardening_level}",
            "",
            f"  Active mitigations ({len(self.active_mitigations)}):",
        ]
        for m in self.active_mitigations:
            sev = m.get("severity", "")
            lines.append(f"    [{sev}] {m['name']}: {m['impact']}")
        lines.append(f"  Inactive mitigations ({len(self.inactive_mitigations)}):")
        for m in self.inactive_mitigations:
            lines.append(f"    {m['name']}: NOT set — {m['impact']}")
        if self.exploitation_notes:
            lines.append(f"  Exploitation notes:")
            for note in self.exploitation_notes:
                lines.append(f"    • {note}")
        return "\n".join(lines)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "config_source": self.config_source,
            "total_options": self.total_options,
            "hardening_level": self.hardening_level,
            "active_mitigations": self.active_mitigations,
            "inactive_mitigations": self.inactive_mitigations,
            "features": self.features,
            "exploitation_notes": self.exploitation_notes,
        }


def _parse_config_text(text: str) -> Dict[str, str]:
    """Parse a kernel .config text into key=value dict."""
    config: Dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            # Check for "# CONFIG_X is not set"
            m = re.match(r"^#\s+(CONFIG_\w+)\s+is not set", line)
            if m:
                config[m.group(1)] = "n"
            continue
        m = re.match(r"^(CONFIG_\w+)=(.+)$", line)
        if m:
            config[m.group(1)] = m.group(2)
    return config


def _fetch_config_from_device(
    ssh_host: str, ssh_port: int = 22, instance: Optional[int] = None,
    adb_port: int = 6520,
) -> Optional[str]:
    """Pull kernel config from the running device via ADB or SSH."""
    from ..infra.verification import _adb_run, _calc_adb_port, _adb_is_alive

    port = _calc_adb_port(instance, adb_port)

    # Try /proc/config.gz first
    rc, stdout, stderr = _adb_run(
        "cat /proc/config.gz | base64", port, timeout=10,
    )
    if rc == 0 and stdout.strip():
        import base64
        try:
            decoded = base64.b64decode(stdout.strip())
            return gzip.decompress(decoded).decode("utf-8", errors="replace")
        except Exception:
            pass

    # Try zcat
    rc, stdout, _ = _adb_run("zcat /proc/config.gz", port, timeout=10)
    if rc == 0 and stdout.strip() and "CONFIG_" in stdout:
        return stdout

    # Try /boot/config-*
    rc, stdout, _ = _adb_run(
        "cat /boot/config-$(uname -r) 2>/dev/null || "
        "cat /boot/config 2>/dev/null",
        port, timeout=10,
    )
    if rc == 0 and "CONFIG_" in stdout:
        return stdout

    return None


def analyze_kernel_config(
    *,
    config_text: Optional[str] = None,
    config_path: Optional[str] = None,
    ssh_host: str = "",
    ssh_port: int = 22,
    instance: Optional[int] = None,
    adb_port: int = 6520,
) -> KernelConfigAnalysis:
    """Analyze kernel configuration for exploitation-relevant settings.

    Accepts config text directly, a path to a config file, or
    pulls /proc/config.gz from the device.
    """
    result = KernelConfigAnalysis()

    # Get config text from available sources
    if config_text:
        result.config_source = "provided text"
    elif config_path:
        import pathlib
        p = pathlib.Path(config_path)
        if p.suffix == ".gz":
            config_text = gzip.decompress(p.read_bytes()).decode(
                "utf-8", errors="replace"
            )
        else:
            config_text = p.read_text()
        result.config_source = str(config_path)
    elif ssh_host:
        console.print("  [dim]Fetching kernel config from device…[/]")
        config_text = _fetch_config_from_device(
            ssh_host, ssh_port, instance, adb_port,
        )
        if config_text:
            result.config_source = "/proc/config.gz (device)"
        else:
            result.config_source = "unavailable"
            result.exploitation_notes.append(
                "Could not retrieve kernel config from device. "
                "/proc/config.gz may not be enabled (CONFIG_IKCONFIG_PROC)."
            )
            return result
    else:
        result.config_source = "no source"
        return result

    # Parse
    config = _parse_config_text(config_text)
    result.total_options = len(config)
    result.raw_values = {
        k: v for k, v in config.items()
        if k in _MITIGATION_MAP
    }

    # Classify mitigations
    high_active = 0
    for mi in _MITIGATIONS:
        val = config.get(mi.config_key)
        entry = {
            "name": mi.name,
            "config_key": mi.config_key,
            "description": mi.description,
            "impact": mi.impact,
            "severity": mi.severity,
        }
        if val is None:
            entry["status"] = "not present"
            result.unknown_mitigations.append(entry)
        elif val == "n":
            entry["status"] = "disabled"
            result.inactive_mitigations.append(entry)
        else:
            entry["status"] = f"enabled ({val})"
            result.active_mitigations.append(entry)
            if mi.severity == "high":
                high_active += 1

    # Feature detection
    result.features = {
        "kasan": config.get("CONFIG_KASAN", "n") not in ("n", None),
        "cfi": config.get("CONFIG_CFI_CLANG", "n") not in ("n", None),
        "scs": config.get("CONFIG_SHADOW_CALL_STACK", "n") not in ("n", None),
        "kaslr": config.get("CONFIG_RANDOMIZE_BASE", "n") not in ("n", None),
        "selinux": config.get("CONFIG_SECURITY_SELINUX", "n") not in ("n", None),
        "seccomp": config.get("CONFIG_SECCOMP", "n") not in ("n", None),
        "userfaultfd": config.get("CONFIG_USERFAULTFD", "n") not in ("n", None),
        "user_ns": config.get("CONFIG_USER_NS", "n") not in ("n", None),
        "freelist_hardened": config.get("CONFIG_SLAB_FREELIST_HARDENED", "n") not in ("n", None),
        "init_on_free": config.get("CONFIG_INIT_ON_FREE_DEFAULT_ON", "n") not in ("n", None),
        "static_usermodehelper": config.get("CONFIG_STATIC_USERMODEHELPER", "n") not in ("n", None),
        "randstruct": config.get("CONFIG_GCC_PLUGIN_RANDSTRUCT", "n") not in ("n", None),
    }

    # Determine hardening level
    if result.features.get("kasan"):
        result.hardening_level = "debug"
        result.exploitation_notes.append(
            "KASAN is enabled — this is a debug/test kernel. Heap corruption "
            "will be detected immediately. Exploitation is unlikely to succeed "
            "without KASAN being triggered."
        )
    elif high_active >= 4:
        result.hardening_level = "hardened"
        result.exploitation_notes.append(
            "Multiple high-severity mitigations active. Exploitation requires "
            "techniques that bypass CFI, SCS, freelist hardening, etc."
        )
    elif high_active >= 2:
        result.hardening_level = "moderate"
    else:
        result.hardening_level = "minimal"
        result.exploitation_notes.append(
            "Few mitigations active — exploitation is more straightforward."
        )

    # Generate specific exploitation notes
    if result.features.get("freelist_hardened"):
        result.exploitation_notes.append(
            "SLAB_FREELIST_HARDENED: freelist pointer overwrite will trigger "
            "BUG_ON. Use cross-cache or page-level reclamation instead."
        )
    if result.features.get("init_on_free"):
        result.exploitation_notes.append(
            "INIT_ON_FREE: freed objects are zeroed. UAF spray must re-fill "
            "the freed slot with controlled data before the exploit reads it."
        )
    if result.features.get("cfi") and not config.get("CONFIG_CFI_PERMISSIVE"):
        result.exploitation_notes.append(
            "CFI (enforcing): indirect calls through corrupted function "
            "pointers will panic. Avoid vtable/ops-table hijacking."
        )
    if result.features.get("static_usermodehelper"):
        result.exploitation_notes.append(
            "STATIC_USERMODEHELPER: modprobe_path overwrite won't work. "
            "Use cred overwrite or task_struct walk for privilege escalation."
        )
    if not result.features.get("userfaultfd"):
        result.exploitation_notes.append(
            "Userfaultfd is DISABLED. Cannot use page-fault-based race "
            "control. Use FUSE, signals, or CPU scheduling for race timing."
        )
    if result.features.get("randstruct"):
        result.exploitation_notes.append(
            "RANDSTRUCT: struct field offsets are randomized per-build. "
            "Hard-coded offsets WILL be wrong. Must discover offsets from "
            "vmlinux or runtime inspection."
        )

    console.print(f"  Config analysis: {result.hardening_level} "
                  f"({len(result.active_mitigations)} active mitigations)")

    return result
