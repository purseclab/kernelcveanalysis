"""
analysis.offset_discovery — Cross-kernel offset auto-discovery.

When exploit offsets from one kernel don't match the target, automatically
discover the correct offsets using vmlinux, nm, objdump, and pattern matching.
"""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ..core.log import console


@dataclass
class OffsetMatch:
    """A discovered kernel symbol/offset."""

    symbol: str
    address: int = 0
    source: str = ""  # "nm", "kallsyms", "objdump", "pattern"
    confidence: str = "high"


@dataclass
class OffsetDiscoveryResult:
    """Result of cross-kernel offset discovery."""

    target_kernel: str = ""
    vmlinux_path: str = ""

    discovered_offsets: Dict[str, int] = field(default_factory=dict)
    struct_offsets: Dict[str, Dict[str, int]] = field(default_factory=dict)
    mismatches: List[Dict[str, Any]] = field(default_factory=list)
    matches: List[OffsetMatch] = field(default_factory=list)

    # Generated header content
    offsets_header: str = ""

    notes: List[str] = field(default_factory=list)

    def summary(self) -> str:
        lines = [
            f"=== Offset Discovery ===",
            f"  Target: {self.target_kernel}",
            f"  vmlinux: {self.vmlinux_path or 'N/A'}",
            f"  Symbols discovered: {len(self.discovered_offsets)}",
            f"  Struct offsets: {sum(len(v) for v in self.struct_offsets.values())}",
            f"  Mismatches fixed: {len(self.mismatches)}",
        ]
        for note in self.notes:
            lines.append(f"  Note: {note}")
        return "\n".join(lines)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target_kernel": self.target_kernel,
            "discovered_offsets": self.discovered_offsets,
            "struct_offsets": self.struct_offsets,
            "mismatches": self.mismatches,
            "notes": self.notes,
        }


def _run_cmd(cmd: List[str], timeout: int = 30) -> Tuple[int, str, str]:
    """Run a command and return (rc, stdout, stderr)."""
    try:
        r = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
        )
        return r.returncode, r.stdout, r.stderr
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        return 1, "", str(e)


def _nm_symbols(vmlinux: str) -> Dict[str, int]:
    """Extract symbols from vmlinux via nm."""
    rc, stdout, _ = _run_cmd(["nm", "-n", vmlinux], timeout=60)
    symbols: Dict[str, int] = {}
    if rc != 0:
        return symbols
    for line in stdout.splitlines():
        parts = line.strip().split()
        if len(parts) >= 3:
            try:
                addr = int(parts[0], 16)
                name = parts[2]
                symbols[name] = addr
            except ValueError:
                continue
    return symbols


def _kallsyms_symbols(kallsyms_path: str) -> Dict[str, int]:
    """Parse a local kallsyms file."""
    symbols: Dict[str, int] = {}
    try:
        with open(kallsyms_path) as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) >= 3:
                    try:
                        addr = int(parts[0], 16)
                        name = parts[2]
                        symbols[name] = addr
                    except ValueError:
                        continue
    except (OSError, IOError):
        pass
    return symbols


def _objdump_search(
    vmlinux: str, pattern: str, section: str = ".text",
) -> List[Tuple[int, str]]:
    """Search for a pattern in objdump disassembly."""
    rc, stdout, _ = _run_cmd(
        ["objdump", "-d", "-j", section, vmlinux],
        timeout=120,
    )
    if rc != 0:
        return []

    matches: List[Tuple[int, str]] = []
    for line in stdout.splitlines():
        if pattern.lower() in line.lower():
            # Parse address from disassembly line
            m = re.match(r"^\s*([0-9a-f]+):", line)
            if m:
                matches.append((int(m.group(1), 16), line.strip()))
    return matches


def _discover_struct_offsets_from_vmlinux(
    vmlinux: str, struct_name: str, fields: List[str],
) -> Dict[str, int]:
    """Try to discover struct field offsets using pahole or heuristics."""
    offsets: Dict[str, int] = {}

    # Try pahole first
    rc, stdout, _ = _run_cmd(
        ["pahole", "-C", struct_name, vmlinux], timeout=30,
    )
    if rc == 0 and stdout.strip():
        for line in stdout.splitlines():
            for fld in fields:
                # pahole output: "    type name; /* offset: N  size: M */"
                if fld in line and "offset:" in line:
                    m = re.search(r"offset:\s*(\d+)", line)
                    if m:
                        offsets[fld] = int(m.group(1))

    return offsets


# Common kernel offsets to discover
_DEFAULT_SYMBOLS = [
    "init_task",
    "init_cred",
    "selinux_state",
    "commit_creds",
    "prepare_kernel_cred",
    "find_task_by_vpid",
    "switch_task_namespaces",
    "avc_denied",
]

# Common struct fields to resolve
_DEFAULT_STRUCT_FIELDS: Dict[str, List[str]] = {
    "task_struct": ["tasks", "pid", "cred", "real_cred", "comm", "fs", "nsproxy"],
    "cred": ["uid", "gid", "euid", "egid", "cap_effective", "security"],
}


def discover_offsets(
    *,
    vmlinux_path: Optional[str] = None,
    kallsyms_path: Optional[str] = None,
    target_kernel: str = "",
    symbols_needed: Optional[List[str]] = None,
    struct_fields: Optional[Dict[str, List[str]]] = None,
    expected_offsets: Optional[Dict[str, int]] = None,
    # Remote target access — used when fetching data from a live device
    ssh_host: Optional[str] = None,
    ssh_port: int = 22,
    instance: Optional[int] = None,
    adb_port: int = 6520,
    use_adb: bool = False,
    # Additional symbols/fields to merge with defaults
    extra_symbols: Optional[List[str]] = None,
    extra_struct_fields: Optional[Dict[str, List[str]]] = None,
) -> OffsetDiscoveryResult:
    """Discover kernel symbol addresses and struct offsets.

    Uses nm, pahole, objdump and pattern matching to find offsets
    that may differ between kernel versions.

    Parameters
    ----------
    vmlinux_path
        Path to vmlinux with debug info.
    kallsyms_path
        Path to a saved /proc/kallsyms file.  If not provided and
        ``use_adb`` is True, we attempt to pull it from the device.
    symbols_needed
        Symbol names to resolve. Uses defaults if not specified.
    struct_fields
        Dict of {struct_name: [field_names]} to resolve offsets for.
    expected_offsets
        Previously known offsets to check for mismatches.
    ssh_host
        SSH host for the build/remote machine.
    ssh_port
        SSH port.
    instance
        Cuttlefish instance number (for ADB port calculation).
    adb_port
        Base ADB port.
    use_adb
        If True, attempt to pull /proc/kallsyms from device via ADB.
    extra_symbols
        Additional symbol names to append to ``symbols_needed``.
    extra_struct_fields
        Additional struct fields to merge into ``struct_fields``.
    """
    result = OffsetDiscoveryResult(target_kernel=target_kernel)

    if symbols_needed is None:
        symbols_needed = list(_DEFAULT_SYMBOLS)
    if struct_fields is None:
        struct_fields = dict(_DEFAULT_STRUCT_FIELDS)

    # Merge extra symbols/fields from caller
    if extra_symbols:
        for sym in extra_symbols:
            if sym not in symbols_needed:
                symbols_needed.append(sym)
    if extra_struct_fields:
        for struct_name, fields in extra_struct_fields.items():
            if struct_name in struct_fields:
                existing = set(struct_fields[struct_name])
                struct_fields[struct_name].extend(
                    f for f in fields if f not in existing
                )
            else:
                struct_fields[struct_name] = list(fields)

    # If no local kallsyms and ADB is available, try fetching remotely
    if not kallsyms_path and use_adb:
        try:
            from ..infra.verification import _adb_run, _calc_adb_port
            import tempfile
            port = _calc_adb_port(instance, adb_port)
            rc, stdout, _ = _adb_run("cat /proc/kallsyms", port)
            if rc == 0 and stdout.strip():
                # Save to a temp file for local parsing
                tmp = tempfile.NamedTemporaryFile(
                    mode="w", suffix="_kallsyms", delete=False,
                )
                tmp.write(stdout)
                tmp.close()
                kallsyms_path = tmp.name
                console.print(
                    f"  [dim]Pulled /proc/kallsyms via ADB "
                    f"(port {port}, {len(stdout.splitlines())} symbols)[/]"
                )
                result.notes.append(
                    f"kallsyms pulled via ADB (port {port})"
                )
        except Exception as exc:
            console.print(f"  [dim]ADB kallsyms pull failed: {exc}[/]")
            result.notes.append(f"ADB kallsyms pull failed: {exc}")

    all_symbols: Dict[str, int] = {}

    # Source 1: nm on vmlinux
    if vmlinux_path and Path(vmlinux_path).is_file():
        result.vmlinux_path = vmlinux_path
        console.print("  [dim]Running nm on vmlinux…[/]")
        nm_syms = _nm_symbols(vmlinux_path)
        for sym in symbols_needed:
            if sym in nm_syms:
                all_symbols[sym] = nm_syms[sym]
                result.matches.append(OffsetMatch(
                    symbol=sym, address=nm_syms[sym], source="nm",
                ))
        console.print(f"    nm: found {len(nm_syms)} total, "
                      f"{sum(1 for s in symbols_needed if s in nm_syms)} needed")

        # Struct offsets via pahole
        for struct_name, fields in struct_fields.items():
            console.print(f"  [dim]Resolving {struct_name} offsets via pahole…[/]")
            offsets = _discover_struct_offsets_from_vmlinux(
                vmlinux_path, struct_name, fields,
            )
            if offsets:
                result.struct_offsets[struct_name] = offsets
                console.print(f"    {struct_name}: {len(offsets)} field offsets")

    # Source 2: kallsyms file
    if kallsyms_path and Path(kallsyms_path).is_file():
        console.print("  [dim]Parsing kallsyms…[/]")
        ksyms = _kallsyms_symbols(kallsyms_path)
        for sym in symbols_needed:
            if sym not in all_symbols and sym in ksyms:
                all_symbols[sym] = ksyms[sym]
                result.matches.append(OffsetMatch(
                    symbol=sym, address=ksyms[sym], source="kallsyms",
                ))
        console.print(f"    kallsyms: {sum(1 for s in symbols_needed if s in ksyms)} found")

    result.discovered_offsets = all_symbols

    # Check for mismatches with expected offsets
    if expected_offsets:
        for sym, expected in expected_offsets.items():
            actual = all_symbols.get(sym)
            if actual is not None and actual != expected:
                result.mismatches.append({
                    "symbol": sym,
                    "expected": hex(expected),
                    "actual": hex(actual),
                    "delta": actual - expected,
                })
            elif actual is None:
                result.notes.append(
                    f"Symbol '{sym}' not found in target — "
                    f"expected at {hex(expected)}"
                )

    # Generate header
    header_lines = [
        "/* Auto-generated kernel offsets */",
        f"/* Target: {target_kernel} */",
        f"/* vmlinux: {vmlinux_path or 'N/A'} */",
        "",
        "#ifndef KERNEL_OFFSETS_H",
        "#define KERNEL_OFFSETS_H",
        "",
    ]
    for sym, addr in sorted(all_symbols.items()):
        c_name = sym.upper()
        header_lines.append(f"#ifndef ADDR_{c_name}")
        header_lines.append(f"#define ADDR_{c_name} 0x{addr:x}UL")
        header_lines.append(f"#endif")
        header_lines.append("")

    for struct_name, offsets in sorted(result.struct_offsets.items()):
        header_lines.append(f"/* {struct_name} field offsets */")
        for fld, off in sorted(offsets.items(), key=lambda x: x[1]):
            c_name = f"OFF_{struct_name.upper()}_{fld.upper()}"
            header_lines.append(f"#ifndef {c_name}")
            header_lines.append(f"#define {c_name} {off}")
            header_lines.append(f"#endif")
        header_lines.append("")

    header_lines.append("#endif /* KERNEL_OFFSETS_H */")
    result.offsets_header = "\n".join(header_lines)

    # Report
    if result.mismatches:
        console.print(f"  [yellow]{len(result.mismatches)} offset mismatches detected[/]")
        for mm in result.mismatches:
            console.print(
                f"    {mm['symbol']}: expected {mm['expected']}, "
                f"actual {mm['actual']} (delta {mm['delta']:+d})"
            )
    else:
        console.print(
            f"  Offset discovery: {len(all_symbols)} symbols, "
            f"{sum(len(v) for v in result.struct_offsets.values())} struct fields"
        )

    return result
