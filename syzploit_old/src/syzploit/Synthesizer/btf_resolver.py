"""
btf_resolver.py

Resolves kernel struct field offsets using BTF (BPF Type Format) data.

BTF data is available in modern kernels via /sys/kernel/btf/vmlinux
and can also be extracted from vmlinux ELF files. This module parses
BTF info to resolve struct offsets dynamically, replacing hardcoded
offset tables.

Supports:
- Parsing BTF JSON dumps (from pahole --json or bpftool)
- Parsing raw /sys/kernel/btf/vmlinux via bpftool
- Extracting offsets from vmlinux using pahole
- Falling back to a manual offset table when BTF is unavailable

Common offsets needed for exploitation:
- task_struct: cred, pid, comm, real_cred, nsproxy, fs
- cred: uid, gid, euid, egid, suid, sgid, fsuid, fsgid, cap_effective
- file: f_op, f_inode, f_path
- msg_msg: m_list, m_type, m_ts
- pipe_buffer: page, offset, len, ops, flags
- pipe_buf_operations: confirm
"""

import json
import os
import re
import subprocess
from pathlib import Path
from typing import Dict, Optional, Any, List
from dataclasses import dataclass, field


# Well-known struct.field pairs we typically need for exploitation
COMMON_FIELDS = [
    ("task_struct", "cred"),
    ("task_struct", "real_cred"),
    ("task_struct", "pid"),
    ("task_struct", "comm"),
    ("task_struct", "nsproxy"),
    ("task_struct", "fs"),
    ("task_struct", "thread_info"),
    ("cred", "uid"),
    ("cred", "gid"),
    ("cred", "euid"),
    ("cred", "egid"),
    ("cred", "suid"),
    ("cred", "sgid"),
    ("cred", "fsuid"),
    ("cred", "fsgid"),
    ("cred", "cap_effective"),
    ("msg_msg", "m_list"),
    ("msg_msg", "m_type"),
    ("msg_msg", "m_ts"),
    ("msg_msg", "security"),
    ("pipe_buffer", "page"),
    ("pipe_buffer", "offset"),
    ("pipe_buffer", "len"),
    ("pipe_buffer", "ops"),
    ("pipe_buffer", "flags"),
    ("pipe_buf_operations", "confirm"),
    ("file", "f_op"),
    ("seq_operations", "start"),
    ("seq_operations", "stop"),
    ("seq_operations", "next"),
    ("seq_operations", "show"),
    ("tty_struct", "ops"),
    ("sk_buff", "head"),
    ("sk_buff", "data"),
    ("sk_buff", "len"),
]


@dataclass
class StructInfo:
    """Information about a kernel struct."""
    name: str
    size: int = 0
    fields: Dict[str, int] = field(default_factory=dict)  # field_name -> offset


@dataclass
class BTFData:
    """Parsed BTF data for a kernel image."""
    kernel_version: str = ""
    arch: str = ""
    structs: Dict[str, StructInfo] = field(default_factory=dict)
    source: str = ""  # "btf_json", "pahole", "manual", etc.

    def get_offset(self, struct_name: str, field_name: str) -> Optional[int]:
        """Get the offset of a field within a struct."""
        si = self.structs.get(struct_name)
        if si:
            return si.fields.get(field_name)
        return None

    def get_struct_size(self, struct_name: str) -> Optional[int]:
        """Get the size of a struct."""
        si = self.structs.get(struct_name)
        if si:
            return si.size
        return None

    def to_offset_dict(self) -> Dict[str, int]:
        """Flatten to a dict of 'struct.field' -> offset."""
        result: Dict[str, int] = {}
        for sname, sinfo in self.structs.items():
            for fname, offset in sinfo.fields.items():
                result[f"{sname}.{fname}"] = offset
        return result

    def to_json(self) -> str:
        """Serialize to JSON."""
        data = {
            "kernel_version": self.kernel_version,
            "arch": self.arch,
            "source": self.source,
            "structs": {},
        }
        for sname, sinfo in self.structs.items():
            data["structs"][sname] = {
                "size": sinfo.size,
                "fields": sinfo.fields,
            }
        return json.dumps(data, indent=2)

    @classmethod
    def from_json(cls, json_str: str) -> "BTFData":
        """Deserialize from JSON."""
        data = json.loads(json_str)
        btf = cls(
            kernel_version=data.get("kernel_version", ""),
            arch=data.get("arch", ""),
            source=data.get("source", "json"),
        )
        for sname, sdata in data.get("structs", {}).items():
            btf.structs[sname] = StructInfo(
                name=sname,
                size=sdata.get("size", 0),
                fields=sdata.get("fields", {}),
            )
        return btf


def resolve_from_btf_json(btf_json_path: str) -> BTFData:
    """
    Parse a BTF JSON dump file (from bpftool btf dump or pahole --json).

    The expected format is a JSON file with struct definitions like:
    {
        "structs": {
            "task_struct": {
                "size": 9024,
                "fields": {"cred": 1640, "pid": 1256, ...}
            }, ...
        }
    }
    """
    with open(btf_json_path) as f:
        data = json.load(f)

    btf = BTFData(source="btf_json")
    btf.kernel_version = data.get("kernel_version", "")
    btf.arch = data.get("arch", "")

    for sname, sdata in data.get("structs", {}).items():
        if isinstance(sdata, dict):
            btf.structs[sname] = StructInfo(
                name=sname,
                size=sdata.get("size", 0),
                fields={k: v for k, v in sdata.get("fields", {}).items()
                        if isinstance(v, int)},
            )

    return btf


def resolve_from_pahole(vmlinux_path: str,
                        struct_names: Optional[List[str]] = None) -> BTFData:
    """
    Use pahole to extract struct offsets from a vmlinux ELF.

    Requires: pahole (dwarves package) installed.
    """
    if not os.path.isfile(vmlinux_path):
        raise FileNotFoundError(f"vmlinux not found: {vmlinux_path}")

    if struct_names is None:
        struct_names = list(set(s for s, _ in COMMON_FIELDS))

    btf = BTFData(source="pahole")

    for struct_name in struct_names:
        try:
            result = subprocess.run(
                ["pahole", "-C", struct_name, vmlinux_path],
                capture_output=True, text=True, timeout=30,
            )
            if result.returncode != 0:
                continue

            si = _parse_pahole_output(struct_name, result.stdout)
            if si:
                btf.structs[struct_name] = si

        except (subprocess.TimeoutExpired, FileNotFoundError):
            continue

    return btf


def _parse_pahole_output(struct_name: str, output: str) -> Optional[StructInfo]:
    """Parse pahole output for a single struct."""
    si = StructInfo(name=struct_name)

    # Parse size from last line: "/* size: 9024, cachelines: ... */"
    size_match = re.search(r'/\*\s*size:\s*(\d+)', output)
    if size_match:
        si.size = int(size_match.group(1))

    # Parse field offsets from lines like:
    # "struct cred *                cred;                 /*  1640     8 */"
    field_pattern = re.compile(
        r'^\s+\S.*?\s+(\w+)(?:\[\d+\])?;\s*/\*\s*(\d+)\s+\d+\s*\*/',
        re.MULTILINE,
    )
    for match in field_pattern.finditer(output):
        field_name = match.group(1)
        offset = int(match.group(2))
        si.fields[field_name] = offset

    return si if si.fields else None


def resolve_from_bpftool(btf_path: str = "/sys/kernel/btf/vmlinux",
                         struct_names: Optional[List[str]] = None) -> BTFData:
    """
    Use bpftool to parse raw BTF data from a running kernel.

    Requires: bpftool installed and BTF data available.
    """
    if struct_names is None:
        struct_names = list(set(s for s, _ in COMMON_FIELDS))

    btf = BTFData(source="bpftool")

    for struct_name in struct_names:
        try:
            result = subprocess.run(
                ["bpftool", "btf", "dump", "file", btf_path,
                 "format", "c", "-j"],
                capture_output=True, text=True, timeout=60,
            )
            if result.returncode == 0 and result.stdout:
                # Parse bpftool JSON output
                data = json.loads(result.stdout)
                # Process the type information
                for entry in data if isinstance(data, list) else []:
                    if (entry.get("kind") == "STRUCT" and
                            entry.get("name") == struct_name):
                        si = StructInfo(name=struct_name,
                                        size=entry.get("size", 0))
                        for member in entry.get("members", []):
                            name = member.get("name", "")
                            offset_bits = member.get("bits_offset", 0)
                            if name:
                                si.fields[name] = offset_bits // 8
                        btf.structs[struct_name] = si
        except (subprocess.TimeoutExpired, FileNotFoundError, json.JSONDecodeError):
            continue

    return btf


def resolve_offsets(vmlinux_path: Optional[str] = None,
                    btf_json_path: Optional[str] = None,
                    btf_sys_path: Optional[str] = None,
                    struct_names: Optional[List[str]] = None) -> BTFData:
    """
    Resolve struct offsets using the best available method.

    Tries in order:
    1. BTF JSON file (if provided)
    2. pahole on vmlinux (if provided and pahole is installed)
    3. bpftool on /sys/kernel/btf/vmlinux (if available)
    4. Empty BTFData (caller should handle missing offsets)
    """
    # Try BTF JSON
    if btf_json_path and os.path.isfile(btf_json_path):
        try:
            return resolve_from_btf_json(btf_json_path)
        except Exception:
            pass

    # Try pahole
    if vmlinux_path and os.path.isfile(vmlinux_path):
        try:
            btf = resolve_from_pahole(vmlinux_path, struct_names)
            if btf.structs:
                return btf
        except Exception:
            pass

    # Try bpftool
    sys_btf = btf_sys_path or "/sys/kernel/btf/vmlinux"
    if os.path.isfile(sys_btf):
        try:
            btf = resolve_from_bpftool(sys_btf, struct_names)
            if btf.structs:
                return btf
        except Exception:
            pass

    # Return empty
    return BTFData(source="none")
