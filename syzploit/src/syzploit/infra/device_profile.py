"""
infra.device_profile — Target device profile management.

Real exploits need per-device kernel constant tables (struct offsets,
symbol addresses, memory layout constants).  This module consolidates
three existing partial solutions (kexploit_bridge, kernel_resolver,
resolve_kernel_offsets) into a unified device profile system.

A device profile contains everything needed to compile an exploit for
a specific target: kernel offsets, memory layout, hardware limits, and
platform characteristics.

Patterns from kernel_PoCs:
  - badspin:        dev_config.h with per-device offset tables
  - bad_io_uring:   kexploit.json with __kexploit_kernel_address macros
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..core.config import Config, load_config
from ..core.log import console


# ═════════════════════════════════════════════════════════════════════
# Known device profiles (bootstrap — can be extended via JSON)
# ═════════════════════════════════════════════════════════════════════

_BUILTIN_PROFILES: Dict[str, Dict[str, Any]] = {
    "cuttlefish_5.10": {
        "device": "Cuttlefish (virtual)",
        "kernel_version": "5.10",
        "arch": "arm64",
        "platform": "android",
        "memory_layout": {
            "VMEMMAP_START": 0xFFFFFC0000000000,
            "PAGE_OFFSET": 0xFFFFFF8000000000,
            "KIMAGE_VADDR": 0xFFFF800010000000,
            "PAGE_SIZE": 4096,
            "STRUCT_PAGE_SIZE": 64,
        },
        "hardware": {
            "max_hw_breakpoints": 4,
            "nr_cpus": 8,
            "has_kasan": False,
        },
        "selinux": {
            "enforcing": True,
            "permissive_available": True,
        },
        "task_struct_offsets": {
            "tasks": None,       # resolve from BTF/vmlinux
            "pid": None,
            "tgid": None,
            "comm": None,
            "cred": None,
            "real_cred": None,
            "real_parent": None,
            "nsproxy": None,
            "files": None,
            "fs": None,
            "seccomp": None,
        },
        "file_struct_offsets": {
            "f_op": None,
            "f_count": None,
            "f_mode": None,
            "f_inode": None,
            "private_data": None,
        },
        "symbols": {
            "init_task": None,
            "anon_pipe_buf_ops": None,
            "selinux_state": None,
        },
        "notes": "Cuttlefish is Google's Android emulator. No hardware-specific quirks.",
    },
    "pixel6_5.10": {
        "device": "Google Pixel 6 (oriole)",
        "kernel_version": "5.10",
        "arch": "arm64",
        "platform": "android",
        "memory_layout": {
            "VMEMMAP_START": 0xFFFFFC0000000000,
            "PAGE_OFFSET": 0xFFFFFF8000000000,
            "KIMAGE_VADDR": 0xFFFF800010000000,
            "PAGE_SIZE": 4096,
            "STRUCT_PAGE_SIZE": 64,
        },
        "hardware": {
            "max_hw_breakpoints": 4,
            "nr_cpus": 8,
            "cpu": "Google Tensor (Exynos 2100)",
            "has_kasan": False,
            "has_mali_gpu": True,
        },
        "selinux": {
            "enforcing": True,
            "permissive_available": False,
        },
        "task_struct_offsets": {},
        "file_struct_offsets": {},
        "symbols": {},
        "notes": (
            "ARM big.LITTLE architecture. CPU pinning should target "
            "little cores (0-3) for stability."
        ),
    },
    "pixel7_5.10": {
        "device": "Google Pixel 7 (panther)",
        "kernel_version": "5.10",
        "arch": "arm64",
        "platform": "android",
        "memory_layout": {
            "VMEMMAP_START": 0xFFFFFC0000000000,
            "PAGE_OFFSET": 0xFFFFFF8000000000,
            "KIMAGE_VADDR": 0xFFFF800010000000,
            "PAGE_SIZE": 4096,
            "STRUCT_PAGE_SIZE": 64,
        },
        "hardware": {
            "max_hw_breakpoints": 4,
            "nr_cpus": 8,
            "cpu": "Google Tensor G2",
            "has_kasan": False,
            "has_mali_gpu": True,
        },
        "selinux": {"enforcing": True, "permissive_available": False},
        "task_struct_offsets": {},
        "file_struct_offsets": {},
        "symbols": {},
        "notes": "Similar to Pixel 6 but Tensor G2 chip.",
    },
}


class DeviceProfile:
    """A device/kernel target profile with all exploit-relevant constants."""

    def __init__(self, data: Dict[str, Any]) -> None:
        self._data = data

    @property
    def device(self) -> str:
        return self._data.get("device", "unknown")

    @property
    def kernel_version(self) -> str:
        return self._data.get("kernel_version", "")

    @property
    def arch(self) -> str:
        return self._data.get("arch", "arm64")

    @property
    def platform(self) -> str:
        return self._data.get("platform", "linux")

    @property
    def memory_layout(self) -> Dict[str, int]:
        return self._data.get("memory_layout", {})

    @property
    def hardware(self) -> Dict[str, Any]:
        return self._data.get("hardware", {})

    @property
    def task_struct_offsets(self) -> Dict[str, Optional[int]]:
        return self._data.get("task_struct_offsets", {})

    @property
    def file_struct_offsets(self) -> Dict[str, Optional[int]]:
        return self._data.get("file_struct_offsets", {})

    @property
    def symbols(self) -> Dict[str, Optional[int]]:
        return self._data.get("symbols", {})

    def missing_offsets(self) -> List[str]:
        """Return list of offset fields that are still None."""
        missing = []
        for field, val in self.task_struct_offsets.items():
            if val is None:
                missing.append(f"task_struct.{field}")
        for field, val in self.file_struct_offsets.items():
            if val is None:
                missing.append(f"file.{field}")
        for sym, val in self.symbols.items():
            if val is None:
                missing.append(f"symbol:{sym}")
        return missing

    def populate_from_kallsyms(self, kallsyms_path: str) -> int:
        """Populate symbol addresses from a /proc/kallsyms dump.

        Returns number of symbols resolved.
        """
        resolved = 0
        try:
            with open(kallsyms_path) as f:
                for line in f:
                    parts = line.strip().split()
                    if len(parts) < 3:
                        continue
                    addr_str, _type, name = parts[0], parts[1], parts[2]
                    if name in self._data.get("symbols", {}):
                        try:
                            self._data["symbols"][name] = int(addr_str, 16)
                            resolved += 1
                        except ValueError:
                            pass
        except FileNotFoundError:
            console.print(f"  [yellow]kallsyms file not found: {kallsyms_path}[/]")
        return resolved

    def populate_from_btf(self, btf_data: Dict[str, Any]) -> int:
        """Populate struct offsets from BTF data (from kexploit bridge).

        btf_data should be a dict like:
            {"task_struct.tasks": 0x398, "task_struct.pid": 0x3a0, ...}
        """
        resolved = 0
        for key, offset in btf_data.items():
            parts = key.split(".")
            if len(parts) != 2:
                continue
            struct_name, field = parts
            if struct_name == "task_struct":
                offsets = self._data.setdefault("task_struct_offsets", {})
                offsets[field] = offset
                resolved += 1
            elif struct_name == "file":
                offsets = self._data.setdefault("file_struct_offsets", {})
                offsets[field] = offset
                resolved += 1
        return resolved

    def generate_header(self) -> str:
        """Generate a C header with all resolved offsets and addresses.

        This replaces the manually-maintained dev_config.h / kernel_offsets.h
        from individual PoCs.
        """
        lines = [
            "#ifndef DEVICE_PROFILE_H",
            "#define DEVICE_PROFILE_H",
            "",
            f"/* Device: {self.device} */",
            f"/* Kernel: {self.kernel_version} ({self.arch}) */",
            f"/* Auto-generated by syzploit device_profile */",
            "",
            "/* ── Memory layout ──────────────────────────────── */",
        ]
        for name, val in self.memory_layout.items():
            lines.append(f"#define {name} 0x{val:X}ULL")

        lines.append("")
        lines.append("/* ── Symbol addresses ───────────────────────────── */")
        for name, val in self.symbols.items():
            if val is not None:
                lines.append(f"#define {name.upper()}_ADDR 0x{val:X}ULL")
            else:
                lines.append(f"/* #define {name.upper()}_ADDR TODO: resolve */")

        lines.append("")
        lines.append("/* ── task_struct offsets ─────────────────────────── */")
        for field, val in self.task_struct_offsets.items():
            define_name = f"TASK_STRUCT_{field.upper()}_OFFSET"
            if val is not None:
                lines.append(f"#define {define_name} 0x{val:X}")
            else:
                lines.append(f"/* #define {define_name} TODO: resolve */")

        lines.append("")
        lines.append("/* ── file struct offsets ────────────────────────── */")
        for field, val in self.file_struct_offsets.items():
            define_name = f"FILE_{field.upper()}_OFFSET"
            if val is not None:
                lines.append(f"#define {define_name} 0x{val:X}")
            else:
                lines.append(f"/* #define {define_name} TODO: resolve */")

        lines.append("")
        lines.append("#endif /* DEVICE_PROFILE_H */")
        return "\n".join(lines) + "\n"

    def to_dict(self) -> Dict[str, Any]:
        return dict(self._data)

    def save(self, path: str) -> None:
        """Save profile to JSON."""
        Path(path).write_text(json.dumps(self._data, indent=2, default=str))

    @classmethod
    def load(cls, path: str) -> DeviceProfile:
        """Load profile from JSON file."""
        data = json.loads(Path(path).read_text())
        return cls(data)


class DeviceProfileRegistry:
    """Registry of known device profiles."""

    def __init__(self) -> None:
        self._profiles: Dict[str, DeviceProfile] = {}
        # Load builtins
        for name, data in _BUILTIN_PROFILES.items():
            self._profiles[name] = DeviceProfile(data)

    def get(self, name: str) -> Optional[DeviceProfile]:
        return self._profiles.get(name)

    def list_profiles(self) -> List[str]:
        return list(self._profiles.keys())

    def add(self, name: str, profile: DeviceProfile) -> None:
        self._profiles[name] = profile

    def load_from_dir(self, profiles_dir: str) -> int:
        """Load device profiles from JSON files in a directory."""
        loaded = 0
        d = Path(profiles_dir)
        if not d.is_dir():
            return 0
        for f in d.glob("*.json"):
            try:
                profile = DeviceProfile.load(str(f))
                self._profiles[f.stem] = profile
                loaded += 1
            except Exception:
                pass
        return loaded

    def find_matching(
        self,
        *,
        kernel_version: Optional[str] = None,
        device: Optional[str] = None,
        arch: str = "arm64",
    ) -> List[DeviceProfile]:
        """Find profiles matching given criteria."""
        results = []
        for profile in self._profiles.values():
            if arch and profile.arch != arch:
                continue
            if kernel_version and kernel_version not in profile.kernel_version:
                continue
            if device and device.lower() not in profile.device.lower():
                continue
            results.append(profile)
        return results

    def generate_device_config(
        self,
        name: str,
        *,
        kallsyms_path: Optional[str] = None,
        btf_data: Optional[Dict[str, Any]] = None,
    ) -> Optional[str]:
        """Generate a device_config.h for the named device.

        Optionally populates symbol addresses from kallsyms and struct
        offsets from BTF data before generating the header.

        Returns the header content, or None if profile not found.
        """
        profile = self._profiles.get(name)
        if not profile:
            return None

        if kallsyms_path:
            n = profile.populate_from_kallsyms(kallsyms_path)
            console.print(f"  [dim]Resolved {n} symbols from kallsyms[/]")

        if btf_data:
            n = profile.populate_from_btf(btf_data)
            console.print(f"  [dim]Resolved {n} offsets from BTF[/]")

        missing = profile.missing_offsets()
        if missing:
            console.print(
                f"  [yellow]Warning: {len(missing)} unresolved offsets: "
                f"{', '.join(missing[:5])}{'...' if len(missing) > 5 else ''}[/]"
            )

        return profile.generate_header()
