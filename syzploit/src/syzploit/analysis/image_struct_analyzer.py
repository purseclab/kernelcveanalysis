"""
analysis.image_struct_analyzer — Per-image kernel struct analysis.

Provides CodeQL-equivalent struct/slab information using only the
kernel image (vmlinux) and runtime data (kallsyms, /proc/slabinfo,
BTF).  This works for EVERY kernel image without needing a CodeQL
database, enabling cross-image comparison of struct properties.

Key capabilities:
1. **Struct layout extraction** — via ``pahole`` or BTF data, get every
   field's offset, size, and type for a given struct.
2. **Slab cache mapping** — via ``/proc/slabinfo`` + heuristics, map
   structs to their runtime slab caches and sizes.
3. **Allocation site inference** — via ``nm``/``objdump``/kallsyms pattern
   matching, find where a struct is allocated (kmalloc/kmem_cache_alloc).
4. **Cross-image comparison** — given two images' struct data, find
   substitute objects with matching slab properties.
5. **Property matching** — find all structs in a given kmalloc-N cache
   that have function pointers, are controllable from userspace, etc.

Usage:
    analyzer = ImageStructAnalyzer(
        vmlinux_path="/path/to/vmlinux",
        kallsyms_path="/path/to/kallsyms",
        slabinfo_text="...",
    )
    layout = analyzer.get_struct_layout("binder_node")
    cache = analyzer.get_slab_cache("binder_node")
    subs = analyzer.find_substitutes("binder_node", other_analyzer)
"""

from __future__ import annotations

import json
import os
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from ..core.log import console


# ── Data models ───────────────────────────────────────────────────────


@dataclass
class StructField:
    """A single field in a kernel struct."""
    name: str
    offset: int  # bytes from struct start
    size: int  # bytes
    type_name: str  # e.g., "unsigned long", "struct list_head"
    is_pointer: bool = False
    is_function_pointer: bool = False
    is_atomic: bool = False
    is_list_head: bool = False
    bit_offset: int = 0
    bit_size: int = 0

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "name": self.name,
            "offset": self.offset,
            "size": self.size,
            "type": self.type_name,
        }
        if self.is_pointer:
            d["pointer"] = True
        if self.is_function_pointer:
            d["func_ptr"] = True
        if self.is_atomic:
            d["atomic"] = True
        if self.is_list_head:
            d["list_head"] = True
        return d


@dataclass
class StructLayout:
    """Complete layout of a kernel struct."""
    name: str
    size: int  # total size in bytes
    fields: List[StructField] = field(default_factory=list)
    has_function_pointers: bool = False
    has_list_heads: bool = False
    pointer_count: int = 0
    function_pointer_offsets: List[int] = field(default_factory=list)
    source: str = ""  # "pahole", "btf", "manual"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "size": self.size,
            "fields": [f.to_dict() for f in self.fields],
            "has_function_pointers": self.has_function_pointers,
            "has_list_heads": self.has_list_heads,
            "pointer_count": self.pointer_count,
            "function_pointer_offsets": self.function_pointer_offsets,
            "source": self.source,
        }

    def kmalloc_cache(self) -> str:
        """Determine which kmalloc-N cache this struct lands in."""
        # Round up to next power of 2 (capped at 8192)
        size = self.size
        if size <= 0:
            return "unknown"
        cache_size = 8
        while cache_size < size and cache_size < 8192:
            cache_size *= 2
        return f"kmalloc-{cache_size}"

    def format_for_prompt(self) -> str:
        """Format as structured text for LLM prompt."""
        lines = [f"struct {self.name} ({self.size} bytes, "
                  f"cache={self.kmalloc_cache()}):"]
        for f in self.fields:
            flags = []
            if f.is_function_pointer:
                flags.append("FUNC_PTR")
            if f.is_pointer:
                flags.append("ptr")
            if f.is_list_head:
                flags.append("list")
            if f.is_atomic:
                flags.append("atomic")
            flag_str = f" [{','.join(flags)}]" if flags else ""
            lines.append(
                f"  +{f.offset:4d} ({f.size:3d}) {f.type_name} {f.name}{flag_str}"
            )
        return "\n".join(lines)


@dataclass
class SlabCacheInfo:
    """Information about a specific slab cache on a running kernel."""
    name: str  # e.g., "kmalloc-256", "binder_node"
    object_size: int
    num_objects: int = 0
    active_objects: int = 0
    is_dedicated: bool = False  # True for dedicated caches (not kmalloc-N)
    structs_in_cache: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "object_size": self.object_size,
            "num_objects": self.num_objects,
            "active_objects": self.active_objects,
            "is_dedicated": self.is_dedicated,
            "structs_in_cache": self.structs_in_cache,
        }


@dataclass
class StructProperties:
    """Aggregate properties of a struct relevant for exploitation."""
    name: str
    size: int
    slab_cache: str  # e.g., "kmalloc-256" or "binder_node"
    has_function_pointers: bool = False
    function_pointer_offsets: List[int] = field(default_factory=list)
    has_list_heads: bool = False
    controllable_from_userspace: bool = False
    allocation_syscalls: List[str] = field(default_factory=list)
    free_syscalls: List[str] = field(default_factory=list)
    lifetime: str = ""  # "persistent", "ephemeral", "transaction"
    refcounted: bool = False
    has_spinlock: bool = False
    has_rcu: bool = False

    def matches_properties(self, other: StructProperties) -> float:
        """Score how well this struct matches another's properties.

        Returns 0.0 (no match) to 1.0 (perfect match).
        Used for finding substitute objects across kernel images.
        """
        score = 0.0
        total = 0.0

        # Same slab cache is critical
        total += 3.0
        if self.slab_cache == other.slab_cache:
            score += 3.0
        elif self.size == other.size:
            score += 2.0

        # Function pointer presence
        total += 2.0
        if self.has_function_pointers == other.has_function_pointers:
            score += 2.0

        # Similar function pointer offsets
        if self.function_pointer_offsets and other.function_pointer_offsets:
            total += 1.0
            common = set(self.function_pointer_offsets) & set(other.function_pointer_offsets)
            if common:
                score += 1.0

        # Userspace controllability
        total += 1.0
        if self.controllable_from_userspace == other.controllable_from_userspace:
            score += 1.0

        # Lifetime similarity
        total += 1.0
        if self.lifetime == other.lifetime:
            score += 1.0

        # List heads (important for unlinking attacks)
        total += 0.5
        if self.has_list_heads == other.has_list_heads:
            score += 0.5

        return score / total if total > 0 else 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "size": self.size,
            "slab_cache": self.slab_cache,
            "has_function_pointers": self.has_function_pointers,
            "function_pointer_offsets": self.function_pointer_offsets,
            "has_list_heads": self.has_list_heads,
            "controllable_from_userspace": self.controllable_from_userspace,
            "allocation_syscalls": self.allocation_syscalls,
            "free_syscalls": self.free_syscalls,
            "lifetime": self.lifetime,
            "refcounted": self.refcounted,
        }


# ── Known userspace-controllable structs ──────────────────────────────

_USERSPACE_CONTROLLABLE: Dict[str, Dict[str, Any]] = {
    "msg_msg": {
        "alloc_syscalls": ["msgsnd"],
        "free_syscalls": ["msgrcv"],
        "lifetime": "persistent",
        "controllable": True,
    },
    "binder_node": {
        "alloc_syscalls": ["ioctl(BINDER_WRITE_READ)"],
        "free_syscalls": ["ioctl(BINDER_WRITE_READ)"],
        "lifetime": "persistent",
        "controllable": True,
    },
    "binder_transaction": {
        "alloc_syscalls": ["ioctl(BINDER_WRITE_READ)"],
        "free_syscalls": ["binder_free_transaction"],
        "lifetime": "transaction",
        "controllable": True,
    },
    "pipe_buffer": {
        "alloc_syscalls": ["pipe", "fcntl(F_SETPIPE_SZ)"],
        "free_syscalls": ["close"],
        "lifetime": "persistent",
        "controllable": True,
    },
    "sk_buff": {
        "alloc_syscalls": ["sendmsg", "sendto"],
        "free_syscalls": ["recvmsg"],
        "lifetime": "ephemeral",
        "controllable": True,
    },
    "epitem": {
        "alloc_syscalls": ["epoll_ctl(EPOLL_CTL_ADD)"],
        "free_syscalls": ["epoll_ctl(EPOLL_CTL_DEL)", "close"],
        "lifetime": "persistent",
        "controllable": True,
    },
    "file": {
        "alloc_syscalls": ["open", "openat"],
        "free_syscalls": ["close"],
        "lifetime": "persistent",
        "controllable": False,
    },
    "inode": {
        "alloc_syscalls": ["open", "mknod"],
        "free_syscalls": ["unlink"],
        "lifetime": "persistent",
        "controllable": False,
    },
    "cred": {
        "alloc_syscalls": ["fork", "clone"],
        "free_syscalls": ["exit"],
        "lifetime": "persistent",
        "controllable": False,
    },
    "task_struct": {
        "alloc_syscalls": ["fork", "clone"],
        "free_syscalls": ["exit"],
        "lifetime": "persistent",
        "controllable": False,
    },
    "seq_file": {
        "alloc_syscalls": ["open(/proc/...)"],
        "free_syscalls": ["close"],
        "lifetime": "persistent",
        "controllable": False,
    },
    "timerfd_ctx": {
        "alloc_syscalls": ["timerfd_create"],
        "free_syscalls": ["close"],
        "lifetime": "persistent",
        "controllable": True,
    },
    "signalfd_ctx": {
        "alloc_syscalls": ["signalfd"],
        "free_syscalls": ["close"],
        "lifetime": "persistent",
        "controllable": True,
    },
    "user_key_payload": {
        "alloc_syscalls": ["add_key"],
        "free_syscalls": ["keyctl(KEYCTL_REVOKE)"],
        "lifetime": "persistent",
        "controllable": True,
    },
}


class ImageStructAnalyzer:
    """Analyze kernel structs from a specific kernel image.

    This provides CodeQL-equivalent information using only:
    - vmlinux (ELF with DWARF/BTF)
    - /proc/kallsyms (runtime)
    - /proc/slabinfo (runtime)
    - pahole (for struct layouts from DWARF)
    """

    def __init__(
        self,
        *,
        vmlinux_path: Optional[str] = None,
        kallsyms_path: Optional[str] = None,
        slabinfo_text: Optional[str] = None,
        btf_json_path: Optional[str] = None,
        image_label: str = "default",
    ) -> None:
        self.vmlinux_path = vmlinux_path
        self.kallsyms_path = kallsyms_path
        self.btf_json_path = btf_json_path
        self.image_label = image_label

        # Caches
        self._struct_layouts: Dict[str, StructLayout] = {}
        self._slab_caches: Dict[str, SlabCacheInfo] = {}
        self._struct_properties: Dict[str, StructProperties] = {}
        self._symbols: Dict[str, int] = {}

        # Parse slabinfo if provided
        if slabinfo_text:
            self._parse_slabinfo(slabinfo_text)

        # Load BTF if available
        if btf_json_path and Path(btf_json_path).is_file():
            self._load_btf_json(btf_json_path)

    def _parse_slabinfo(self, text: str) -> None:
        """Parse /proc/slabinfo output."""
        for line in text.splitlines():
            if line.startswith("#") or line.startswith("slabinfo"):
                continue
            parts = line.split()
            if len(parts) >= 4:
                name = parts[0]
                try:
                    self._slab_caches[name] = SlabCacheInfo(
                        name=name,
                        object_size=int(parts[3]),
                        active_objects=int(parts[1]),
                        num_objects=int(parts[2]),
                        is_dedicated=not name.startswith("kmalloc-"),
                    )
                except (ValueError, IndexError):
                    continue

    def _load_btf_json(self, path: str) -> None:
        """Load struct layouts from a BTF JSON dump."""
        try:
            with open(path) as f:
                data = json.load(f)
            for struct_name, struct_data in data.items():
                if isinstance(struct_data, dict):
                    fields = []
                    for field_data in struct_data.get("fields", []):
                        sf = StructField(
                            name=field_data.get("name", ""),
                            offset=field_data.get("offset", 0),
                            size=field_data.get("size", 0),
                            type_name=field_data.get("type", ""),
                            is_pointer="*" in field_data.get("type", ""),
                            is_function_pointer=(
                                "(*)" in field_data.get("type", "") or
                                "func" in field_data.get("type", "").lower()
                            ),
                        )
                        fields.append(sf)

                    layout = StructLayout(
                        name=struct_name,
                        size=struct_data.get("size", 0),
                        fields=fields,
                        source="btf",
                    )
                    self._finalize_layout(layout)
                    self._struct_layouts[struct_name] = layout
        except Exception as e:
            console.print(f"  [yellow]BTF load failed: {e}[/]")

    def _finalize_layout(self, layout: StructLayout) -> None:
        """Compute derived properties for a struct layout."""
        layout.pointer_count = sum(1 for f in layout.fields if f.is_pointer)
        layout.has_function_pointers = any(
            f.is_function_pointer for f in layout.fields
        )
        layout.function_pointer_offsets = [
            f.offset for f in layout.fields if f.is_function_pointer
        ]
        layout.has_list_heads = any(
            f.is_list_head or "list_head" in f.type_name
            for f in layout.fields
        )
        # Also mark list_head fields
        for f in layout.fields:
            if "list_head" in f.type_name:
                f.is_list_head = True
            if "atomic" in f.type_name:
                f.is_atomic = True

    def get_struct_layout(self, struct_name: str) -> Optional[StructLayout]:
        """Get the layout of a kernel struct.

        Tries in order: cached → BTF → pahole → upstream source → None.
        """
        if struct_name in self._struct_layouts:
            return self._struct_layouts[struct_name]

        # Try pahole if vmlinux is available
        if self.vmlinux_path and Path(self.vmlinux_path).is_file():
            layout = self._run_pahole(struct_name)
            if layout:
                self._struct_layouts[struct_name] = layout
                return layout

        # Fallback: try upstream source extraction (no pahole/bpftool needed)
        layout = self._try_upstream_source(struct_name)
        if layout:
            self._struct_layouts[struct_name] = layout
            return layout

        return None

    def _try_upstream_source(self, struct_name: str) -> Optional[StructLayout]:
        """Fallback: extract struct layout from upstream kernel source."""
        try:
            from ..analysis.kernel_struct_extractor import lookup_struct
            kernel_ver = getattr(self, "_kernel_version", None) or "5.10"
            result = lookup_struct(
                struct_name, kernel_ver,
                vmlinux_path=self.vmlinux_path,
                prefer_btf=False,
            )
            if result and result.get("fields"):
                fields = []
                for f in result["fields"]:
                    fields.append(StructField(
                        name=f.get("name", ""),
                        type_name=f.get("type", ""),
                        offset=f.get("offset", 0),
                        size=f.get("size", 8),
                        is_function_pointer="(*" in f.get("type", ""),
                    ))
                return StructLayout(
                    name=struct_name,
                    size=result.get("size", 0),
                    fields=fields,
                    source="upstream_source",
                )
        except Exception:
            pass
        return None

    def _run_pahole(self, struct_name: str) -> Optional[StructLayout]:
        """Run pahole to extract struct layout from vmlinux DWARF info."""
        try:
            result = subprocess.run(
                ["pahole", "-C", struct_name, self.vmlinux_path],
                capture_output=True, text=True, timeout=30,
            )
            if result.returncode != 0 or not result.stdout.strip():
                return None
            return self._parse_pahole_output(struct_name, result.stdout)
        except FileNotFoundError:
            if not getattr(self, "_pahole_warned", False):
                console.print(
                    "  [dim]pahole not installed — using upstream "
                    "source fallback for struct analysis[/]"
                )
                self._pahole_warned = True
            return None
        except Exception:
            return None

    def _parse_pahole_output(
        self, struct_name: str, output: str
    ) -> Optional[StructLayout]:
        """Parse pahole output into a StructLayout.

        Example pahole output:
            struct binder_node {
                int                        debug_id;             /*     0     4 */
                ...
                /* size: 256, cachelines: 4, members: 20 */
            };
        """
        fields: List[StructField] = []
        total_size = 0

        # Match "/* size: NNN" at end
        size_match = re.search(r"/\*\s+size:\s+(\d+)", output)
        if size_match:
            total_size = int(size_match.group(1))

        # Parse field lines
        # Pattern: TYPE SPACES NAME; /* OFFSET SIZE */
        field_pattern = re.compile(
            r"^\s+(.+?)\s+(\w+)(?:\[(\d+)\])?;\s*/\*\s+(\d+)\s+(\d+)\s*\*/"
        )
        for line in output.splitlines():
            m = field_pattern.match(line)
            if m:
                type_name = m.group(1).strip()
                name = m.group(2)
                array_size = int(m.group(3)) if m.group(3) else 0
                offset = int(m.group(4))
                size = int(m.group(5))

                sf = StructField(
                    name=name,
                    offset=offset,
                    size=size,
                    type_name=type_name,
                    is_pointer="*" in type_name,
                    is_function_pointer=(
                        "(*)" in type_name or
                        (type_name.endswith("*") and
                         any(kw in name for kw in ("ops", "func", "callback",
                                                    "handler", "hook")))
                    ),
                    is_list_head="list_head" in type_name,
                    is_atomic="atomic" in type_name,
                )
                fields.append(sf)

        if not fields and total_size == 0:
            return None

        layout = StructLayout(
            name=struct_name,
            size=total_size,
            fields=fields,
            source="pahole",
        )
        self._finalize_layout(layout)
        return layout

    def get_slab_cache(self, struct_name: str) -> str:
        """Determine which slab cache a struct is allocated from.

        Checks:
        1. Dedicated cache in /proc/slabinfo (e.g., "binder_node")
        2. Known mapping from slab_oracle
        3. Computed from struct size → kmalloc-N
        """
        # Check dedicated cache
        if struct_name in self._slab_caches:
            return struct_name

        # Check well-known dedicated caches
        from .slab_oracle import SlabOracle
        oracle = SlabOracle()
        known_cache = oracle.get_cache_for_struct(struct_name)
        if known_cache:
            return known_cache

        # Compute from layout size
        layout = self.get_struct_layout(struct_name)
        if layout:
            return layout.kmalloc_cache()

        return "unknown"

    def get_struct_properties(self, struct_name: str) -> Optional[StructProperties]:
        """Get comprehensive properties of a struct for exploitation analysis."""
        if struct_name in self._struct_properties:
            return self._struct_properties[struct_name]

        layout = self.get_struct_layout(struct_name)
        if not layout:
            # Check if we have static knowledge
            if struct_name not in _USERSPACE_CONTROLLABLE:
                return None
            # Build minimal properties from static knowledge
            known = _USERSPACE_CONTROLLABLE[struct_name]
            props = StructProperties(
                name=struct_name,
                size=0,
                slab_cache=self.get_slab_cache(struct_name),
                controllable_from_userspace=known.get("controllable", False),
                allocation_syscalls=known.get("alloc_syscalls", []),
                free_syscalls=known.get("free_syscalls", []),
                lifetime=known.get("lifetime", ""),
            )
            self._struct_properties[struct_name] = props
            return props

        # Build from layout + static knowledge
        known = _USERSPACE_CONTROLLABLE.get(struct_name, {})
        props = StructProperties(
            name=struct_name,
            size=layout.size,
            slab_cache=self.get_slab_cache(struct_name),
            has_function_pointers=layout.has_function_pointers,
            function_pointer_offsets=layout.function_pointer_offsets,
            has_list_heads=layout.has_list_heads,
            controllable_from_userspace=known.get("controllable", False),
            allocation_syscalls=known.get("alloc_syscalls", []),
            free_syscalls=known.get("free_syscalls", []),
            lifetime=known.get("lifetime", ""),
            refcounted=any(
                "refcount" in f.name or "kref" in f.type_name
                for f in layout.fields
            ),
            has_spinlock=any(
                "spinlock" in f.type_name for f in layout.fields
            ),
            has_rcu=any(
                "rcu" in f.name or "rcu_head" in f.type_name
                for f in layout.fields
            ),
        )
        self._struct_properties[struct_name] = props
        return props

    def find_structs_in_cache(self, cache_name: str) -> List[StructProperties]:
        """Find all known structs that land in a given slab cache.

        This is the key function for finding substitute objects:
        if the exploit needs an object in kmalloc-256, this returns
        all structs whose size rounds up to 256.
        """
        results: List[StructProperties] = []

        # Parse cache size from name
        cache_size = 0
        m = re.match(r"kmalloc-(\d+)", cache_name)
        if m:
            cache_size = int(m.group(1))

        # Check all known userspace-controllable structs
        for struct_name in _USERSPACE_CONTROLLABLE:
            props = self.get_struct_properties(struct_name)
            if props:
                if props.slab_cache == cache_name:
                    results.append(props)
                elif cache_size > 0 and 0 < props.size <= cache_size:
                    # Check if it rounds up to this cache
                    actual_cache = 8
                    while actual_cache < props.size and actual_cache < 8192:
                        actual_cache *= 2
                    if actual_cache == cache_size:
                        results.append(props)

        # Check cached layouts
        for struct_name, layout in self._struct_layouts.items():
            if struct_name in _USERSPACE_CONTROLLABLE:
                continue  # Already checked
            if layout.kmalloc_cache() == cache_name:
                props = self.get_struct_properties(struct_name)
                if props:
                    results.append(props)

        return results

    def find_substitutes(
        self,
        target_struct: str,
        other_image: Optional[ImageStructAnalyzer] = None,
        min_score: float = 0.5,
    ) -> List[Tuple[StructProperties, float]]:
        """Find structs that can substitute for target_struct.

        If other_image is provided, searches its struct catalog.
        Otherwise, searches this image's known structs.

        Returns [(struct_properties, match_score)] sorted by score.
        Used when the original reclaim object isn't available on a
        different kernel image.
        """
        target_props = self.get_struct_properties(target_struct)
        if not target_props:
            return []

        search_image = other_image or self
        candidates: List[Tuple[StructProperties, float]] = []

        # Search all known structs
        for struct_name in list(_USERSPACE_CONTROLLABLE.keys()):
            if struct_name == target_struct:
                continue
            props = search_image.get_struct_properties(struct_name)
            if not props:
                continue
            score = target_props.matches_properties(props)
            if score >= min_score:
                candidates.append((props, score))

        # Also search cached layouts from the other image
        if other_image:
            for struct_name in other_image._struct_layouts:
                if struct_name == target_struct:
                    continue
                if struct_name in _USERSPACE_CONTROLLABLE:
                    continue  # Already checked
                props = other_image.get_struct_properties(struct_name)
                if props:
                    score = target_props.matches_properties(props)
                    if score >= min_score:
                        candidates.append((props, score))

        candidates.sort(key=lambda x: -x[1])
        return candidates

    def compare_with(
        self,
        other: ImageStructAnalyzer,
        struct_name: str,
    ) -> Dict[str, Any]:
        """Compare a struct's properties between two kernel images.

        Returns a diff showing what changed (size, offsets, fields,
        slab cache) between this image and another.
        """
        my_layout = self.get_struct_layout(struct_name)
        other_layout = other.get_struct_layout(struct_name)

        result: Dict[str, Any] = {
            "struct": struct_name,
            "image_a": self.image_label,
            "image_b": other.image_label,
            "available_a": my_layout is not None,
            "available_b": other_layout is not None,
        }

        if not my_layout or not other_layout:
            result["comparable"] = False
            return result

        result["comparable"] = True
        result["size_a"] = my_layout.size
        result["size_b"] = other_layout.size
        result["size_changed"] = my_layout.size != other_layout.size
        result["cache_a"] = my_layout.kmalloc_cache()
        result["cache_b"] = other_layout.kmalloc_cache()
        result["cache_changed"] = (
            my_layout.kmalloc_cache() != other_layout.kmalloc_cache()
        )

        # Field-level diff
        my_fields = {f.name: f for f in my_layout.fields}
        other_fields = {f.name: f for f in other_layout.fields}

        added = set(other_fields) - set(my_fields)
        removed = set(my_fields) - set(other_fields)
        common = set(my_fields) & set(other_fields)

        offset_changes = {}
        for fname in common:
            mf = my_fields[fname]
            of = other_fields[fname]
            if mf.offset != of.offset:
                offset_changes[fname] = {
                    "offset_a": mf.offset,
                    "offset_b": of.offset,
                    "delta": of.offset - mf.offset,
                }

        result["fields_added"] = list(added)
        result["fields_removed"] = list(removed)
        result["offset_changes"] = offset_changes
        result["func_ptr_offsets_a"] = my_layout.function_pointer_offsets
        result["func_ptr_offsets_b"] = other_layout.function_pointer_offsets

        return result

    def format_for_prompt(
        self,
        struct_names: Optional[List[str]] = None,
    ) -> str:
        """Format struct analysis results for LLM prompt injection."""
        parts = [f"=== Kernel Struct Analysis ({self.image_label}) ==="]

        names = struct_names or list(self._struct_layouts.keys())[:20]
        for name in names:
            layout = self.get_struct_layout(name)
            if layout:
                parts.append(f"\n{layout.format_for_prompt()}")

        # Slab cache summary
        if self._slab_caches:
            parts.append("\n--- Active Slab Caches ---")
            for cache in sorted(self._slab_caches.values(),
                                 key=lambda c: c.object_size)[:20]:
                parts.append(
                    f"  {cache.name}: obj_size={cache.object_size}, "
                    f"active={cache.active_objects}/{cache.num_objects}"
                    f"{' [DEDICATED]' if cache.is_dedicated else ''}"
                )

        return "\n".join(parts)

    def format_comparison_for_prompt(
        self,
        other: ImageStructAnalyzer,
        struct_names: List[str],
    ) -> str:
        """Format cross-image comparison for LLM prompt."""
        parts = [
            f"=== Cross-Image Struct Comparison ===",
            f"Image A: {self.image_label}",
            f"Image B: {other.image_label}",
        ]

        for name in struct_names:
            diff = self.compare_with(other, name)
            if not diff.get("comparable"):
                parts.append(f"\n{name}: NOT comparable "
                              f"(A={'present' if diff['available_a'] else 'MISSING'}, "
                              f"B={'present' if diff['available_b'] else 'MISSING'})")
                continue

            parts.append(f"\n{name}:")
            if diff["size_changed"]:
                parts.append(f"  SIZE CHANGED: {diff['size_a']} → {diff['size_b']}")
            if diff["cache_changed"]:
                parts.append(f"  CACHE CHANGED: {diff['cache_a']} → {diff['cache_b']}")
            if diff["fields_added"]:
                parts.append(f"  Fields added: {diff['fields_added']}")
            if diff["fields_removed"]:
                parts.append(f"  Fields removed: {diff['fields_removed']}")
            if diff["offset_changes"]:
                parts.append(f"  Offset changes: {len(diff['offset_changes'])}")
                for fname, ch in list(diff["offset_changes"].items())[:5]:
                    parts.append(
                        f"    {fname}: +{ch['offset_a']} → +{ch['offset_b']} "
                        f"(delta={ch['delta']:+d})"
                    )

        return "\n".join(parts)

    def format_substitutes_for_prompt(
        self,
        target_struct: str,
        other_image: Optional[ImageStructAnalyzer] = None,
    ) -> str:
        """Format substitute object recommendations for LLM prompt."""
        subs = self.find_substitutes(target_struct, other_image)
        if not subs:
            return (
                f"No substitute objects found for '{target_struct}'. "
                f"Manual analysis required."
            )

        target_props = self.get_struct_properties(target_struct)
        parts = [
            f"=== Substitute Objects for {target_struct} ===",
            f"Target: size={target_props.size if target_props else '?'}, "
            f"cache={target_props.slab_cache if target_props else '?'}",
            f"",
            f"Candidates (sorted by compatibility score):",
        ]

        for props, score in subs[:10]:
            parts.append(
                f"  {props.name} (score={score:.2f}): "
                f"size={props.size}, cache={props.slab_cache}, "
                f"func_ptrs={props.has_function_pointers}, "
                f"controllable={props.controllable_from_userspace}, "
                f"alloc={props.allocation_syscalls}"
            )

        return "\n".join(parts)
