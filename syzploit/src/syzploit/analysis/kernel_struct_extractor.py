"""
analysis.kernel_struct_extractor — Extract struct definitions from kernel source.

Provides concrete struct definitions (field names, types, offsets) to prevent
the LLM from hallucinating struct fields.  Supports three modes:

1. **Upstream source parsing** — fetches kernel source files from
   googlesource.com / kernel.org and parses ``struct`` definitions
   with a regex-based C parser.
2. **BTF extraction** — when a vmlinux ELF with BTF data is available,
   uses ``bpftool btf dump`` for byte-accurate struct layouts.
3. **Template struct extraction** — parses typedef structs from the
   syzploit template library headers so the LLM knows the exact
   field names of helper types like ``task_struct_offsets_t``.

Results are cached per session to avoid redundant HTTP fetches.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ..core.log import console


# ── Data models ───────────────────────────────────────────────────────

@dataclass
class StructField:
    """A single field within a struct definition."""
    name: str
    type_str: str           # raw C type string, e.g. "struct list_head"
    offset_bytes: int = -1  # byte offset from start (-1 if unknown)
    bitfield_size: int = 0  # non-zero if this is a bitfield
    is_pointer: bool = False
    array_size: str = ""    # e.g. "16" or "COMM_LEN"

    def format_c(self) -> str:
        """Format as a C struct field declaration."""
        arr = f"[{self.array_size}]" if self.array_size else ""
        ptr = " *" if self.is_pointer else " "
        bf = f" : {self.bitfield_size}" if self.bitfield_size else ""
        return f"    {self.type_str}{ptr}{self.name}{arr}{bf};"


@dataclass
class StructDefinition:
    """A parsed C struct definition."""
    name: str               # e.g. "dst_entry", "task_struct"
    fields: List[StructField] = field(default_factory=list)
    total_size: int = -1    # size in bytes (-1 if unknown)
    source_file: str = ""   # e.g. "include/net/dst.h"
    source_ref: str = ""    # e.g. "googlesource:android13-5.10-lts"
    source: str = "upstream"  # "upstream", "btf", "template"
    raw_code: str = ""      # original C source text

    @property
    def field_names(self) -> List[str]:
        return [f.name for f in self.fields]

    def format_c(self) -> str:
        """Format as a C struct definition."""
        lines = [f"struct {self.name} {{"]
        for f in self.fields:
            comment = ""
            if f.offset_bytes >= 0:
                comment = f"  /* offset {f.offset_bytes} */"
            lines.append(f"{f.format_c()}{comment}")
        lines.append("};")
        if self.total_size >= 0:
            lines.append(f"/* sizeof(struct {self.name}) = {self.total_size} */")
        return "\n".join(lines)

    def format_summary(self) -> str:
        """Format as a compact summary for LLM prompts."""
        header = f"struct {self.name}"
        if self.total_size >= 0:
            header += f" (size={self.total_size})"
        if self.source_file:
            header += f" from {self.source_file}"
        parts = [header + " {"]
        for f in self.fields:
            offset_str = f"@{f.offset_bytes}" if f.offset_bytes >= 0 else ""
            arr = f"[{f.array_size}]" if f.array_size else ""
            parts.append(f"    {f.type_str} {'*' if f.is_pointer else ''}{f.name}{arr}; {offset_str}")
        parts.append("};")
        return "\n".join(parts)


# ── Session cache ─────────────────────────────────────────────────────

_STRUCT_CACHE: Dict[str, StructDefinition] = {}


def _cache_key(struct_name: str, kernel_version: str = "", source: str = "") -> str:
    return f"{source}:{kernel_version}:{struct_name}"


# ── 1. Upstream source parsing ───────────────────────────────────────

def extract_struct_from_upstream(
    struct_name: str,
    kernel_version: str,
    *,
    extra_files: Optional[List[str]] = None,
) -> Optional[StructDefinition]:
    """Fetch kernel source from googlesource/kernel.org and parse a struct.

    Uses the existing ``kernel_source_fetcher`` infrastructure to fetch
    the files where the struct is defined, then parses the struct body.

    Args:
        struct_name: Struct name without ``struct`` prefix (e.g. "dst_entry")
        kernel_version: Kernel version string (e.g. "5.10.107-android13-...")
        extra_files: Additional source files to search in

    Returns:
        StructDefinition or None if not found.
    """
    ckey = _cache_key(struct_name, kernel_version, "upstream")
    if ckey in _STRUCT_CACHE:
        return _STRUCT_CACHE[ckey]

    from .kernel_source_fetcher import (
        _STRUCT_SOURCE_FILES,
        parse_kernel_version,
        resolve_and_fetch,
    )

    version = parse_kernel_version(kernel_version)

    # Determine which files to search
    files_to_try: List[str] = []
    if struct_name in _STRUCT_SOURCE_FILES:
        for f in _STRUCT_SOURCE_FILES[struct_name]:
            if f.endswith(".h"):
                files_to_try.append(f)
        # .c files as fallback
        for f in _STRUCT_SOURCE_FILES[struct_name]:
            if f.endswith(".c") and f not in files_to_try:
                files_to_try.append(f)

    # Try common header paths if struct not in mapping
    if not files_to_try:
        files_to_try = [
            f"include/linux/{struct_name}.h",
            f"include/net/{struct_name}.h",
            f"include/linux/sched.h",     # task_struct
            f"include/linux/fs.h",        # file, inode
            f"include/linux/cred.h",      # cred
            f"include/linux/mm_types.h",  # mm_struct, vm_area_struct
        ]

    if extra_files:
        for f in extra_files:
            if f not in files_to_try:
                files_to_try.append(f)

    # Try each file
    for filepath in files_to_try[:10]:  # Limit to avoid excessive fetching
        content, ref = resolve_and_fetch(
            filepath, version, prefer_android=version.is_android
        )
        if not content:
            continue

        result = parse_struct_from_source(content, struct_name)
        if result:
            result.source_file = filepath
            result.source_ref = ref
            result.source = "upstream"
            _STRUCT_CACHE[ckey] = result
            console.print(
                f"  [dim]Extracted struct {struct_name} from "
                f"{filepath} ({ref}): {len(result.fields)} fields[/]"
            )
            return result

    return None


def extract_multiple_structs_from_upstream(
    struct_names: List[str],
    kernel_version: str,
) -> Dict[str, StructDefinition]:
    """Extract multiple struct definitions from upstream kernel source.

    Returns a dict mapping struct_name → StructDefinition for all found structs.
    """
    results: Dict[str, StructDefinition] = {}
    for name in struct_names:
        defn = extract_struct_from_upstream(name, kernel_version)
        if defn:
            results[name] = defn
    return results


# ── C struct parser ───────────────────────────────────────────────────

def parse_struct_from_source(
    source: str,
    struct_name: str,
) -> Optional[StructDefinition]:
    """Parse a struct definition from C source text.

    Handles:
    - Direct struct definitions: ``struct name { ... };``
    - Nested structs/unions (at one level)
    - Pointer fields, array fields, bitfields
    - Multi-line field declarations
    - #ifdef blocks (kept as-is)

    Does NOT handle:
    - Deeply nested anonymous structs (flattens to top level)
    - Complex macro-generated fields
    """
    # Find struct definition: struct name {
    pattern = re.compile(
        rf'struct\s+{re.escape(struct_name)}\s*\{{',
        re.MULTILINE,
    )
    match = pattern.search(source)
    if not match:
        return None

    # Extract the struct body by brace matching
    start = match.start()
    body_start = match.end()  # right after the opening {
    depth = 1
    pos = body_start
    while pos < len(source) and depth > 0:
        ch = source[pos]
        if ch == '{':
            depth += 1
        elif ch == '}':
            depth -= 1
        pos += 1

    if depth != 0:
        return None

    # Find the closing };
    # pos is right after the closing }
    # Check for extra text before ;
    end_pos = pos
    semicolon = source.find(';', end_pos - 1, end_pos + 20)
    if semicolon >= 0:
        end_pos = semicolon + 1

    body = source[body_start:pos - 1]  # content between { and }
    raw_code = source[start:end_pos]

    # Parse fields from body
    fields = _parse_struct_fields(body)

    defn = StructDefinition(
        name=struct_name,
        fields=fields,
        raw_code=raw_code,
    )

    return defn


def _parse_struct_fields(body: str) -> List[StructField]:
    """Parse field declarations from a struct body.

    Handles multi-line declarations, nested structs/unions,
    pointers, arrays, and bitfields.
    """
    fields: List[StructField] = []

    # Remove C comments to avoid false matches
    body = re.sub(r'/\*.*?\*/', '', body, flags=re.DOTALL)
    body = re.sub(r'//[^\n]*', '', body)

    # Remove preprocessor lines (#ifdef, #endif, etc.) but keep them noted
    body = re.sub(r'^\s*#\s*(?:if|ifdef|ifndef|else|elif|endif|define|undef)\b[^\n]*',
                  '', body, flags=re.MULTILINE)

    # Handle nested anonymous structs/unions
    # Replace: struct { ... } field_name; → extracted fields
    # Replace: union { ... } field_name; → single field entry
    anon_pattern = re.compile(
        r'(?:struct|union)\s*\{([^{}]*)\}\s*(\w+)?\s*;',
        re.DOTALL,
    )
    while anon_pattern.search(body):
        m = anon_pattern.search(body)
        if not m:
            break
        inner = m.group(1)
        name = m.group(2)
        if name:
            # Named nested struct → treat as a single field
            fields.append(StructField(
                name=name,
                type_str="struct/union",
            ))
        else:
            # Anonymous → flatten fields
            inner_fields = _parse_struct_fields(inner)
            fields.extend(inner_fields)
        body = body[:m.start()] + body[m.end():]

    # Now parse remaining field declarations
    # Pattern: type [*] name [: bitfield] [array] ;
    #
    # Field declarations in kernel structs can be complex:
    #   struct list_head tasks;
    #   unsigned long flags;
    #   void *stack;
    #   int (*fn)(struct task_struct *);  (function pointers)
    #   u64 field : 3;                   (bitfields)
    #   char comm[TASK_COMM_LEN];        (arrays)

    # Split on semicolons and process each declaration
    declarations = re.split(r';', body)
    for decl in declarations:
        decl = decl.strip()
        if not decl:
            continue

        # Skip function pointer declarations for now
        if '(' in decl and ')' in decl and '*' in decl:
            # Try to extract the name from function pointer:
            # return_type (*name)(params)
            fp_m = re.search(r'\(\s*\*\s*(\w+)\s*\)', decl)
            if fp_m:
                fields.append(StructField(
                    name=fp_m.group(1),
                    type_str="function_pointer",
                    is_pointer=True,
                ))
            continue

        # Handle bitfields: type name : bits
        bf_m = re.match(r'(.+?)\s+(\w+)\s*:\s*(\d+)\s*$', decl.strip())
        if bf_m:
            fields.append(StructField(
                name=bf_m.group(2),
                type_str=bf_m.group(1).strip(),
                bitfield_size=int(bf_m.group(3)),
            ))
            continue

        # Handle arrays: type name[size]
        arr_m = re.match(r'(.+?)\s+(\w+)\s*\[([^\]]*)\]\s*$', decl.strip())
        if arr_m:
            type_str = arr_m.group(1).strip()
            is_ptr = '*' in type_str
            if is_ptr:
                type_str = type_str.replace('*', '').strip()
            fields.append(StructField(
                name=arr_m.group(2),
                type_str=type_str,
                is_pointer=is_ptr,
                array_size=arr_m.group(3).strip(),
            ))
            continue

        # Handle plain fields: type [*] name
        # Match the last word as the field name
        plain_m = re.match(r'(.+?)\s+\*?\s*(\w+)\s*$', decl.strip())
        if plain_m:
            type_str = plain_m.group(1).strip()
            name = plain_m.group(2)
            is_ptr = '*' in decl  # check full decl for pointer
            if is_ptr:
                type_str = type_str.replace('*', '').strip()
            fields.append(StructField(
                name=name,
                type_str=type_str,
                is_pointer=is_ptr,
            ))

    return fields


# ── 2. BTF extraction ────────────────────────────────────────────────

def extract_struct_from_btf(
    struct_name: str,
    vmlinux_path: str,
) -> Optional[StructDefinition]:
    """Extract a struct definition from a vmlinux ELF using BTF data.

    Requires ``bpftool`` to be installed. Falls back gracefully if
    BTF data is not available.

    Args:
        struct_name: Struct name (e.g. "task_struct")
        vmlinux_path: Path to vmlinux ELF with BTF data

    Returns:
        StructDefinition with byte-accurate offsets, or None.
    """
    ckey = _cache_key(struct_name, vmlinux_path, "btf")
    if ckey in _STRUCT_CACHE:
        return _STRUCT_CACHE[ckey]

    if not Path(vmlinux_path).exists():
        return None

    try:
        # Run bpftool to dump BTF as JSON
        raw = subprocess.check_output(
            ['bpftool', 'btf', 'dump', '--json', 'file', vmlinux_path],
            timeout=60,
            stderr=subprocess.DEVNULL,
        )
        btf_data = json.loads(raw)
    except (subprocess.SubprocessError, json.JSONDecodeError, FileNotFoundError):
        console.print(
            f"  [dim]BTF extraction failed for {struct_name} "
            f"(bpftool not available or no BTF in vmlinux)[/]"
        )
        return None

    # Build a type map from BTF JSON
    type_map: Dict[int, Dict[str, Any]] = {}
    for t in btf_data.get('types', []):
        type_map[t.get('id', 0)] = t

    # Find the target struct
    target = None
    for t in btf_data.get('types', []):
        if t.get('kind') == 'STRUCT' and t.get('name') == struct_name:
            target = t
            break

    if not target:
        return None

    # Parse fields
    fields: List[StructField] = []
    for member in target.get('members', []):
        m_name = member.get('name', '(anon)')
        m_type_id = member.get('type_id', 0)
        m_bits_offset = member.get('bits_offset', 0)
        m_bitfield_size = member.get('bitfield_size', 0)

        # Resolve type name
        type_str = _resolve_btf_type_name(m_type_id, type_map)
        is_ptr = _is_btf_ptr(m_type_id, type_map)

        fields.append(StructField(
            name=m_name,
            type_str=type_str,
            offset_bytes=m_bits_offset // 8,
            bitfield_size=m_bitfield_size,
            is_pointer=is_ptr,
        ))

    defn = StructDefinition(
        name=struct_name,
        fields=fields,
        total_size=target.get('size', -1),
        source="btf",
    )
    _STRUCT_CACHE[ckey] = defn

    console.print(
        f"  [dim]Extracted struct {struct_name} from BTF: "
        f"{len(fields)} fields, size={defn.total_size}[/]"
    )

    return defn


def _resolve_btf_type_name(type_id: int, type_map: Dict[int, Dict]) -> str:
    """Resolve a BTF type ID to a human-readable type name."""
    visited: set[int] = set()
    ptr_depth = 0
    const = False

    while type_id in type_map and type_id not in visited:
        visited.add(type_id)
        t = type_map[type_id]
        kind = t.get('kind', '')

        if kind == 'PTR':
            ptr_depth += 1
            type_id = t.get('type_id', 0)
        elif kind == 'CONST':
            const = True
            type_id = t.get('type_id', 0)
        elif kind == 'VOLATILE':
            type_id = t.get('type_id', 0)
        elif kind == 'TYPEDEF':
            # Return the typedef name
            name = t.get('name', '')
            if name:
                prefix = "const " if const else ""
                suffix = " " + "*" * ptr_depth if ptr_depth else ""
                return f"{prefix}{name}{suffix}"
            type_id = t.get('type_id', 0)
        elif kind == 'STRUCT':
            name = t.get('name', '(anonymous)')
            prefix = "const " if const else ""
            suffix = " " + "*" * ptr_depth if ptr_depth else ""
            return f"{prefix}struct {name}{suffix}"
        elif kind == 'UNION':
            name = t.get('name', '(anonymous)')
            prefix = "const " if const else ""
            suffix = " " + "*" * ptr_depth if ptr_depth else ""
            return f"{prefix}union {name}{suffix}"
        elif kind == 'ENUM':
            name = t.get('name', '(anonymous)')
            return f"enum {name}"
        elif kind == 'INT':
            name = t.get('name', 'int')
            prefix = "const " if const else ""
            suffix = " " + "*" * ptr_depth if ptr_depth else ""
            return f"{prefix}{name}{suffix}"
        elif kind == 'ARRAY':
            elem_type = _resolve_btf_type_name(t.get('type_id', 0), type_map)
            nr_elems = t.get('nr_elems', 0)
            return f"{elem_type}[{nr_elems}]"
        elif kind == 'FUNC_PROTO':
            return f"function_pointer{'*' * ptr_depth}"
        elif kind == 'FWD':
            name = t.get('name', '')
            return f"struct {name}" if name else "void"
        elif kind == 'VOID':
            suffix = " " + "*" * ptr_depth if ptr_depth else ""
            return f"void{suffix}"
        else:
            break

    return "unknown"


def _is_btf_ptr(type_id: int, type_map: Dict[int, Dict]) -> bool:
    """Check if a BTF type is (transitively) a pointer."""
    visited: set[int] = set()
    while type_id in type_map and type_id not in visited:
        visited.add(type_id)
        t = type_map[type_id]
        kind = t.get('kind', '')
        if kind == 'PTR':
            return True
        elif kind in ('CONST', 'VOLATILE', 'TYPEDEF'):
            type_id = t.get('type_id', 0)
        else:
            break
    return False


# ── 3. Template struct extraction ─────────────────────────────────────

def extract_template_structs() -> Dict[str, StructDefinition]:
    """Parse all typedef struct definitions from template library headers.

    Returns a dict mapping type name (e.g. "task_struct_offsets_t")
    to its StructDefinition.
    """
    ckey = _cache_key("__all__", "", "templates")
    if ckey in _STRUCT_CACHE:
        # Return all cached template structs
        return {
            k.split(":")[-1]: v
            for k, v in _STRUCT_CACHE.items()
            if k.startswith("templates::")
        }

    # Find template directory
    templates_dir = Path(__file__).parent.parent / "exploit" / "templates"
    if not templates_dir.is_dir():
        return {}

    results: Dict[str, StructDefinition] = {}

    # Walk all .h files
    for h_path in templates_dir.rglob("*.h"):
        try:
            content = h_path.read_text(errors="replace")
        except OSError:
            continue

        # Parse typedef struct { ... } name; patterns
        for m in re.finditer(
            r'typedef\s+struct\s*(?:\w+\s*)?\{([^}]*)\}\s*(\w+)\s*;',
            content, re.DOTALL,
        ):
            body = m.group(1)
            tname = m.group(2)
            fields = _parse_typedef_fields(body)
            if fields:
                rel_path = str(h_path.relative_to(templates_dir))
                defn = StructDefinition(
                    name=tname,
                    fields=fields,
                    source_file=f"templates/{rel_path}",
                    source="template",
                )
                results[tname] = defn
                _STRUCT_CACHE[_cache_key(tname, "", "templates")] = defn

        # Also parse plain struct definitions (struct name { ... };)
        for m in re.finditer(
            r'struct\s+(\w+)\s*\{([^}]*)\}\s*;',
            content, re.DOTALL,
        ):
            sname = m.group(1)
            body = m.group(2)
            # Skip if name ends with _s (these are wrapped in typedef)
            if sname.endswith('_s'):
                continue
            fields = _parse_typedef_fields(body)
            if fields:
                rel_path = str(h_path.relative_to(templates_dir))
                defn = StructDefinition(
                    name=sname,
                    fields=fields,
                    source_file=f"templates/{rel_path}",
                    source="template",
                )
                results[sname] = defn
                _STRUCT_CACHE[_cache_key(sname, "", "templates")] = defn

    # Mark that we've loaded all templates
    _STRUCT_CACHE[ckey] = StructDefinition(name="__all__")

    return results


def _parse_typedef_fields(body: str) -> List[StructField]:
    """Parse fields from a typedef struct body text."""
    fields: List[StructField] = []

    # Remove comments
    body = re.sub(r'/\*.*?\*/', '', body, flags=re.DOTALL)
    body = re.sub(r'//[^\n]*', '', body)

    for m in re.finditer(
        r'(?:^|\n)\s*([\w\s*]+?)\s+\*?\s*(\w+)\s*(?:\[([^\]]*)\])?\s*;',
        body,
    ):
        type_str = m.group(1).strip()
        name = m.group(2)
        arr = m.group(3) or ""
        is_ptr = '*' in type_str or '*' in m.group(0)
        type_str = type_str.replace('*', '').strip()

        fields.append(StructField(
            name=name,
            type_str=type_str,
            is_pointer=is_ptr,
            array_size=arr,
        ))

    return fields


# ── 4. High-level API ────────────────────────────────────────────────

def lookup_struct(
    struct_name: str,
    kernel_version: str = "",
    vmlinux_path: str = "",
    prefer_btf: bool = True,
) -> Optional[StructDefinition]:
    """Look up a struct definition, trying BTF first, then upstream source.

    This is the main entry point for callers who just want a struct
    definition without caring about the source.

    Args:
        struct_name: Struct name (e.g. "dst_entry", "task_struct")
        kernel_version: Kernel version string (for upstream fetching)
        vmlinux_path: Path to vmlinux (for BTF extraction)
        prefer_btf: If True and vmlinux is available, try BTF first

    Returns:
        StructDefinition or None.
    """
    # Check template structs first (for our own helper types)
    template_structs = extract_template_structs()
    if struct_name in template_structs:
        return template_structs[struct_name]

    # Also check with "struct " prefix stripped + "_t" suffix
    for tname, tdefn in template_structs.items():
        if tname.replace("_t", "") == struct_name:
            return tdefn

    # Try BTF if vmlinux is available
    if prefer_btf and vmlinux_path:
        btf_result = extract_struct_from_btf(struct_name, vmlinux_path)
        if btf_result:
            return btf_result

    # Try upstream source
    if kernel_version:
        return extract_struct_from_upstream(struct_name, kernel_version)

    return None


def lookup_multiple_structs(
    struct_names: List[str],
    kernel_version: str = "",
    vmlinux_path: str = "",
) -> Dict[str, StructDefinition]:
    """Look up multiple struct definitions.

    Returns a dict mapping struct_name → StructDefinition for found structs.
    """
    results: Dict[str, StructDefinition] = {}
    for name in struct_names:
        defn = lookup_struct(name, kernel_version, vmlinux_path)
        if defn:
            results[name] = defn
    return results


# ── 5. Prompt formatting ─────────────────────────────────────────────

def format_struct_definitions_for_prompt(
    struct_defs: Dict[str, StructDefinition],
    *,
    max_chars: int = 8000,
    include_offsets: bool = True,
) -> str:
    """Format struct definitions as a prompt section for LLM injection.

    Separates template structs (which the LLM must use exactly) from
    kernel structs (which provide context).

    Args:
        struct_defs: Dict of struct_name → StructDefinition
        max_chars: Maximum total characters
        include_offsets: Include byte offsets in output

    Returns:
        Formatted string ready for prompt injection.
    """
    if not struct_defs:
        return ""

    template_parts: List[str] = []
    kernel_parts: List[str] = []

    for name, defn in struct_defs.items():
        if defn.source == "template":
            template_parts.append(
                f"/* TEMPLATE STRUCT — use these EXACT field names, "
                f"do NOT invent others */\n"
                f"{defn.format_summary()}"
            )
        else:
            kernel_parts.append(defn.format_summary())

    sections: List[str] = []

    if template_parts:
        sections.append(
            "═══ TEMPLATE LIBRARY STRUCT DEFINITIONS (SACRED — use exact field names) ═══\n"
            + "\n\n".join(template_parts)
        )

    if kernel_parts:
        sections.append(
            "═══ KERNEL STRUCT DEFINITIONS (from source/BTF) ═══\n"
            + "\n\n".join(kernel_parts)
        )

    result = "\n\n".join(sections)

    # Truncate if too long
    if len(result) > max_chars:
        result = result[:max_chars] + "\n/* ... truncated ... */"

    return result


def auto_collect_struct_definitions(
    *,
    affected_structs: Optional[List[str]] = None,
    kernel_version: str = "",
    vmlinux_path: str = "",
    include_template_structs: bool = True,
    include_kernel_structs: bool = True,
) -> Dict[str, StructDefinition]:
    """Automatically collect struct definitions for exploit generation.

    Collects:
    1. All template library structs (if include_template_structs)
    2. Kernel struct definitions for affected_structs (if include_kernel_structs)

    This is the primary function called by the exploit pipeline to
    gather struct context before code generation.
    """
    results: Dict[str, StructDefinition] = {}

    if include_template_structs:
        results.update(extract_template_structs())

    if include_kernel_structs and affected_structs:
        for struct_name in affected_structs:
            if struct_name in results:
                continue
            defn = lookup_struct(
                struct_name,
                kernel_version=kernel_version,
                vmlinux_path=vmlinux_path,
            )
            if defn:
                results[struct_name] = defn

    return results
