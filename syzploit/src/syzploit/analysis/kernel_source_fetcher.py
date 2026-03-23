"""
analysis.kernel_source_fetcher — Fetch upstream kernel source by version.

Resolves the closest matching upstream kernel tag for a running kernel's
version string and fetches individual source files from:

- android.googlesource.com  (android-* branches / tags)
- git.kernel.org            (mainline & stable tags like v5.10.107)

No local git checkout is required — files are fetched over HTTP and
cached in-memory per session.

Also provides source-level slab cache analysis: searches fetched files
for ``kmem_cache_create()``, ``KMEM_CACHE()``, ``kmalloc()`` and
related allocation calls to identify which slab cache a struct ends up
in.
"""

from __future__ import annotations

import base64
import re
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ..core.log import console


# ── Version resolution ────────────────────────────────────────────────

# Maps from "kernel subsystem/struct file" to known source paths.
_STRUCT_SOURCE_FILES: Dict[str, List[str]] = {
    # Networking
    "dst_entry": [
        "include/net/dst.h", "net/core/dst.c",
        "net/ipv6/route.c", "net/ipv4/route.c",  # cache creation lives here
    ],
    "rt6_info": [
        "include/net/ip6_route.h", "net/ipv6/route.c",
        "include/net/dst.h", "net/core/dst.c",
    ],
    "rtable": [
        "include/net/route.h", "net/ipv4/route.c",
        "include/net/dst.h", "net/core/dst.c",
    ],
    "sk_buff": ["include/linux/skbuff.h", "net/core/skbuff.c"],
    "sock": ["include/net/sock.h", "net/core/sock.c"],
    "inet_sock": ["include/net/inet_sock.h"],
    "tcp_sock": ["include/net/tcp.h", "net/ipv4/tcp.c"],
    "ipv6_pinfo": ["include/linux/ipv6.h"],
    "fib6_info": ["include/net/ip6_fib.h", "net/ipv6/ip6_fib.c"],
    "rt6_info": ["include/net/ip6_route.h", "net/ipv6/route.c"],
    "nf_conn": ["include/net/netfilter/nf_conntrack.h", "net/netfilter/nf_conntrack_core.c"],
    "nft_rule_dp": ["include/net/netfilter/nf_tables.h", "net/netfilter/nf_tables_core.c"],
    # File system
    "file": ["include/linux/fs.h", "fs/file_table.c"],
    "inode": ["include/linux/fs.h", "fs/inode.c"],
    "dentry": ["include/linux/dcache.h", "fs/dcache.c"],
    "pipe_inode_info": ["include/linux/pipe_fs_i.h", "fs/pipe.c"],
    "pipe_buffer": ["include/linux/pipe_fs_i.h"],
    # io_uring
    "io_kiocb": ["include/linux/io_uring_types.h", "io_uring/io_uring.c", "fs/io_uring.c"],
    # Memory / process
    "task_struct": ["include/linux/sched.h", "kernel/fork.c"],
    "cred": ["include/linux/cred.h", "kernel/cred.c"],
    "mm_struct": ["include/linux/mm_types.h", "kernel/fork.c"],
    "vm_area_struct": ["include/linux/mm_types.h", "kernel/fork.c"],
    # IPC / Binder
    "binder_node": ["drivers/android/binder.c", "drivers/android/binder_internal.h"],
    "binder_ref": ["drivers/android/binder.c", "drivers/android/binder_internal.h"],
    "binder_transaction": ["drivers/android/binder.c", "drivers/android/binder_internal.h"],
    "binder_buffer": ["drivers/android/binder_alloc.h", "drivers/android/binder_alloc.c"],
    "binder_proc": ["drivers/android/binder_internal.h", "drivers/android/binder.c"],
    # msg_msg
    "msg_msg": ["include/linux/msg.h", "ipc/msgutil.c"],
    # tty
    "tty_struct": ["include/linux/tty.h", "drivers/tty/tty_io.c"],
    # epoll
    "epitem": ["fs/eventpoll.c"],
    # seq_file
    "seq_operations": ["include/linux/seq_file.h"],
    "seq_file": ["include/linux/seq_file.h", "fs/seq_file.c"],
    # Timer
    "timerfd_ctx": ["fs/timerfd.c"],
}

# Structs that are embedded in larger "container" structs.
# E.g. dst_entry is embedded in rt6_info / rtable, and the cache
# is created for the container, not the embedded struct directly.
_STRUCT_CONTAINERS: Dict[str, List[str]] = {
    "dst_entry": ["rt6_info", "rtable", "dst_metrics_default"],
    "sock": ["inet_sock", "tcp_sock", "udp_sock"],
    "inet_sock": ["tcp_sock", "udp_sock"],
}


@dataclass
class KernelVersionInfo:
    """Parsed kernel version components."""

    raw: str = ""
    major: int = 0
    minor: int = 0
    patch: int = 0
    android_release: str = ""  # e.g. "android13"
    android_sub: str = ""  # e.g. "4-00052"
    is_android: bool = False
    extra: str = ""  # anything after version triple

    @property
    def base_version(self) -> str:
        """e.g. '5.10.107'"""
        return f"{self.major}.{self.minor}.{self.patch}"

    @property
    def mainline_tag(self) -> str:
        """Git tag for mainline/stable, e.g. 'v5.10.107'"""
        return f"v{self.base_version}"

    @property
    def android_branch_prefix(self) -> str:
        """e.g. 'android13-5.10'"""
        if self.android_release:
            return f"{self.android_release}-{self.major}.{self.minor}"
        return f"android-{self.major}.{self.minor}"


def parse_kernel_version(version_str: str) -> KernelVersionInfo:
    """Parse a kernel version string like '5.10.107-android13-4-00052-...'"""
    info = KernelVersionInfo(raw=version_str)

    # Strip trailing junk after whitespace
    version_str = version_str.strip().split()[0] if version_str else ""

    # Match: major.minor.patch[-extra]
    m = re.match(r"(\d+)\.(\d+)\.(\d+)(.*)", version_str)
    if not m:
        # Try major.minor only
        m = re.match(r"(\d+)\.(\d+)(.*)", version_str)
        if m:
            info.major = int(m.group(1))
            info.minor = int(m.group(2))
            info.extra = m.group(3)
        return info

    info.major = int(m.group(1))
    info.minor = int(m.group(2))
    info.patch = int(m.group(3))
    extra = m.group(4)
    info.extra = extra

    # Check if it's an Android kernel
    android_m = re.search(r"-?(android\d+)-?(.+)?", extra)
    if android_m:
        info.is_android = True
        info.android_release = android_m.group(1)
        info.android_sub = android_m.group(2) or ""
    elif "android" in version_str.lower() or "maybe-dirty" in extra:
        # Heuristic: Cuttlefish kernels often don't carry android tag.
        # Guess the android release from the kernel version:
        #   5.10.x → android13 (most common for Cuttlefish)
        #   5.15.x → android14
        #   6.1.x  → android14/15
        info.is_android = True
        _ver_to_release = {
            (5, 4):  "android12",
            (5, 10): "android13",
            (5, 15): "android14",
            (6, 1):  "android14",
            (6, 6):  "android15",
        }
        info.android_release = _ver_to_release.get(
            (info.major, info.minor), "android13"
        )

    return info


# ── HTTP Fetchers ─────────────────────────────────────────────────────

_FILE_CACHE: Dict[str, Optional[str]] = {}


def _fetch_with_retry(
    url: str,
    *,
    decode_base64: bool = False,
    timeout: int = 10,
    max_retries: int = 2,
) -> Optional[str]:
    """HTTP GET with retry + backoff.  Returns body text or None."""
    if url in _FILE_CACHE:
        return _FILE_CACHE[url]

    headers = {"User-Agent": "syzploit/1.0 (+kernel-source-fetcher)"}
    backoff = 0.5

    for attempt in range(max_retries):
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = resp.read()
                if decode_base64:
                    try:
                        text = base64.b64decode(data).decode(errors="replace")
                    except Exception:
                        text = data.decode(errors="replace")
                else:
                    text = data.decode(errors="replace")
                _FILE_CACHE[url] = text
                return text
        except Exception:
            if attempt < max_retries - 1:
                time.sleep(backoff)
                backoff *= 2

    _FILE_CACHE[url] = None
    return None


def fetch_file_from_googlesource(
    filepath: str,
    ref: str,
    *,
    repo: str = "kernel/common",
) -> Optional[str]:
    """Fetch a single file from android.googlesource.com.

    Args:
        filepath: Path relative to repo root, e.g. 'net/core/dst.c'
        ref: Branch or tag, e.g. 'android13-5.10-lts' or commit hash
        repo: Repository path, e.g. 'kernel/common'

    Returns:
        File content as text, or None on failure.
    """
    # googlesource returns base64 when ?format=TEXT
    url = (
        f"https://android.googlesource.com/{repo}"
        f"/+/{ref}/{filepath}?format=TEXT"
    )
    return _fetch_with_retry(url, decode_base64=True)


def fetch_file_from_kernel_org(
    filepath: str,
    tag: str,
    *,
    repo: str = "pub/scm/linux/kernel/git/stable/linux-stable.git",
) -> Optional[str]:
    """Fetch a single file from git.kernel.org via cgit plain view.

    Args:
        filepath: Path relative to repo root
        tag: Git tag like 'v5.10.107'
        repo: cgit repo path
    """
    url = (
        f"https://git.kernel.org/pub/scm/linux/kernel/git/stable/"
        f"linux-stable.git/plain/{filepath}?h={tag}"
    )
    return _fetch_with_retry(url, decode_base64=False)


def _resolve_android_refs(version: KernelVersionInfo) -> List[str]:
    """Generate candidate git refs to try on android.googlesource.com.

    Ordered from most-specific to least-specific.
    """
    refs: List[str] = []
    v = version

    # Exact version tag (rare but possible)
    if v.android_release:
        refs.append(f"{v.android_release}-{v.major}.{v.minor}-lts")
        refs.append(f"{v.android_release}-{v.major}.{v.minor}")

    # Common android branch patterns
    for release in ["android15", "android14", "android13", "android12"]:
        if v.android_release and release != v.android_release:
            continue
        refs.append(f"{release}-{v.major}.{v.minor}-lts")
        refs.append(f"{release}-{v.major}.{v.minor}")

    # Common-android branches (used for binder, Cuttlefish kernels)
    if v.android_release:
        refs.append(f"common-{v.android_release}-{v.major}.{v.minor}-lts")
        refs.append(f"common-{v.android_release}-{v.major}.{v.minor}")

    # Fall back to android-mainline or version-based branch
    refs.append(f"android-{v.major}.{v.minor}-stable")
    refs.append(f"android-{v.major}.{v.minor}")

    # Deduplicate while preserving order
    seen: set[str] = set()
    unique: List[str] = []
    for r in refs:
        if r not in seen:
            seen.add(r)
            unique.append(r)
    return unique


def _resolve_stable_tags(version: KernelVersionInfo) -> List[str]:
    """Generate candidate git tags to try on git.kernel.org stable tree."""
    tags: List[str] = []
    v = version

    # Exact match first
    tags.append(f"v{v.major}.{v.minor}.{v.patch}")

    # Try nearby patch levels (±5)
    for delta in range(1, 6):
        for sign in (+1, -1):
            p = v.patch + sign * delta
            if p >= 0:
                tags.append(f"v{v.major}.{v.minor}.{p}")

    # Base version (no patch)
    tags.append(f"v{v.major}.{v.minor}")

    return tags


def resolve_and_fetch(
    filepath: str,
    version: KernelVersionInfo,
    *,
    prefer_android: bool = True,
    _resolved_ref_cache: Dict[str, str] = {},
) -> Tuple[Optional[str], str]:
    """Try to fetch a source file for the given kernel version.

    Attempts android.googlesource.com first (if Android kernel), then
    falls back to git.kernel.org stable tree.  Caches the first
    successful ref so subsequent files are fetched much faster.

    Returns:
        (file_content, resolved_ref) or (None, "").
    """
    # If we previously found a working ref, try it first
    if _resolved_ref_cache:
        cached_source = _resolved_ref_cache.get("source", "")
        cached_ref = _resolved_ref_cache.get("ref", "")
        if cached_source == "googlesource" and cached_ref:
            content = fetch_file_from_googlesource(filepath, cached_ref)
            if content:
                return content, f"googlesource:{cached_ref}"
        elif cached_source == "kernel.org" and cached_ref:
            content = fetch_file_from_kernel_org(filepath, cached_ref)
            if content:
                return content, f"kernel.org:{cached_ref}"

    # Try Android sources first if it's an Android kernel
    if prefer_android and version.is_android:
        for ref in _resolve_android_refs(version):
            content = fetch_file_from_googlesource(filepath, ref)
            if content:
                _resolved_ref_cache["source"] = "googlesource"
                _resolved_ref_cache["ref"] = ref
                return content, f"googlesource:{ref}"

    # Try kernel.org stable tree (exact + nearby patches)
    for tag in _resolve_stable_tags(version)[:5]:
        content = fetch_file_from_kernel_org(filepath, tag)
        if content:
            _resolved_ref_cache["source"] = "kernel.org"
            _resolved_ref_cache["ref"] = tag
            return content, f"kernel.org:{tag}"

    # Last resort: try Android common even for non-android kernels
    if not (prefer_android and version.is_android):
        for ref in _resolve_android_refs(version)[:2]:
            content = fetch_file_from_googlesource(filepath, ref)
            if content:
                _resolved_ref_cache["source"] = "googlesource"
                _resolved_ref_cache["ref"] = ref
                return content, f"googlesource:{ref}"

    return None, ""


# ── Source-based slab analysis ────────────────────────────────────────


@dataclass
class SourceSlabInfo:
    """Slab allocation information found via source analysis."""

    struct_name: str = ""
    cache_name: str = ""        # e.g. "ip6_dst_cache", "filp"
    cache_var: str = ""         # variable name, e.g. "ip6_dst_ops.kmem_cachep"
    alloc_function: str = ""    # e.g. "dst_alloc", "kmem_cache_alloc"
    alloc_file: str = ""        # source file where alloc was found
    alloc_line: int = 0
    object_size: str = ""       # e.g. "sizeof(struct rt6_info)" or literal
    flags: str = ""             # SLAB_* flags
    source_ref: str = ""        # resolved git ref
    confidence: str = "low"     # low / medium / high
    evidence: List[str] = field(default_factory=list)


def _find_kmem_cache_create(
    source: str,
    struct_name: str,
) -> List[Dict[str, Any]]:
    """Search source text for kmem_cache_create() calls related to a struct.

    Looks for patterns like:
        kmem_cache_create("cache_name", sizeof(struct foo), ...)
        KMEM_CACHE(foo, ...)
    """
    results: List[Dict[str, Any]] = []

    # Pattern 1: kmem_cache_create("name", sizeof(struct X), ...)
    # The call may span multiple lines, so we search generously
    pattern1 = re.compile(
        r'kmem_cache_create\s*\(\s*"([^"]+)"\s*,\s*sizeof\s*\(\s*struct\s+(\w+)\s*\)',
        re.MULTILINE,
    )
    for m in pattern1.finditer(source):
        cache_name = m.group(1)
        alloc_struct = m.group(2)
        line_no = source[:m.start()].count("\n") + 1
        results.append({
            "cache_name": cache_name,
            "struct": alloc_struct,
            "type": "kmem_cache_create",
            "match": m.group(0),
            "line": line_no,
            "relevant": (
                alloc_struct == struct_name
                or struct_name in cache_name
            ),
        })

    # Pattern 2: kmem_cache_create("name", size, ...)  where size is a variable/expression
    pattern1b = re.compile(
        r'kmem_cache_create\s*\(\s*"([^"]+)"\s*,\s*([^,]+),',
        re.MULTILINE,
    )
    for m in pattern1b.finditer(source):
        cache_name = m.group(1)
        size_expr = m.group(2).strip()
        # Skip if already captured by pattern1
        if f"sizeof(struct" in size_expr:
            continue
        line_no = source[:m.start()].count("\n") + 1
        results.append({
            "cache_name": cache_name,
            "struct": "",
            "size_expr": size_expr,
            "type": "kmem_cache_create",
            "match": m.group(0),
            "line": line_no,
            "relevant": struct_name in cache_name,
        })

    # Pattern 3: KMEM_CACHE(struct_name, flags)
    pattern2 = re.compile(
        r'KMEM_CACHE\s*\(\s*(\w+)\s*,\s*([^)]*)\)',
        re.MULTILINE,
    )
    for m in pattern2.finditer(source):
        alloc_struct = m.group(1)
        flags = m.group(2).strip()
        line_no = source[:m.start()].count("\n") + 1
        results.append({
            "cache_name": alloc_struct,  # KMEM_CACHE uses struct name as cache name
            "struct": alloc_struct,
            "flags": flags,
            "type": "KMEM_CACHE",
            "match": m.group(0),
            "line": line_no,
            "relevant": alloc_struct == struct_name,
        })

    # Pattern 4: dst_alloc / dst_ops.kmem_cachep pattern (networking)
    # Many networking structs use dst_alloc(&ops, ...) where ops has
    # ops.kmem_cachep set to a specific cache
    pattern3 = re.compile(
        r'(\w+_ops)\s*\.\s*kmem_cachep\s*=\s*'
        r'kmem_cache_create\s*\(\s*"([^"]+)"',
        re.MULTILINE,
    )
    for m in pattern3.finditer(source):
        ops_var = m.group(1)
        cache_name = m.group(2)
        line_no = source[:m.start()].count("\n") + 1
        results.append({
            "cache_name": cache_name,
            "struct": "",
            "ops_var": ops_var,
            "type": "dst_ops.kmem_cachep",
            "match": m.group(0),
            "line": line_no,
            "relevant": struct_name.lower() in cache_name.lower(),
        })

    return results


def _find_kmalloc_patterns(
    source: str,
    struct_name: str,
) -> List[Dict[str, Any]]:
    """Search for kmalloc/kzalloc calls that allocate the target struct."""
    results: List[Dict[str, Any]] = []

    # kmalloc(sizeof(struct X), ...) or kzalloc(sizeof(struct X), ...)  
    pattern = re.compile(
        r'(k[mz]alloc|kvmalloc|__kmalloc)\s*\(\s*sizeof\s*\(\s*'
        r'(?:struct\s+)?(\w+)\s*\)',
        re.MULTILINE,
    )
    for m in pattern.finditer(source):
        alloc_fn = m.group(1)
        alloc_struct = m.group(2)
        line_no = source[:m.start()].count("\n") + 1
        if alloc_struct == struct_name:
            results.append({
                "alloc_function": alloc_fn,
                "struct": alloc_struct,
                "type": "kmalloc",
                "match": m.group(0),
                "line": line_no,
            })

    return results


def _find_cache_alloc_patterns(
    source: str,
    struct_name: str,
) -> List[Dict[str, Any]]:
    """Search for kmem_cache_alloc/zalloc calls referencing a cache variable."""
    results: List[Dict[str, Any]] = []

    # kmem_cache_alloc(cache_var, GFP_...)
    # Also look for the surrounding function to identify what struct it returns
    pattern = re.compile(
        r'(kmem_cache_[az]+alloc(?:_node)?)\s*\(\s*(\w+)',
        re.MULTILINE,
    )
    for m in pattern.finditer(source):
        alloc_fn = m.group(1)
        cache_var = m.group(2)
        line_no = source[:m.start()].count("\n") + 1
        results.append({
            "alloc_function": alloc_fn,
            "cache_var": cache_var,
            "type": "kmem_cache_alloc",
            "match": m.group(0),
            "line": line_no,
        })

    return results


def _estimate_kmalloc_cache(size_expr: str, source: str) -> str:
    """Estimate the kmalloc-N bucket for a given struct.

    Tries to find sizeof(struct X) from the source, then rounds up
    to the nearest power-of-2 kmalloc bucket.
    """
    # Try to find struct size from source text
    m = re.search(
        r'#define\s+\w*SIZE\w*\s+sizeof\s*\(\s*struct\s+\w+\s*\)\s*'
        r'/\*\s*(\d+)\s*\*/',
        source,
    )
    if m:
        try:
            size = int(m.group(1))
            return _size_to_kmalloc_bucket(size)
        except ValueError:
            pass
    return ""


def _size_to_kmalloc_bucket(size: int) -> str:
    """Map an object size to kmalloc-N bucket name."""
    buckets = [8, 16, 32, 64, 96, 128, 192, 256, 512, 1024, 2048, 4096, 8192]
    for b in buckets:
        if size <= b:
            if b == 1024:
                return "kmalloc-1k"
            elif b == 2048:
                return "kmalloc-2k"
            elif b == 4096:
                return "kmalloc-4k"
            elif b == 8192:
                return "kmalloc-8k"
            return f"kmalloc-{b}"
    return "kmalloc-8k"


def _find_assigned_cache_creates(
    source: str,
) -> Dict[str, str]:
    """Find all ``variable = kmem_cache_create("name", ...)`` assignments.

    Returns a mapping from variable/field expression to cache name.
    Handles patterns like:
        my_cache = kmem_cache_create("my_cache", ...)
        ops.kmem_cachep = kmem_cache_create("ip6_dst_cache", ...)
        foo->bar = kmem_cache_create("baz", ...)
    Also handles multi-line patterns where the assignment and create are
    on adjacent lines.
    """
    result: Dict[str, str] = {}

    # Single-line: var = kmem_cache_create("name", ...)
    pattern = re.compile(
        r'([\w.>-]+)\s*=\s*\n?\s*kmem_cache_create\s*\(\s*"([^"]+)"',
        re.MULTILINE,
    )
    for m in pattern.finditer(source):
        var = m.group(1).strip()
        cache_name = m.group(2)
        result[var] = cache_name

    return result


def analyze_slab_from_source(
    struct_name: str,
    version: KernelVersionInfo,
    *,
    extra_files: Optional[List[str]] = None,
    vulnerable_function: str = "",
    vulnerable_file: str = "",
) -> List[SourceSlabInfo]:
    """Fetch upstream source and analyze slab cache for a struct.

    Steps:
    1. Determine which source files to fetch based on struct name
       (including container structs, e.g. dst_entry -> rt6_info)
    2. Fetch them from the closest matching upstream ref
    3. Search for kmem_cache_create / KMEM_CACHE / kmalloc patterns
    4. Follow indirections (ops->kmem_cachep = kmem_cache_create(...))
    5. Return all slab allocation evidence found

    Args:
        struct_name: Kernel struct name (without 'struct ' prefix)
        version: Parsed kernel version
        extra_files: Additional source files to fetch and search
        vulnerable_function: If known, the vulnerable function name
        vulnerable_file: If known, the source file containing the vuln

    Returns:
        List of SourceSlabInfo with all allocation evidence.
    """
    results: List[SourceSlabInfo] = []

    # Determine which files to fetch  --  include container structs
    files_to_fetch: List[str] = []
    structs_to_search = [struct_name]

    # Add container structs (e.g. dst_entry -> rt6_info, rtable)
    if struct_name in _STRUCT_CONTAINERS:
        structs_to_search.extend(_STRUCT_CONTAINERS[struct_name])

    for sn in structs_to_search:
        if sn in _STRUCT_SOURCE_FILES:
            for f in _STRUCT_SOURCE_FILES[sn]:
                if f not in files_to_fetch:
                    files_to_fetch.append(f)

    if vulnerable_file:
        if vulnerable_file not in files_to_fetch:
            files_to_fetch.append(vulnerable_file)

    if extra_files:
        for f in extra_files:
            if f not in files_to_fetch:
                files_to_fetch.append(f)

    if not files_to_fetch:
        console.print(
            f"  [dim]No known source files for struct {struct_name} -- "
            f"trying common allocation patterns[/]"
        )
        _guess_source_files(struct_name, files_to_fetch)

    if not files_to_fetch:
        return results

    # Limit file count to avoid excessive fetching
    max_files = 8
    if len(files_to_fetch) > max_files:
        files_to_fetch = files_to_fetch[:max_files]

    console.print(
        f"  [dim]Fetching {len(files_to_fetch)} source files for "
        f"{struct_name} analysis (kernel {version.base_version})...[/]"
    )

    # Fetch each file and analyze
    fetched_sources: Dict[str, Tuple[str, str]] = {}  # filepath -> (content, ref)
    for fpath in files_to_fetch:
        content, ref = resolve_and_fetch(fpath, version, prefer_android=version.is_android)
        if content:
            fetched_sources[fpath] = (content, ref)
            console.print(f"    [dim]+ {fpath} ({ref})[/]")
        else:
            console.print(f"    [dim]x {fpath} (not found)[/]")

    if not fetched_sources:
        console.print(f"  [yellow]Could not fetch any source files[/]")
        return results

    # Collect all patterns across all fetched files
    all_cache_creates: List[Dict[str, Any]] = []
    all_kmallocs: List[Dict[str, Any]] = []
    all_cache_allocs: List[Dict[str, Any]] = []
    # Global map: variable -> cache name  (from assignments)
    global_var_to_cache: Dict[str, str] = {}

    for fpath, (content, ref) in fetched_sources.items():
        # Search for ALL struct names (target + containers)
        for sn in structs_to_search:
            creates = _find_kmem_cache_create(content, sn)
            for c in creates:
                c["file"] = fpath
                c["ref"] = ref
                c["search_struct"] = sn
            all_cache_creates.extend(creates)

            kmallocs = _find_kmalloc_patterns(content, sn)
            for k in kmallocs:
                k["file"] = fpath
                k["ref"] = ref
            all_kmallocs.extend(kmallocs)

        cache_allocs = _find_cache_alloc_patterns(content, struct_name)
        for ca in cache_allocs:
            ca["file"] = fpath
            ca["ref"] = ref
        all_cache_allocs.extend(cache_allocs)

        # Build variable -> cache name map
        assigned = _find_assigned_cache_creates(content)
        for var, cache_name in assigned.items():
            global_var_to_cache[var] = cache_name
            # Also store without prefix (e.g. "kmem_cachep" from "ops.kmem_cachep")
            if "." in var:
                field = var.split(".")[-1]
                global_var_to_cache[field] = cache_name
            if "->" in var:
                field = var.split("->")[-1]
                global_var_to_cache[field] = cache_name

    # ── Build results from findings ──────────────────────────────────

    # Priority 1: Direct kmem_cache_create for target or container struct
    relevant_creates = [c for c in all_cache_creates if c.get("relevant")]
    for c in relevant_creates:
        search_struct = c.get("search_struct", struct_name)
        is_container = search_struct != struct_name
        info = SourceSlabInfo(
            struct_name=struct_name,
            cache_name=c["cache_name"],
            alloc_function=c["type"],
            alloc_file=c["file"],
            alloc_line=c["line"],
            flags=c.get("flags", ""),
            source_ref=c["ref"],
            confidence="high",
            evidence=[
                f"Found {c['type']}(\"{c['cache_name']}\") in {c['file']}:{c['line']}",
                f"Match: {c['match']}",
            ],
        )
        if c.get("struct"):
            info.object_size = f"sizeof(struct {c['struct']})"
        if is_container:
            info.evidence.append(
                f"Via container struct {search_struct} (embeds {struct_name})"
            )
        results.append(info)

    # Priority 2: Follow ops->kmem_cachep indirection
    # If a cache_alloc uses ops->kmem_cachep and we know what that maps to
    if not results:
        for ca in all_cache_allocs:
            cache_var = ca["cache_var"]
            # Check direct variable match
            if cache_var in global_var_to_cache:
                cache_name = global_var_to_cache[cache_var]
                info = SourceSlabInfo(
                    struct_name=struct_name,
                    cache_name=cache_name,
                    cache_var=cache_var,
                    alloc_function=ca["alloc_function"],
                    alloc_file=ca["file"],
                    alloc_line=ca["line"],
                    source_ref=ca["ref"],
                    confidence="medium",
                    evidence=[
                        f"{ca['alloc_function']}({cache_var}) in {ca['file']}:{ca['line']}",
                        f"Variable {cache_var} maps to cache \"{cache_name}\"",
                    ],
                )
                results.append(info)
            else:
                # Check if cache_var is an indirection like ops->kmem_cachep
                # and see if any context mentions our struct  
                fpath = ca["file"]
                content = fetched_sources[fpath][0]
                lines = content.splitlines()
                start = max(0, ca["line"] - 30)
                end = min(len(lines), ca["line"] + 30)
                context_block = "\n".join(lines[start:end])
                for sn in structs_to_search:
                    if sn in context_block:
                        # Check the global map for any matching variable
                        for var, cn in global_var_to_cache.items():
                            if cache_var in var or var in cache_var:
                                info = SourceSlabInfo(
                                    struct_name=struct_name,
                                    cache_name=cn,
                                    cache_var=f"{cache_var} (via {var})",
                                    alloc_function=ca["alloc_function"],
                                    alloc_file=ca["file"],
                                    alloc_line=ca["line"],
                                    source_ref=ca["ref"],
                                    confidence="medium",
                                    evidence=[
                                        f"{ca['alloc_function']}({cache_var}) near "
                                        f"{sn} in {ca['file']}:{ca['line']}",
                                        f"Likely uses cache \"{cn}\" "
                                        f"(assigned to {var})",
                                    ],
                                )
                                results.append(info)
                                break
                        break

    # Priority 3: kmalloc for this struct -> kmalloc-N bucket
    if not results:
        for k in all_kmallocs:
            info = SourceSlabInfo(
                struct_name=struct_name,
                alloc_function=k["alloc_function"],
                alloc_file=k["file"],
                alloc_line=k["line"],
                object_size=f"sizeof(struct {k['struct']})",
                source_ref=k["ref"],
                confidence="medium",
                evidence=[
                    f"Found {k['alloc_function']}(sizeof(struct {k['struct']})) "
                    f"in {k['file']}:{k['line']}",
                ],
            )
            source_content = fetched_sources[k["file"]][0]
            bucket = _estimate_kmalloc_cache(struct_name, source_content)
            if bucket:
                info.cache_name = bucket
            results.append(info)

    # Priority 4: All cache_create in relevant files as low-confidence hints
    if not results and all_cache_creates:
        for c in all_cache_creates[:5]:
            info = SourceSlabInfo(
                struct_name=struct_name,
                cache_name=c["cache_name"],
                alloc_function=c["type"],
                alloc_file=c["file"],
                alloc_line=c["line"],
                source_ref=c["ref"],
                confidence="low",
                evidence=[
                    f"Found {c['type']}(\"{c['cache_name']}\") in {c['file']}:{c['line']} "
                    f"(not directly matched to {struct_name})",
                ],
            )
            results.append(info)

    return results


def _guess_source_files(struct_name: str, files: List[str]) -> None:
    """Heuristic: guess source file paths from struct name."""
    # Common patterns: struct foo_bar → foo_bar.c or foo/bar.c
    name = struct_name.lower()

    # Driver/subsystem guesses
    guesses = [
        f"include/linux/{name}.h",
        f"include/net/{name}.h",
    ]

    # Try splitting on underscore for subsystem
    parts = name.split("_")
    if len(parts) >= 2:
        guesses.append(f"include/linux/{parts[0]}.h")
        guesses.append(f"include/net/{parts[0]}.h")

    for g in guesses:
        if g not in files:
            files.append(g)


def fetch_function_source(
    function_name: str,
    version: KernelVersionInfo,
    *,
    known_file: str = "",
    struct_name: str = "",
) -> Optional[Tuple[str, str, str]]:
    """Fetch the source of a specific function from upstream.

    Tries known_file first, then searches common paths.

    Returns:
        (function_body, file_path, ref) or None
    """
    files_to_try: List[str] = []
    if known_file:
        files_to_try.append(known_file)

    # Try struct source files if we have a struct name
    if struct_name and struct_name in _STRUCT_SOURCE_FILES:
        for f in _STRUCT_SOURCE_FILES[struct_name]:
            if f not in files_to_try:
                files_to_try.append(f)

    for fpath in files_to_try:
        content, ref = resolve_and_fetch(fpath, version, prefer_android=version.is_android)
        if not content:
            continue

        # Try to extract the function
        body = _extract_function_from_source(content, function_name)
        if body:
            return body, fpath, ref

    return None


def _extract_function_from_source(source: str, function_name: str) -> Optional[str]:
    """Extract a C function body from source text."""
    # Look for function definition: <type> function_name(...)
    pattern = re.compile(
        rf'^[a-zA-Z_][\w\s\*]*\b{re.escape(function_name)}\s*\([^;]*$',
        re.MULTILINE,
    )
    m = pattern.search(source)
    if not m:
        return None

    lines = source.splitlines()
    start_line = source[:m.start()].count("\n")

    # Find opening brace
    brace_start = None
    for i in range(start_line, min(start_line + 5, len(lines))):
        if "{" in lines[i]:
            brace_start = i
            break

    if brace_start is None:
        # Return a few lines as context
        end = min(start_line + 30, len(lines))
        return "\n".join(lines[start_line:end])

    # Count braces to find function end
    depth = 0
    body_lines: List[str] = []
    for i in range(start_line, min(start_line + 500, len(lines))):
        line = lines[i]
        body_lines.append(line)
        depth += line.count("{") - line.count("}")
        if depth <= 0 and i > brace_start:
            break

    return "\n".join(body_lines) if body_lines else None


def format_source_analysis_summary(
    results: List[SourceSlabInfo],
    version: KernelVersionInfo,
) -> str:
    """Format source analysis results as a human-readable summary."""
    if not results:
        return f"No slab allocation evidence found in upstream source (kernel {version.base_version})"

    lines = [
        f"=== Source-Level Slab Analysis (kernel {version.base_version}) ===",
    ]
    for i, r in enumerate(results, 1):
        lines.append(f"  [{i}] cache=\"{r.cache_name}\" (confidence: {r.confidence})")
        lines.append(f"      struct: {r.struct_name}")
        lines.append(f"      allocator: {r.alloc_function}")
        if r.object_size:
            lines.append(f"      size: {r.object_size}")
        lines.append(f"      file: {r.alloc_file}:{r.alloc_line}")
        lines.append(f"      ref: {r.source_ref}")
        for ev in r.evidence:
            lines.append(f"      evidence: {ev}")

    return "\n".join(lines)
