"""
analysis.slab_identifier -- Empirical + source-level slab cache identification.

Monitors /proc/slabinfo on the target device before and after triggering
a vulnerability to identify which slab cache the freed object belongs to.
Also cross-references with known struct sizes from BTF/pahole.

When a kernel version is available, fetches the closest matching upstream
source from android.googlesource.com or git.kernel.org and searches for
kmem_cache_create / KMEM_CACHE / kmalloc patterns to identify the cache
via static source analysis -- no local git checkout required.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from ..core.log import console


@dataclass
class SlabDelta:
    """Change in a single slab cache between snapshots."""

    name: str
    active_before: int = 0
    active_after: int = 0
    total_before: int = 0
    total_after: int = 0
    object_size: int = 0
    active_delta: int = 0
    total_delta: int = 0


@dataclass
class SlabIdentificationResult:
    """Result of empirical slab cache identification."""

    target_cache: str = ""
    target_object_size: int = 0
    confidence: str = "low"  # "high", "medium", "low"

    # All caches with significant deltas
    cache_deltas: List[SlabDelta] = field(default_factory=list)
    top_candidates: List[Dict[str, Any]] = field(default_factory=list)

    # Cross-reference with known structs
    struct_matches: List[Dict[str, Any]] = field(default_factory=list)

    # Source-level analysis results
    source_analysis: List[Dict[str, Any]] = field(default_factory=list)
    source_ref: str = ""  # Git ref that matched (e.g. "kernel.org:v5.10.107")

    notes: List[str] = field(default_factory=list)

    def summary(self) -> str:
        lines = [
            f"=== Slab Cache Identification ===",
            f"  Target cache : {self.target_cache or 'unidentified'}",
            f"  Object size  : {self.target_object_size}",
            f"  Confidence   : {self.confidence}",
        ]
        if self.top_candidates:
            lines.append(f"  Top candidates:")
            for c in self.top_candidates[:5]:
                lines.append(
                    f"    {c['name']}: delta={c['delta']:+d} "
                    f"(size={c['object_size']})"
                )
        if self.struct_matches:
            lines.append(f"  Struct matches:")
            for s in self.struct_matches:
                lines.append(
                    f"    {s['struct']}: size={s['size']} → {s['cache']}"
                )
        if self.source_analysis:
            lines.append(f"  Source analysis ({self.source_ref}):")
            for sa in self.source_analysis:
                lines.append(
                    f"    cache=\"{sa.get('cache_name', '?')}\" "
                    f"(confidence: {sa.get('confidence', '?')}) — "
                    f"{sa.get('alloc_function', '?')} in {sa.get('alloc_file', '?')}"
                )
        for note in self.notes:
            lines.append(f"  Note: {note}")
        return "\n".join(lines)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target_cache": self.target_cache,
            "target_object_size": self.target_object_size,
            "confidence": self.confidence,
            "top_candidates": self.top_candidates,
            "struct_matches": self.struct_matches,
            "source_analysis": self.source_analysis,
            "source_ref": self.source_ref,
            "notes": self.notes,
        }


def _parse_slabinfo(text: str) -> Dict[str, Dict[str, int]]:
    """Parse /proc/slabinfo output into {name: {active, total, size}}."""
    caches: Dict[str, Dict[str, int]] = {}
    for line in text.strip().splitlines():
        if line.startswith("slabinfo") or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) < 6:
            continue
        name = parts[0]
        try:
            caches[name] = {
                "active_objs": int(parts[1]),
                "num_objs": int(parts[2]),
                "objsize": int(parts[3]),
                "objperslab": int(parts[4]),
                "pagesperslab": int(parts[5]),
            }
        except (ValueError, IndexError):
            continue
    return caches


def _compute_deltas(
    before: Dict[str, Dict[str, int]],
    after: Dict[str, Dict[str, int]],
    min_delta: int = 1,
) -> List[SlabDelta]:
    """Compute allocation deltas between two slabinfo snapshots."""
    deltas: List[SlabDelta] = []
    all_names = set(before.keys()) | set(after.keys())

    for name in sorted(all_names):
        b = before.get(name, {"active_objs": 0, "num_objs": 0, "objsize": 0})
        a = after.get(name, {"active_objs": 0, "num_objs": 0, "objsize": 0})

        active_delta = a["active_objs"] - b["active_objs"]
        total_delta = a["num_objs"] - b["num_objs"]

        if abs(active_delta) >= min_delta or abs(total_delta) >= min_delta:
            deltas.append(SlabDelta(
                name=name,
                active_before=b["active_objs"],
                active_after=a["active_objs"],
                total_before=b["num_objs"],
                total_after=a["num_objs"],
                object_size=a.get("objsize", 0) or b.get("objsize", 0),
                active_delta=active_delta,
                total_delta=total_delta,
            ))

    # Sort by absolute active delta descending
    deltas.sort(key=lambda d: abs(d.active_delta), reverse=True)
    return deltas


# Known struct → slab cache mappings
_KNOWN_STRUCT_CACHES: Dict[str, Dict[str, Any]] = {
    "binder_node": {"size": 184, "cache": "binder_node", "kmalloc": "kmalloc-192"},
    "binder_ref": {"size": 96, "cache": "binder_ref", "kmalloc": "kmalloc-128"},
    "binder_transaction": {"size": 248, "cache": "binder_transaction", "kmalloc": "kmalloc-256"},
    "binder_buffer": {"size": 104, "cache": "binder_buffer", "kmalloc": "kmalloc-128"},
    "pipe_buffer": {"size": 40, "cache": "kmalloc-64"},
    "pipe_inode_info": {"size": 640, "cache": "kmalloc-1k"},
    "msg_msg": {"size": 48, "cache": "kmalloc-64"},
    "sk_buff": {"size": 232, "cache": "skbuff_head_cache"},
    "file": {"size": 232, "cache": "filp"},
    "inode": {"size": 608, "cache": "inode_cache"},
    "dentry": {"size": 192, "cache": "dentry"},
    "task_struct": {"size": 6144, "cache": "task_struct"},
    "cred": {"size": 176, "cache": "cred_jar"},
    "seq_operations": {"size": 32, "cache": "kmalloc-32"},
    "tty_struct": {"size": 696, "cache": "kmalloc-1k"},
    "io_kiocb": {"size": 232, "cache": "io_kiocb"},
    "nft_rule_dp": {"size": 0, "cache": "kmalloc-varies"},
    "epitem": {"size": 128, "cache": "eventpoll_epi"},
    "timerfd_ctx": {"size": 0, "cache": "kmalloc-256"},
}


def identify_slab_cache(
    *,
    reproducer_path: Optional[str] = None,
    target_structs: Optional[List[str]] = None,
    kernel_version: str = "",
    vulnerable_function: str = "",
    vulnerable_file: str = "",
    ssh_host: str = "",
    ssh_port: int = 22,
    instance: Optional[int] = None,
    adb_port: int = 6520,
    timeout: int = 30,
) -> SlabIdentificationResult:
    """Identify target slab cache via empirical + source-level analysis.

    Steps:
    1. Snapshot /proc/slabinfo
    2. Run reproducer (if provided)
    3. Snapshot /proc/slabinfo again
    4. Compute deltas and identify candidate caches
    5. Cross-reference with known struct sizes
    6. If kernel_version is provided, fetch upstream source and
       search for kmem_cache_create / KMEM_CACHE / kmalloc patterns
    7. Cross-reference source findings with empirical deltas

    Parameters
    ----------
    reproducer_path
        Path to reproducer binary to run between snapshots.
    target_structs
        Names of structs to cross-reference with known cache mappings.
    kernel_version
        Kernel version string (e.g. ``"5.10.107-android13-4"``).  When
        provided, enables source-level analysis by fetching the nearest
        upstream source from android.googlesource.com or git.kernel.org.
    vulnerable_function
        Name of the vulnerable function (helps narrow file search).
    vulnerable_file
        Source file path of the vulnerability (e.g. ``"net/core/dst.c"``).
    """
    from ..infra.verification import _adb_run, _calc_adb_port

    result = SlabIdentificationResult()
    port = _calc_adb_port(instance, adb_port)

    # Step 1: Before snapshot
    console.print("  [dim]Capturing slabinfo before…[/]")
    rc, stdout_before, _ = _adb_run(
        "cat /proc/slabinfo", port, timeout=10,
    )
    if rc != 0 or not stdout_before.strip():
        result.notes.append("Could not read /proc/slabinfo — may not be readable")
        # Try without root
        rc, stdout_before, _ = _adb_run(
            "su -c 'cat /proc/slabinfo'", port, timeout=10,
        )
        if rc != 0:
            result.notes.append("slabinfo not accessible even with su")

    before = _parse_slabinfo(stdout_before) if stdout_before else {}

    # Step 2: Run reproducer if provided
    if reproducer_path:
        from ..infra.verification import _adb_push
        console.print("  [dim]Running reproducer for slab analysis…[/]")
        remote_path = f"/data/local/tmp/slab_repro"
        try:
            push_ok = _adb_push(reproducer_path, remote_path, port)
            if not push_ok:
                result.notes.append(
                    f"ADB push failed for {reproducer_path} — file may "
                    f"not exist or is a source file instead of a compiled binary"
                )
            else:
                _adb_run(f"chmod 755 {remote_path}", port, timeout=5)
                # Run with short timeout — we just need it to trigger alloc/free
                _adb_run(
                    f"{remote_path} &\nsleep 2\nkill $! 2>/dev/null",
                    port, timeout=timeout,
                )
        except Exception as e:
            result.notes.append(f"Reproducer execution error: {e}")

    # Step 3: After snapshot
    console.print("  [dim]Capturing slabinfo after…[/]")
    rc, stdout_after, _ = _adb_run(
        "cat /proc/slabinfo", port, timeout=10,
    )
    if rc != 0:
        rc, stdout_after, _ = _adb_run(
            "su -c 'cat /proc/slabinfo'", port, timeout=10,
        )

    after = _parse_slabinfo(stdout_after) if stdout_after else {}

    if not before or not after:
        result.notes.append("Insufficient slabinfo data for analysis")
        # Fall back to struct-based identification
        if target_structs:
            for struct in target_structs:
                if struct in _KNOWN_STRUCT_CACHES:
                    info = _KNOWN_STRUCT_CACHES[struct]
                    result.struct_matches.append({
                        "struct": struct,
                        "size": info.get("size", 0),
                        "cache": info.get("cache", ""),
                    })
                    if not result.target_cache:
                        cache = info.get("cache", info.get("kmalloc", ""))
                        result.target_cache = cache
                        result.target_object_size = info.get("size", 0)
                        result.confidence = "medium"
        # Still run source analysis even without slabinfo
        if kernel_version and target_structs:
            result = _run_source_analysis(
                result,
                target_structs=target_structs,
                kernel_version=kernel_version,
                vulnerable_function=vulnerable_function,
                vulnerable_file=vulnerable_file,
            )
        console.print(f"  Slab identification: {result.target_cache or 'unknown'} "
                      f"(confidence: {result.confidence})")
        return result

    # Step 4: Compute deltas
    deltas = _compute_deltas(before, after, min_delta=1)
    result.cache_deltas = deltas

    # Build top candidates (exclude noise caches)
    noise_caches = {
        "kmem_cache_node", "kmem_cache_cpu",
        "dma-kmalloc-", "names_cache",
    }
    candidates = []
    for d in deltas:
        if any(n in d.name for n in noise_caches):
            continue
        candidates.append({
            "name": d.name,
            "delta": d.active_delta,
            "total_delta": d.total_delta,
            "object_size": d.object_size,
        })
    result.top_candidates = candidates[:10]

    # Pick the most likely target cache
    # Prefer caches with positive free delta (objects freed = UAF target)
    freed_candidates = [c for c in candidates if c["delta"] < 0]
    alloc_candidates = [c for c in candidates if c["delta"] > 0]

    if freed_candidates:
        best = freed_candidates[0]
        result.target_cache = best["name"]
        result.target_object_size = best["object_size"]
        result.confidence = "high" if abs(best["delta"]) > 3 else "medium"
    elif alloc_candidates:
        best = alloc_candidates[0]
        result.target_cache = best["name"]
        result.target_object_size = best["object_size"]
        result.confidence = "medium"

    # Step 5: Cross-reference with structs
    if target_structs:
        for struct in target_structs:
            if struct in _KNOWN_STRUCT_CACHES:
                info = _KNOWN_STRUCT_CACHES[struct]
                result.struct_matches.append({
                    "struct": struct,
                    "size": info.get("size", 0),
                    "cache": info.get("cache", ""),
                    "kmalloc_cache": info.get("kmalloc", ""),
                })

    # Step 6: Source-level analysis (if kernel version is available)
    if kernel_version and target_structs:
        result = _run_source_analysis(
            result,
            target_structs=target_structs,
            kernel_version=kernel_version,
            vulnerable_function=vulnerable_function,
            vulnerable_file=vulnerable_file,
        )

    console.print(f"  Slab identification: {result.target_cache or 'unknown'} "
                  f"(confidence: {result.confidence})")
    return result


def _run_source_analysis(
    result: SlabIdentificationResult,
    *,
    target_structs: List[str],
    kernel_version: str,
    vulnerable_function: str = "",
    vulnerable_file: str = "",
) -> SlabIdentificationResult:
    """Fetch upstream source and analyze slab allocation patterns.

    Updates *result* in-place with source analysis findings and may
    promote confidence or correct the target_cache if source evidence
    is stronger than the empirical signal.
    """
    from .kernel_source_fetcher import (
        SourceSlabInfo,
        analyze_slab_from_source,
        format_source_analysis_summary,
        parse_kernel_version,
    )

    try:
        version = parse_kernel_version(kernel_version)
        console.print(
            f"  [dim]Source analysis: kernel {version.base_version} "
            f"(android={version.is_android})…[/]"
        )

        for struct_name in target_structs:
            source_results = analyze_slab_from_source(
                struct_name,
                version,
                vulnerable_function=vulnerable_function,
                vulnerable_file=vulnerable_file,
            )

            if not source_results:
                result.notes.append(
                    f"Source analysis: no allocation evidence for "
                    f"'{struct_name}' in upstream source"
                )
                continue

            # Store all source findings
            for sr in source_results:
                result.source_analysis.append({
                    "struct_name": sr.struct_name,
                    "cache_name": sr.cache_name,
                    "cache_var": sr.cache_var,
                    "alloc_function": sr.alloc_function,
                    "alloc_file": sr.alloc_file,
                    "alloc_line": sr.alloc_line,
                    "object_size": sr.object_size,
                    "confidence": sr.confidence,
                    "evidence": sr.evidence,
                    "source_ref": sr.source_ref,
                })
                if sr.source_ref and not result.source_ref:
                    result.source_ref = sr.source_ref

            # Cross-reference source findings with empirical data
            high_confidence = [s for s in source_results if s.confidence == "high"]

            if high_confidence:
                src_cache = high_confidence[0].cache_name

                if not result.target_cache:
                    # No empirical result — use source analysis directly
                    result.target_cache = src_cache
                    result.confidence = "medium"
                    result.notes.append(
                        f"Target cache set from source analysis: {src_cache}"
                    )
                elif result.target_cache == src_cache:
                    # Source confirms empirical — boost confidence
                    result.confidence = "high"
                    result.notes.append(
                        f"Source analysis confirms empirical cache: {src_cache}"
                    )
                else:
                    # Disagreement — check if source cache is in candidates
                    empirical_names = {
                        c["name"] for c in result.top_candidates
                    }
                    if src_cache in empirical_names:
                        result.notes.append(
                            f"Source analysis suggests '{src_cache}' (seen "
                            f"in empirical candidates); empirical pick is "
                            f"'{result.target_cache}'"
                        )
                    else:
                        result.notes.append(
                            f"Source analysis suggests '{src_cache}' but "
                            f"empirical pick is '{result.target_cache}' — "
                            f"verify which is correct"
                        )

            summary = format_source_analysis_summary(source_results, version)
            console.print(f"  [dim]{summary}[/]")

    except Exception as exc:
        result.notes.append(f"Source analysis error: {exc}")
        console.print(f"  [yellow]Source analysis failed: {exc}[/]")

    return result
