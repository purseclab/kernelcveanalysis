"""
correlation.py  –  Cross-domain correlation for the syzploit pipeline.

Links crash analysis (SyzAnalyze), dynamic tracing (SyzVerify), and exploit
synthesis (Synthesizer) by building a unified function identity map:

    crash‑stack function  ↔  GDB trace event  ↔  exploit plan step

Usage::

    from syzploit.Synthesizer.correlation import (
        build_correlation,
        CorrelationReport,
    )

    report = build_correlation(
        static_analysis=json.loads(Path("static_analysis.json").read_text()),
        trace_analysis=json.loads(Path("trace_analysis.json").read_text()),
        plan=exploit_plan,             # ExploitPlan instance
        dynamic_analysis=dyn,          # optional raw GDB export
    )
    print(report.summary())
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from difflib import SequenceMatcher
from typing import Any, Dict, List, Optional, Set, Tuple

from .core import ExploitPlan, normalize_steps

# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------

@dataclass
class FunctionRecord:
    """Unified record for a single kernel function across all domains."""

    name: str

    # --- SyzAnalyze (static) ---
    in_crash_stack: bool = False
    crash_stack_index: Optional[int] = None          # 0 = top of stack
    source_file: Optional[str] = None
    source_line: Optional[int] = None
    role: Optional[str] = None                        # alloc / free / access

    # --- SyzVerify (dynamic) ---
    runtime_address: Optional[str] = None
    trace_hits: int = 0
    in_alloc_path: bool = False
    in_free_path: bool = False
    backtrace_chain_depth: Optional[int] = None       # from chain match

    # --- Synthesizer (plan) ---
    mapped_step: Optional[str] = None                 # plan step name
    step_index: Optional[int] = None

    @property
    def coverage(self) -> int:
        """How many domains reference this function (0-3)."""
        n = 0
        if self.in_crash_stack or self.role:
            n += 1
        if self.runtime_address or self.trace_hits > 0:
            n += 1
        if self.mapped_step:
            n += 1
        return n


@dataclass
class CorrelationReport:
    """Aggregated cross-domain correlation results."""

    functions: Dict[str, FunctionRecord] = field(default_factory=dict)
    plan_coverage: float = 0.0           # fraction of plan steps mapped
    trace_coverage: float = 0.0          # fraction of crash funcs seen in trace
    unmapped_steps: List[str] = field(default_factory=list)
    unmapped_crash_funcs: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    # Struct / object correlation
    vuln_object_cache: str = ""
    vuln_object_size: int = 0
    vuln_object_offset: int = 0
    vuln_type: str = ""

    # Lifecycle correlation
    lifecycle_phases: List[Dict[str, Any]] = field(default_factory=list)

    def summary(self) -> str:
        """Human-readable summary."""
        lines = ["=== Cross-Domain Correlation Report ===", ""]

        lines.append(f"Functions tracked: {len(self.functions)}")
        multi = [f for f in self.functions.values() if f.coverage >= 2]
        lines.append(f"  Multi-domain (≥2): {len(multi)}")
        lines.append(f"  Crash-stack coverage in trace: {self.trace_coverage:.0%}")
        lines.append(f"  Plan step mapping: {self.plan_coverage:.0%}")
        lines.append("")

        if self.vuln_type:
            lines.append(f"Vulnerability: {self.vuln_type}")
            lines.append(f"  Object: {self.vuln_object_cache} "
                         f"(size={self.vuln_object_size}, "
                         f"offset={self.vuln_object_offset})")
            lines.append("")

        if self.lifecycle_phases:
            lines.append("Lifecycle phases:")
            for phase in self.lifecycle_phases:
                lines.append(f"  {phase['phase']}: "
                             f"{phase.get('function', '?')} "
                             f"(addr={phase.get('address', '?')}, "
                             f"hits={phase.get('hits', 0)})")
            lines.append("")

        if self.unmapped_steps:
            lines.append(f"Unmapped plan steps ({len(self.unmapped_steps)}):")
            for s in self.unmapped_steps:
                lines.append(f"  - {s}")
            lines.append("")

        if self.unmapped_crash_funcs:
            lines.append(f"Crash functions not seen in trace "
                         f"({len(self.unmapped_crash_funcs)}):")
            for f in self.unmapped_crash_funcs:
                lines.append(f"  - {f}")
            lines.append("")

        if self.warnings:
            lines.append("Warnings:")
            for w in self.warnings:
                lines.append(f"  ⚠ {w}")

        return "\n".join(lines)

    def to_dict(self) -> Dict[str, Any]:
        """Serialisable dict (for JSON export)."""
        return {
            "functions": {
                name: {
                    "name": rec.name,
                    "in_crash_stack": rec.in_crash_stack,
                    "crash_stack_index": rec.crash_stack_index,
                    "source_file": rec.source_file,
                    "source_line": rec.source_line,
                    "role": rec.role,
                    "runtime_address": rec.runtime_address,
                    "trace_hits": rec.trace_hits,
                    "in_alloc_path": rec.in_alloc_path,
                    "in_free_path": rec.in_free_path,
                    "backtrace_chain_depth": rec.backtrace_chain_depth,
                    "mapped_step": rec.mapped_step,
                    "step_index": rec.step_index,
                    "coverage": rec.coverage,
                }
                for name, rec in self.functions.items()
            },
            "plan_coverage": self.plan_coverage,
            "trace_coverage": self.trace_coverage,
            "unmapped_steps": self.unmapped_steps,
            "unmapped_crash_funcs": self.unmapped_crash_funcs,
            "warnings": self.warnings,
            "vuln_type": self.vuln_type,
            "vuln_object_cache": self.vuln_object_cache,
            "vuln_object_size": self.vuln_object_size,
            "vuln_object_offset": self.vuln_object_offset,
            "lifecycle_phases": self.lifecycle_phases,
        }


# ---------------------------------------------------------------------------
# Step-to-function heuristic mapping
# ---------------------------------------------------------------------------

# Map common plan step name fragments → likely kernel function roles
_STEP_ROLE_HINTS: Dict[str, str] = {
    "trigger": "access",
    "free": "free",
    "dealloc": "free",
    "release": "free",
    "spray": "alloc",
    "alloc": "alloc",
    "reclaim": "alloc",
    "setup": "alloc",
    "leak": "access",
    "read": "access",
    "write": "access",
    "overwrite": "access",
    "corrupt": "access",
    "escalat": "access",
    "privesc": "access",
}


def _infer_role_from_step(step_name: str) -> Optional[str]:
    """Infer a function role (alloc/free/access) from a plan step name."""
    lower = step_name.lower()
    for fragment, role in _STEP_ROLE_HINTS.items():
        if fragment in lower:
            return role
    return None


def _fuzzy_match_name(a: str, b: str, threshold: float = 0.6) -> bool:
    """Return True if *a* and *b* are fuzzy-similar function names."""
    if a == b:
        return True
    # Normalise
    na = a.lower().replace("-", "_").strip("()")
    nb = b.lower().replace("-", "_").strip("()")
    if na == nb:
        return True
    # One is a substring of the other
    if na in nb or nb in na:
        return True
    return SequenceMatcher(None, na, nb).ratio() >= threshold


# ---------------------------------------------------------------------------
# Builder
# ---------------------------------------------------------------------------

def _get_or_create(funcs: Dict[str, FunctionRecord],
                   name: str) -> FunctionRecord:
    if name not in funcs:
        funcs[name] = FunctionRecord(name=name)
    return funcs[name]


def _extract_func_name(frame_str: str) -> Optional[str]:
    """Extract bare function name from a crash frame string."""
    # "ep_free+0x28/0x120" → "ep_free"
    m = re.match(r"(\w+?)(?:\+0x|\s|$)", frame_str.strip())
    return m.group(1) if m else None


def build_correlation(
    static_analysis: Optional[Dict[str, Any]] = None,
    trace_analysis: Optional[Dict[str, Any]] = None,
    plan: Optional[ExploitPlan] = None,
    dynamic_analysis: Optional[Dict[str, Any]] = None,
) -> CorrelationReport:
    """
    Build a cross-domain correlation report.

    Parameters
    ----------
    static_analysis : dict
        Contents of ``static_analysis.json`` (from SyzAnalyze).
    trace_analysis : dict
        Contents of ``trace_analysis.json`` (from SyzVerify/run_bug).
    plan : ExploitPlan
        The exploit plan from the Synthesizer.
    dynamic_analysis : dict, optional
        Raw ``dynamic_analysis.json`` from GDB (for finer event-level data).
    """
    report = CorrelationReport()
    funcs: Dict[str, FunctionRecord] = {}

    # ---- Phase 1: Static crash analysis ----
    if static_analysis:
        _ingest_static(static_analysis, funcs, report)

    # ---- Phase 2: Dynamic trace analysis ----
    if trace_analysis:
        _ingest_trace(trace_analysis, funcs, report)

    # ---- Phase 3: Raw GDB events (optional, finer granularity) ----
    if dynamic_analysis:
        _ingest_dynamic(dynamic_analysis, funcs, report)

    # ---- Phase 4: Exploit plan mapping ----
    if plan:
        _ingest_plan(plan, funcs, report)

    # ---- Phase 5: Compute coverage metrics ----
    report.functions = funcs
    _compute_metrics(funcs, report, plan, trace_analysis)

    # ---- Phase 6: Lifecycle reconstruction ----
    _build_lifecycle(funcs, report)

    return report


# ---------------------------------------------------------------------------
# Ingestion helpers
# ---------------------------------------------------------------------------

def _ingest_static(data: Dict[str, Any],
                   funcs: Dict[str, FunctionRecord],
                   report: CorrelationReport) -> None:
    """Ingest static_analysis.json."""
    parsed = data.get("parsed", {})

    # Vulnerability object info
    obj = parsed.get("object_info", {})
    report.vuln_object_cache = obj.get("cache", "")
    report.vuln_object_size = obj.get("obj_size", 0) or obj.get("size", 0)
    report.vuln_object_offset = obj.get("offset", 0)
    report.vuln_type = parsed.get("kind", data.get("classification", {})
                                   .get("primitive", ""))

    # Crash stack frames
    frames = parsed.get("frames", [])
    for idx, frame in enumerate(frames):
        fname = frame.get("func") or frame.get("function", "")
        if not fname:
            continue
        rec = _get_or_create(funcs, fname)
        rec.in_crash_stack = True
        if rec.crash_stack_index is None:
            rec.crash_stack_index = idx
        rec.source_file = frame.get("file", rec.source_file)
        rec.source_line = frame.get("line", rec.source_line)

    # Allocated-by stack → role=alloc
    for raw in parsed.get("allocated_by", []):
        fname = _extract_func_name(str(raw))
        if fname:
            rec = _get_or_create(funcs, fname)
            rec.role = rec.role or "alloc"

    # Freed-by stack → role=free
    for raw in parsed.get("freed_by", []):
        fname = _extract_func_name(str(raw))
        if fname:
            rec = _get_or_create(funcs, fname)
            rec.role = rec.role or "free"

    # Additional crash_stack / stack_frames (alternate keys)
    for alt_key in ("crash_stack", "stack_frames"):
        for sf in parsed.get(alt_key, []):
            fname = sf.get("func") or sf.get("function", "")
            if fname:
                rec = _get_or_create(funcs, fname)
                rec.in_crash_stack = True


def _ingest_trace(data: Dict[str, Any],
                  funcs: Dict[str, FunctionRecord],
                  report: CorrelationReport) -> None:
    """Ingest trace_analysis.json."""
    # Crash functions with hit counts
    for cf in data.get("crash_functions", []):
        fname = cf.get("function", "")
        if not fname:
            continue
        rec = _get_or_create(funcs, fname)
        rec.trace_hits = max(rec.trace_hits, cf.get("hits", 0))

    # Runtime addresses
    rt = data.get("runtime_addresses", {})
    for fname, addr in (rt.get("crash_stack", {}) or {}).items():
        rec = _get_or_create(funcs, fname)
        rec.runtime_address = addr

    for fname, addr in (rt.get("alloc_functions", {}) or {}).items():
        rec = _get_or_create(funcs, fname)
        rec.runtime_address = addr
        rec.in_alloc_path = True

    for fname, addr in (rt.get("free_functions", {}) or {}).items():
        rec = _get_or_create(funcs, fname)
        rec.runtime_address = addr
        rec.in_free_path = True

    # Backtrace chain matches (path verification)
    pv = data.get("path_verification", {})
    for bcm in pv.get("backtrace_chain_matches", []):
        fname = bcm.get("func", "")
        if fname:
            rec = _get_or_create(funcs, fname)
            depth = bcm.get("chain_depth")
            if depth is not None:
                rec.backtrace_chain_depth = depth


def _ingest_dynamic(data: Dict[str, Any],
                    funcs: Dict[str, FunctionRecord],
                    report: CorrelationReport) -> None:
    """Ingest raw dynamic_analysis.json (event-level detail)."""
    # func_hits map
    for fname, count in (data.get("func_hits", {}) or {}).items():
        rec = _get_or_create(funcs, fname)
        rec.trace_hits = max(rec.trace_hits, count)

    # Breakpoint info
    bp = data.get("breakpoints", {})
    for fname, addr in (bp.get("crash_stack_addrs", {}) or {}).items():
        rec = _get_or_create(funcs, fname)
        rec.runtime_address = rec.runtime_address or addr


def _ingest_plan(plan: ExploitPlan,
                 funcs: Dict[str, FunctionRecord],
                 report: CorrelationReport) -> None:
    """Map plan steps to kernel functions via heuristic matching."""
    plan.normalize()
    steps = plan.steps

    for idx, step in enumerate(steps):
        step_name = step.get("name", step.get("action", ""))
        if not step_name:
            continue

        # Try direct name match first (step name == function name)
        matched = False
        if step_name in funcs:
            funcs[step_name].mapped_step = step_name
            funcs[step_name].step_index = idx
            matched = True
        else:
            # Try role-based heuristic: infer what the step does,
            # then pick the best-matching function with that role
            role = _infer_role_from_step(step_name)
            if role:
                candidates = [
                    (n, r) for n, r in funcs.items()
                    if r.mapped_step is None  # not already taken
                    and _role_matches(r, role)
                ]
                if candidates:
                    # Prefer functions with more trace evidence
                    best_n, best_r = max(
                        candidates,
                        key=lambda x: (x[1].trace_hits, x[1].in_crash_stack),
                    )
                    best_r.mapped_step = step_name
                    best_r.step_index = idx
                    matched = True

        if not matched:
            report.unmapped_steps.append(step_name)


def _role_matches(rec: FunctionRecord, role: str) -> bool:
    """Check if a function record's known role matches."""
    if role == "alloc":
        return rec.in_alloc_path or rec.role == "alloc"
    if role == "free":
        return rec.in_free_path or rec.role == "free"
    if role == "access":
        return rec.in_crash_stack
    return False


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------

def _compute_metrics(funcs: Dict[str, FunctionRecord],
                     report: CorrelationReport,
                     plan: Optional[ExploitPlan],
                     trace: Optional[Dict[str, Any]]) -> None:
    """Compute plan_coverage and trace_coverage."""
    # Plan coverage: fraction of plan steps that mapped to a function
    if plan:
        plan.normalize()
        total_steps = len(plan.steps)
        if total_steps > 0:
            mapped = sum(1 for r in funcs.values() if r.mapped_step is not None)
            report.plan_coverage = mapped / total_steps
        else:
            report.plan_coverage = 0.0

    # Trace coverage: fraction of crash-stack functions seen in trace
    crash_funcs = [r for r in funcs.values() if r.in_crash_stack]
    if crash_funcs:
        seen = sum(1 for r in crash_funcs
                   if r.trace_hits > 0 or r.runtime_address is not None)
        report.trace_coverage = seen / len(crash_funcs)
        report.unmapped_crash_funcs = [
            r.name for r in crash_funcs
            if r.trace_hits == 0 and r.runtime_address is None
        ]
    else:
        report.trace_coverage = 0.0

    # Warnings
    if report.trace_coverage < 0.5 and crash_funcs:
        report.warnings.append(
            f"Low trace coverage ({report.trace_coverage:.0%}): "
            "many crash-stack functions were not hit during tracing. "
            "Consider extending trace duration or checking breakpoints."
        )
    if report.plan_coverage < 0.5 and plan and plan.steps:
        report.warnings.append(
            f"Low plan coverage ({report.plan_coverage:.0%}): "
            "many plan steps could not be mapped to observed functions. "
            "The exploit plan may need refinement."
        )


# ---------------------------------------------------------------------------
# Lifecycle reconstruction
# ---------------------------------------------------------------------------

def _build_lifecycle(funcs: Dict[str, FunctionRecord],
                     report: CorrelationReport) -> None:
    """
    Reconstruct the vulnerability lifecycle phases from correlated data.

    Attempts to identify: alloc → use → free → re-use (for UAF) or similar
    sequences, using the combined evidence from all domains.
    """
    phases: List[Dict[str, Any]] = []

    # Collect functions by role
    alloc_funcs = sorted(
        [r for r in funcs.values() if r.in_alloc_path or r.role == "alloc"],
        key=lambda r: (r.crash_stack_index or 999, -r.trace_hits),
    )
    free_funcs = sorted(
        [r for r in funcs.values() if r.in_free_path or r.role == "free"],
        key=lambda r: (r.crash_stack_index or 999, -r.trace_hits),
    )
    access_funcs = sorted(
        [r for r in funcs.values()
         if r.in_crash_stack and r.role not in ("alloc", "free")],
        key=lambda r: (r.crash_stack_index or 999),
    )

    # Build ordered phases
    for r in alloc_funcs[:2]:  # top 2 most relevant
        phases.append({
            "phase": "allocate",
            "function": r.name,
            "address": r.runtime_address,
            "hits": r.trace_hits,
            "mapped_step": r.mapped_step,
        })

    for r in free_funcs[:2]:
        phases.append({
            "phase": "free",
            "function": r.name,
            "address": r.runtime_address,
            "hits": r.trace_hits,
            "mapped_step": r.mapped_step,
        })

    for r in access_funcs[:3]:
        phases.append({
            "phase": "access",
            "function": r.name,
            "address": r.runtime_address,
            "hits": r.trace_hits,
            "crash_stack_pos": r.crash_stack_index,
            "mapped_step": r.mapped_step,
        })

    report.lifecycle_phases = phases
