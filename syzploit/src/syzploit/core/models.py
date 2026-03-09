"""
core.models — Canonical data models for the entire syzploit pipeline.

Every module speaks the same language through these Pydantic models.
They replace the mix of dataclasses, TypedDicts, and plain dicts
from the old codebase with a single, validated, serializable set.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


# ── Vulnerability classification ──────────────────────────────────────


class VulnType(str, Enum):
    """Known kernel vulnerability classes."""

    UAF = "uaf"
    OOB_READ = "oob_read"
    OOB_WRITE = "oob_write"
    DOUBLE_FREE = "double_free"
    RACE_CONDITION = "race_condition"
    TYPE_CONFUSION = "type_confusion"
    INTEGER_OVERFLOW = "integer_overflow"
    USE_BEFORE_INIT = "use_before_init"
    NULL_DEREF = "null_deref"
    LOGIC_BUG = "logic_bug"
    UNKNOWN = "unknown"

    @classmethod
    def from_str(cls, s: str) -> VulnType:
        """Fuzzy-parse a vulnerability type string."""
        s_lower = s.lower().replace("-", "_").replace(" ", "_")
        for member in cls:
            if member.value == s_lower:
                return member
        _HEURISTICS: list[tuple[list[str], VulnType]] = [
            (["uaf", "use_after_free"], cls.UAF),
            (["oob_read", "oob read", "out_of_bounds_read", "slab_out_of_bounds_read"], cls.OOB_READ),
            (["oob_write", "oob write", "out_of_bounds_write", "slab_out_of_bounds_write"], cls.OOB_WRITE),
            (["out_of_bounds", "slab_out_of_bounds", "oob"], cls.OOB_WRITE),  # default OOB → write
            (["double_free", "double free"], cls.DOUBLE_FREE),
            (["race", "toctou"], cls.RACE_CONDITION),
            (["type_confusion", "type confusion"], cls.TYPE_CONFUSION),
            (["integer", "overflow"], cls.INTEGER_OVERFLOW),
            (["uninit", "use_before"], cls.USE_BEFORE_INIT),
            (["null_deref", "null pointer"], cls.NULL_DEREF),
        ]
        for keywords, vtype in _HEURISTICS:
            if any(kw in s_lower for kw in keywords):
                return vtype
        return cls.UNKNOWN


class ControlClassification(str, Enum):
    """Post-condition control level of a vulnerability."""

    NONE = "none"
    DATA_ONLY = "data_only"
    LIMITED_WRITE = "limited_write"
    IP_CONTROL = "ip_control"
    ARBITRARY_KRW = "arbitrary_krw"
    ARBITRARY_RCE = "arbitrary_rce"


class Confidence(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class Arch(str, Enum):
    X86_64 = "x86_64"
    ARM64 = "arm64"


class Platform(str, Enum):
    LINUX = "linux"
    ANDROID = "android"
    GENERIC = "generic"


# ── Crash representation ──────────────────────────────────────────────


class CrashFrame(BaseModel):
    """A single stack frame from a kernel crash."""

    function: str
    file: Optional[str] = None
    line: Optional[int] = None
    offset: Optional[str] = None
    module: Optional[str] = None
    source_snippet: Optional[str] = None

    def display(self) -> str:
        loc = f"{self.file}:{self.line}" if self.file and self.line else ""
        return f"{self.function} ({loc})" if loc else self.function


class CrashReport(BaseModel):
    """Parsed representation of a kernel crash / KASAN report."""

    raw_log: str = ""
    crash_type: str = ""  # e.g. "KASAN: slab-use-after-free"
    bug_type: VulnType = VulnType.UNKNOWN
    corrupted_function: str = ""
    access_type: str = ""  # "read" / "write"
    access_size: Optional[int] = None
    access_address: Optional[str] = None
    stack_frames: List[CrashFrame] = Field(default_factory=list)
    alloc_frames: List[CrashFrame] = Field(default_factory=list)
    free_frames: List[CrashFrame] = Field(default_factory=list)
    subsystem: str = ""
    slab_cache: str = ""
    object_size: Optional[int] = None
    kernel_version: str = ""
    arch: Arch = Arch.X86_64
    reproducer_c: Optional[str] = None
    reproducer_syz: Optional[str] = None
    cve_id: Optional[str] = None
    syzbot_url: Optional[str] = None

    # Additional metadata
    metadata: Dict[str, Any] = Field(default_factory=dict)


# ── Root cause analysis ───────────────────────────────────────────────


class RootCauseAnalysis(BaseModel):
    """LLM-generated root cause understanding."""

    summary: str = ""
    vulnerable_function: str = ""
    vulnerable_file: str = ""
    vulnerability_type: VulnType = VulnType.UNKNOWN
    root_cause_description: str = ""
    trigger_conditions: List[str] = Field(default_factory=list)
    affected_subsystem: str = ""
    affected_structs: List[str] = Field(default_factory=list)
    affected_fields: List[str] = Field(default_factory=list)
    fix_commit: Optional[str] = None
    fix_description: Optional[str] = None

    # Post-conditions
    control_classification: ControlClassification = ControlClassification.NONE
    exploitability_score: int = 0
    confidence: Confidence = Confidence.LOW

    # Evidence from analysis
    evidence: List[Dict[str, Any]] = Field(default_factory=list)
    source_snippets: Dict[str, str] = Field(default_factory=dict)

    # Kernel identifiers discovered
    kernel_structs: List[str] = Field(default_factory=list)
    kernel_functions: List[str] = Field(default_factory=list)
    syscalls: List[str] = Field(default_factory=list)
    slab_caches: List[str] = Field(default_factory=list)

    # Detailed exploitation technique info (from blog analysis)
    exploitation_details: Dict[str, Any] = Field(default_factory=dict)


# ── Target system information ─────────────────────────────────────────


class TargetSystemInfo(BaseModel):
    """Information collected from the running target system.

    Obtained by booting the VM and running commands via ADB/SSH to
    discover the target's kernel version, architecture, loaded modules,
    available symbols, etc.  Used for feasibility checks when no crash
    report is available (CVE / blog-only input).
    """

    kernel_version: str = ""  # e.g. "5.10.177-android13-4-00052-..."
    kernel_release: str = ""  # uname -r
    arch: str = ""  # uname -m (aarch64, x86_64)
    android_version: str = ""  # getprop ro.build.version.release
    security_patch: str = ""  # getprop ro.build.version.security_patch
    build_type: str = ""  # getprop ro.build.type (userdebug/eng/user)
    device_model: str = ""  # getprop ro.product.model

    # Symbol information
    kallsyms_available: bool = False
    kallsyms_path: Optional[str] = None  # local path to downloaded kallsyms
    symbol_count: int = 0

    # Module / config info
    loaded_modules: List[str] = Field(default_factory=list)
    kasan_enabled: bool = False
    config_gz_available: bool = False
    config_gz_path: Optional[str] = None

    # SELinux
    selinux_enforcing: bool = True
    selinux_mode: str = ""  # enforcing / permissive / disabled

    # Raw outputs
    uname_a: str = ""
    dmesg_boot_excerpt: str = ""  # first 200 lines of dmesg

    notes: List[str] = Field(default_factory=list)

    def summary(self) -> str:
        lines = [
            f"=== Target System Info ===",
            f"  Kernel     : {self.kernel_release or 'N/A'}",
            f"  Arch       : {self.arch or 'N/A'}",
            f"  Android    : {self.android_version or 'N/A'}",
            f"  Patch level: {self.security_patch or 'N/A'}",
            f"  Build type : {self.build_type or 'N/A'}",
            f"  KASAN      : {'yes' if self.kasan_enabled else 'no'}",
            f"  SELinux    : {self.selinux_mode or 'N/A'}",
            f"  Symbols    : {self.symbol_count} ({'available' if self.kallsyms_available else 'unavailable'})",
            f"  Modules    : {len(self.loaded_modules)} loaded",
        ]
        for note in self.notes:
            lines.append(f"  Note: {note}")
        return "\n".join(lines)


# ── Feasibility ───────────────────────────────────────────────────────


class SymbolCheckResult(BaseModel):
    """Result of checking if crash-path symbols exist on target kernel."""

    symbols_checked: List[str] = Field(default_factory=list)
    symbols_found: List[str] = Field(default_factory=list)
    symbols_missing: List[str] = Field(default_factory=list)
    source: str = ""  # "remote_kallsyms", "kallsyms", "system_map", "vmlinux_nm", "none"
    verdict: str = "unknown"  # "present", "absent", "partial", "unknown"
    hit_ratio: float = 0.0


class FixBackportResult(BaseModel):
    """Result of checking whether the known fix has been backported."""

    fix_commits: List[str] = Field(default_factory=list)
    backported: bool = False
    strategy: str = ""  # "merge_base", "grep", "cherry_pick", "changelog"
    evidence: str = ""
    verdict: str = "unknown"  # "patched", "unpatched", "unknown"


class SourceDiffResult(BaseModel):
    """Result of source-level diff between original and target kernel versions.

    Compares the vulnerable function's source code across kernel versions
    using ``git diff``.  If the function body is unchanged, the bug is
    very likely still present.  Significant changes weaken that signal.
    """

    files_checked: List[str] = Field(default_factory=list)
    files_unchanged: List[str] = Field(default_factory=list)
    files_changed: List[str] = Field(default_factory=list)
    files_missing: List[str] = Field(default_factory=list)
    functions_checked: List[str] = Field(default_factory=list)
    functions_unchanged: List[str] = Field(default_factory=list)
    functions_changed: List[str] = Field(default_factory=list)
    total_diff_lines: int = 0
    diff_excerpts: Dict[str, str] = Field(default_factory=dict)
    similarity_ratio: float = 0.0  # 0.0 = completely different, 1.0 = identical
    verdict: str = "unknown"  # "identical", "minor_changes", "major_changes", "missing", "unknown"


class LiveTestResult(BaseModel):
    """Result of running the reproducer against the target kernel."""

    repro_compiled: bool = False
    repro_ran: bool = False
    crash_triggered: bool = False
    crash_signature_match: bool = False
    crash_log_excerpt: str = ""
    expected_functions: List[str] = Field(default_factory=list)
    matched_functions: List[str] = Field(default_factory=list)
    verdict: str = "unknown"  # "triggered", "no_crash", "different_crash", "compile_fail", "unknown"


class GdbPathCheckResult(BaseModel):
    """Result of GDB-based crash-path verification.

    Attaches GDB to a running kernel with breakpoints on the expected
    crash-stack functions, runs the reproducer, and checks which fire.
    """

    expected_functions: List[str] = Field(default_factory=list)
    hit_functions: List[str] = Field(default_factory=list)
    missed_functions: List[str] = Field(default_factory=list)
    func_hit_counts: Dict[str, int] = Field(default_factory=dict)
    events_captured: int = 0
    crash_detected: bool = False
    crash_backtrace: List[str] = Field(default_factory=list)
    hit_ratio: float = 0.0
    verdict: str = "unknown"  # "path_confirmed", "partial_path", "path_diverged", "no_hits", "error", "unknown"


class DmesgLogAnalysis(BaseModel):
    """Analysis of dmesg / GDB logs for dynamic feasibility evidence.

    When KASAN is not enabled, crashes are unlikely.  This model captures
    evidence from dmesg patterns (allocation activity, binder messages,
    subsystem activity) and GDB breakpoint hits to determine if the
    vulnerable code path was exercised.
    """

    # Allocation / free patterns found in dmesg
    alloc_patterns: List[str] = Field(default_factory=list)
    free_patterns: List[str] = Field(default_factory=list)

    # Subsystem-specific activity observed (e.g. binder transactions)
    subsystem_activity: List[str] = Field(default_factory=list)

    # GDB log lines showing breakpoint hits, watchpoints, etc.
    gdb_breakpoint_hits: List[str] = Field(default_factory=list)
    gdb_log_excerpt: str = ""

    # New dmesg lines relevant to the vulnerability
    dmesg_new_lines: List[str] = Field(default_factory=list)
    dmesg_excerpt: str = ""

    # Evidence summary
    evidence_score: float = 0.0  # 0.0 = no evidence, 1.0 = strong evidence
    verdict: str = "unknown"  # "strong_evidence", "weak_evidence", "no_evidence", "unknown"
    notes: List[str] = Field(default_factory=list)


class FeasibilityReport(BaseModel):
    """Comprehensive feasibility assessment for cross-version exploitation."""

    bug_id: str = ""
    original_kernel: str = ""
    target_kernel: str = ""

    verdict: str = "unknown"  # "likely_feasible", "likely_patched", "inconclusive", "unknown"
    confidence: float = 0.0  # 0.0 – 1.0 continuous score

    # Per-check results (None = check was skipped)
    symbol_check: Optional[SymbolCheckResult] = None
    fix_check: Optional[FixBackportResult] = None
    source_diff: Optional[SourceDiffResult] = None
    live_test: Optional[LiveTestResult] = None
    gdb_path_check: Optional[GdbPathCheckResult] = None
    dynamic_log_analysis: Optional[DmesgLogAnalysis] = None

    notes: List[str] = Field(default_factory=list)

    def summary(self) -> str:
        lines = [
            f"=== Feasibility Report: {self.bug_id or '(unknown)'} ===",
            f"  Original kernel : {self.original_kernel or 'N/A'}",
            f"  Target kernel   : {self.target_kernel or 'N/A'}",
            f"  Verdict         : {self.verdict}",
            f"  Confidence      : {self.confidence:.0%}",
        ]
        if self.symbol_check:
            sc = self.symbol_check
            lines.append(
                f"  Symbol check    : {sc.verdict} "
                f"({len(sc.symbols_found)}/{len(sc.symbols_checked)} found)"
            )
        if self.fix_check:
            lines.append(f"  Fix backport    : {self.fix_check.verdict}")
        if self.source_diff:
            sd = self.source_diff
            lines.append(
                f"  Source diff      : {sd.verdict} "
                f"(similarity={sd.similarity_ratio:.0%})"
            )
        if self.live_test:
            lines.append(f"  Live test       : {self.live_test.verdict}")
        if self.gdb_path_check:
            gpc = self.gdb_path_check
            lines.append(
                f"  GDB path check  : {gpc.verdict} "
                f"({len(gpc.hit_functions)}/{len(gpc.expected_functions)} hit, "
                f"ratio={gpc.hit_ratio:.0%})"
            )
        if self.dynamic_log_analysis:
            dla = self.dynamic_log_analysis
            lines.append(
                f"  Dynamic log     : {dla.verdict} "
                f"(evidence_score={dla.evidence_score:.0%}, "
                f"bp_hits={len(dla.gdb_breakpoint_hits)}, "
                f"alloc={len(dla.alloc_patterns)}, "
                f"free={len(dla.free_patterns)})"
            )
        for note in self.notes:
            lines.append(f"  Note: {note}")
        return "\n".join(lines)


# ── Primitives & exploit planning ─────────────────────────────────────


class Primitive(BaseModel):
    """A capability primitive contributed by an adapter or analysis."""

    name: str
    category: str = ""
    description: str = ""
    requirements: Dict[str, Any] = Field(default_factory=dict)
    provides: Dict[str, Any] = Field(default_factory=dict)
    code_template: Optional[str] = None
    pddl_predicates: List[str] = Field(default_factory=list)


class ExploitStep(BaseModel):
    """A single step in an exploit plan."""

    name: str
    action: str = ""
    description: str = ""
    requires: List[str] = Field(default_factory=list)
    provides: List[str] = Field(default_factory=list)
    provider: str = ""
    code_hint: str = ""
    code: Optional[str] = None


class ExploitPlan(BaseModel):
    """
    Canonical exploit plan — the unified representation used everywhere.

    Replaces the three incompatible definitions from the old codebase.
    """

    vulnerability_type: VulnType = VulnType.UNKNOWN
    target_struct: str = ""
    slab_cache: str = ""
    technique: str = ""
    steps: List[ExploitStep] = Field(default_factory=list)
    goal: str = "privilege_escalation"
    platform: Platform = Platform.LINUX
    target_arch: Arch = Arch.X86_64
    target_kernel: str = ""
    offsets: Dict[str, int] = Field(default_factory=dict)
    target_info: Dict[str, Any] = Field(default_factory=dict)
    primitives: List[Primitive] = Field(default_factory=list)
    notes: List[str] = Field(default_factory=list)
    constants: Dict[str, Any] = Field(default_factory=dict)
    exploitation_technique: str = ""
    description: str = ""
    code_hints: Dict[str, str] = Field(default_factory=dict)
    poc_path: Optional[str] = None
    poc_source: Optional[str] = None

    def action_names(self) -> List[str]:
        return [s.name for s in self.steps]


# ── Pipeline results ──────────────────────────────────────────────────


class ReproducerResult(BaseModel):
    """Result of reproducer generation + verification."""

    success: bool = False
    source_code: Optional[str] = None
    source_path: Optional[str] = None
    binary_path: Optional[str] = None
    crash_confirmed: bool = False
    crash_log: Optional[str] = None
    target_kernel: str = ""
    arch: Arch = Arch.X86_64
    notes: List[str] = Field(default_factory=list)


class VerificationAttempt(BaseModel):
    """Record of a single exploit or reproducer verification attempt.

    Stored in ``TaskContext.verification_history`` so the agent can
    review past attempts and adjust strategy accordingly.
    """

    attempt_number: int = 1
    target: str = ""  # "exploit" or "reproducer"
    binary_path: Optional[str] = None
    success: bool = False

    # Exploit-specific
    uid_before: Optional[int] = None
    uid_after: Optional[int] = None
    privilege_escalated: bool = False

    # Crash-specific (reproducer or exploit side-effect)
    crash_occurred: bool = False
    crash_pattern: str = ""
    crash_log_excerpt: str = ""

    # Device health
    device_stable: bool = True

    # Actionable feedback for the agent
    failure_reason: str = ""
    feedback: str = ""

    # Raw outputs
    exploit_output: str = ""
    dmesg_new: str = ""

    # GDB trace results (structured — not buried in free-text feedback)
    gdb_functions_hit: List[str] = Field(default_factory=list)
    gdb_functions_missed: List[str] = Field(default_factory=list)
    gdb_crash_info: Optional[Dict[str, Any]] = None  # registers, backtrace at crash


class ExploitResult(BaseModel):
    """Result of exploit generation + verification."""

    success: bool = False
    plan: Optional[ExploitPlan] = None
    source_code: Optional[str] = None
    source_path: Optional[str] = None
    binary_path: Optional[str] = None
    privilege_escalation_confirmed: bool = False
    uid_before: Optional[int] = None
    uid_after: Optional[int] = None
    verification_log: Optional[str] = None
    target_kernel: str = ""
    arch: Arch = Arch.X86_64
    notes: List[str] = Field(default_factory=list)


# ── Execution tracing ─────────────────────────────────────────────────


class TraceStep(BaseModel):
    """A single recorded step in an agentic execution trace.

    Captures *what* the agent chose, *why* (LLM reasoning), the pipeline
    state before and after, timing, and what artefacts changed.
    """

    step: int
    timestamp: str = ""  # ISO-8601 UTC
    tool: str = ""
    reason: str = ""
    kwargs: Dict[str, Any] = Field(default_factory=dict)
    duration_ms: float = 0.0
    success: bool = True
    error: str = ""

    # Compact state snapshots (bool flags + key identifiers)
    state_before: Dict[str, Any] = Field(default_factory=dict)
    state_after: Dict[str, Any] = Field(default_factory=dict)

    # Which artefacts were newly produced or changed by this step
    state_changed: List[str] = Field(default_factory=list)


class ExecutionTrace(BaseModel):
    """Full execution trace for one syzploit run.

    Written to ``execution_trace.json`` in *work_dir* so that
    different runs on the same input can be compared side-by-side.
    """

    run_id: str = ""
    mode: str = ""  # "agent" or "pipeline"
    goal: str = ""
    started_at: str = ""
    finished_at: str = ""
    total_steps: int = 0
    total_duration_ms: float = 0.0
    final_outcome: str = ""  # "done", "stop", "max_iterations", "error"
    final_reason: str = ""

    input_type: str = ""
    input_value: str = ""
    target_kernel: str = ""
    target_arch: str = ""
    target_platform: str = ""

    # Ordered list of tool names — the "signature" of a run
    tool_sequence: List[str] = Field(default_factory=list)
    steps: List[TraceStep] = Field(default_factory=list)
    errors: List[str] = Field(default_factory=list)

