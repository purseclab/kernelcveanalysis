"""
orchestrator.context — Mutable accumulator for pipeline artefacts.

``TaskContext`` is passed between every tool invocation so that
later stages can see what earlier stages produced.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from ..core.models import (
    Arch,
    CrashReport,
    ExecutionTrace,
    ExploitPlan,
    ExploitResult,
    FeasibilityReport,
    Platform,
    ReproducerResult,
    RootCauseAnalysis,
    TargetSystemInfo,
    TraceStep,
    VerificationAttempt,
)


class TaskContext(BaseModel):
    """
    Running state for a single syzploit invocation.

    Every tool reads from and writes to this context, keeping
    the orchestrator loop stateless with respect to individual tools.
    """

    # ── Input ─────────────────────────────────────────────────────────
    input_type: str = ""  # "cve", "syzbot", "crash_log", "blog_post", "poc"
    input_value: str = ""  # The raw input (CVE-ID, URL, file path, etc.)

    # ── Target environment ────────────────────────────────────────────
    target_kernel: str = ""
    target_arch: Arch = Arch.ARM64
    target_platform: Platform = Platform.ANDROID

    # ── Additional input context ──────────────────────────────────────
    blog_urls: List[str] = Field(default_factory=list)
    extra_context: str = ""

    # ── SSH / VM configuration (overrides from CLI) ───────────────────
    ssh_host: str = ""
    ssh_port: int = 22
    instance: Optional[int] = None
    start_cmd: str = ""
    stop_cmd: str = ""
    exploit_start_cmd: str = ""
    kernel_image: str = ""
    gdb_port: int = 1234
    setup_tunnels: bool = False
    persistent: bool = True

    # ── Accumulated artefacts ─────────────────────────────────────────
    crash_report: Optional[CrashReport] = None
    root_cause: Optional[RootCauseAnalysis] = None
    target_system_info: Optional[TargetSystemInfo] = None
    feasibility: Optional[FeasibilityReport] = None
    reproducer: Optional[ReproducerResult] = None
    exploit_plan: Optional[ExploitPlan] = None
    exploit_result: Optional[ExploitResult] = None

    # ── Verification / feedback loop ──────────────────────────────────
    verification_history: List[VerificationAttempt] = Field(default_factory=list)
    max_verification_attempts: int = 5  # per artefact type

    # ── Working directory for intermediate files ──────────────────────
    work_dir: Optional[Path] = None

    # ── Raw analysis JSON (compatibility with old static_analysis.json)
    analysis_data: Dict[str, Any] = Field(default_factory=dict)

    # ── New module artefacts ──────────────────────────────────────────
    kernel_offsets_header: str = ""  # Generated kernel_offsets.h content
    kernel_source_context: str = ""  # Extracted kernel source for LLM
    spray_strategy: Optional[Dict[str, Any]] = None  # Slab oracle results
    resolved_symbols: Dict[str, int] = Field(default_factory=dict)  # Symbol → address

    # ── GDB trace accumulator (structured for agent decisions) ────────
    gdb_trace_results: List[Dict[str, Any]] = Field(default_factory=list)
    # Each entry: {"target": "exploit"|"reproducer", "attempt": N,
    #              "functions_hit": [...], "functions_missed": [...],
    #              "crash_info": {...} or None}

    # ── Logs / decisions made by the agent ────────────────────────────
    history: List[Dict[str, Any]] = Field(default_factory=list)
    errors: List[str] = Field(default_factory=list)

    # ── Execution tracing (agentic run comparison) ────────────────────
    run_id: str = Field(default_factory=lambda: uuid.uuid4().hex[:12])
    run_started_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    execution_trace: Optional[ExecutionTrace] = None

    class Config:
        arbitrary_types_allowed = True

    # ── Helpers ───────────────────────────────────────────────────────

    def log(self, tool: str, action: str, detail: str = "") -> None:
        """Append an event to the history trace."""
        self.history.append({
            "tool": tool,
            "action": action,
            "detail": detail,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

    def state_snapshot(self) -> Dict[str, Any]:
        """Capture a compact snapshot of current pipeline state.

        Used for execution tracing — records which artefacts exist and
        key status flags so we can see exactly what changed after each
        agent step.
        """
        return {
            "has_crash_report": self.crash_report is not None,
            "has_root_cause": self.root_cause is not None,
            "has_target_info": self.target_system_info is not None,
            "has_feasibility": self.feasibility is not None,
            "feasibility_verdict": (
                self.feasibility.verdict if self.feasibility else None
            ),
            "has_reproducer": self.has_reproducer(),
            "reproducer_verified": self.has_verified_reproducer(),
            "has_exploit_plan": self.exploit_plan is not None,
            "has_exploit": self.has_exploit(),
            "exploit_verified": self.has_verified_exploit(),
            "has_kernel_offsets": bool(self.kernel_offsets_header),
            "has_kernel_source": bool(self.kernel_source_context),
            "has_spray_strategy": self.spray_strategy is not None,
            "resolved_symbol_count": len(self.resolved_symbols),
            "has_gdb_traces": len(self.gdb_trace_results) > 0,
            "exploit_verify_count": len(self.exploit_verification_attempts()),
            "repro_verify_count": len(self.reproducer_verification_attempts()),
            "error_count": len(self.errors),
        }

    def has_crash(self) -> bool:
        return self.crash_report is not None

    def has_root_cause(self) -> bool:
        return self.root_cause is not None

    def has_vuln_info(self) -> bool:
        """True if we have enough vulnerability info for feasibility checks.

        Returns True when either a crash report exists (with stack frames)
        or a root cause analysis exists (with kernel_functions from
        CVE / blog analysis).  In either case we have function names
        and subsystem information to check against the target.
        """
        if self.crash_report and self.crash_report.stack_frames:
            return True
        if self.root_cause and self.root_cause.kernel_functions:
            return True
        return False

    def has_reproducer(self) -> bool:
        return self.reproducer is not None and self.reproducer.success

    def has_exploit(self) -> bool:
        return self.exploit_result is not None and self.exploit_result.success

    def has_verified_exploit(self) -> bool:
        """True if the exploit has been verified as achieving privesc."""
        return (
            self.exploit_result is not None
            and self.exploit_result.privilege_escalation_confirmed
        )

    def has_verified_reproducer(self) -> bool:
        """True if the reproducer has been verified to trigger a crash."""
        return (
            self.reproducer is not None
            and self.reproducer.crash_confirmed
        )

    def exploit_verification_attempts(self) -> List[VerificationAttempt]:
        """Return only exploit-targeted verification attempts."""
        return [v for v in self.verification_history if v.target == "exploit"]

    def reproducer_verification_attempts(self) -> List[VerificationAttempt]:
        """Return only reproducer-targeted verification attempts."""
        return [v for v in self.verification_history if v.target == "reproducer"]

    def can_retry_exploit_verification(self) -> bool:
        """True if we haven't exceeded the max attempts for exploit verification."""
        return len(self.exploit_verification_attempts()) < self.max_verification_attempts

    def can_retry_reproducer_verification(self) -> bool:
        """True if we haven't exceeded the max attempts for reproducer verification."""
        return len(self.reproducer_verification_attempts()) < self.max_verification_attempts

    def last_verification_feedback(self) -> str:
        """Return the feedback string from the most recent verification attempt."""
        if self.verification_history:
            return self.verification_history[-1].feedback
        return ""

    def format_gdb_trace_context(self) -> str:
        """Format accumulated GDB trace results for inclusion in LLM prompts.

        Returns a human-readable summary of which kernel functions were
        reached during reproducer/exploit verification.  This gives the
        LLM concrete evidence about what code paths are actually
        triggered, which is far more useful than guessing.
        """
        if not self.gdb_trace_results:
            return ""

        parts = ["=== GDB Kernel Path Trace Results ==="]
        for trace in self.gdb_trace_results:
            target = trace.get("target", "?")
            attempt = trace.get("attempt", "?")
            hit = trace.get("functions_hit", [])
            missed = trace.get("functions_missed", [])
            crash_info = trace.get("crash_info")

            parts.append(f"\n[{target} attempt {attempt}]")
            if hit:
                parts.append(f"  Functions REACHED: {', '.join(hit)}")
            if missed:
                parts.append(f"  Functions NOT reached: {', '.join(missed)}")
            if crash_info:
                if crash_info.get("crash_function"):
                    parts.append(f"  Crash location: {crash_info['crash_function']}")
                if crash_info.get("backtrace"):
                    parts.append(f"  Backtrace:\n    {crash_info['backtrace'][:500]}")
                if crash_info.get("registers"):
                    parts.append(f"  Registers: {crash_info['registers'][:300]}")

        parts.append(
            "\nUse these results to understand which exploit stages succeed "
            "and where the exploit diverges from expected behavior."
        )
        return "\n".join(parts)
