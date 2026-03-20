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
    extra_context: str = ""  # Free-form text injected into prompts
    reference_exploit_path: str = ""  # Path to a reference exploit file/dir

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
    static_only: bool = False  # --static: skip all VM/ADB/SSH steps

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
    max_verification_attempts: int = 15  # per artefact type

    # ── Working directory for intermediate files ──────────────────────
    work_dir: Optional[Path] = None

    # ── Raw analysis JSON (compatibility with old static_analysis.json)
    analysis_data: Dict[str, Any] = Field(default_factory=dict)

    # ── Structured investigation briefing (pre-formatted prompt sections)
    investigation_briefing: Optional[Any] = None  # InvestigationBriefing

    # ── Vulnerability pre/post conditions ─────────────────────────────
    vuln_conditions: Optional[Any] = None  # VulnConditions from analysis.vuln_conditions

    # ── New module artefacts ──────────────────────────────────────────
    kernel_offsets_header: str = ""  # Generated kernel_offsets.h content
    kernel_source_context: str = ""  # Extracted kernel source for LLM
    spray_strategy: Optional[Dict[str, Any]] = None  # Slab oracle results
    resolved_symbols: Dict[str, int] = Field(default_factory=dict)  # Symbol → address

    # ── Reflection briefs (intermediate LLM reasoning) ────────────────
    reflection_brief: str = ""  # Latest LLM reflection on gathered data
    reflection_count: int = 0   # How many reflections have been done

    # ── GDB trace accumulator (structured for agent decisions) ────────
    gdb_trace_results: List[Dict[str, Any]] = Field(default_factory=list)
    # Each entry: {"target": "exploit"|"reproducer", "attempt": N,
    #              "functions_hit": [...], "functions_missed": [...],
    #              "crash_info": {...} or None}

    # ── Prompt strategy tracking (auto-rotate on consecutive failures) ─
    strategy_tracker_state: Optional[Any] = Field(default=None, exclude=True)

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

    def is_done(self) -> bool:
        """True if the pipeline has reached a terminal success state.

        A task is considered done when the exploit has been verified
        to achieve privilege escalation.
        """
        return self.has_verified_exploit()

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

    def get_strategy_tracker(self) -> Any:
        """Get or create the StrategyTracker for exploit prompt rotation.

        Returns a ``StrategyTracker`` instance that persists across
        generate → verify → regenerate cycles.  When one prompting
        approach fails twice in a row, the tracker automatically
        rotates to a different approach.
        """
        if self.strategy_tracker_state is None:
            from ..exploit.prompt_strategies import StrategyTracker
            self.strategy_tracker_state = StrategyTracker()
        return self.strategy_tracker_state

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

    # ── Decision-prompt context ───────────────────────────────────────

    def decision_context_summary(self) -> str:
        """Build a compact summary of all accumulated knowledge for the
        agent's decision prompt.

        This surfaces information from ``analysis_data``, root cause,
        crash report, feasibility, investigation, and GDB traces that
        would otherwise be invisible to the decision LLM.  The agent
        can use this to make informed choices about which tools to call
        and what parameters to pass.
        """
        sections: list[str] = []

        # ── Root cause summary ────────────────────────────────────────
        if self.root_cause:
            rc = self.root_cause
            rc_parts = []
            if rc.vulnerability_type:
                rc_parts.append(f"Bug type: {rc.vulnerability_type.value}")
            if rc.vulnerable_function:
                rc_parts.append(f"Vulnerable function: {rc.vulnerable_function}")
            if rc.affected_subsystem:
                rc_parts.append(f"Subsystem: {rc.affected_subsystem}")
            if rc.kernel_functions:
                rc_parts.append(
                    f"Related functions: {', '.join(rc.kernel_functions[:8])}"
                )
            if rc.exploitation_details:
                ed = rc.exploitation_details
                if isinstance(ed, dict):
                    if ed.get("technique"):
                        rc_parts.append(f"Technique: {ed['technique']}")
                    if ed.get("slab_cache"):
                        rc_parts.append(f"Target slab: {ed['slab_cache']}")
            if rc.summary:
                rc_parts.append(f"Summary: {rc.summary[:200]}")
            if rc_parts:
                sections.append("Root cause:\n  " + "\n  ".join(rc_parts))

        # ── Feasibility verdict ───────────────────────────────────────
        if self.feasibility:
            f = self.feasibility
            verdict = getattr(f, "verdict", "unknown")
            # FeasibilityReport.summary is a method, not a field — call it
            reason = getattr(f, "reasoning", "")
            if not reason:
                _summary = getattr(f, "summary", "")
                reason = _summary() if callable(_summary) else (_summary or "")
            if not isinstance(reason, str):
                reason = str(reason) if reason else ""
            sections.append(
                f"Feasibility: {verdict}"
                + (f" — {reason[:150]}" if reason else "")
            )

        # ── Analysis data keys (what prep the agent has gathered) ─────
        if self.analysis_data:
            ad_parts = []
            # Keys whose values need expanded display for
            # the reflection to reason about dynamic analysis.
            _EXPANDED_KEYS = {
                "gdb_command_output", "target_command_output",
                "gdb_last_command", "gdb_session_status",
                "dynamic_exploitation_notes",
            }
            for key, val in self.analysis_data.items():
                if val is None:
                    continue
                expanded = key in _EXPANDED_KEYS
                # Show a compact summary depending on the type
                if isinstance(val, dict):
                    if expanded:
                        # Show most useful fields from substep outputs
                        _parts = []
                        for dk in ("command", "output", "returncode",
                                   "summary", "technique"):
                            if dk in val:
                                _parts.append(
                                    f"{dk}={str(val[dk])[:300]}"
                                )
                        if _parts:
                            ad_parts.append(
                                f"{key}: " + "; ".join(_parts)
                            )
                        else:
                            ad_parts.append(
                                f"{key}: (dict, {len(val)} keys)"
                            )
                    else:
                        summary = val.get(
                            "summary", val.get("technique", "")
                        )
                        if summary:
                            ad_parts.append(
                                f"{key}: {str(summary)[:100]}"
                            )
                        else:
                            ad_parts.append(
                                f"{key}: (dict, {len(val)} keys)"
                            )
                elif isinstance(val, list):
                    ad_parts.append(f"{key}: ({len(val)} items)")
                elif isinstance(val, str):
                    if expanded:
                        ad_parts.append(f"{key}:\n{val[:500]}")
                    else:
                        ad_parts.append(f"{key}: {val[:80]}")
                else:
                    ad_parts.append(f"{key}: {str(val)[:60]}")
            if ad_parts:
                sections.append(
                    "Gathered data:\n  " + "\n  ".join(ad_parts[:15])
                )

        # ── Investigation briefing summary ────────────────────────────
        if self.investigation_briefing:
            ib = self.investigation_briefing
            ib_parts = []
            if hasattr(ib, "exploits_found") and ib.exploits_found:
                ib_parts.append(
                    f"Reference exploits: {len(ib.exploits_found)}"
                )
            if hasattr(ib, "patches_found") and ib.patches_found:
                ib_parts.append(f"Patches: {len(ib.patches_found)}")
            if hasattr(ib, "technique_hints") and ib.technique_hints:
                ib_parts.append(
                    f"Techniques: {', '.join(ib.technique_hints[:3])}"
                )
            if ib_parts:
                sections.append(
                    "Investigation: " + "; ".join(ib_parts)
                )

        # ── Exploit plan summary ──────────────────────────────────────
        if self.exploit_plan:
            ep = self.exploit_plan
            ep_parts = []
            if hasattr(ep, "technique") and ep.technique:
                ep_parts.append(f"Technique: {ep.technique}")
            if hasattr(ep, "slab_cache") and ep.slab_cache:
                ep_parts.append(f"Target slab: {ep.slab_cache}")
            if hasattr(ep, "steps") and ep.steps:
                ep_parts.append(f"Steps: {len(ep.steps)}")
            if ep_parts:
                sections.append("Exploit plan: " + ", ".join(ep_parts))

        # ── Strategy tracker state ────────────────────────────────────
        try:
            st = self.get_strategy_tracker()
            sections.append(
                f"Strategy: {st.current_strategy_name.value}, "
                f"{st._consecutive_failures} consecutive failures, "
                f"{st._total_attempts} total attempts"
            )
        except Exception:
            pass

        # ── GDB trace summary (with crash diagnostics) ─────────────────
        if self.gdb_trace_results:
            # Aggregate functions hit/missed across ALL traces
            all_hit: set[str] = set()
            all_missed: set[str] = set()
            for trace in self.gdb_trace_results:
                all_hit.update(trace.get("functions_hit", []))
                all_missed.update(trace.get("functions_missed", []))
            # Remove functions that were hit in any attempt
            only_missed = all_missed - all_hit

            trace_parts = []
            if all_hit:
                trace_parts.append(
                    f"Functions reached (any attempt): "
                    f"{', '.join(sorted(all_hit)[:10])}"
                )
            if only_missed:
                trace_parts.append(
                    f"Functions NEVER reached: "
                    f"{', '.join(sorted(only_missed)[:10])}"
                )

            # Show crash info from most recent trace
            last_trace = self.gdb_trace_results[-1]
            crash_info = last_trace.get("crash_info")
            if crash_info:
                if crash_info.get("crash_function"):
                    trace_parts.append(
                        f"Last crash at: {crash_info['crash_function']}"
                    )
                if crash_info.get("backtrace"):
                    trace_parts.append(
                        f"Backtrace: {crash_info['backtrace'][:300]}"
                    )

            trace_parts.append(
                f"({len(self.gdb_trace_results)} total GDB traces)"
            )
            sections.append(
                "GDB traces:\n  " + "\n  ".join(trace_parts)
            )

        # ── Recent interactive GDB commands ──────────────────────────
        gdb_history = self.analysis_data.get("gdb_command_history", [])
        if gdb_history:
            hist_lines = []
            for entry in gdb_history[-5:]:
                cmd = entry.get("command", "?")
                out = entry.get("output", "")
                # Truncate output for compact display
                out_preview = out[:100].replace("\n", " ")
                if len(out) > 100:
                    out_preview += "..."
                hist_lines.append(f"  >>> {cmd}  →  {out_preview}")
            sections.append(
                "Recent GDB commands:\n" + "\n".join(hist_lines)
            )

        # ── Latest reflection brief ──────────────────────────────────
        if self.reflection_brief:
            sections.append(
                f"REFLECTION (#{self.reflection_count}):\n"
                + self.reflection_brief
            )

        if not sections:
            return ""
        return "\n".join(sections)
