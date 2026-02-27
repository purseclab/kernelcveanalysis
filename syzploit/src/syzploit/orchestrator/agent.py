"""
orchestrator.agent — LLM-driven agentic loop.

The ``Agent`` receives an input, classifies it, then iteratively
decides which tool to call next until the goal is achieved or no
further progress can be made.

Cost-reduction strategies:
- Regex-based input classification skips LLM for obvious patterns
- Context-aware tool filtering shows only relevant tools per state
- Optional cheaper model for decision routing (SYZPLOIT_LLM_DECISION_MODEL)
- Decision calls use capped max_tokens (1024 vs 8192 for generation)
- Failed-tool tracking prevents re-invoking the same broken tool
- Compressed history format reduces prompt tokens
"""

from __future__ import annotations

import json
import re
import time
import traceback
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set

from ..core.config import Config, load_config
from ..core.llm import LLMClient
from ..core.log import console
from ..core.models import ExecutionTrace, TraceStep
from ..core.reporting import save_execution_trace, save_pipeline_summary
from .context import TaskContext
from .tools import ToolRegistry, default_registry

# Maximum reasoning iterations before we force-stop
_MAX_ITERATIONS = 20

# ── Input classification ──────────────────────────────────────────────

_INPUT_CLASSIFICATION_PROMPT = """\
Classify the following input into exactly one category and return JSON:
{{"type": "<type>", "value": "<cleaned value>"}}

Categories:
- "cve"        — a CVE identifier (e.g. CVE-2024-36971)
- "syzbot"     — a syzbot bug URL or bug ID
- "crash_log"  — raw kernel crash / KASAN / UBSAN log text
- "blog_post"  — a URL to a blog post or write-up
- "poc"        — path to a C proof-of-concept source file

Input:
{input}
"""

# ── Agent decision prompt ─────────────────────────────────────────────

_DECISION_PROMPT = """\
You are the syzploit orchestrator.  Your goal: {goal}

Available tools:
{tools}

Current state:
- Input: {input_type} = {input_value}
- Has crash report: {has_crash}
- Has root cause analysis: {has_root_cause}
- Has vulnerability info (crash stack or CVE functions): {has_vuln_info}
- Has target system info (kernel version, kallsyms): {has_target_info}
- Has kernel offsets (resolved symbols/structs): {has_kernel_offsets}
- Has kernel source context: {has_kernel_source}
- Has spray strategy: {has_spray_strategy}
- Has reproducer: {has_reproducer}
- Reproducer verified (crash confirmed): {reproducer_verified}
- Has exploit: {has_exploit}
- Exploit verified (privesc confirmed): {exploit_verified}
- Target kernel: {target_kernel}
- SSH host configured: {has_ssh}
- Verification attempts (exploit): {exploit_verify_count}/{max_verify_attempts}
- Verification attempts (reproducer): {repro_verify_count}/{max_verify_attempts}
- Errors so far: {errors}

{verification_feedback}

History of actions taken:
{history}

WORKFLOW GUIDANCE:
- For CVE-only or blog-only inputs (no crash log), after 'analyze', call
  'collect_target_info' to boot the VM and gather the target kernel version,
  /proc/kallsyms, and other system info.  Then call 'check_feasibility_static'
  which will use the collected kallsyms to verify vulnerable symbols exist.
- For crash-log or syzbot inputs, you already have stack frames — proceed
  directly to feasibility checks.
- BEFORE generating an exploit, call 'resolve_kernel_offsets' (if kallsyms or
  vmlinux is available) to get real kernel addresses and struct offsets.
  This prevents the LLM from hallucinating incorrect values.
- Optionally call 'get_spray_strategy' to query the slab oracle for heap
  spray recommendations when the exploit involves heap spraying.
- Optionally call 'get_kernel_source' to extract real source code of
  vulnerable functions for LLM context (requires kernel_tree_path config).
- If kexploit is installed, you have three additional tools:
  * 'query_struct_offsets' — look up struct field offsets from BTF data for
    the target kernel. Use this instead of guessing struct layouts.
  * 'query_codeql_allocations' — query CodeQL databases for kernel
    allocation sites (kmalloc, kzalloc, etc.) related to a struct or
    subsystem. Useful when crafting heap spray strategies.
  * 'adapt_exploit_offsets' — translate addresses, ROP gadgets, and struct
    offsets from one kernel version to another using vmlinux ELF binaries.
    Essential when porting a known exploit to a different kernel build.
- After generating an exploit or reproducer, you MUST verify it on the
  target device using verify_exploit or verify_reproducer (if SSH is
  configured).
- If verification fails, read the feedback and device output carefully.
  Common issues on Android:
    * BINDER_SET_CONTEXT_MGR returns EBUSY → use fork() so child becomes
      context manager, or try /dev/hwbinder / /dev/vndbinder
    * ioctl returns EINVAL → struct fields or buffer sizes are wrong
    * msg_msg returns ENOSYS → use pipe_buffer or seq_operations for spray
    * kallsyms returns zeros → restricted on Android, use other leak methods
  Decide whether to regenerate with fixes, try a different technique, or stop.
- CRITICAL: If exploit verification fails (UID didn't change), call 'exploit'
  again to regenerate with the failure feedback — do NOT keep calling
  'check_feasibility_dynamic' or 'check_feasibility_static' in a loop.
  The feasibility was already confirmed.  Focus on FIXING THE EXPLOIT.
- NEVER call the same tool more than twice in a row without calling a
  different tool in between.  If your approach isn't working after 2
  attempts, change strategy (e.g., try 'exploit' with a different technique,
  or call 'analyze' to re-examine the vulnerability).

The task is NOT complete until the exploit is verified (privilege
escalation confirmed) or all retry options are exhausted.

Decide the NEXT action.  Return JSON:
{{"tool": "<tool_name>", "reason": "<why>", "kwargs": {{}}}}

If the goal is fully achieved (exploit verified), return:
{{"tool": "done", "reason": "<summary>"}}

If no further progress is possible, return:
{{"tool": "stop", "reason": "<explanation>"}}

IMPORTANT: Keep your "reason" field concise (1-2 sentences max).
Return ONLY the JSON object, no other text.
"""


class Agent:
    """
    LLM-driven orchestrator that coordinates syzploit components.

    Usage::

        agent = Agent(goal="analyze and exploit")
        result = agent.run("CVE-2024-36971", target_kernel="6.1.75")
    """

    def __init__(
        self,
        *,
        goal: str = "Analyze the vulnerability, understand root cause, generate a reproducer, and produce an exploit",
        registry: Optional[ToolRegistry] = None,
        cfg: Optional[Config] = None,
    ) -> None:
        self.goal = goal
        self.registry = registry or default_registry
        self.cfg = cfg or load_config()
        self.llm = LLMClient(self.cfg)
        self.decision_llm = self.llm.for_task("decision")

        # Track tools that repeatedly fail to avoid re-invoking them
        self._tool_fail_count: Dict[str, int] = {}
        self._max_tool_failures = 2

        # Track consecutive same-tool invocations (loop detection)
        self._consecutive_tool: str = ""
        self._consecutive_count: int = 0
        self._max_consecutive_same_tool: int = 2  # force different tool after 2 repeats

    # ── Public entry-point ────────────────────────────────────────────

    def run(
        self,
        input_value: str,
        *,
        target_kernel: str = "",
        target_arch: str = "arm64",
        target_platform: str = "android",
        work_dir: Optional[str] = None,
        ctx: Optional[TaskContext] = None,
    ) -> TaskContext:
        """
        Run the agentic loop on the given input.

        Returns the final ``TaskContext`` with all accumulated artefacts.
        A full ``ExecutionTrace`` is attached to ``ctx.execution_trace``
        and saved as ``execution_trace.json`` so different runs can be
        compared later.

        Parameters
        ----------
        ctx:
            Optional pre-built ``TaskContext`` with infra options already
            populated (SSH, instance, start/stop commands, etc.).  When
            provided, the ``target_*`` / ``work_dir`` keyword args are
            ignored (they're already in ctx).
        """
        from ..core.models import Arch, Platform
        from pathlib import Path

        run_start = time.monotonic()

        if ctx is None:
            ctx = TaskContext(
                input_value=input_value,
                target_kernel=target_kernel,
                target_arch=Arch(target_arch) if target_arch in ("x86_64", "arm64") else Arch.ARM64,
                target_platform=Platform(target_platform) if target_platform in ("linux", "android", "generic") else Platform.ANDROID,
                work_dir=Path(work_dir) if work_dir else None,
            )
        else:
            # Ensure input_value is set even when ctx is pre-built
            if not ctx.input_value:
                ctx.input_value = input_value

        # Initialise the execution trace
        trace = ExecutionTrace(
            run_id=ctx.run_id,
            mode="agent",
            goal=self.goal,
            started_at=ctx.run_started_at,
            input_type="(pending classification)",
            input_value=input_value[:200],
            target_kernel=target_kernel,
            target_arch=ctx.target_arch.value,
            target_platform=ctx.target_platform.value,
        )

        # Step 0: classify input
        ctx = self._classify_input(ctx)
        trace.input_type = ctx.input_type

        # Agentic reasoning loop
        final_outcome = "max_iterations"
        final_reason = f"Reached {_MAX_ITERATIONS} iterations without done/stop"

        for iteration in range(1, _MAX_ITERATIONS + 1):
            decision = self._decide_next(ctx)
            tool_name = decision.get("tool", "stop")
            reason = decision.get("reason", "")
            kwargs = decision.get("kwargs", {})

            if tool_name in ("done", "stop"):
                ctx.log("agent", tool_name, reason)
                console.print(f"[bold green]Agent {tool_name}:[/] {reason}")
                final_outcome = tool_name
                final_reason = reason
                break

            # ── Block tools that repeatedly fail ──────────────────────
            if self._tool_fail_count.get(tool_name, 0) >= self._max_tool_failures:
                msg = f"{tool_name} blocked (failed {self._max_tool_failures}+ times)"
                ctx.log("agent", "skip_blocked", msg)
                console.print(f"[yellow]Skipping {tool_name}:[/] {msg}")
                trace.steps.append(TraceStep(
                    step=iteration,
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    tool=tool_name,
                    reason=reason,
                    success=False,
                    error=msg,
                ))
                continue

            # ── Detect tool-repetition loops ──────────────────────────
            if tool_name == self._consecutive_tool:
                self._consecutive_count += 1
            else:
                self._consecutive_tool = tool_name
                self._consecutive_count = 1

            if self._consecutive_count > self._max_consecutive_same_tool:
                msg = (
                    f"{tool_name} called {self._consecutive_count}x consecutively "
                    f"without progress — forcing the agent to try a different approach"
                )
                ctx.errors.append(msg)
                ctx.log("agent", "loop_detected", msg)
                console.print(f"[yellow]Loop detected:[/] {msg}")
                trace.steps.append(TraceStep(
                    step=iteration,
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    tool=tool_name,
                    reason=reason,
                    success=False,
                    error=msg,
                ))
                # Temporarily block this tool for 1 iteration
                self._tool_fail_count[tool_name] = self._tool_fail_count.get(tool_name, 0) + 1
                continue

            tool = self.registry.get(tool_name)
            if tool is None:
                ctx.errors.append(f"Unknown tool: {tool_name}")
                ctx.log("agent", "error", f"Unknown tool: {tool_name}")
                trace.steps.append(TraceStep(
                    step=iteration,
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    tool=tool_name,
                    reason=reason,
                    success=False,
                    error=f"Unknown tool: {tool_name}",
                ))
                continue

            console.print(f"[bold cyan]Step {iteration}:[/] {tool_name} — {reason}")
            ctx.log("agent", "invoke", f"{tool_name}: {reason}")

            # ── Capture state BEFORE ──────────────────────────────────
            state_before = ctx.state_snapshot()
            step_start = time.monotonic()

            try:
                ctx = tool(ctx, self.cfg, **kwargs)
                step_ok = True
                step_err = ""
            except Exception as exc:
                tb = traceback.format_exc()
                ctx.errors.append(f"{tool_name} failed: {exc}")
                ctx.log("agent", "error", f"{tool_name}: {exc}\n{tb}")
                console.print(f"[bold red]Error in {tool_name}:[/] {exc}")
                step_ok = False
                step_err = str(exc)
                # Track failure count
                self._tool_fail_count[tool_name] = self._tool_fail_count.get(tool_name, 0) + 1

            # ── Capture state AFTER + diff ────────────────────────────
            step_duration = (time.monotonic() - step_start) * 1000
            state_after = ctx.state_snapshot()

            changed = [
                key for key in state_after
                if state_after[key] != state_before.get(key)
            ]

            trace.steps.append(TraceStep(
                step=iteration,
                timestamp=datetime.now(timezone.utc).isoformat(),
                tool=tool_name,
                reason=reason,
                kwargs=kwargs,
                duration_ms=round(step_duration, 1),
                success=step_ok,
                error=step_err,
                state_before=state_before,
                state_after=state_after,
                state_changed=changed,
            ))
            trace.tool_sequence.append(tool_name)

        # ── Finalise trace ────────────────────────────────────────────
        trace.finished_at = datetime.now(timezone.utc).isoformat()
        trace.total_steps = len(trace.steps)
        trace.total_duration_ms = round(
            (time.monotonic() - run_start) * 1000, 1
        )
        trace.final_outcome = final_outcome
        trace.final_reason = final_reason
        trace.errors = list(ctx.errors)

        ctx.execution_trace = trace

        # ── Persist reports ───────────────────────────────────────────
        save_execution_trace(trace, ctx.work_dir)
        save_pipeline_summary(ctx, ctx.work_dir)

        return ctx

    # ── Internal helpers ──────────────────────────────────────────────

    def _classify_input(self, ctx: TaskContext) -> TaskContext:
        """Classify input type — regex fast-path, LLM fallback."""
        val = ctx.input_value.strip()

        # ── Fast regex classification (saves 1 LLM call) ─────────────
        if re.match(r"CVE-\d{4}-\d+", val, re.IGNORECASE):
            ctx.input_type = "cve"
            ctx.log("agent", "classify_regex", "type=cve")
            return ctx
        if "syzkaller" in val or "syzbot" in val or "bugs.chromium.org" in val:
            ctx.input_type = "syzbot"
            ctx.log("agent", "classify_regex", "type=syzbot")
            return ctx
        if val.startswith("http"):
            ctx.input_type = "blog_post"
            ctx.log("agent", "classify_regex", "type=blog_post")
            return ctx
        if val.endswith(".c") and "/" in val:
            ctx.input_type = "poc"
            ctx.log("agent", "classify_regex", "type=poc")
            return ctx
        if any(sig in val.lower() for sig in ("bug:", "kasan:", "oops:", "call trace:", "panic")):
            ctx.input_type = "crash_log"
            ctx.log("agent", "classify_regex", "type=crash_log")
            return ctx

        # ── LLM fallback for ambiguous inputs ────────────────────────
        prompt = _INPUT_CLASSIFICATION_PROMPT.format(input=val)
        try:
            result = self.decision_llm.ask_json(prompt, max_tokens=256)
            ctx.input_type = result.get("type", "crash_log")
            ctx.log("agent", "classify", f"type={ctx.input_type}")
        except Exception:
            ctx.input_type = "crash_log"
            ctx.log("agent", "classify_fallback", f"type={ctx.input_type}")
        return ctx

    def _relevant_tools(self, ctx: TaskContext) -> List[Dict[str, str]]:
        """Return only the tools relevant to the current pipeline state.

        This reduces the prompt size from ~20 tool descriptions to ~5-10,
        saving significant tokens per decision call.
        """
        all_tools = self.registry.list_tools()
        state = ctx.state_snapshot()
        blocked = {
            name for name, cnt in self._tool_fail_count.items()
            if cnt >= self._max_tool_failures
        }

        # Always-available tools (information gathering / analysis)
        always = {"analyze", "collect_target_info", "query_bug_db"}

        # Conditionally include get_kernel_source only if kernel tree configured
        if getattr(self.cfg, "kernel_tree_path", None):
            always.add("get_kernel_source")

        # Phase-gated tools
        early = {"pull_syzbot"}  # only if syzbot input
        feasibility = {"check_feasibility", "check_feasibility_static", "check_feasibility_dynamic"}
        repro_gen = {"reproduce"}
        repro_verify = {"verify_reproducer"}
        exploit_prep = {
            "resolve_kernel_offsets", "get_spray_strategy",
            "plan_kaslr_bypass", "get_rw_primitive",
        }
        # kexploit tools — only include if kexploit is importable
        try:
            import kexploit  # noqa: F401
            exploit_prep |= {
                "query_struct_offsets", "query_codeql_allocations",
                "adapt_exploit_offsets",
            }
        except ImportError:
            pass
        exploit_gen = {"exploit", "scaffold_exploit"}
        exploit_verify = {"verify_exploit", "complete_exploit"}

        allowed: Set[str] = set(always)

        # Syzbot pull only for syzbot inputs
        if ctx.input_type == "syzbot":
            allowed |= early

        # Feasibility available once we have analysis
        if state.get("has_crash") or state.get("has_root_cause"):
            allowed |= feasibility

        # Reproducer generation once we have vuln info
        if state.get("has_vuln_info") or state.get("has_crash"):
            allowed |= repro_gen

        # Reproducer verification once we have a reproducer
        if state.get("has_reproducer"):
            allowed |= repro_verify

        # Exploit prep once we have root cause or target info
        if state.get("has_root_cause") or state.get("has_target_info"):
            allowed |= exploit_prep

        # Exploit generation once we have vuln info
        if state.get("has_vuln_info") or state.get("has_root_cause"):
            allowed |= exploit_gen

        # Exploit verification once we have an exploit
        if state.get("has_exploit"):
            allowed |= exploit_verify

        # Filter out blocked tools and non-relevant ones
        return [
            t for t in all_tools
            if t["name"] in allowed and t["name"] not in blocked
        ]

    def _decide_next(self, ctx: TaskContext) -> Dict[str, Any]:
        """Ask the LLM what tool to invoke next.

        Cost optimisations vs. the original implementation:
        - Only include tools relevant to current pipeline state
        - Exclude tools that have failed repeatedly
        - Compressed history format (~3x shorter)
        - Truncated verification feedback
        - Uses cheaper decision model when configured
        - Capped max_tokens (1024 vs 8192)
        """
        # ── Context-aware tool list ───────────────────────────────────
        relevant = self._relevant_tools(ctx)
        tools_desc = "\n".join(
            f"- {t['name']}: {t['description']}" for t in relevant
        )

        # ── Compressed history (terse format) ─────────────────────────
        history_lines = "\n".join(
            f"  {i+1}. {h['tool']}→{h['action'][:40]}"
            for i, h in enumerate(ctx.history[-8:])
        )

        # ── Blocked-tool notes ────────────────────────────────────────
        blocked_notes = ""
        if self._tool_fail_count:
            blocked = [
                f"{n}({c}x)" for n, c in self._tool_fail_count.items()
                if c >= self._max_tool_failures
            ]
            if blocked:
                blocked_notes = f"\nBlocked tools (failed too many times): {', '.join(blocked)}"

        # ── Truncated verification feedback ───────────────────────────
        verification_feedback = ""
        if ctx.verification_history:
            last = ctx.verification_history[-1]
            verification_feedback = (
                f"Last verification ({last.target}, #{last.attempt_number}): "
                f"{'OK' if last.success else 'FAIL'}"
            )
            if last.failure_reason:
                verification_feedback += f" — {last.failure_reason[:200]}"
            if last.feedback:
                verification_feedback += f"\n  Feedback: {last.feedback[:300]}"
            if last.crash_occurred:
                verification_feedback += f"\n  Crash: {last.crash_pattern}"
            if last.exploit_output:
                verification_feedback += (
                    f"\n  Output: {last.exploit_output[:400]}"
                )
            if last.dmesg_new:
                verification_feedback += (
                    f"\n  dmesg: {last.dmesg_new[:300]}"
                )

        prompt = _DECISION_PROMPT.format(
            goal=self.goal,
            tools=tools_desc or "(none registered yet)",
            input_type=ctx.input_type,
            input_value=ctx.input_value[:200],
            has_crash=ctx.has_crash(),
            has_root_cause=ctx.has_root_cause(),
            has_vuln_info=ctx.has_vuln_info(),
            has_target_info=ctx.target_system_info is not None,
            has_kernel_offsets=bool(getattr(ctx, "kernel_offsets_header", "")),
            has_kernel_source=bool(getattr(ctx, "kernel_source_context", "")),
            has_spray_strategy=bool(getattr(ctx, "spray_strategy", None)),
            has_reproducer=ctx.has_reproducer(),
            reproducer_verified=ctx.has_verified_reproducer(),
            has_exploit=ctx.has_exploit(),
            exploit_verified=ctx.has_verified_exploit(),
            target_kernel=ctx.target_kernel or "(not specified)",
            has_ssh=bool(ctx.ssh_host),
            exploit_verify_count=len(ctx.exploit_verification_attempts()),
            repro_verify_count=len(ctx.reproducer_verification_attempts()),
            max_verify_attempts=ctx.max_verification_attempts,
            errors="; ".join(ctx.errors[-3:]) if ctx.errors else "none",
            verification_feedback=verification_feedback + blocked_notes,
            history=history_lines or "  (none yet)",
        )

        max_tok = self.cfg.llm_decision_max_tokens
        try:
            result = self.decision_llm.ask_json(prompt, max_tokens=max_tok)
            if self.cfg.debug:
                console.print(f"[dim]Decision OK: tool={result.get('tool')}[/]")
            return result
        except Exception as first_exc:
            console.print(
                f"[yellow]LLM decision attempt 1 failed: {first_exc}[/]"
            )
            # Retry with higher max_tokens (reason field is often long)
            time.sleep(2)
            try:
                result = self.decision_llm.ask_json(
                    prompt, max_tokens=max(max_tok * 2, 8192)
                )
                if self.cfg.debug:
                    console.print(f"[dim]Decision OK (attempt 2): tool={result.get('tool')}[/]")
                return result
            except Exception as second_exc:
                console.print(
                    f"[yellow]LLM decision attempt 2 failed: {second_exc}[/]"
                )
                # Final attempt: no json_mode (some models reject it)
                time.sleep(2)
                try:
                    from ..core.llm import _extract_json
                    raw = self.decision_llm.ask(
                        prompt,
                        max_tokens=max(max_tok * 2, 8192),
                        json_mode=False,
                    )
                    if self.cfg.debug:
                        console.print(f"[dim]Raw LLM response (attempt 3): {raw[:300]}[/]")
                    result = _extract_json(raw)
                    if self.cfg.debug:
                        console.print(f"[dim]Decision OK (attempt 3): tool={result.get('tool')}[/]")
                    return result
                except Exception as third_exc:
                    console.print(
                        f"[red]LLM decision attempt 3 also failed: "
                        f"{third_exc}[/]"
                    )
                    return {
                        "tool": "stop",
                        "reason": (
                            f"Failed to get agent decision from LLM after "
                            f"3 attempts. Last error: {third_exc}"
                        ),
                    }
