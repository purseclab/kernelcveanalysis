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
_MAX_ITERATIONS = 60

# Substep tools: execute but don't count toward step limits.
# This enables the LLM to perform extended dynamic analysis
# (GDB debugging, ADB investigation, edit-recompile-rerun
# cycles) without exhausting the step budget.
_SUBSTEP_TOOLS: set[str] = {
    "run_target_command", "read_target_file",
    "gdb_session", "gdb_command",
    "read_exploit_source", "edit_exploit_module",
    "recompile_exploit", "show_compilation_errors",
    "debug_exploit",
}

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

{accumulated_knowledge}

{verification_feedback}

History of actions taken:
{history}

WORKFLOW GUIDANCE:
You have full control over which tools to call and in what order.  The
phase gates only prevent calling tools whose prerequisites aren't met
(e.g. you can't verify an exploit that doesn't exist yet).  Within those
constraints, you decide the plan.

Use your judgment based on the "Accumulated knowledge" above to decide
what information you still need.  For example:
- If you see "Gathered data" is empty, you haven't done prep work yet.
  Consider calling resolve_kernel_offsets, get_spray_strategy, etc.
- If root cause shows a specific exploitation technique, call the
  corresponding prep tools (get_rw_primitive, plan_kaslr_bypass, etc.)
- If GDB traces show functions were MISSED, the exploit's approach to
  that stage is wrong — regenerate with that feedback.
- If the strategy tracker shows multiple consecutive failures, consider
  a fundamentally different approach (different technique, different
  spray object, different trigger mechanism).

ANDROID / HARDENED KERNEL CONSTRAINTS:
  Many Android kernels are significantly more restricted than upstream Linux.
  Check these constraints via run_target_command BEFORE generating spray/trigger code:

  SPRAY MECHANISM SELECTION (run: cat /proc/config.gz | zcat | grep CONFIG_SYSVIPC):
  - If CONFIG_SYSVIPC is NOT SET → msg_msg spray is UNAVAILABLE.
    Use setxattr spray instead (requires writable file: /data/local/tmp/f).
    setxattr allocates kernel memory of the specified value size (avoid msg_msg entirely).
  - If CONFIG_SYSVIPC=y → msg_msg spray is available.
  - sk_buff spray: usable via sendmsg() with large cmsg data (always available).
  - pipe_buffer spray: usable via pipe() + write() (always available).

  TRIGGER MECHANISM VALIDATION (run: test binary or run_target_command):
  - RTM_NEWLINK requires CAP_NET_ADMIN. Test by creating NETLINK_ROUTE socket
    and calling send() with RTM_NEWLINK. If errno=EACCES/EPERM → BLOCKED by SELinux.
  - RTM_NEWLINK from u:r:shell:s0 SELinux domain is typically BLOCKED on Android.
    PROVEN ALTERNATIVE: check for setuid su binary first:
      run_target_command command="ls -la /system/xbin/su 2>/dev/null || ls -la /system/bin/su 2>/dev/null"
    If su is -rwsr-x--- (setuid, group=shell), then uid=2000 CAN exec it.
    Use: system("/system/xbin/su 0 ip link set <iface> down") or a persistent
    root shell (fork+pipe+exec su 0 /system/bin/sh) for interface toggle.
    This is the CORRECT trigger path for CVE-2024-36971 on Android Cuttlefish.
  - INTERFACE SELECTION: Do NOT use loopback (lo/127.0.0.1) for dst_entry UAFs.
    Loopback routes are never freed via dst_negative_advice.
    Use the primary data interface (e.g. buried_eth0, eth0):
      run_target_command command="ip route | grep default"
    Connect sockets to the default gateway IP, NOT to 127.0.0.1.
  - SINGLE-CPU QEMU: Check CPU count before generating spray code:
      run_target_command command="cat /sys/devices/system/cpu/online"
    If output is '0' (single CPU), limit spray threads to ≤4.
    Creating 64+ threads on single-CPU causes extreme overhead and VM timeout.

  SLAB CACHE AWARENESS:
  - struct rtable → ip_dst_cache slab (DEDICATED, not kmalloc-256).
    With CONFIG_SLAB_MERGE_DEFAULT=n, ip_dst_cache ≠ kmalloc-256.
    Cross-cache attack needed to reclaim freed rtables with msg_msg/setxattr.
  - struct dst_entry is embedded at offset 0 of struct rtable.

  CFI / PAN on Android:
  - CONFIG_CFI_CLANG=y blocks arbitrary function pointer redirection.
    Use only type-matched function pointers that exist in the kernel.
  - CONFIG_ARM64_PAN=y → kernel cannot execute userspace memory.
    All code payloads must be kernel-space addresses.
  - With nokaslr in cmdline, kernel addresses are fixed (use compile-time offsets).

  POST-EXPLOIT — KERNEL CRED OVERWRITE (no su shortcuts):
  - Root MUST come from kernel cred_t overwrite via kread64/kwrite64.
    NEVER add a su/sudo fallback in post_exploit.c — it proves nothing
    about the kernel exploit and is not acceptable as a final result.
    The su binary is only permitted in trigger.c for interface toggle.
  - If kread64/kwrite64 are NULL (rw_primitive failed), return -1 from
    post_exploit and fix the upstream spray/rw_primitive stage instead.
  - KERNEL READ WITHOUT /proc/kcore: use the dst_entry._metrics primitive.
    Set _metrics in the reclaimed spray object to target_addr - RTAX_MTU*4,
    then call getsockopt(victim_sock, IPPROTO_IP, IP_MTU, &val, &len).
    val = *(uint32_t *)(target_addr). This is a data pointer read — no CFI.
  - KASLR: if nokaslr is in /proc/cmdline, kernel_base = compile-time constant.
    Skip /proc/kallsyms scan entirely (saves 30 sec when kptr_restrict active).
  - /proc/kallsyms FAST-EXIT: if kptr_restrict is active, ALL addresses are 0.
    Check only the first line — if first addr=0, return 0 immediately.

KEY PRINCIPLES:
- If accumulated knowledge includes a REFLECTION section, follow its
  RECOMMENDED NEXT STEPS unless you have a strong reason not to.
  The reflection has already interpreted all gathered data for you.
- For CVE-only or blog-only inputs (no crash log), after 'analyze', call
  'collect_target_info' to boot the VM and gather the target kernel version,
  /proc/kallsyms, and other system info.
- DYNAMIC FEASIBILITY: After static feasibility passes, generate a
  reproducer ('reproduce') and then run 'verify_reproducer' to
  confirm the vulnerable code path is exercised on the actual target VM.
- BEFORE generating an exploit, call 'resolve_kernel_offsets' to get
  real kernel addresses and struct offsets.  This prevents the LLM from
  hallucinating incorrect values.
- After generating an exploit, you MUST verify it on the target device.
- If verification fails, read the failure details above carefully.
  Focus on FIXING THE EXPLOIT, not re-running feasibility checks.
- The 'exploit' tool generates + compiles — it does NOT verify.
  The typical iteration loop is:
  exploit → verify_exploit → (if failed) exploit → verify_exploit → …
- You may call 'review_exploit_code' before verify_exploit to inspect
  the generated code for obvious issues without a VM boot cycle.
- You may call 'summarize_progress' at any point to get a detailed
  summary of everything gathered so far.
- NEVER call the same tool more than three times in a row.

FINE-GRAINED EDITING (prefer this over full regeneration):
  After 'exploit' generates code, prefer TARGETED FIXES over re-running
  'exploit' which regenerates everything from scratch.  Use this workflow:

  1. show_compilation_errors  — see per-file errors
  2. read_exploit_source filename=trigger.c  — read the problematic file
  3. edit_exploit_module filename=trigger.c instruction="fix X"  — fix it
  4. recompile_exploit  — incremental recompile
  5. verify_exploit  — test on target

  These tools are MUCH faster than calling 'exploit' again because they
  only change the files that need fixing.

  Use 'runtime_feedback' after a compiled exploit fails verification —
  it automatically diagnoses which phase failed and fixes that module.

  Use 'run_target_command' or 'read_target_file' for diagnostics:
  - run_target_command command="cat /proc/slabinfo | head -30"
  - read_target_file filepath=/proc/kallsyms grep=commit_creds

INTERACTIVE GDB DEBUGGING (default — preferred over batch monitoring):
  Use 'gdb_session' and 'gdb_command' for interactive kernel debugging.
  This is the PRIMARY way to inspect kernel state during exploit/reproducer
  verification.  The batch GDB monitor is the fallback.

  Typical workflow:
  1. gdb_session action="start"  — connect to QEMU GDB stub
  2. gdb_command command="break commit_creds"  — set SW breakpoint
  3. gdb_command command="break __dst_negative_advice"  — set on vuln func
  4. gdb_command command="continue"  — resume kernel
  5. (run exploit/reproducer via run_target_command)
  6. gdb_command command="bt 20"  — check backtrace at breakpoint
  7. gdb_command command="info registers"  — inspect CPU state
  8. gdb_command command="syz-cred-check"  — verify privilege escalation
  9. gdb_session action="stop"  — clean up

  CRITICAL RULES for gdb_command:
  - NEVER repeat the same command more than twice.  If you already set
    "break __dst_negative_advice", do NOT set it again.
  - After setting breakpoints, you MUST issue "continue" then run the
    exploit via run_target_command, then use diagnostic commands.
  - Use DIFFERENT commands each call: bt, info registers, x/16gx $sp,
    print $pc, info breakpoints, syz-cred-check, syz-vuln-state.
  - If the device crashed, use "bt 20" and "info registers" to see WHERE
    the crash happened, then fix the exploit code with edit_exploit_module.

  AFTER VERIFICATION FAILURE — mandatory diagnostic sequence:
  1. gdb_session action="start"
  2. gdb_command command="break commit_creds"
  3. gdb_command command="continue"
  4. run_target_command command="<run the exploit>"
  5. gdb_command command="bt 20"
  6. gdb_command command="info registers"
  7. gdb_command command="syz-cred-check"
  8. Based on results: edit_exploit_module to fix the issue

  BREAKPOINTS: Use 'break' (software breakpoints).  Use 'hbreak' only
  as fallback if SW breakpoints don't fire (limited to 4 on ARM64).

  ADAPTIVE DEBUGGING by failure pattern:
  - CRASH: Use 'bt 20' and 'info registers' at crash site.  Check if
    the crash is in a kernel function related to the vuln or in unrelated
    code (wrong offset or spray collision).
  - TIMEOUT/HANG: The exploit is blocking.  Use 'info threads' to see
    what thread is stuck, then 'thread N' + 'bt' to identify the
    blocking syscall.  Common: blocking in recvmsg, epoll_wait, or
    futex (deadlock).  Add alarm() and SO_RCVTIMEO.
  - UAF NOT TRIGGERED: The vulnerability path isn't reached.  Set
    breakpoints on the specific vuln function (e.g., __dst_negative_advice)
    and check if it fires during exploit execution.
  - PRIVESC NOT REACHED: The exploit runs but commit_creds is never hit.
    Check if earlier phases (trigger/spray/rw_primitive) actually succeeded
    by examining their return values.
  - Your GDB command history is tracked — avoid repeating the same commands.

RECOMMENDED TOOL ORDER (adapt based on context):
  1. analyze
  2. collect_target_info
  3. check_feasibility_static / get_kernel_source
  4. reproduce  →  verify_reproducer
  5. resolve_kernel_offsets / get_spray_strategy / get_rw_primitive
  6. exploit  →  verify_exploit
  7. If compilation failed:
     show_compilation_errors → edit_exploit_module → recompile_exploit
     *** EDIT LIMIT: max 3 edits per module file without a successful compile.
     After 3 edits to the same .c file, STOP and call recompile_exploit or
     runtime_feedback instead of editing again. ***
  8. If verification failed:
     runtime_feedback (or: read_exploit_source → edit_exploit_module
     → recompile_exploit → verify_exploit)
     *** EDIT LOOP WARNING: If you have called edit_exploit_module 3+ times
     on the same module without progress, DO NOT edit it again. Instead:
     (a) call runtime_feedback to diagnose which module is actually failing,
     (b) or call exploit to fully regenerate with all feedback incorporated.
     Repeated edits to a non-failing module waste the step budget. ***

IMPORTANT: Call 'get_kernel_source' early (after analyze + collect_target_info)
to fetch upstream source code for vulnerable functions and structs.  This
provides concrete struct layouts and function source for both the LLM
(better code generation) and GDB (symbol resolution).  Especially
important when /proc/kallsyms is restricted (kptr_restrict=1).

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
        max_iterations: Optional[int] = None,
        replay_sequence: Optional[List[Dict[str, Any]]] = None,
    ) -> None:
        self.goal = goal
        self.registry = registry or default_registry
        self.cfg = cfg or load_config()
        self._max_iterations = max_iterations or _MAX_ITERATIONS
        self.llm = LLMClient(self.cfg)
        self.decision_llm = self.llm.for_task("decision")

        # Replay mode: pre-loaded tool sequence (skip LLM decisions)
        self._replay_sequence = replay_sequence or []
        self._replay_idx = 0

        # Track tools that cause exceptions to avoid re-invoking them
        self._tool_fail_count: Dict[str, int] = {}
        self._max_tool_failures = 5  # only block after 5 actual exceptions

        # Track consecutive same-tool invocations (loop detection)
        self._consecutive_tool: str = ""
        self._consecutive_count: int = 0
        self._max_consecutive_same_tool: int = 3  # force different tool after 3 repeats

        # Global tool-call tracking: total invocations per tool name
        self._tool_call_count: Dict[str, int] = {}
        # Per-signature repeat counter for gdb_command (allows 2 repeats)
        self._gdb_cmd_repeats: Dict[tuple, int] = {}
        # Per-module edit counter — tracks how many times each module file
        # has been edited.  After _max_edits_per_module edits to the same
        # file without a successful compile+verify, the loop is forced to
        # either switch to a different module or trigger full regeneration.
        self._module_edit_count: Dict[str, int] = {}
        self._max_edits_per_module: int = 3  # after 3 edits, force regen or switch
        self._consecutive_edit_blocks: int = 0  # escalating penalty counter
        # Max total calls before soft-blocking a tool (overridable per tool)
        self._max_total_calls: Dict[str, int] = {
            "query_bug_db": 3,
            "investigate": 2,
            "collect_target_info": 2,
            "check_feasibility_static": 2,
            "analyze_struct": 2,
            "analyze_conditions": 2,
            "adapt_templates": 2,
            "get_spray_strategy": 2,
            "resolve_kernel_offsets": 2,
            "reproduce": 4,
            "verify_reproducer": 4,
            # Source manipulation and dynamic-analysis tools get higher
            # budgets — the agent may need many read/edit/recompile
            # cycles and interactive investigation sessions.
            "read_exploit_source": 30,
            "edit_exploit_module": 6,   # lowered from 10: 3 edits/module×2 modules max
            "recompile_exploit": 15,
            "show_compilation_errors": 15,
            "run_target_command": 25,
            "read_target_file": 20,
            "runtime_feedback": 8,
            "complete_exploit": 10,
            "gdb_session": 10,
            "gdb_command": 50,
            "get_rw_primitive": 3,
            "get_spray_strategy": 3,
        }
        self._max_total_calls_default: int = 8

        # Same-args deduplication: set of (tool_name, args_key) tuples
        self._seen_tool_calls: set = set()

        # Progress tracking: which "milestone" tools have been called
        self._milestone_tools_called: set = set()

        # Forced next-tool override (set after exploit/complete_exploit)
        self._forced_next_tool: Optional[str] = None
        self._forced_next_reason: str = ""

        # Reflection tracking
        self._steps_since_reflection: int = 0
        self._reflect_every_n: int = 3  # auto-reflect after N tool calls
        self._last_tool_was_skipped: bool = False  # idempotency guard fired

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
        final_reason = f"Reached {self._max_iterations} iterations without done/stop"

        # Soft cap: after _max_iterations, allow only exploit-related
        # tools until the exploit is verified (or hard cap at 2x).
        _HARD_CAP = self._max_iterations * 2
        _SOFTCAP_TOOLS = {
            "exploit", "complete_exploit", "verify_exploit",
            "recompile_exploit", "edit_exploit_module",
            "read_exploit_source", "show_compilation_errors",
            "runtime_feedback", "reflect", "stop", "done",
            "gdb_session", "gdb_command",
            # Substep tools are always allowed past soft cap
            "run_target_command", "read_target_file",
        }
        step = 0        # counts only real, non-substep tool executions
        loop_round = 0  # counts every loop pass (safety cap)
        _MAX_LOOP_ROUNDS = 100  # hard limit on total decision rounds
        while True:
            loop_round += 1

            # ── Safety valve: prevent infinite loops ──────────────
            if loop_round > _MAX_LOOP_ROUNDS:
                final_reason = (
                    f"Safety cap reached ({_MAX_LOOP_ROUNDS} loop "
                    f"rounds, {step} real steps)"
                )
                break

            # ── Early termination: exploit already verified ────────
            if ctx.has_verified_exploit():
                final_outcome = "done"
                final_reason = (
                    f"Exploit verified — privilege escalation confirmed "
                    f"(step {step})"
                )
                break

            # ── Hard cap: absolute maximum real steps ─────────────
            if step >= _HARD_CAP:
                final_reason = (
                    f"Reached hard cap ({_HARD_CAP} steps)"
                )
                break

            # ── Soft cap: after _max_iterations, force verify or stop
            if step >= self._max_iterations:
                if ctx.has_verified_exploit():
                    final_outcome = "done"
                    final_reason = (
                        "Exploit verified after soft-cap extension "
                        f"(step {step})"
                    )
                    break
                elif not ctx.has_exploit():
                    # No compiled exploit at all after max_iterations → stop
                    final_reason = (
                        f"Reached {self._max_iterations} steps "
                        "without a compiled exploit"
                    )
                    break
            # ── Progress-based forced transition ──────────────────────
            # If the agent has gathered enough info but hasn't moved to
            # reproduce/exploit after several steps, force progression.
            # Uses `step` (real steps only) so substeps don't trigger.
            if (
                not self._forced_next_tool
                and step >= 8
                and ctx.has_root_cause()
                and not ctx.has_reproducer()
                and not ctx.has_exploit()
                and "reproduce" not in self._milestone_tools_called
                and "exploit" not in self._milestone_tools_called
            ):
                self._forced_next_tool = "reproduce"
                self._forced_next_reason = (
                    "Agent has root cause analysis but hasn't attempted "
                    "reproducer/exploit generation after "
                    f"{step} steps — forcing reproduce."
                )
            elif (
                not self._forced_next_tool
                and step >= 12
                and ctx.has_root_cause()
                and not ctx.has_exploit()
                and "exploit" not in self._milestone_tools_called
            ):
                self._forced_next_tool = "exploit"
                self._forced_next_reason = (
                    "Agent has root cause analysis but hasn't attempted "
                    "exploit generation after "
                    f"{step} steps — forcing exploit."
                )
            # ── Loop-round escalation: force exploit when soft-blocked
            # reproduce keeps the agent looping without advancing step.
            elif (
                not self._forced_next_tool
                and loop_round >= 15
                and ctx.has_root_cause()
                and ctx.has_reproducer()
                and not ctx.has_exploit()
                and "exploit" not in self._milestone_tools_called
            ):
                self._forced_next_tool = "exploit"
                self._forced_next_reason = (
                    "Agent has been looping for "
                    f"{loop_round} rounds with a confirmed reproducer "
                    "— forcing exploit generation."
                )
            # ── Loop-round escalation: force reproduce when the agent
            # is looping without a reproducer (e.g. stuck on deduped
            # check_feasibility_dynamic or repeated GDB commands).
            elif (
                not self._forced_next_tool
                and loop_round >= 10
                and ctx.has_root_cause()
                and not ctx.has_reproducer()
                and not ctx.has_exploit()
                and "reproduce" not in self._milestone_tools_called
            ):
                self._forced_next_tool = "reproduce"
                self._forced_next_reason = (
                    "Agent has been looping for "
                    f"{loop_round} rounds without a reproducer "
                    "— forcing reproduce generation."
                )
            # ── Loop-round escalation: after verification failure, force
            # the agent into the runtime_feedback → fix → verify cycle.
            elif (
                not self._forced_next_tool
                and loop_round % 5 == 0  # periodic nudge every 5 rounds
                and ctx.has_exploit()
                and ctx.verification_history
                and not ctx.verification_history[-1].success
            ):
                self._forced_next_tool = "runtime_feedback"
                self._forced_next_reason = (
                    "Verification failed and agent has been looping for "
                    f"{loop_round} rounds — forcing runtime_feedback to "
                    "diagnose and fix the exploit."
                )

            # ── Forced transition (exploit → verify_exploit) ─────────
            if self._forced_next_tool:
                tool_name = self._forced_next_tool
                reason = self._forced_next_reason
                kwargs = {}
                self._forced_next_tool = None
                self._forced_next_reason = ""
                console.print(
                    f"[bold magenta]Forced transition →[/] {tool_name}"
                )
            elif self._replay_sequence and self._replay_idx < len(self._replay_sequence):
                # Replay mode: use pre-loaded tool sequence
                replay_step = self._replay_sequence[self._replay_idx]
                tool_name = replay_step["tool"]
                reason = f"[REPLAY] {replay_step.get('reason', '')}"
                kwargs = replay_step.get("kwargs", {})
                self._replay_idx += 1
                console.print(
                    f"[bold cyan]Replay step {self._replay_idx}/"
                    f"{len(self._replay_sequence)} →[/] {tool_name}"
                )
            elif self._replay_sequence:
                # Replay sequence exhausted
                tool_name = "done"
                reason = "Replay sequence completed"
                kwargs = {}
            else:
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

            # ── Soft cap enforcement: restrict tools after max_iterations
            if (
                step >= self._max_iterations
                and tool_name not in _SOFTCAP_TOOLS
            ):
                # Redirect to verify_exploit if we have a binary,
                # otherwise force another exploit attempt.
                if ctx.has_exploit():
                    tool_name = "verify_exploit"
                    reason = (
                        f"Soft cap active (step {step} >= "
                        f"{self._max_iterations}) — redirecting to "
                        f"verify_exploit before stopping."
                    )
                else:
                    tool_name = "exploit"
                    reason = (
                        f"Soft cap active (step {step} >= "
                        f"{self._max_iterations}) — must generate "
                        f"exploit before stopping."
                    )
                kwargs = {}
                console.print(
                    f"[bold magenta]Soft cap redirect →[/] {tool_name}"
                )

            # ── Block tools that repeatedly fail ──────────────────────
            if self._tool_fail_count.get(tool_name, 0) >= self._max_tool_failures:
                msg = f"{tool_name} blocked (failed {self._max_tool_failures}+ times)"
                ctx.log("agent", "skip_blocked", msg)
                console.print(f"[yellow]Skipping {tool_name}:[/] {msg}")
                trace.steps.append(TraceStep(
                    step=step,
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    tool=tool_name,
                    reason=reason,
                    success=False,
                    error=msg,
                ))
                continue  # no step increment for skips

            # ── Detect tool-repetition loops ──────────────────────────
            if tool_name == self._consecutive_tool:
                self._consecutive_count += 1
            else:
                self._consecutive_tool = tool_name
                self._consecutive_count = 1

            if self._consecutive_count > self._max_consecutive_same_tool:
                # Source manipulation tools get a higher consecutive budget
                # since read→edit→read→edit is a valid workflow pattern
                _SOURCE_TOOLS = {
                    "read_exploit_source", "edit_exploit_module",
                    "recompile_exploit", "show_compilation_errors",
                    "run_target_command", "read_target_file",
                    "gdb_command", "gdb_session",
                }
                effective_max = (
                    self._max_consecutive_same_tool + 5
                    if tool_name in _SOURCE_TOOLS
                    else self._max_consecutive_same_tool
                )
                if self._consecutive_count > effective_max:
                    msg = (
                        f"{tool_name} called {self._consecutive_count}x consecutively "
                        f"without progress — forcing the agent to try a different approach"
                    )
                    ctx.errors.append(msg)
                    ctx.log("agent", "loop_detected", msg)
                    console.print(f"[yellow]Loop detected:[/] {msg}")
                    trace.steps.append(TraceStep(
                        step=step,
                        timestamp=datetime.now(timezone.utc).isoformat(),
                        tool=tool_name,
                        reason=reason,
                        success=False,
                        error=msg,
                    ))
                    # Skip this iteration only — do NOT permanently block the tool.
                    # Reset consecutive count so the agent can try again after
                    # picking a different tool next iteration.
                    self._consecutive_count = 0
                    # If we're looping on exploit and have a compiled binary,
                    # redirect to verify_exploit instead of just skipping.
                    if tool_name in ("exploit", "complete_exploit") and ctx.has_exploit():
                        self._forced_next_tool = "verify_exploit"
                        self._forced_next_reason = (
                            "Redirected from exploit loop — verifying current "
                            "exploit before regenerating"
                        )
                    elif tool_name == "edit_exploit_module":
                        # Edit loop detected — stop editing and take stock.
                        # If we have a compiled binary, verify it; otherwise
                        # use runtime_feedback to figure out what's broken.
                        if ctx.has_exploit():
                            self._forced_next_tool = "verify_exploit"
                            self._forced_next_reason = (
                                "Redirected from edit_exploit_module loop — "
                                "exploit compiled; testing current state instead "
                                "of more editing"
                            )
                        else:
                            self._forced_next_tool = "runtime_feedback"
                            self._forced_next_reason = (
                                "Redirected from edit_exploit_module loop — "
                                "calling runtime_feedback to diagnose which "
                                "module is actually failing"
                            )
                    elif tool_name in (
                        "get_rw_primitive", "get_spray_strategy",
                        "plan_kaslr_bypass", "get_multiprocess_scaffold",
                        "generate_binder_trigger", "get_race_template",
                    ) and ctx.has_exploit():
                        self._forced_next_tool = "runtime_feedback"
                        self._forced_next_reason = (
                            f"Redirected from {tool_name} loop — exploit "
                            "already compiled; using runtime_feedback to "
                            "diagnose and fix the exploit code"
                        )
                    continue  # no step increment for loop-detected skips

            # ── Same-args deduplication ────────────────────────────────
            # Prevent the exact same tool+args call from running again.
            try:
                args_key = str(sorted(kwargs.items())) if kwargs else ""
            except Exception:
                args_key = str(kwargs)
            call_signature = (tool_name, args_key)
            if call_signature in self._seen_tool_calls and tool_name not in (
                "exploit", "complete_exploit", "verify_exploit",
                "verify_reproducer", "reflect", "summarize_progress",
                "review_exploit_code", "refine_exploit_plan",
                # Source manipulation tools often need repeat calls
                # with different or same args (read after edit, etc.)
                "read_exploit_source", "edit_exploit_module",
                "recompile_exploit", "show_compilation_errors",
                "run_target_command", "read_target_file",
                "runtime_feedback",
                # GDB session management may need retries
                "gdb_session",
            ):
                # gdb_command: allow 'continue' repeats but block other
                # identical commands after 2 uses
                if tool_name == "gdb_command":
                    _gdb_cmd = kwargs.get("command", "")
                    _gdb_sig_count = self._gdb_cmd_repeats.get(call_signature, 0)
                    if _gdb_cmd.strip().lower() in ("continue", "c"):
                        pass  # always allow continue
                    elif _gdb_sig_count >= 2:
                        self._consecutive_gdb_blocks = getattr(self, "_consecutive_gdb_blocks", 0) + 1
                        _penalty = min(self._consecutive_gdb_blocks, 3)
                        msg = (
                            f"gdb_command already called with '{_gdb_cmd}' "
                            f"{_gdb_sig_count} times — use a DIFFERENT command "
                            f"or a DIFFERENT tool entirely. "
                            f"Do NOT call gdb_command with the same arguments again."
                        )
                        ctx.errors.append(msg)
                        ctx.log("agent", "gdb_repeat_block", msg)
                        console.print(f"[yellow]GDB repeat:[/] {msg}")
                        trace.steps.append(TraceStep(
                            step=step,
                            timestamp=datetime.now(timezone.utc).isoformat(),
                            tool=tool_name,
                            reason=reason,
                            success=False,
                            error=msg,
                        ))
                        step += _penalty  # escalating penalty
                        continue
                    else:
                        self._consecutive_gdb_blocks = 0
                    # Track repeat count
                    self._gdb_cmd_repeats[call_signature] = _gdb_sig_count + 1
                else:
                    msg = (
                        f"{tool_name} already called with identical arguments — "
                        f"skipping duplicate. Try a different tool or different parameters."
                    )
                    ctx.errors.append(msg)
                    ctx.log("agent", "dedup_skip", msg)
                    console.print(f"[yellow]Dedup skip:[/] {msg}")
                    trace.steps.append(TraceStep(
                        step=step,
                        timestamp=datetime.now(timezone.utc).isoformat(),
                        tool=tool_name,
                        reason=reason,
                        success=False,
                        error=msg,
                    ))
                    continue  # no step increment for dedup skips

            # ── Global total-call-count soft-block ────────────────────
            max_for_tool = self._max_total_calls.get(
                tool_name, self._max_total_calls_default
            )
            if self._tool_call_count.get(tool_name, 0) >= max_for_tool:
                # Suggest the next logical phase, not the blocked tool
                if tool_name in ("reproduce", "verify_reproducer"):
                    _suggest = (
                        "The reproducer is confirmed — move to exploit "
                        "generation. Call 'exploit' now."
                    )
                elif tool_name in ("exploit", "verify_exploit"):
                    _suggest = (
                        "Consider 'runtime_feedback', 'edit_exploit_module', "
                        "or 'recompile_exploit' for targeted fixes."
                    )
                elif tool_name in ("edit_exploit_module", "complete_exploit",
                                   "recompile_exploit"):
                    _suggest = (
                        "You have exhausted edit/complete cycles. Call "
                        "'exploit' to regenerate from scratch with all "
                        "feedback, or 'verify_exploit' to test current code."
                    )
                    # Force verify_exploit if exploit exists, so the pipeline
                    # can progress rather than spinning on blocked edits.
                    if ctx.has_exploit():
                        self._forced_next_tool = "verify_exploit"
                        self._forced_next_reason = (
                            f"{tool_name} max calls exhausted — forcing "
                            "verify_exploit to test the current exploit code."
                        )
                else:
                    _suggest = (
                        "Move on to the next phase — consider calling "
                        "'reproduce' or 'exploit'."
                    )
                msg = (
                    f"{tool_name} reached max total calls ({max_for_tool}). "
                    f"{_suggest}"
                )
                ctx.errors.append(msg)
                ctx.log("agent", "max_calls_skip", msg)
                console.print(f"[yellow]Max calls:[/] {msg}")
                trace.steps.append(TraceStep(
                    step=step,
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    tool=tool_name,
                    reason=reason,
                    success=False,
                    error=msg,
                ))
                # Max-calls skips for substep tools must count as a real
                # step — otherwise the agent loops endlessly on a blocked
                # substep tool without consuming its step budget.
                if tool_name in _SUBSTEP_TOOLS:
                    step += 1
                continue

            # ── Per-module edit throttle ──────────────────────────────
            # Track how many times edit_exploit_module has been called on
            # each source file.  After _max_edits_per_module edits without
            # a successful compile+verify, we force the agent to either:
            #   a) call recompile_exploit+verify_exploit (if compiled), or
            #   b) call runtime_feedback (to reassess what to fix next)
            # This breaks the "stuck editing rw_primitive.c 8 times" pattern.
            if tool_name == "edit_exploit_module":
                _edit_file = kwargs.get("filename") or kwargs.get("module_name") or ""
                if _edit_file:
                    _edit_n = self._module_edit_count.get(_edit_file, 0) + 1
                    self._module_edit_count[_edit_file] = _edit_n
                    if _edit_n > self._max_edits_per_module:
                        self._consecutive_edit_blocks += 1
                        _penalty = min(self._consecutive_edit_blocks, 3)
                        msg = (
                            f"edit_exploit_module('{_edit_file}') called "
                            f"{_edit_n} times without verified progress — "
                            f"STOP editing this module and instead: "
                            f"(1) call recompile_exploit then verify_exploit "
                            f"to test the current state, OR "
                            f"(2) call runtime_feedback to reassess which "
                            f"module is actually failing. "
                            f"Do NOT keep editing {_edit_file} — it may not "
                            f"be the root cause of the failure."
                        )
                        ctx.errors.append(msg)
                        ctx.log("agent", "edit_throttle", msg)
                        console.print(f"[yellow]Edit throttle ({_edit_file}):[/] {msg}")
                        trace.steps.append(TraceStep(
                            step=step,
                            timestamp=datetime.now(timezone.utc).isoformat(),
                            tool=tool_name,
                            reason=reason,
                            success=False,
                            error=msg,
                        ))
                        # Force the most useful next action
                        if ctx.has_exploit():
                            self._forced_next_tool = "verify_exploit"
                            self._forced_next_reason = (
                                f"Forced after {_edit_n}x edits to {_edit_file} "
                                "— test current code before further edits"
                            )
                        else:
                            self._forced_next_tool = "runtime_feedback"
                            self._forced_next_reason = (
                                f"Forced after {_edit_n}x edits to {_edit_file} "
                                "— reassess failing phase"
                            )
                        step += _penalty  # escalating penalty counts against step budget
                        continue

            tool = self.registry.get(tool_name)
            if tool is None:
                ctx.errors.append(f"Unknown tool: {tool_name}")
                ctx.log("agent", "error", f"Unknown tool: {tool_name}")
                trace.steps.append(TraceStep(
                    step=step,
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    tool=tool_name,
                    reason=reason,
                    success=False,
                    error=f"Unknown tool: {tool_name}",
                ))
                continue  # no step increment for unknown tools

            # ── Substep vs real step ──────────────────────────────────
            # Substep tools (dynamic analysis, source editing, GDB)
            # execute but do NOT consume from the step budget, allowing
            # the LLM to iteratively investigate and modify the
            # reproducer/exploit without hitting the step limit.
            is_substep = tool_name in _SUBSTEP_TOOLS
            if is_substep:
                console.print(
                    f"[dim]  └─ {tool_name}[/] — {reason}"
                )
            else:
                step += 1
                console.print(
                    f"[bold cyan]Step {step}:[/] {tool_name} — {reason}"
                )
            ctx.log("agent", "invoke", f"{tool_name}: {reason}")

            # ── Record this call for dedup + count tracking ───────────
            self._tool_call_count[tool_name] = self._tool_call_count.get(tool_name, 0) + 1
            self._seen_tool_calls.add(call_signature)
            self._milestone_tools_called.add(tool_name)

            # ── Capture state BEFORE ──────────────────────────────────
            state_before = ctx.state_snapshot()
            step_start = time.monotonic()

            try:
                ctx = tool(ctx, self.cfg, **kwargs)
                step_ok = True
                step_err = ""
                # Success: clear any accumulated failure count for this tool
                self._tool_fail_count.pop(tool_name, None)

                # Detect idempotency skip (tool returned without doing work)
                self._last_tool_was_skipped = any(
                    h.get("action", "").startswith("skipped:")
                    for h in ctx.history[-2:]
                    if h.get("tool") == tool_name
                )
                if not self._last_tool_was_skipped:
                    self._steps_since_reflection += 1

                # A successful recompile_exploit clears the per-module edit
                # counter — the code compiled, so previous edits "worked".
                # This prevents stale counts from blocking future edits after
                # a legitimate fix+compile cycle.
                if tool_name == "recompile_exploit" and step_ok:
                    self._module_edit_count.clear()
                    self._consecutive_edit_blocks = 0

                # After exploit or complete_exploit produces a compiled
                # binary, FORCE verify_exploit as the next step.
                if (
                    tool_name in ("exploit", "complete_exploit")
                    and ctx.has_exploit()
                ):
                    self._forced_next_tool = "verify_exploit"
                    self._forced_next_reason = (
                        "Exploit compiled successfully — must verify on "
                        "target device before any other action."
                    )

                # After verify_exploit FAILS, immediately chain into
                # runtime_feedback instead of letting the decision model
                # loop on GDB commands.  This creates a tight
                # verify→feedback→fix→recompile→verify loop.
                if (
                    tool_name == "verify_exploit"
                    and ctx.verification_history
                    and not ctx.verification_history[-1].success
                    and ctx.can_retry_exploit_verification()
                    and not self._forced_next_tool  # don't override existing chain
                ):
                    self._forced_next_tool = "runtime_feedback"
                    self._forced_next_reason = (
                        "Verification failed — immediately entering "
                        "runtime_feedback to diagnose and fix the exploit."
                    )
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

            # ── Auto-reflect when needed ──────────────────────────────
            if self._should_reflect(ctx, step_ok):
                ctx = self._reflect(ctx)

            trace.steps.append(TraceStep(
                step=step,
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

    # ── Intermediate reflection ───────────────────────────────────────

    _REFLECTION_PROMPT = """\
You are the syzploit orchestrator's **reflection module**, thinking like an
experienced **vulnerability researcher and exploit developer**.  Your job is
to pause, interpret ALL gathered data through the lens of practical exploit
development, and produce a concise action brief.

Target: {input_type} = {input_value}
Target kernel: {target_kernel}
Goal: {goal}

──── GATHERED CONTEXT ────
{gathered_context}

──── TOOL HISTORY (last 20 steps) ────
{history}

──── ERRORS ────
{errors}

──── INSTRUCTIONS ────
Think like a vulnerability researcher.  For each phase, assess:
- Is the trigger RELIABLY reaching the vulnerable code path?
- Is the freed object ACTUALLY being reclaimed by the spray?
- Are kread64/kwrite64 REAL implementations or stubs?
- Are kernel struct offsets VERIFIED or guessed?
- Were compilation errors from MISSING symbols or WRONG APIs?

PAY SPECIAL ATTENTION to substep outputs.  Entries marked [substep] are
GDB commands, ADB shell commands, or source editing steps from dynamic
analysis sessions.  These contain CRITICAL runtime evidence:
- GDB backtraces and breakpoint hits prove whether code paths are reached
- ADB command output reveals kernel state, slab info, dmesg, etc.
- Source edits and recompile results show what was changed and whether it built

Synthesise ALL substep findings into your assessment.  For example:
- If gdb_command shows a breakpoint was never hit → the trigger isn't working
- If run_target_command shows /proc/slabinfo data → use it for slab targeting
- If edit_exploit_module + recompile failed → note the error and suggest a fix

Produce a brief (≤ 400 words) with EXACTLY these sections:

COMPLETED:
- Bullet list of phases/data that are done (cite specific data)

DYNAMIC ANALYSIS FINDINGS:
- Summarise any GDB, ADB, or runtime investigation results that are
  relevant for exploitation (breakpoint hits, memory state, kernel
  version details, slab layout observations, etc.)
- If no dynamic analysis was performed yet, write "None yet"

EXPLOITATION CHAIN STATUS:
- Trigger: [WORKING|PARTIAL|BROKEN] — one-line assessment
- Reclaim/Spray: [WORKING|PARTIAL|BROKEN] — one-line assessment
- R/W Primitive: [WORKING|PARTIAL|BROKEN] — one-line assessment
- Privilege Escalation: [WORKING|PARTIAL|BROKEN] — one-line assessment

GAPS:
- What is still missing or incomplete (prioritised by exploit impact)
- If kread/kwrite are stubs, this is the HIGHEST priority gap

KEY INSIGHTS (VULNERABILITY RESEARCHER PERSPECTIVE):
- 1-3 technical observations that would guide a real exploit developer
  (e.g. "ip6_dst_cache is a dedicated slab — MUST use same-object spray,
  pipe_buffer cross-cache won't work without page-level exhaustion",
  or "trigger uses MSG_CONFIRM which doesn't reliably hit negative_advice,
  use setsockopt(SO_CNX_ADVICE) instead")
- If the exploit was verified and failed, explain WHY from a technical
  perspective (wrong slab? race too narrow? stubs?)

RECOMMENDED NEXT STEPS:
1. Specific tool to call next, with clear technical reasoning
2. Second priority
3. (Optional) third step

DO NOT suggest re-running tools whose data is already gathered.
Be concrete — cite function names, struct names, slab caches, offsets.
If the exploit has stub functions, recommend 'complete_exploit' FIRST.
If dynamic analysis is needed, recommend specific gdb_command or
run_target_command calls with exact commands to run.
"""

    def _should_reflect(self, ctx: TaskContext, last_step_ok: bool) -> bool:
        """Decide whether to run an intermediate reflection now.

        Triggers:
        - Every ``_reflect_every_n`` successful tool calls
        - After a tool was skipped by an idempotency guard (agent is
          confused about what data it already has)
        - After a verification failure (need to reassess strategy)
        - After a burst of substep tools (dynamic analysis) to
          synthesise findings before proceeding to the next real step
        """
        # After an idempotency skip — agent needs a reality check
        if self._last_tool_was_skipped:
            self._last_tool_was_skipped = False
            return True

        # After a verification failure
        if (
            ctx.verification_history
            and not ctx.verification_history[-1].success
            and self._steps_since_reflection >= 1
        ):
            return True

        # Periodic reflection every N real steps
        if self._steps_since_reflection >= self._reflect_every_n:
            return True

        # After a burst of substeps — reflect to synthesise dynamic
        # analysis findings.  Count recent consecutive substep entries
        # in history.  If >= 5 substep calls have happened since the
        # last non-substep (or last reflection), trigger reflection so
        # the LLM can digest GDB/ADB results before deciding the next
        # major action.
        consecutive_substeps = 0
        for h in reversed(ctx.history):
            if h.get("action") != "invoke":
                break
            invoked = h.get("detail", "").split(":", 1)[0]
            if invoked in _SUBSTEP_TOOLS:
                consecutive_substeps += 1
            else:
                break
        if consecutive_substeps >= 5 and self._steps_since_reflection >= 1:
            return True

        return False

    def _reflect(self, ctx: TaskContext) -> TaskContext:
        """Run a lightweight LLM call to interpret gathered data and
        produce an action brief.  This is much cheaper than a full
        tool call — it only reads context and writes a short brief.
        """
        self._steps_since_reflection = 0

        # Build gathered context from decision_context_summary + extras
        gathered = ctx.decision_context_summary()
        if not gathered:
            gathered = "(no data gathered yet)"

        # Add state booleans for completeness
        state = ctx.state_snapshot()
        state_lines = "\n".join(
            f"  {k}: {v}" for k, v in sorted(state.items())
        )
        gathered = f"State:\n{state_lines}\n\n{gathered}"

        # Build history with expanded substep detail so the
        # reflection can reason about GDB/ADB investigation results.
        history_parts: list[str] = []
        for i, h in enumerate(ctx.history[-20:]):
            tool_h = h.get("tool", "")
            action_h = h.get("action", "")
            detail_h = h.get("detail", "")
            # Check if this is a substep invocation
            invoked_name = (
                detail_h.split(":", 1)[0]
                if action_h == "invoke" else ""
            )
            if invoked_name in _SUBSTEP_TOOLS:
                # Show expanded detail for substep entries
                history_parts.append(
                    f"  {i+1}. [substep] {invoked_name} → "
                    f"{detail_h[:200]}"
                )
            else:
                history_parts.append(
                    f"  {i+1}. {tool_h} → {action_h[:80]}"
                )
        history_lines = "\n".join(history_parts)

        prompt = self._REFLECTION_PROMPT.format(
            input_type=ctx.input_type,
            input_value=ctx.input_value[:200],
            target_kernel=ctx.target_kernel or "(unknown)",
            goal=self.goal,
            gathered_context=gathered,
            history=history_lines or "(none yet)",
            errors="; ".join(ctx.errors[-5:]) if ctx.errors else "none",
        )

        try:
            brief = self.decision_llm.ask(
                prompt,
                max_tokens=1024,
                json_mode=False,
            )
            ctx.reflection_brief = brief.strip()
            ctx.reflection_count += 1
            ctx.log("agent", "reflect", f"reflection #{ctx.reflection_count}")
            console.print(
                f"[bold blue]Reflection #{ctx.reflection_count}[/] completed"
            )
            if self.cfg.debug:
                console.print(f"[dim]{ctx.reflection_brief[:300]}[/]")
        except Exception as exc:
            console.print(f"[yellow]Reflection failed: {exc}[/]")
            ctx.log("agent", "reflect_error", str(exc))

        # Enrich context with exploitation-phase analysis
        ctx = self._enrich_exploitation_guidance(ctx)

        return ctx

    def _enrich_exploitation_guidance(self, ctx: TaskContext) -> TaskContext:
        """Analyse exploit state and inject dynamic guidance into context.

        This runs after reflection and adds concrete exploitation tips
        based on detected failure patterns — stubs, wrong slab targeting,
        verification failures, etc.  The guidance is stored in
        ``ctx.analysis_data["dynamic_exploitation_notes"]`` and automatically
        included in subsequent prompts via ``agent_context``.
        """
        notes: list[str] = []

        # Check verification history for patterns
        if ctx.verification_history:
            last = ctx.verification_history[-1]
            if not last.success:
                output = getattr(last, 'output', '') or ''
                if "UID stayed" in output or "No privilege change" in output:
                    notes.append(
                        "VERIFICATION FAILURE: Exploit ran but did NOT "
                        "escalate privileges.  Common causes:\n"
                        "  1. kread64/kwrite64 are stubs (most likely)\n"
                        "  2. task_struct offsets are wrong\n"
                        "  3. Trigger did not actually free the object\n"
                        "  4. Spray did not reclaim the freed slot\n"
                        "→ Use complete_exploit to fix stub functions, "
                        "then re-verify."
                    )
                if "SIGSEGV" in output or "segfault" in output:
                    notes.append(
                        "VERIFICATION CRASH: Exploit SIGSEGV'd.  This usually "
                        "means a bad pointer dereference — either the leaked "
                        "address is wrong, or the R/W primitive is corrupting "
                        "memory incorrectly."
                    )
                if "killed" in output.lower() or "SIGKILL" in output:
                    notes.append(
                        "VERIFICATION KILLED: Exploit was killed (seccomp or "
                        "kernel panic).  Check if seccomp is blocking syscalls."
                    )

        # Check for known stub patterns in exploit code
        exploit_result = getattr(ctx, 'exploit_result', None)
        if exploit_result and hasattr(exploit_result, 'source_files'):
            for fname, content in (exploit_result.source_files or {}).items():
                if not content:
                    continue
                import re
                # Check for functions that are just printf+return
                func_bodies = re.findall(
                    r'(?:int|void|uint64_t)\s+\w+\s*\([^)]*\)\s*\{([^}]{0,500})\}',
                    content, re.DOTALL
                )
                for body in func_bodies:
                    stripped = body.strip()
                    lines = [l.strip() for l in stripped.split('\n')
                             if l.strip() and not l.strip().startswith('//')]
                    if len(lines) <= 2 and all(
                        l.startswith('printf') or l.startswith('return')
                        or l.startswith('fprintf') or l == ''
                        for l in lines
                    ):
                        notes.append(
                            f"STUB DETECTED in {fname}: function body has "
                            f"only printf/return, no real exploit logic.  "
                            f"Use complete_exploit to fill in real code."
                        )
                        break

                # Check for placeholder values
                if '0xdeadbeef' in content or '0xcafebabe' in content:
                    notes.append(
                        f"PLACEHOLDER VALUE in {fname}: 0xdeadbeef or similar "
                        f"found.  Replace with real address from leak/spray."
                    )

        # Check for compilation errors that indicate missing knowledge
        recent_errors = ctx.errors[-10:] if ctx.errors else []
        for err in recent_errors:
            if "implicit declaration" in err.lower():
                notes.append(
                    "COMPILATION: 'implicit declaration' errors — the code "
                    "is calling functions that aren't declared.  Ensure the "
                    "correct headers are included."
                )
                break
            if "undefined reference" in err.lower():
                notes.append(
                    "COMPILATION: 'undefined reference' — a function is "
                    "declared but not defined.  Check if a required module "
                    "is missing or if function names are misspelled."
                )
                break

        if notes:
            ctx.analysis_data["dynamic_exploitation_notes"] = "\n\n".join(notes)
            console.print(
                f"  [dim]Dynamic guidance: {len(notes)} exploitation notes added[/]"
            )

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
        always = {"analyze", "collect_target_info", "query_bug_db",
                  "summarize_progress", "hunt_cves", "reflect"}

        # Conditionally include get_kernel_source only if kernel tree configured
        if getattr(self.cfg, "kernel_tree_path", None):
            always.add("get_kernel_source")

        # Phase-gated tools
        early = {"pull_syzbot"}  # only if syzbot input
        # investigate — deep web-scraping CVE investigation (exploits,
        # blogs, patches, source).  Available for CVE inputs always and
        # for other input types once we have root-cause analysis (the
        # agent may discover related CVEs it wants to investigate).
        investigate = {"investigate"}
        feasibility = {"check_feasibility", "check_feasibility_static", "map_attack_surface", "analyze_conditions"}
        # check_feasibility_dynamic requires a reproducer/exploit binary — gate separately
        feasibility_dynamic = {"check_feasibility_dynamic"}
        repro_gen = {"reproduce"}
        repro_verify = {"verify_reproducer"}
        exploit_prep = {
            "resolve_kernel_offsets", "get_spray_strategy",
            "plan_kaslr_bypass", "get_rw_primitive",
            "generate_device_config", "get_multiprocess_scaffold",
            "generate_binder_trigger", "get_race_template",
            "resolve_symbol_address", "adapt_templates",
            "analyze_struct",
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
        exploit_verify = {"verify_exploit", "complete_exploit", "run_exploit_monitor", "review_exploit_code"}
        # Source manipulation tools — fine-grained code reading, editing,
        # recompilation, and target diagnostics.
        source_manip = {
            "read_exploit_source", "edit_exploit_module",
            "recompile_exploit", "show_compilation_errors",
            "runtime_feedback",
        }
        target_diag = {"run_target_command", "read_target_file"}

        # New analysis & exploit tools
        analysis_tools = {"benchmark_exploit", "analyze_kernel_config",
                          "measure_crash_stability", "identify_slab_cache",
                          "discover_offsets"}
        exploit_refinement = {"minimize_exploit", "port_exploit",
                              "validate_exploit_plan", "refine_exploit_plan"}

        allowed: Set[str] = set(always)

        # investigate available for CVE inputs or once root cause exists
        if ctx.input_type == "cve" or state.get("has_root_cause"):
            allowed |= investigate

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
            # Dynamic feasibility requires a reproducer/exploit binary to run
            allowed |= feasibility_dynamic
            # Crash stability and slab ID need a reproducer
            allowed |= {"measure_crash_stability", "identify_slab_cache"}

        # Exploit prep once we have root cause or target info
        if state.get("has_root_cause") or state.get("has_target_info"):
            allowed |= exploit_prep
            # Kernel config analysis and offset discovery available with target info
            allowed |= {"analyze_kernel_config", "discover_offsets"}
            # Plan validation available once we could have a plan
            allowed |= {"validate_exploit_plan"}

        # Exploit generation once we have vuln info
        if state.get("has_vuln_info") or state.get("has_root_cause"):
            allowed |= exploit_gen

        # Exploit verification/completion once we have exploit output
        # (even if compilation failed — complete_exploit can fix it)
        if state.get("has_exploit") or (
            hasattr(ctx, 'exploit_result') and ctx.exploit_result is not None
        ):
            allowed |= exploit_verify
            # Dynamic feasibility can use exploit binary as trigger
            allowed |= feasibility_dynamic
            # Source manipulation tools become crucial at this phase
            allowed |= source_manip
            # Benchmarking, minimization, porting, refinement need an exploit
            allowed |= {"benchmark_exploit", "minimize_exploit",
                         "port_exploit", "refine_exploit_plan"}
            # Once we have a compiled exploit, remove pure analysis/prep
            # tools — the agent should focus on verify → fix → verify loop.
            analysis_tools_to_drop = {
                "analyze_struct", "analyze_conditions", "adapt_templates",
                "query_bug_db", "check_feasibility_static",
                "hunt_cves", "investigate",
                # Prep tools are already baked into the exploit source;
                # the agent should edit the code, not re-fetch templates.
                "get_rw_primitive", "get_spray_strategy",
                "plan_kaslr_bypass", "get_multiprocess_scaffold",
                "generate_binder_trigger", "get_race_template",
            }
            allowed -= analysis_tools_to_drop

        # Target diagnostic commands are available whenever SSH/ADB is configured
        if (ctx.ssh_host or ctx.instance) and not ctx.static_only:
            allowed |= target_diag
            # Interactive GDB tools — available once we have something to debug
            if state.get("has_vuln_info") or state.get("has_root_cause") or state.get("has_reproducer") or state.get("has_exploit"):
                allowed |= {"gdb_session", "gdb_command"}

        # --static mode: remove all tools that require a running VM/device
        if ctx.static_only:
            vm_tools = {
                "collect_target_info", "verify_reproducer", "verify_exploit",
                "run_target_command", "read_target_file", "runtime_feedback",
                "identify_slab_cache", "measure_crash_stability",
                "benchmark_exploit", "run_exploit_monitor",
                "check_feasibility_dynamic",
                "gdb_session", "gdb_command",
            }
            allowed -= vm_tools

        # Also block tools that have exhausted their total call budget
        # so the LLM doesn't even see them in the available tools list.
        for tool_name, count in self._tool_call_count.items():
            max_for = self._max_total_calls.get(
                tool_name, self._max_total_calls_default
            )
            if count >= max_for:
                blocked.add(tool_name)

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
            f"  {i+1}. {h['tool']}→{h['action'][:60]}"
            for i, h in enumerate(ctx.history[-12:])
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
                verification_feedback += f" — {last.failure_reason[:300]}"
            if last.feedback:
                verification_feedback += f"\n  Feedback: {last.feedback[:500]}"
            if last.crash_occurred:
                verification_feedback += f"\n  Crash: {last.crash_pattern}"
            if last.exploit_output:
                verification_feedback += (
                    f"\n  Output: {last.exploit_output[:600]}"
                )
            if last.dmesg_new:
                verification_feedback += (
                    f"\n  dmesg: {last.dmesg_new[:400]}"
                )
            # GDB function hits/misses from last verification
            if hasattr(last, "gdb_functions_hit") and last.gdb_functions_hit:
                verification_feedback += (
                    f"\n  GDB hit: {', '.join(last.gdb_functions_hit)}"
                )
            if hasattr(last, "gdb_functions_missed") and last.gdb_functions_missed:
                verification_feedback += (
                    f"\n  GDB missed: {', '.join(last.gdb_functions_missed)}"
                )
            # Monitor feedback from verification wrapper
            if hasattr(last, "monitor_feedback") and last.monitor_feedback:
                verification_feedback += (
                    f"\n  Monitor: {last.monitor_feedback[:400]}"
                )

            # Multi-attempt summary across ALL verification attempts
            if len(ctx.verification_history) > 1:
                n_total = len(ctx.verification_history)
                n_crash = sum(
                    1 for v in ctx.verification_history if v.crash_occurred
                )
                n_timeout = sum(
                    1 for v in ctx.verification_history
                    if v.failure_reason and "timeout" in v.failure_reason.lower()
                )
                n_ok = sum(
                    1 for v in ctx.verification_history if v.success
                )
                # Aggregate GDB hits across attempts
                all_gdb_hit: set[str] = set()
                for v in ctx.verification_history:
                    if hasattr(v, "gdb_functions_hit") and v.gdb_functions_hit:
                        all_gdb_hit.update(v.gdb_functions_hit)

                summary_parts = [
                    f"\n  All attempts ({n_total}): "
                    f"{n_ok} OK, {n_crash} crashed, {n_timeout} timeout"
                ]
                if all_gdb_hit:
                    summary_parts.append(
                        f"  GDB hit (any attempt): "
                        f"{', '.join(sorted(all_gdb_hit)[:10])}"
                    )
                if n_crash == n_total:
                    summary_parts.append(
                        "  Pattern: ALL attempts crashed — "
                        "use GDB to diagnose crash location"
                    )
                verification_feedback += "\n".join(summary_parts)

        # ── Accumulated knowledge summary ─────────────────────────────
        accumulated_knowledge = ""
        try:
            knowledge = ctx.decision_context_summary()
            if knowledge:
                accumulated_knowledge = (
                    "Accumulated knowledge:\n" + knowledge
                )
        except Exception:
            pass

        # ── GDB trace context (crash diagnostics) ────────────────────
        try:
            gdb_trace_ctx = ctx.format_gdb_trace_context()
            if gdb_trace_ctx:
                accumulated_knowledge += "\n\n" + gdb_trace_ctx
        except Exception:
            pass

        # ── Android constraints (from probe in collect_target_info) ──
        android_constraints = ctx.analysis_data.get("android_constraints")
        if android_constraints:
            constraint_lines = []
            if not android_constraints.get("msg_msg_available"):
                constraint_lines.append("• CONFIG_SYSVIPC NOT SET → msg_msg UNAVAILABLE (use setxattr/sk_buff)")
            if android_constraints.get("rtm_newlink_likely_blocked"):
                constraint_lines.append("• RTM_NEWLINK BLOCKED by SELinux → use ICMP-error trigger fallback")
            if android_constraints.get("setxattr_available"):
                constraint_lines.append("• setxattr spray AVAILABLE")
            if not android_constraints.get("user_ns"):
                constraint_lines.append("• CONFIG_USER_NS not set → no network namespace capability escape")
            if constraint_lines:
                accumulated_knowledge += (
                    "\n\nAndroid kernel constraints (probed on device):\n"
                    + "\n".join(constraint_lines)
                )

        # ── User-supplied extra context ───────────────────────────────
        if ctx.extra_context:
            accumulated_knowledge += (
                "\n\nUser-supplied context:\n"
                + ctx.extra_context[:5000]
            )

        # ── Tool usage stats + progress warning ──────────────────────
        tool_usage_notes = ""
        if self._tool_call_count:
            usage_lines = ", ".join(
                f"{n}:{c}x" for n, c in sorted(self._tool_call_count.items())
            )
            tool_usage_notes = f"\nTool call counts: {usage_lines}"

        progress_warning = ""
        total_steps = sum(self._tool_call_count.values())
        has_rc = ctx.has_root_cause()
        has_repro = ctx.has_reproducer()
        has_expl = ctx.has_exploit()
        repro_verified = ctx.has_verified_reproducer()
        if has_repro and repro_verified and not has_expl:
            repro_calls = self._tool_call_count.get("reproduce", 0)
            progress_warning = (
                "\n\n⚠ PROGRESS WARNING: The reproducer is VERIFIED and "
                "crash has been CONFIRMED. You have called 'reproduce' "
                f"{repro_calls} time(s). Do NOT call 'reproduce' again. "
                "IMMEDIATELY call 'exploit' to generate a privilege "
                "escalation exploit. If you need kernel offsets first, "
                "call 'resolve_kernel_offsets'."
            )
        elif total_steps >= 5 and has_rc and not has_repro and not has_expl:
            progress_warning = (
                "\n\n⚠ PROGRESS WARNING: You have root cause analysis but "
                "have NOT yet called 'reproduce' or 'exploit'. You have "
                f"used {total_steps} steps on information gathering. "
                "Stop searching for more data and IMMEDIATELY call "
                "'reproduce' to generate a crash reproducer, or 'exploit' "
                "to generate an exploit. Do NOT call query_bug_db, "
                "investigate, or other data-gathering tools again."
            )
        elif total_steps >= 3 and not has_rc:
            # Still don't have root cause after 3 steps — that's fine,
            # but nudge toward analyze if not done yet
            if "analyze" not in self._milestone_tools_called:
                progress_warning = (
                    "\n\n⚠ PROGRESS WARNING: You haven't called 'analyze' "
                    f"yet after {total_steps} steps. Start with 'analyze' "
                    "to get root cause analysis."
                )

        # Static mode note for LLM
        static_note = ""
        if ctx.static_only:
            static_note = (
                "\n\n⚠ STATIC-ONLY MODE: No VM, ADB, or SSH access is available. "
                "Do NOT attempt collect_target_info, verify_reproducer, "
                "verify_exploit, run_target_command, read_target_file, or "
                "runtime_feedback. Focus on: investigate → analyze → "
                "check_feasibility_static → resolve_kernel_offsets → "
                "reproduce (generate only) → exploit (generate + compile only). "
                "Once the exploit compiles successfully, call 'done'."
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
            errors="; ".join(ctx.errors[-5:]) if ctx.errors else "none",
            accumulated_knowledge=accumulated_knowledge + tool_usage_notes + progress_warning + static_note,
            verification_feedback=verification_feedback + blocked_notes,
            history=history_lines or "  (none yet)",
        )

        max_tok = self.cfg.llm_decision_max_tokens

        def _ensure_dict(val: Any) -> dict:
            """Normalize LLM JSON output to a dict (handles list responses)."""
            if isinstance(val, dict):
                return val
            if isinstance(val, list):
                # Some models wrap the response in a list — extract first dict
                for item in val:
                    if isinstance(item, dict) and "tool" in item:
                        return item
                # Fall through: try first element
                if val and isinstance(val[0], dict):
                    return val[0]
            raise ValueError(f"Expected dict, got {type(val).__name__}: {str(val)[:200]}")

        try:
            result = _ensure_dict(self.decision_llm.ask_json(prompt, max_tokens=max_tok))
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
                result = _ensure_dict(self.decision_llm.ask_json(
                    prompt, max_tokens=max(max_tok * 2, 8192)
                ))
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
                    result = _ensure_dict(_extract_json(raw))
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
