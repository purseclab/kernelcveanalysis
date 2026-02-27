"""
reproducer.generator — LLM-driven reproducer C code generation.

Given a ``RootCauseAnalysis`` (or ``CrashReport``), asks the LLM to
generate a minimal C program that triggers the vulnerability on a
specified target kernel version.
"""

from __future__ import annotations

from typing import Optional

from ..core.config import Config, load_config
from ..core.llm import LLMClient, RESEARCH_SYSTEM_PROMPT
from ..core.log import console
from ..core.models import CrashReport, RootCauseAnalysis
from .compiler import _is_truncated

# ── Prompt ────────────────────────────────────────────────────────────

_REPRODUCER_PROMPT = """\
Generate a minimal C reproducer that triggers the following Linux kernel vulnerability.
The reproducer must work on the TARGET kernel version specified below.

Vulnerability details:
- Type: {vuln_type}
- Affected function: {function}
- Affected subsystem: {subsystem}
- Root cause: {root_cause}
- Trigger conditions: {triggers}
- Relevant structs: {structs}
- Relevant syscalls: {syscalls}
- Slab cache: {slab_cache}

Target kernel version: {target_kernel}
Target architecture: {arch}

{existing_reproducer}

{previous_feedback}

Requirements:
1. Self-contained single .c file
2. No external dependencies beyond standard libc and Linux headers
3. Must compile with a cross-compiler (no kernel build tree needed)
4. Include clear comments explaining what each section does
5. Use syscalls directly where needed (via syscall() or inline assembly)
6. Handle errors gracefully and print status messages
7. IMPORTANT: Keep the code CONCISE — aim for under 500 lines total.
   The code MUST NOT be truncated — ensure it includes a complete main().

Return ONLY the complete C source code, no markdown fences or explanation.
"""


def generate_reproducer_code(
    root_cause: RootCauseAnalysis,
    *,
    crash: Optional[CrashReport] = None,
    target_kernel: str = "",
    arch: str = "arm64",
    previous_feedback: str = "",
    previous_source: str = "",
    cfg: Optional[Config] = None,
) -> str:
    """
    Use LLM to generate a C reproducer for the vulnerability.

    Parameters
    ----------
    previous_feedback:
        Feedback from the last failed verification attempt, including
        the reproducer's stdout/stderr and dmesg output.  Helps the LLM
        avoid repeating failed approaches.
    previous_source:
        The C source code of the previous failed reproducer, so the LLM
        can see exactly what was tried and what to change.

    Returns the C source code as a string.
    """
    cfg = cfg or load_config()
    llm = LLMClient(cfg).for_task("codegen")

    existing = ""
    if crash and crash.reproducer_c:
        existing = (
            f"An existing reproducer exists (may need adaptation for the target kernel):\n"
            f"```c\n{crash.reproducer_c[:8000]}\n```"
        )

    # Build previous-failure context
    feedback_section = ""
    if previous_feedback or previous_source:
        feedback_section = "PREVIOUS ATTEMPT FAILED — do NOT repeat the same mistakes:\n"
        if previous_feedback:
            feedback_section += (
                f"Failure feedback:\n{previous_feedback[:2000]}\n\n"
            )
        if previous_source:
            feedback_section += (
                f"Previous reproducer code that FAILED (study the errors above and fix them):\n"
                f"```c\n{previous_source[:6000]}\n```\n"
            )
        feedback_section += (
            "\nYou MUST address the specific errors above. "
            "If EBUSY was returned by BINDER_SET_CONTEXT_MGR, use fork() so "
            "the child registers as context manager. If EINVAL was returned by "
            "an ioctl, ensure all struct fields match what the kernel expects. "
            "If no crash occurred, add debug printf() calls to show which code "
            "path was reached and what return codes were received.\n"
        )

    prompt = _REPRODUCER_PROMPT.format(
        vuln_type=root_cause.vulnerability_type.value,
        function=root_cause.vulnerable_function,
        subsystem=root_cause.affected_subsystem,
        root_cause=root_cause.root_cause_description,
        triggers=", ".join(root_cause.trigger_conditions) or "unknown",
        structs=", ".join(root_cause.affected_structs) or "unknown",
        syscalls=", ".join(root_cause.syscalls) or "unknown",
        slab_cache=", ".join(root_cause.slab_caches) or "unknown",
        target_kernel=target_kernel or "latest",
        arch=arch,
        existing_reproducer=existing,
        previous_feedback=feedback_section,
    )

    code = llm.research_chat(
        [{"role": "user", "content": prompt}],
        max_retries=3,
        max_tokens=16384,
    )

    # Strip markdown fences if present
    code = code.strip()
    if code.startswith("```"):
        lines = code.split("\n")
        # Remove first and last fence lines
        if lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        code = "\n".join(lines)

    # Detect and recover from truncation
    if _is_truncated(code):
        console.print("  [yellow]Generated reproducer appears truncated, requesting completion…[/]")
        continuation_prompt = (
            "The C code you just generated was TRUNCATED. "
            "Here is the end of what was generated:\n\n"
            f"```c\n{code[-3000:]}\n```\n\n"
            "Please complete the remaining code starting from where it was "
            "cut off. Include all remaining functions and a complete main(). "
            "Return ONLY the continuation C code."
        )
        continuation = llm.research_chat(
            [{"role": "user", "content": continuation_prompt}],
            max_retries=2,
            max_tokens=16384,
        )
        continuation = continuation.strip()
        if continuation.startswith("```"):
            clines = continuation.split("\n")
            if clines[0].startswith("```"):
                clines = clines[1:]
            if clines and clines[-1].strip() == "```":
                clines = clines[:-1]
            continuation = "\n".join(clines)
        if continuation and len(continuation) > 50:
            code = code + "\n" + continuation

    return code
