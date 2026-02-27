"""
analysis.root_cause — LLM-driven root cause reasoning.

Given a parsed ``CrashReport`` (and optionally kernel source snippets),
ask the LLM to explain *why* the crash happens, what the underlying
bug is, and what an attacker can control.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from ..core.config import Config, load_config
from ..core.llm import LLMClient
from ..core.models import (
    Confidence,
    ControlClassification,
    CrashReport,
    RootCauseAnalysis,
    VulnType,
)

# ── Prompt ────────────────────────────────────────────────────────────

_ROOT_CAUSE_PROMPT = """\
You are a senior Linux kernel security researcher.

Analyze the following kernel crash and provide a detailed root cause analysis.

Crash type: {crash_type}
Bug type: {bug_type}
Corrupted function: {corrupted_function}
Access: {access_type} of size {access_size}
Slab cache: {slab_cache}
Object size: {object_size}
Kernel version: {kernel_version}

Stack trace (crash):
{stack_trace}

Allocation trace:
{alloc_trace}

Free trace:
{free_trace}

{source_context}

Return JSON:
{{
    "summary": "<1-2 sentence summary of the vulnerability>",
    "vulnerable_function": "<the function containing the bug>",
    "vulnerable_file": "<source file if determinable>",
    "vulnerability_type": "<uaf|oob_read|oob_write|double_free|race_condition|type_confusion|integer_overflow|null_deref|logic_bug|unknown>",
    "root_cause_description": "<detailed explanation of why the bug occurs>",
    "trigger_conditions": ["<list of conditions needed to trigger>"],
    "affected_subsystem": "<kernel subsystem>",
    "affected_structs": ["<struct names involved>"],
    "affected_fields": ["<specific struct fields if identifiable>"],
    "control_classification": "<none|data_only|limited_write|ip_control|arbitrary_krw|arbitrary_rce>",
    "exploitability_score": <0-100>,
    "confidence": "<low|medium|high>",
    "evidence": [
        {{"id": 1, "file": "<file>", "line": <line>, "text": "<code line>", "reason": "<why relevant>"}}
    ],
    "kernel_structs": ["<structs referenced in crash path>"],
    "kernel_functions": ["<important functions in call chain>"],
    "syscalls": ["<syscalls that can trigger this path>"],
    "slab_caches": ["<relevant slab caches>"]
}}
"""


def root_cause_analysis(
    crash: CrashReport,
    *,
    source_snippets: Optional[Dict[str, str]] = None,
    cfg: Optional[Config] = None,
) -> RootCauseAnalysis:
    """
    Produce an LLM-driven root cause analysis from a parsed crash report.

    Args:
        crash: A parsed ``CrashReport``.
        source_snippets: Optional map of ``function_name → source code``.
        cfg: Configuration (uses default if not provided).

    Returns:
        ``RootCauseAnalysis`` with structured findings.
    """
    cfg = cfg or load_config()
    llm = LLMClient(cfg).for_task("analysis")

    # Format stack traces
    def fmt_frames(frames: list) -> str:
        if not frames:
            return "  (not available)"
        return "\n".join(f"  {f.display()}" for f in frames[:20])

    source_ctx = ""
    if source_snippets:
        parts = []
        for func, code in list(source_snippets.items())[:10]:
            parts.append(f"--- {func} ---\n{code[:2000]}")
        source_ctx = "Relevant source code:\n" + "\n\n".join(parts)

    prompt = _ROOT_CAUSE_PROMPT.format(
        crash_type=crash.crash_type,
        bug_type=crash.bug_type.value,
        corrupted_function=crash.corrupted_function,
        access_type=crash.access_type or "unknown",
        access_size=crash.access_size or "unknown",
        slab_cache=crash.slab_cache or "unknown",
        object_size=crash.object_size or "unknown",
        kernel_version=crash.kernel_version or "unknown",
        stack_trace=fmt_frames(crash.stack_frames),
        alloc_trace=fmt_frames(crash.alloc_frames),
        free_trace=fmt_frames(crash.free_frames),
        source_context=source_ctx,
    )

    result = llm.ask_json(
        prompt,
        system="You are a kernel vulnerability researcher performing root cause analysis.",
    )

    return RootCauseAnalysis(
        summary=result.get("summary", ""),
        vulnerable_function=result.get("vulnerable_function", crash.corrupted_function),
        vulnerable_file=result.get("vulnerable_file", ""),
        vulnerability_type=VulnType.from_str(result.get("vulnerability_type", crash.bug_type.value)),
        root_cause_description=result.get("root_cause_description", ""),
        trigger_conditions=result.get("trigger_conditions", []),
        affected_subsystem=result.get("affected_subsystem", crash.subsystem),
        affected_structs=result.get("affected_structs", []),
        affected_fields=result.get("affected_fields", []),
        fix_commit=result.get("fix_commit"),
        control_classification=ControlClassification(
            result.get("control_classification", "none")
        )
        if result.get("control_classification") in [e.value for e in ControlClassification]
        else ControlClassification.NONE,
        exploitability_score=result.get("exploitability_score", 0),
        confidence=Confidence(result.get("confidence", "low"))
        if result.get("confidence") in [e.value for e in Confidence]
        else Confidence.LOW,
        evidence=result.get("evidence", []),
        kernel_structs=result.get("kernel_structs", []),
        kernel_functions=result.get("kernel_functions", []),
        syscalls=result.get("syscalls", []),
        slab_caches=result.get("slab_caches", []),
    )
