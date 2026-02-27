"""
orchestrator.pipeline — Deterministic (non-agentic) pipelines.

For users who want a predictable sequence rather than an LLM-driven
loop, these functions run fixed stages in order:

    analyze → reproduce → exploit

Each stage is optional and can be skipped via flags.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Optional

from pydantic import BaseModel, Field

from ..core.config import Config, load_config
from ..core.log import console
from ..core.models import Arch, Platform
from ..core.reporting import save_report, save_pipeline_summary
from .context import TaskContext


class PipelineResult(BaseModel):
    """Final output of a deterministic pipeline run."""

    ctx: TaskContext
    success: bool = False
    summary: str = ""


def run_pipeline(
    input_value: str,
    *,
    target_kernel: str = "",
    target_arch: str = "arm64",
    target_platform: str = "android",
    work_dir: Optional[str] = None,
    skip_analysis: bool = False,
    skip_reproducer: bool = False,
    skip_exploit: bool = False,
    cfg: Optional[Config] = None,
    ctx: Optional[TaskContext] = None,
) -> PipelineResult:
    """
    Run the full deterministic pipeline:

    1. **Analyze** — parse crash / fetch CVE / scrape blog → root cause
    2. **Reproduce** — generate reproducer for target kernel, compile, verify
    3. **Exploit** — plan exploitation, generate code, verify priv-esc

    Returns a ``PipelineResult`` with the accumulated ``TaskContext``.

    Parameters
    ----------
    ctx:
        Optional pre-built ``TaskContext`` with infra options already
        populated.  When provided, ``target_*`` / ``work_dir`` keyword
        args are ignored.
    """
    cfg = cfg or load_config()
    if ctx is None:
        ctx = TaskContext(
            input_value=input_value,
            target_kernel=target_kernel,
            target_arch=Arch(target_arch) if target_arch in ("x86_64", "arm64") else Arch.ARM64,
            target_platform=Platform(target_platform) if target_platform in ("linux", "android", "generic") else Platform.ANDROID,
            work_dir=Path(work_dir) if work_dir else None,
        )

    # ── Stage 1: Analysis ─────────────────────────────────────────────
    if not skip_analysis:
        console.print("[bold]Stage 1: Analysis[/]")
        try:
            from ..analysis import analyze_input
            ctx = analyze_input(ctx, cfg)
            ctx.log("pipeline", "analyze", "completed")
            # Save analysis reports
            meta = {"input_type": ctx.input_type, "input_value": ctx.input_value}
            if ctx.crash_report:
                save_report("crash_report", ctx.crash_report, ctx.work_dir, metadata=meta)
            if ctx.root_cause:
                save_report("root_cause_analysis", ctx.root_cause, ctx.work_dir, metadata=meta)
        except Exception as exc:
            ctx.errors.append(f"Analysis failed: {exc}")
            ctx.log("pipeline", "analyze", f"failed: {exc}")
            console.print(f"[red]Analysis failed: {exc}[/]")

    # ── Stage 2: Reproducer ───────────────────────────────────────────
    if not skip_reproducer:
        console.print("[bold]Stage 2: Reproducer[/]")
        try:
            from ..reproducer import generate_reproducer
            ctx = generate_reproducer(ctx, cfg)
            ctx.log("pipeline", "reproduce", "completed")
            if ctx.reproducer:
                save_report(
                    "reproducer", ctx.reproducer, ctx.work_dir,
                    metadata={"target_kernel": ctx.target_kernel},
                )
        except Exception as exc:
            ctx.errors.append(f"Reproducer failed: {exc}")
            ctx.log("pipeline", "reproduce", f"failed: {exc}")
            console.print(f"[red]Reproducer failed: {exc}[/]")

    # ── Stage 3: Exploit ──────────────────────────────────────────────
    if not skip_exploit:
        console.print("[bold]Stage 3: Exploit[/]")
        try:
            from ..exploit import generate_exploit
            ctx = generate_exploit(ctx, cfg)
            ctx.log("pipeline", "exploit", "completed")
            if ctx.exploit_plan:
                save_report(
                    "exploit_plan", ctx.exploit_plan, ctx.work_dir,
                    metadata={"target_kernel": ctx.target_kernel},
                )
            if ctx.exploit_result:
                save_report(
                    "exploit_result", ctx.exploit_result, ctx.work_dir,
                    metadata={"target_kernel": ctx.target_kernel},
                )
        except Exception as exc:
            ctx.errors.append(f"Exploit failed: {exc}")
            ctx.log("pipeline", "exploit", f"failed: {exc}")
            console.print(f"[red]Exploit failed: {exc}[/]")

    success = ctx.has_exploit() or ctx.has_reproducer() or ctx.has_root_cause()
    summary_parts = []
    if ctx.has_root_cause():
        summary_parts.append("root cause identified")
    if ctx.has_reproducer():
        summary_parts.append("reproducer generated")
    if ctx.has_exploit():
        summary_parts.append("exploit generated")
    if ctx.errors:
        summary_parts.append(f"{len(ctx.errors)} error(s)")

    # ── Save final pipeline summary ───────────────────────────────────
    save_pipeline_summary(ctx, ctx.work_dir)

    return PipelineResult(
        ctx=ctx,
        success=success,
        summary="; ".join(summary_parts) if summary_parts else "no results",
    )
