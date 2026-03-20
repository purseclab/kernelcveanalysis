"""
orchestrator.pipeline — Deterministic (non-agentic) pipelines.

For users who want a predictable sequence rather than an LLM-driven
loop, these functions run fixed stages in order:

    analyze → reproduce → exploit

Each stage is optional and can be skipped via flags.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, Optional

from pydantic import BaseModel, Field

from ..core.config import Config, load_config
from ..core.log import console
from ..core.models import (
    Arch,
    CrashReport,
    FeasibilityReport,
    Platform,
    RootCauseAnalysis,
    TargetSystemInfo,
)
from ..core.reporting import save_report, save_pipeline_summary
from .context import TaskContext


class PipelineResult(BaseModel):
    """Final output of a deterministic pipeline run."""

    ctx: TaskContext
    success: bool = False
    summary: str = ""


# ── Report hydration (for --skip-* flags) ─────────────────────────────


def _hydrate_ctx_from_reports(ctx: TaskContext) -> None:
    """
    When pipeline stages are skipped, load their saved reports from the
    work directory so that downstream stages can use them.

    This is a best-effort loader — if a report file is missing or
    corrupted we simply skip it (the downstream stage will produce
    its own error appropriately).
    """
    wd = ctx.work_dir
    if wd is None:
        return

    wd = Path(wd)
    if not wd.is_dir():
        return

    # Map of (report file name, ctx attribute, model class)
    _REPORT_MAP: list[tuple[str, str, type[BaseModel]]] = [
        ("root_cause_analysis_report.json", "root_cause", RootCauseAnalysis),
        ("target_system_info_report.json", "target_system_info", TargetSystemInfo),
        ("feasibility_static_report.json", "feasibility", FeasibilityReport),
    ]

    for fname, attr, model_cls in _REPORT_MAP:
        if getattr(ctx, attr) is not None:
            continue  # already populated
        report_path = wd / fname
        if not report_path.exists():
            continue
        try:
            raw = json.loads(report_path.read_text())
            data = raw.get("data", raw)
            obj = model_cls.model_validate(data)
            setattr(ctx, attr, obj)
            console.print(
                f"  [dim]↻ Loaded {attr} from {fname}[/]"
            )
        except Exception as exc:
            console.print(
                f"  [yellow]Warning: could not hydrate {attr} from {fname}: {exc}[/]"
            )

    # Also try loading investigation_briefing if available
    if not getattr(ctx, "investigation_briefing", None):
        briefing_path = wd / "investigation_briefing.json"
        if briefing_path.exists():
            try:
                from ..analysis.investigation_briefing import InvestigationBriefing  # type: ignore[import-untyped]

                raw = json.loads(briefing_path.read_text())
                data = raw.get("data", raw)
                ctx.investigation_briefing = InvestigationBriefing.model_validate(data)  # type: ignore[attr-defined]
                console.print("  [dim]↻ Loaded investigation_briefing from investigation_briefing.json[/]")
            except Exception:
                pass  # optional field


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
    skip_verify: bool = False,
    cfg: Optional[Config] = None,
    ctx: Optional[TaskContext] = None,
) -> PipelineResult:
    """
    Run the full deterministic pipeline:

    1. **Analyze** — parse crash / fetch CVE / scrape blog → root cause
    2. **Reproduce** — generate reproducer for target kernel, compile, verify
    3. **Exploit** — plan exploitation, generate code, compile
    4. **Verify** — deploy exploit to target, check privilege escalation

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

    # ── Hydrate context from existing reports when stages are skipped ─
    if skip_analysis or skip_reproducer:
        _hydrate_ctx_from_reports(ctx)

    # ── Classify input type if not already set ────────────────────────
    if not ctx.input_type:
        val = ctx.input_value.strip()
        if re.match(r"CVE-\d{4}-\d+", val, re.IGNORECASE):
            ctx.input_type = "cve"
        elif "syzkaller" in val or "syzbot" in val or "bugs.chromium.org" in val:
            ctx.input_type = "syzbot"
        elif val.startswith("http"):
            ctx.input_type = "blog_post"
        elif val.endswith(".c") and "/" in val:
            ctx.input_type = "poc"
        elif any(sig in val.lower() for sig in ("bug:", "kasan:", "oops:", "call trace:", "panic")):
            ctx.input_type = "crash_log"

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

    # ── Stage 4: Verification ─────────────────────────────────────────
    if not skip_verify and ctx.has_exploit() and ctx.ssh_host:
        console.print("[bold]Stage 4: Verification[/]")
        try:
            binary_path = ctx.exploit_result.binary_path  # type: ignore[union-attr]
            if binary_path:
                from ..exploit.pipeline import _verify_exploit_step
                ctx = _verify_exploit_step(ctx, cfg, binary_path)
                ctx.log("pipeline", "verify", "completed")
                if ctx.has_verified_exploit():
                    save_report(
                        "verification_result",
                        {"status": "privilege_escalation_confirmed"},
                        ctx.work_dir,
                        metadata={"target_kernel": ctx.target_kernel},
                    )
            else:
                ctx.log("pipeline", "verify", "skipped — no binary path")
                console.print("  [yellow]Skipping verification — no binary path[/]")
        except Exception as exc:
            ctx.errors.append(f"Verification failed: {exc}")
            ctx.log("pipeline", "verify", f"failed: {exc}")
            console.print(f"[red]Verification failed: {exc}[/]")
    elif not skip_verify and ctx.has_exploit() and not ctx.ssh_host:
        console.print(
            "[yellow]Stage 4: Skipped — no SSH host configured. "
            "Use --ssh-host or syzploit verify-exploit to verify manually.[/]"
        )

    success = ctx.has_verified_exploit() or ctx.has_exploit() or ctx.has_reproducer() or ctx.has_root_cause()
    summary_parts = []
    if ctx.has_root_cause():
        summary_parts.append("root cause identified")
    if ctx.has_reproducer():
        summary_parts.append("reproducer generated")
    if ctx.has_exploit():
        summary_parts.append("exploit generated")
    if ctx.has_verified_exploit():
        summary_parts.append("exploit VERIFIED — privilege escalation confirmed")
    if ctx.errors:
        summary_parts.append(f"{len(ctx.errors)} error(s)")

    # ── Save final pipeline summary ───────────────────────────────────
    save_pipeline_summary(ctx, ctx.work_dir)

    return PipelineResult(
        ctx=ctx,
        success=success,
        summary="; ".join(summary_parts) if summary_parts else "no results",
    )
