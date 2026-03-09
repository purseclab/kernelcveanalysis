"""
core.reporting — Structured JSON report persistence.

Provides helpers to save per-component reports and a final pipeline
summary so that every stage's findings (evidence, reasoning, root cause,
feasibility, reproduction, exploitation, verification) are written to
disk for later review.

All reports use a standard JSON *envelope*::

    {
        "syzploit_report": true,
        "version": "1.0",
        "stage": "<component>",
        "generated_at": "2025-…",
        "metadata": { … },
        "data": { <model fields> }
    }
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from pydantic import BaseModel

from .log import console


# ── Envelope builder ──────────────────────────────────────────────────


def _report_envelope(
    stage: str,
    data: Any,
    *,
    metadata: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Wrap component data in a standard envelope with timestamp + metadata."""
    envelope: Dict[str, Any] = {
        "syzploit_report": True,
        "version": "1.0",
        "stage": stage,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
    if metadata:
        envelope["metadata"] = metadata

    # Serialize the payload
    if isinstance(data, BaseModel):
        envelope["data"] = data.model_dump(mode="json")
    elif isinstance(data, dict):
        envelope["data"] = data
    elif isinstance(data, list):
        envelope["data"] = [
            item.model_dump(mode="json") if isinstance(item, BaseModel) else item
            for item in data
        ]
    else:
        envelope["data"] = str(data)

    return envelope


# ── Per-component report saving ───────────────────────────────────────


def save_report(
    stage: str,
    data: Any,
    work_dir: Optional[Path],
    *,
    filename: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> Optional[Path]:
    """
    Save a report for a single pipeline component as JSON.

    Parameters
    ----------
    stage:
        Pipeline stage name — ``"analysis"``, ``"feasibility"``,
        ``"reproducer"``, ``"exploit"``, ``"verification"``, etc.
    data:
        A Pydantic ``BaseModel``, dict, or list to serialize.
    work_dir:
        Output directory.  If ``None`` the report is silently skipped.
    filename:
        Custom filename.  Defaults to ``"{stage}_report.json"``.
    metadata:
        Extra metadata to include in the envelope (e.g. target kernel).

    Returns
    -------
    Path to the written file, or ``None`` if *work_dir* was unset.
    """
    if work_dir is None:
        return None

    work_dir = Path(work_dir)
    work_dir.mkdir(parents=True, exist_ok=True)

    fname = filename or f"{stage}_report.json"
    path = work_dir / fname

    envelope = _report_envelope(stage, data, metadata=metadata)
    path.write_text(json.dumps(envelope, indent=2, default=str))

    console.print(f"  [dim]📄 Report saved: {path}[/]")
    return path


# ── Full pipeline summary ─────────────────────────────────────────────


def save_pipeline_summary(
    ctx: Any,  # TaskContext — typed as Any to avoid circular import
    work_dir: Optional[Path] = None,
) -> Optional[Path]:
    """
    Save a comprehensive pipeline summary covering *all* components.

    Aggregates every accumulated artefact from the ``TaskContext`` into
    a single ``pipeline_summary.json`` file.
    """
    # Use ctx.work_dir as fallback
    resolved_dir = work_dir or getattr(ctx, "work_dir", None)
    if resolved_dir is None:
        return None

    resolved_dir = Path(resolved_dir)
    resolved_dir.mkdir(parents=True, exist_ok=True)

    summary: Dict[str, Any] = {
        "syzploit_report": True,
        "version": "1.0",
        "stage": "pipeline_summary",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "run_id": getattr(ctx, "run_id", ""),
        "input": {
            "type": getattr(ctx, "input_type", ""),
            "value": getattr(ctx, "input_value", ""),
        },
        "target": {
            "kernel": getattr(ctx, "target_kernel", ""),
            "arch": ctx.target_arch.value if getattr(ctx, "target_arch", None) else "",
            "platform": ctx.target_platform.value if getattr(ctx, "target_platform", None) else "",
        },
        "components": {},
        "outcomes": {
            "has_root_cause": ctx.has_root_cause(),
            "has_reproducer": ctx.has_reproducer(),
            "reproducer_verified": ctx.has_verified_reproducer(),
            "has_exploit": ctx.has_exploit(),
            "exploit_verified": ctx.has_verified_exploit(),
        },
        "errors": list(getattr(ctx, "errors", [])),
        "history": list(getattr(ctx, "history", [])),
    }

    # ── Component data ────────────────────────────────────────────────

    if ctx.crash_report:
        summary["components"]["crash_report"] = ctx.crash_report.model_dump(mode="json")

    if ctx.root_cause:
        summary["components"]["root_cause"] = ctx.root_cause.model_dump(mode="json")

    if ctx.feasibility:
        summary["components"]["feasibility"] = ctx.feasibility.model_dump(mode="json")

    if ctx.reproducer:
        summary["components"]["reproducer"] = ctx.reproducer.model_dump(mode="json")

    if ctx.exploit_plan:
        summary["components"]["exploit_plan"] = ctx.exploit_plan.model_dump(mode="json")

    if ctx.exploit_result:
        summary["components"]["exploit_result"] = ctx.exploit_result.model_dump(mode="json")

    if getattr(ctx, "verification_history", None):
        summary["components"]["verification_history"] = [
            v.model_dump(mode="json") for v in ctx.verification_history
        ]

    # Include the execution trace tool sequence for quick inspection
    trace = getattr(ctx, "execution_trace", None)
    if trace is not None:
        summary["execution_trace"] = {
            "run_id": trace.run_id,
            "mode": trace.mode,
            "tool_sequence": trace.tool_sequence,
            "total_steps": trace.total_steps,
            "total_duration_ms": trace.total_duration_ms,
            "final_outcome": trace.final_outcome,
        }

    path = resolved_dir / "pipeline_summary.json"
    path.write_text(json.dumps(summary, indent=2, default=str))

    console.print(f"\n  [bold]📋 Pipeline summary saved: {path}[/]")
    return path


# ── Execution trace persistence ───────────────────────────────────────


def save_execution_trace(
    trace: Any,  # ExecutionTrace — typed as Any to avoid circular import
    work_dir: Optional[Path] = None,
) -> Optional[Path]:
    """
    Save the full execution trace for an agentic run.

    The trace captures *every* agent decision: which tool was chosen,
    the LLM's reasoning, timing of each step, state snapshots before
    and after, and what changed.  Each run gets a unique ``run_id`` so
    traces stored in the same directory are distinguishable.

    File: ``execution_trace_{run_id}.json``
    """
    if work_dir is None:
        return None

    work_dir = Path(work_dir)
    work_dir.mkdir(parents=True, exist_ok=True)

    fname = f"execution_trace_{trace.run_id}.json"
    path = work_dir / fname

    envelope: Dict[str, Any] = {
        "syzploit_report": True,
        "version": "1.0",
        "stage": "execution_trace",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "data": trace.model_dump(mode="json"),
    }
    path.write_text(json.dumps(envelope, indent=2, default=str))

    console.print(f"  [dim]📄 Execution trace saved: {path}[/]")
    return path


# ── Trace comparison ──────────────────────────────────────────────────


def compare_execution_traces(
    trace_paths: List[Path],
) -> Dict[str, Any]:
    """
    Compare multiple execution trace files and produce a diff report.

    Returns a dict with:
        - ``runs``: per-run summary (run_id, tool_sequence, outcome, timing)
        - ``tool_sequences_match``: bool — whether all runs chose the
          same tools in the same order
        - ``sequence_alignment``: step-by-step alignment across runs
        - ``divergence_points``: where runs first differ
        - ``timing_comparison``: per-step and total duration comparison
    """
    traces: List[Dict[str, Any]] = []
    for p in trace_paths:
        raw = json.loads(Path(p).read_text())
        data = raw.get("data", raw)
        traces.append(data)

    if not traces:
        return {"error": "No traces provided"}

    # ── Per-run summary ───────────────────────────────────────────────
    runs = []
    for t in traces:
        runs.append({
            "run_id": t.get("run_id", "?"),
            "started_at": t.get("started_at", ""),
            "mode": t.get("mode", ""),
            "total_steps": t.get("total_steps", 0),
            "total_duration_ms": t.get("total_duration_ms", 0),
            "final_outcome": t.get("final_outcome", ""),
            "final_reason": t.get("final_reason", ""),
            "tool_sequence": t.get("tool_sequence", []),
            "errors": t.get("errors", []),
        })

    # ── Sequence comparison ───────────────────────────────────────────
    sequences = [tuple(t.get("tool_sequence", [])) for t in traces]
    all_match = len(set(sequences)) == 1

    # Step-by-step alignment (pad shorter sequences with None)
    max_steps = max(len(s) for s in sequences) if sequences else 0
    alignment: List[Dict[str, Any]] = []
    first_divergence: Optional[int] = None

    for step_idx in range(max_steps):
        row: Dict[str, Any] = {"step": step_idx + 1}
        tools_at_step: List[Optional[str]] = []
        for run_idx, seq in enumerate(sequences):
            tool = seq[step_idx] if step_idx < len(seq) else None
            row[f"run_{run_idx}_tool"] = tool
            tools_at_step.append(tool)

        row["all_same"] = len(set(tools_at_step)) == 1
        alignment.append(row)

        if first_divergence is None and not row["all_same"]:
            first_divergence = step_idx + 1

    # ── Timing comparison ─────────────────────────────────────────────
    timing: List[Dict[str, Any]] = []
    for step_idx in range(max_steps):
        row: Dict[str, Any] = {"step": step_idx + 1}
        for run_idx, t in enumerate(traces):
            steps = t.get("steps", [])
            if step_idx < len(steps):
                s = steps[step_idx]
                row[f"run_{run_idx}_tool"] = s.get("tool", "")
                row[f"run_{run_idx}_ms"] = s.get("duration_ms", 0)
                row[f"run_{run_idx}_ok"] = s.get("success", True)
            else:
                row[f"run_{run_idx}_tool"] = None
                row[f"run_{run_idx}_ms"] = None
                row[f"run_{run_idx}_ok"] = None
        timing.append(row)

    # ── State change comparison ───────────────────────────────────────
    state_diffs: List[Dict[str, Any]] = []
    for step_idx in range(max_steps):
        row: Dict[str, Any] = {"step": step_idx + 1}
        for run_idx, t in enumerate(traces):
            steps = t.get("steps", [])
            if step_idx < len(steps):
                s = steps[step_idx]
                row[f"run_{run_idx}_tool"] = s.get("tool", "")
                row[f"run_{run_idx}_reason"] = s.get("reason", "")
                row[f"run_{run_idx}_changed"] = s.get("state_changed", [])
            else:
                row[f"run_{run_idx}_tool"] = None
                row[f"run_{run_idx}_reason"] = None
                row[f"run_{run_idx}_changed"] = None
        state_diffs.append(row)

    return {
        "runs_compared": len(traces),
        "tool_sequences_match": all_match,
        "first_divergence_step": first_divergence,
        "runs": runs,
        "sequence_alignment": alignment,
        "timing_comparison": timing,
        "state_change_comparison": state_diffs,
    }
