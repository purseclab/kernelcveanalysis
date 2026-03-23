"""
orchestrator.hunter — Autonomous CVE hunting and exploit chain generation.

Discovers CVEs for a target kernel, then runs the full agent pipeline
on each candidate, creating a separate work directory per CVE.

Usage::

    from syzploit.orchestrator.hunter import HunterOrchestrator

    hunter = HunterOrchestrator(kernel_version="5.10.107", cfg=cfg)
    results = hunter.run()
"""

from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..analysis.cve_hunter import CVECandidate, hunt_cves
from ..core.config import Config, load_config
from ..core.log import console
from ..core.reporting import save_report


class HunterOrchestrator:
    """Autonomous CVE hunter that discovers and exploits vulnerabilities.

    Workflow:
    1. Discover CVEs affecting the target kernel
    2. Rank by exploitability
    3. For each candidate (in priority order):
       a. Create a dedicated work directory
       b. Run the full agent pipeline
       c. Record results
    4. Generate a summary report of all attempts
    """

    def __init__(
        self,
        *,
        kernel_version: str,
        platform: str = "android",
        arch: str = "arm64",
        max_targets: int = 10,
        max_iterations_per_target: int = 20,
        output_dir: Optional[Path] = None,
        cfg: Optional[Config] = None,
        # Pass-through infra options
        ssh_host: str = "",
        ssh_port: int = 22,
        instance: Optional[int] = None,
        start_cmd: str = "",
        stop_cmd: str = "",
        exploit_start_cmd: str = "",
        gdb_port: int = 1234,
        setup_tunnels: bool = False,
        persistent: bool = False,
        kernel_image: str = "",
        goal: str = "",
    ):
        self.kernel_version = kernel_version
        self.platform = platform
        self.arch = arch
        self.max_targets = max_targets
        self.max_iterations = max_iterations_per_target
        self.cfg = cfg or load_config()
        self.output_dir = output_dir or Path(f"hunt_{kernel_version.replace('.', '_')}")

        # Infra pass-through
        self.ssh_host = ssh_host
        self.ssh_port = ssh_port
        self.instance = instance
        self.start_cmd = start_cmd
        self.stop_cmd = stop_cmd
        self.exploit_start_cmd = exploit_start_cmd
        self.gdb_port = gdb_port
        self.setup_tunnels = setup_tunnels
        self.persistent = persistent
        self.kernel_image = kernel_image
        self.goal = goal or (
            "Analyze vulnerability, understand root cause, generate "
            "and verify a working privilege escalation exploit"
        )

        self.results: list[dict[str, Any]] = []

    def run(
        self,
        *,
        candidates: Optional[list[CVECandidate]] = None,
        skip_discovery: bool = False,
    ) -> list[dict[str, Any]]:
        """Run the full hunt-and-exploit pipeline.

        Parameters
        ----------
        candidates:
            Pre-supplied CVE candidates (skip discovery phase).
        skip_discovery:
            If True *and* candidates is None, loads candidates from
            a previous hunt_candidates.json in the output directory.

        Returns
        -------
        List of per-CVE result dicts with keys:
            cve_id, priority, work_dir, outcome, duration_s, error
        """
        from .agent import Agent
        from .context import TaskContext
        from ..core.models import Arch, Platform

        self.output_dir.mkdir(parents=True, exist_ok=True)
        hunt_start = time.monotonic()

        # ── Phase 1: Discovery ────────────────────────────────────────
        if candidates is None:
            if skip_discovery:
                # Try loading from previous run
                prev = self.output_dir / "hunt_candidates.json"
                if prev.is_file():
                    console.print(f"[dim]Loading previous candidates from {prev}[/]")
                    raw = json.loads(prev.read_text())
                    candidates = [
                        CVECandidate(**c) for c in raw
                    ]
                else:
                    console.print("[yellow]No previous candidates found, running discovery[/]")
                    candidates = self._discover()
            else:
                candidates = self._discover()

        if not candidates:
            console.print("[bold red]No CVE candidates found. Exiting.[/]")
            return []

        # Save candidates for resume
        candidates_path = self.output_dir / "hunt_candidates.json"
        candidates_path.write_text(
            json.dumps([c.to_dict() for c in candidates], indent=2)
        )

        # ── Phase 2: Exploit each candidate ───────────────────────────
        console.print(
            f"\n[bold]Phase 2: Running agent on {len(candidates)} targets[/]"
        )

        arch_enum = Arch(self.arch) if self.arch in ("x86_64", "arm64") else Arch.ARM64
        plat_enum = (
            Platform(self.platform)
            if self.platform in ("linux", "android", "generic")
            else Platform.ANDROID
        )

        for i, candidate in enumerate(candidates, 1):
            cve_id = candidate.cve_id
            console.rule(f"[bold blue]Target {i}/{len(candidates)}: {cve_id}")

            # Create per-CVE work directory
            safe_name = cve_id.replace("-", "_").lower()
            work_dir = self.output_dir / f"analysis_{safe_name}"
            work_dir.mkdir(parents=True, exist_ok=True)

            # Check if already completed
            summary_file = work_dir / "pipeline_summary.json"
            if summary_file.is_file():
                console.print(f"  [dim]Already completed, skipping[/]")
                try:
                    summary = json.loads(summary_file.read_text())
                    outcome = summary.get("components", {}).get(
                        "exploit", {}
                    ).get("success", False)
                    self.results.append({
                        "cve_id": cve_id,
                        "priority": candidate.priority,
                        "work_dir": str(work_dir),
                        "outcome": "exploit_success" if outcome else "previous_run",
                        "duration_s": 0,
                        "error": "",
                    })
                except Exception:
                    pass
                continue

            # Build agent context
            target_start = time.monotonic()
            result_entry: dict[str, Any] = {
                "cve_id": cve_id,
                "priority": candidate.priority,
                "work_dir": str(work_dir),
                "outcome": "unknown",
                "duration_s": 0,
                "error": "",
            }

            try:
                ctx = TaskContext(
                    input_value=cve_id,
                    input_type="cve",
                    target_kernel=self.kernel_version,
                    target_arch=arch_enum,
                    target_platform=plat_enum,
                    work_dir=work_dir,
                )

                # Set infra options
                ctx.ssh_host = self.ssh_host or self.cfg.ssh_host
                ctx.ssh_port = self.ssh_port or self.cfg.ssh_port
                if self.instance is not None:
                    ctx.instance = self.instance
                ctx.start_cmd = self.start_cmd or self.cfg.start_cmd or ""
                ctx.stop_cmd = self.stop_cmd or self.cfg.stop_cmd or ""
                ctx.exploit_start_cmd = (
                    self.exploit_start_cmd or self.cfg.exploit_start_cmd or ""
                )
                ctx.gdb_port = self.gdb_port
                ctx.setup_tunnels = self.setup_tunnels
                ctx.persistent = self.persistent
                ctx.kernel_image = self.kernel_image or self.cfg.kernel_image or ""

                # Store hunter metadata
                if ctx.analysis_data is None:
                    ctx.analysis_data = {}
                ctx.analysis_data["hunter_candidate"] = candidate.to_dict()

                # Run agent
                agent = Agent(
                    goal=self.goal,
                    cfg=self.cfg,
                    max_iterations=self.max_iterations,
                )
                ctx = agent.run(cve_id, ctx=ctx)

                # Assess outcome
                duration = time.monotonic() - target_start
                result_entry["duration_s"] = round(duration, 1)

                if ctx.is_done():
                    result_entry["outcome"] = "exploit_success"
                elif ctx.has_exploit():
                    result_entry["outcome"] = "exploit_generated"
                elif ctx.root_cause is not None:
                    result_entry["outcome"] = "analysis_only"
                else:
                    result_entry["outcome"] = "incomplete"

            except Exception as e:
                result_entry["outcome"] = "error"
                result_entry["error"] = str(e)[:500]
                result_entry["duration_s"] = round(
                    time.monotonic() - target_start, 1
                )
                console.print(f"  [bold red]Error: {e}[/]")

            self.results.append(result_entry)

            # Brief progress report
            successes = sum(
                1 for r in self.results if r["outcome"] == "exploit_success"
            )
            console.print(
                f"  Outcome: {result_entry['outcome']} "
                f"({result_entry['duration_s']}s) — "
                f"Total successes: {successes}/{len(self.results)}"
            )

        # ── Phase 3: Summary report ──────────────────────────────────
        total_duration = time.monotonic() - hunt_start
        report = self._build_report(total_duration)
        report_path = self.output_dir / "hunt_report.json"
        report_path.write_text(json.dumps(report, indent=2))

        self._print_summary(report)

        return self.results

    def _discover(self) -> list[CVECandidate]:
        """Run the CVE discovery phase."""
        console.print(
            f"\n[bold]Phase 1: Discovering CVEs for kernel "
            f"{self.kernel_version}[/]"
        )
        candidates = hunt_cves(
            self.kernel_version,
            platform=self.platform,
            arch=self.arch,
            max_results=self.max_targets,
            cfg=self.cfg,
        )
        return candidates

    def _build_report(self, total_duration: float) -> dict[str, Any]:
        """Build the final hunt report."""
        successes = [r for r in self.results if r["outcome"] == "exploit_success"]
        generated = [r for r in self.results if r["outcome"] == "exploit_generated"]
        errors = [r for r in self.results if r["outcome"] == "error"]

        return {
            "hunt_report": True,
            "version": "1.0",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "target": {
                "kernel_version": self.kernel_version,
                "platform": self.platform,
                "arch": self.arch,
            },
            "summary": {
                "total_targets": len(self.results),
                "exploits_successful": len(successes),
                "exploits_generated": len(generated),
                "analysis_only": sum(
                    1 for r in self.results if r["outcome"] == "analysis_only"
                ),
                "errors": len(errors),
                "total_duration_s": round(total_duration, 1),
            },
            "results": self.results,
            "successful_cves": [r["cve_id"] for r in successes],
            "generated_cves": [
                r["cve_id"] for r in generated
            ],
        }

    def _print_summary(self, report: dict) -> None:
        """Print a formatted hunt summary."""
        from rich.table import Table

        s = report["summary"]
        console.print(f"\n{'═' * 60}")
        console.print(f"[bold]Hunt Complete — kernel {self.kernel_version}[/]")
        console.print(f"{'═' * 60}")

        table = Table(show_header=True, header_style="bold")
        table.add_column("CVE")
        table.add_column("Priority")
        table.add_column("Outcome")
        table.add_column("Duration")
        table.add_column("Error")

        for r in report["results"]:
            style = ""
            if r["outcome"] == "exploit_success":
                style = "bold green"
            elif r["outcome"] == "exploit_generated":
                style = "yellow"
            elif r["outcome"] == "error":
                style = "red"

            table.add_row(
                r["cve_id"],
                str(r.get("priority", "?")),
                r["outcome"],
                f"{r['duration_s']}s",
                r.get("error", "")[:60],
                style=style,
            )

        console.print(table)
        console.print(
            f"\n  Successful exploits: {s['exploits_successful']}/{s['total_targets']}"
        )
        console.print(f"  Total time: {s['total_duration_s']}s")
        console.print(f"  Report: {self.output_dir / 'hunt_report.json'}")
