"""
cli.app — Main Typer application with sub-command groups.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import List, Optional

import typer
from rich.console import Console
from rich.table import Table

from ..core.config import load_config
from ..core.models import Arch, Platform
from ..core.reporting import save_pipeline_summary, save_report

app = typer.Typer(
    name="syzploit",
    help="Kernel vulnerability analysis and exploit synthesis toolkit.",
    no_args_is_help=True,
)
console = Console()


# ── Shared helpers ────────────────────────────────────────────────────


def _build_config(**cli_overrides: object):
    """Build a ``Config`` from .env + CLI overrides, dropping None values."""
    return load_config(**{k: v for k, v in cli_overrides.items() if v is not None})


def _populate_ctx_infra(ctx, *, cfg, ssh_host, ssh_port, instance, start_cmd,
                        stop_cmd, exploit_start_cmd, kernel_image,
                        gdb_port, setup_tunnels, persistent, blog_urls):
    """Copy CLI infra options into the TaskContext."""
    ctx.ssh_host = ssh_host or cfg.ssh_host
    ctx.ssh_port = ssh_port or cfg.ssh_port
    ctx.instance = instance if instance is not None else cfg.instance
    ctx.start_cmd = start_cmd or cfg.start_cmd or ""
    ctx.stop_cmd = stop_cmd or cfg.stop_cmd or ""
    ctx.exploit_start_cmd = exploit_start_cmd or cfg.exploit_start_cmd or ""
    ctx.kernel_image = kernel_image or cfg.kernel_image or ""
    ctx.gdb_port = gdb_port if gdb_port is not None else cfg.gdb_port
    ctx.setup_tunnels = setup_tunnels or cfg.setup_tunnels
    ctx.persistent = persistent if persistent is not None else cfg.persistent
    ctx.blog_urls = list(blog_urls or [])
    return ctx


# ═════════════════════════════════════════════════════════════════════
#  Agent (agentic mode)
# ═════════════════════════════════════════════════════════════════════


@app.command()
def agent(
    input_value: str = typer.Argument(help="CVE ID, syzbot URL, crash log path, blog URL, or PoC path"),
    # Target
    target_kernel: str = typer.Option("", "--kernel", "-k", help="Target kernel version"),
    arch: str = typer.Option("arm64", "--arch", "-a", help="Target architecture (arm64/x86_64)"),
    platform: str = typer.Option("android", "--platform", "-p", help="Target platform (linux/android)"),
    output_dir: Optional[str] = typer.Option(None, "--output-dir", "-o", help="Output directory"),
    goal: Optional[str] = typer.Option(None, "--goal", "-g", help="Custom goal for the agent"),
    # Input context
    blog_url: Optional[List[str]] = typer.Option(None, "--blog-url", help="Blog / write-up URL(s) for context (repeatable)"),
    # Infrastructure
    ssh_host: Optional[str] = typer.Option(None, "--ssh-host", help="SSH host for Cuttlefish / QEMU"),
    ssh_port: int = typer.Option(22, "--ssh-port", help="SSH port"),
    instance: Optional[int] = typer.Option(None, "--instance", help="Cuttlefish instance number"),
    persistent: Optional[bool] = typer.Option(None, "--persistent/--no-persistent", help="Keep VM running between runs"),
    setup_tunnels: bool = typer.Option(False, "--setup-tunnels", help="Set up ADB/SSH tunnels"),
    start_cmd: Optional[str] = typer.Option(None, "--start-cmd", help="Command to start the VM"),
    stop_cmd: Optional[str] = typer.Option(None, "--stop-cmd", help="Command to stop the VM"),
    exploit_start_cmd: Optional[str] = typer.Option(None, "--exploit-start-cmd", help="VM start command for exploit testing (no GDB)"),
    gdb_port: int = typer.Option(1234, "--gdb-port", help="GDB port on crosvm (for gdb_run.sh starts)"),
    kernel_image: Optional[str] = typer.Option(None, "--kernel-image", help="Path to kernel Image"),
    # LLM
    model: Optional[str] = typer.Option(None, "--model", "-m", help="LLM model (e.g. openrouter/anthropic/claude-sonnet-4.6)"),
    decision_model: Optional[str] = typer.Option(None, "--decision-model", help="Model for agent routing decisions (cheaper/faster)"),
    analysis_model: Optional[str] = typer.Option(None, "--analysis-model", help="Model for crash/CVE/blog analysis"),
    codegen_model: Optional[str] = typer.Option(None, "--codegen-model", help="Model for exploit/reproducer code generation"),
    planning_model: Optional[str] = typer.Option(None, "--planning-model", help="Model for exploit strategy planning"),
    debug: bool = typer.Option(False, "--debug", help="Enable debug output"),
) -> None:
    """Run the agentic orchestrator (LLM-driven analysis loop)."""
    from ..orchestrator.agent import Agent
    from ..orchestrator.context import TaskContext
    from ..core.models import Arch as ArchEnum, Platform as PlatformEnum

    cfg = _build_config(
        llm_model=model,
        llm_decision_model=decision_model,
        llm_analysis_model=analysis_model,
        llm_codegen_model=codegen_model,
        llm_planning_model=planning_model,
        debug=debug,
    )

    # Build context with ALL infra options BEFORE the agent starts
    ctx = TaskContext(
        input_value=input_value,
        target_kernel=target_kernel,
        target_arch=ArchEnum(arch) if arch in ("x86_64", "arm64") else ArchEnum.ARM64,
        target_platform=PlatformEnum(platform) if platform in ("linux", "android", "generic") else PlatformEnum.ANDROID,
        work_dir=Path(output_dir) if output_dir else None,
    )
    ctx = _populate_ctx_infra(
        ctx, cfg=cfg, ssh_host=ssh_host, ssh_port=ssh_port,
        instance=instance, start_cmd=start_cmd, stop_cmd=stop_cmd,
        exploit_start_cmd=exploit_start_cmd, kernel_image=kernel_image,
        gdb_port=gdb_port,
        setup_tunnels=setup_tunnels, persistent=persistent, blog_urls=blog_url,
    )

    ag = Agent(
        goal=goal or "Analyze vulnerability, understand root cause, generate reproducer and exploit",
        cfg=cfg,
    )
    ctx = ag.run(
        input_value,
        ctx=ctx,
    )

    _print_agent_result(ctx)
    _print_execution_trace(ctx)
    _print_report_paths(ctx)


# ═════════════════════════════════════════════════════════════════════
#  Pipeline (deterministic mode)
# ═════════════════════════════════════════════════════════════════════


@app.command()
def pipeline(
    input_value: str = typer.Argument(help="CVE ID, syzbot URL, crash log, blog URL, or PoC path"),
    # Target
    target_kernel: str = typer.Option("", "--kernel", "-k", help="Target kernel version"),
    arch: str = typer.Option("arm64", "--arch", "-a", help="Target architecture"),
    platform: str = typer.Option("android", "--platform", "-p", help="Target platform"),
    output_dir: Optional[str] = typer.Option(None, "--output-dir", "-o", help="Output directory"),
    # Stage skipping
    skip_analysis: bool = typer.Option(False, "--skip-analysis", help="Skip analysis stage"),
    skip_reproducer: bool = typer.Option(False, "--skip-reproducer", help="Skip reproducer stage"),
    skip_exploit: bool = typer.Option(False, "--skip-exploit", help="Skip exploit stage"),
    # Input context
    blog_url: Optional[List[str]] = typer.Option(None, "--blog-url", help="Blog / write-up URL(s) for context (repeatable)"),
    # Infrastructure
    ssh_host: Optional[str] = typer.Option(None, "--ssh-host", help="SSH host"),
    ssh_port: int = typer.Option(22, "--ssh-port", help="SSH port"),
    instance: Optional[int] = typer.Option(None, "--instance", help="Cuttlefish instance number"),
    persistent: Optional[bool] = typer.Option(None, "--persistent/--no-persistent", help="Keep VM running"),
    setup_tunnels: bool = typer.Option(False, "--setup-tunnels", help="Set up ADB/SSH tunnels"),
    start_cmd: Optional[str] = typer.Option(None, "--start-cmd", help="Command to start the VM"),
    stop_cmd: Optional[str] = typer.Option(None, "--stop-cmd", help="Command to stop the VM"),
    exploit_start_cmd: Optional[str] = typer.Option(None, "--exploit-start-cmd", help="VM start for exploit testing"),
    gdb_port: int = typer.Option(1234, "--gdb-port", help="GDB port on crosvm (for gdb_run.sh starts)"),
    kernel_image: Optional[str] = typer.Option(None, "--kernel-image", help="Path to kernel Image"),
    # LLM
    model: Optional[str] = typer.Option(None, "--model", "-m", help="LLM model identifier"),
    decision_model: Optional[str] = typer.Option(None, "--decision-model", help="Model for agent routing decisions (cheaper/faster)"),
    analysis_model: Optional[str] = typer.Option(None, "--analysis-model", help="Model for crash/CVE/blog analysis"),
    codegen_model: Optional[str] = typer.Option(None, "--codegen-model", help="Model for exploit/reproducer code generation"),
    planning_model: Optional[str] = typer.Option(None, "--planning-model", help="Model for exploit strategy planning"),
    planner: str = typer.Option("auto", "--planner", help="Exploit planner strategy (auto/llm)"),
    debug: bool = typer.Option(False, "--debug", help="Enable debug output"),
) -> None:
    """Run the deterministic pipeline (analyze → reproduce → exploit)."""
    from ..orchestrator.pipeline import run_pipeline
    from ..orchestrator.context import TaskContext
    from ..core.models import Arch as ArchEnum, Platform as PlatformEnum

    cfg = _build_config(
        llm_model=model,
        llm_decision_model=decision_model,
        llm_analysis_model=analysis_model,
        llm_codegen_model=codegen_model,
        llm_planning_model=planning_model,
        debug=debug,
    )

    # Build context with ALL infra options BEFORE the pipeline starts
    ctx = TaskContext(
        input_value=input_value,
        target_kernel=target_kernel,
        target_arch=ArchEnum(arch) if arch in ("x86_64", "arm64") else ArchEnum.ARM64,
        target_platform=PlatformEnum(platform) if platform in ("linux", "android", "generic") else PlatformEnum.ANDROID,
        work_dir=Path(output_dir) if output_dir else None,
    )
    ctx = _populate_ctx_infra(
        ctx, cfg=cfg, ssh_host=ssh_host, ssh_port=ssh_port,
        instance=instance, start_cmd=start_cmd, stop_cmd=stop_cmd,
        exploit_start_cmd=exploit_start_cmd, kernel_image=kernel_image,
        gdb_port=gdb_port,
        setup_tunnels=setup_tunnels, persistent=persistent, blog_urls=blog_url,
    )

    result = run_pipeline(
        input_value,
        skip_analysis=skip_analysis,
        skip_reproducer=skip_reproducer,
        skip_exploit=skip_exploit,
        cfg=cfg,
        ctx=ctx,
    )
    console.print(f"\n[bold]Pipeline {'succeeded' if result.success else 'failed'}:[/] {result.summary}")
    _print_agent_result(result.ctx)
    _print_report_paths(result.ctx)


# ═════════════════════════════════════════════════════════════════════
#  Analyze commands
# ═════════════════════════════════════════════════════════════════════


@app.command()
def analyze_cve(
    cve_id: str = typer.Argument(help="CVE identifier (e.g., CVE-2024-36971)"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Write analysis JSON to file"),
    blog_url: Optional[List[str]] = typer.Option(None, "--blog-url", help="Blog / write-up URL(s) for extra context"),
    model: Optional[str] = typer.Option(None, "--model", "-m", help="LLM model"),
    debug: bool = typer.Option(False, "--debug", help="Enable debug output"),
) -> None:
    """Analyze a CVE from NVD/MITRE with LLM classification."""
    from ..analysis.cve_analyzer import analyze_cve as _analyze_cve

    cfg = _build_config(llm_model=model, debug=debug)
    rca = _analyze_cve(cve_id)
    _print_root_cause(rca)
    if output:
        out_path = Path(output)
        save_report(
            "root_cause_analysis", rca, out_path.parent,
            filename=out_path.name,
            metadata={"cve_id": cve_id},
        )


@app.command()
def analyze_blog(
    url: str = typer.Argument(help="Blog post / write-up URL"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Write analysis JSON to file"),
    model: Optional[str] = typer.Option(None, "--model", "-m", help="LLM model"),
    debug: bool = typer.Option(False, "--debug", help="Enable debug output"),
) -> None:
    """Analyze a security blog post URL."""
    from ..analysis.blog_analyzer import analyze_blog as _analyze_blog

    cfg = _build_config(llm_model=model, debug=debug)
    rca = _analyze_blog(url)
    _print_root_cause(rca)
    if output:
        out_path = Path(output)
        save_report(
            "root_cause_analysis", rca, out_path.parent,
            filename=out_path.name,
            metadata={"url": url},
        )


@app.command()
def analyze_crash(
    crash_log: str = typer.Argument(help="Path to crash log file or raw crash text"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Write analysis JSON to file"),
) -> None:
    """Parse and analyze a kernel crash log."""
    from ..analysis.crash_parser import parse_crash_log
    from ..analysis.root_cause import root_cause_analysis
    from ..analysis.exploitability import classify_exploitability

    raw = crash_log
    p = Path(crash_log)
    if p.exists():
        raw = p.read_text()

    crash = parse_crash_log(raw)
    console.print(f"  Crash type: {crash.crash_type}")
    console.print(f"  Bug type: {crash.bug_type.value}")
    console.print(f"  Function: {crash.corrupted_function}")
    console.print(f"  Frames: {len(crash.stack_frames)}")

    rca = root_cause_analysis(crash)
    rca = classify_exploitability(crash, rca)
    _print_root_cause(rca)

    if output:
        out_path = Path(output)
        # Save both crash report and root cause in the output directory
        save_report(
            "crash_report", crash, out_path.parent,
            filename="crash_report.json",
        )
        save_report(
            "root_cause_analysis", rca, out_path.parent,
            filename=out_path.name,
        )


# ═════════════════════════════════════════════════════════════════════
#  Feasibility
# ═════════════════════════════════════════════════════════════════════


@app.command()
def check_feasibility(
    crash_log: str = typer.Argument(help="Path to crash log"),
    target_kernel: str = typer.Option("", "--kernel", "-k", help="Target kernel version"),
    kallsyms: Optional[str] = typer.Option(None, "--kallsyms", help="Path to kallsyms"),
    system_map: Optional[str] = typer.Option(None, "--system-map", help="Path to System.map"),
    vmlinux: Optional[str] = typer.Option(None, "--vmlinux", help="Path to vmlinux"),
    ssh_host: Optional[str] = typer.Option(None, "--ssh-host", help="SSH host for remote checks"),
    ssh_port: int = typer.Option(22, "--ssh-port"),
    kernel_tree: Optional[str] = typer.Option(None, "--kernel-tree", help="Path to kernel git tree"),
    original_tag: Optional[str] = typer.Option(None, "--original-tag", help="Git tag for original kernel"),
    target_tag: Optional[str] = typer.Option(None, "--target-tag", help="Git tag for target kernel"),
    fix_commits: Optional[str] = typer.Option(None, "--fix-commits", help="Comma-separated fix commit hashes"),
    reproducer: Optional[str] = typer.Option(None, "--reproducer", help="Path to reproducer C source"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Write feasibility JSON to file"),
) -> None:
    """Check cross-version feasibility of a vulnerability."""
    from ..analysis.crash_parser import parse_crash_log
    from ..analysis.feasibility import assess_feasibility

    raw = Path(crash_log).read_text()
    crash = parse_crash_log(raw)

    commits = [c.strip() for c in fix_commits.split(",")] if fix_commits else None

    report = assess_feasibility(
        crash,
        target_kernel=target_kernel,
        kallsyms_path=kallsyms,
        system_map_path=system_map,
        vmlinux_path=vmlinux,
        ssh_host=ssh_host,
        ssh_port=ssh_port,
        kernel_tree_path=kernel_tree,
        original_tag=original_tag,
        target_tag=target_tag,
        fix_commits=commits,
        reproducer_path=reproducer,
    )
    console.print(report.summary())

    if output:
        out_path = Path(output)
        save_report(
            "feasibility", report, out_path.parent,
            filename=out_path.name,
            metadata={"target_kernel": target_kernel},
        )


# ═════════════════════════════════════════════════════════════════════
#  Data / scraping
# ═════════════════════════════════════════════════════════════════════


@app.command()
def pull(
    kernel_name: str = typer.Argument(help="Kernel name (e.g., upstream, android-6.1)"),
    no_filter: bool = typer.Option(False, "--no-filter", help="Include bugs without C reproducers"),
) -> None:
    """Pull bugs from syzbot dashboard."""
    from ..data.bug_db import BugDatabase
    from ..data.scraper import pull_bugs

    db = BugDatabase(kernel_name)
    try:
        bugs = pull_bugs(db, kernel_name, apply_filter=not no_filter)
        console.print(f"Stored {len(bugs)} bugs")
    finally:
        db.close()


@app.command()
def query(
    kernel_name: str = typer.Argument(help="Kernel name"),
    search: Optional[str] = typer.Option(None, "--search", "-s", help="Search query"),
) -> None:
    """Query the local bug database."""
    from ..data.bug_db import BugDatabase

    db = BugDatabase(kernel_name)
    try:
        bugs = db.search(search) if search else db.get_all()
        table = Table(title=f"Bugs for {kernel_name}")
        table.add_column("ID", style="dim", max_width=12)
        table.add_column("Title", max_width=60)
        table.add_column("Type")
        table.add_column("Status")
        for bug in bugs[:50]:
            table.add_row(bug.id[:12], bug.title[:60], bug.crash_type, bug.status)
        console.print(table)
        console.print(f"Total: {len(bugs)} bugs")
    finally:
        db.close()


# ═════════════════════════════════════════════════════════════════════
#  Run comparison
# ═════════════════════════════════════════════════════════════════════


@app.command(name="compare-runs")
def compare_runs(
    traces: List[str] = typer.Argument(help="Paths to execution_trace_*.json files (2+)"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Write comparison JSON to file"),
) -> None:
    """Compare execution traces from multiple agentic runs.

    Shows how the agent chose different tools in different orders
    across runs, where and when runs diverged, and timing differences.

    Example::

        syzploit compare-runs run1/execution_trace_abc123.json run2/execution_trace_def456.json
    """
    from ..core.reporting import compare_execution_traces

    if len(traces) < 2:
        console.print("[red]Need at least 2 trace files to compare.[/]")
        raise typer.Exit(1)

    for t in traces:
        if not Path(t).exists():
            console.print(f"[red]Not found: {t}[/]")
            raise typer.Exit(1)

    result = compare_execution_traces([Path(t) for t in traces])

    # ── Pretty-print comparison ───────────────────────────────────────
    console.print("\n[bold]═══ Run Comparison ═══[/]")
    console.print(f"  Runs compared: {result['runs_compared']}")
    console.print(
        f"  Tool sequences match: "
        f"{'[green]YES[/]' if result['tool_sequences_match'] else '[yellow]NO[/]'}"
    )
    if result.get("first_divergence_step"):
        console.print(
            f"  First divergence at step: {result['first_divergence_step']}"
        )

    # Per-run summaries
    for i, run in enumerate(result.get("runs", [])):
        console.print(f"\n  [bold cyan]Run {i + 1}[/] ({run['run_id']}):")
        console.print(f"    Outcome: {run['final_outcome']}")
        console.print(f"    Steps: {run['total_steps']}")
        console.print(f"    Duration: {run['total_duration_ms']:.0f}ms")
        seq = " → ".join(run.get("tool_sequence", []))
        console.print(f"    Sequence: {seq or '(empty)'}")
        if run.get("errors"):
            console.print(f"    Errors: {len(run['errors'])}")

    # Step-by-step alignment table
    alignment = result.get("sequence_alignment", [])
    if alignment:
        console.print("\n  [bold]Step-by-step alignment:[/]")
        n_runs = result["runs_compared"]
        table = Table(show_header=True, header_style="bold")
        table.add_column("Step", style="dim", width=5)
        for i in range(n_runs):
            table.add_column(f"Run {i + 1}", min_width=18)
        table.add_column("Match", width=5)

        for row in alignment:
            cells = [str(row["step"])]
            for i in range(n_runs):
                tool = row.get(f"run_{i}_tool", "—")
                cells.append(tool or "—")
            cells.append("✓" if row.get("all_same") else "✗")
            table.add_row(*cells)
        console.print(table)

    # Timing table
    timing = result.get("timing_comparison", [])
    if timing:
        console.print("\n  [bold]Timing comparison:[/]")
        table = Table(show_header=True, header_style="bold")
        table.add_column("Step", style="dim", width=5)
        n_runs = result["runs_compared"]
        for i in range(n_runs):
            table.add_column(f"Run {i + 1} Tool", min_width=14)
            table.add_column(f"Run {i + 1} ms", min_width=8, justify="right")
        for row in timing:
            cells = [str(row["step"])]
            for i in range(n_runs):
                tool = row.get(f"run_{i}_tool", "—") or "—"
                ms = row.get(f"run_{i}_ms")
                cells.append(tool)
                cells.append(f"{ms:.0f}" if ms is not None else "—")
            table.add_row(*cells)
        console.print(table)

    if output:
        out_path = Path(output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(result, indent=2, default=str))
        console.print(f"\n  📄 Comparison written to {out_path}")


# ═════════════════════════════════════════════════════════════════════
#  Manual verification commands
# ═════════════════════════════════════════════════════════════════════


@app.command(name="verify-exploit")
def verify_exploit_cmd(
    binary: str = typer.Argument(help="Path to the compiled exploit binary"),
    # Infrastructure
    ssh_host: str = typer.Option(..., "--ssh-host", help="SSH host for target device"),
    ssh_port: int = typer.Option(22, "--ssh-port", help="SSH port"),
    ssh_user: str = typer.Option("root", "--ssh-user", help="SSH user"),
    ssh_key: Optional[str] = typer.Option(None, "--ssh-key", help="SSH private key path"),
    instance: Optional[int] = typer.Option(None, "--instance", help="Cuttlefish instance number"),
    persistent: Optional[bool] = typer.Option(None, "--persistent/--no-persistent", help="Keep VM running"),
    setup_tunnels: bool = typer.Option(False, "--setup-tunnels", help="Set up ADB/SSH tunnels"),
    start_cmd: Optional[str] = typer.Option(None, "--start-cmd", help="Command to start the VM"),
    stop_cmd: Optional[str] = typer.Option(None, "--stop-cmd", help="Command to stop the VM"),
    exploit_start_cmd: Optional[str] = typer.Option(None, "--exploit-start-cmd", help="VM start command without GDB"),
    gdb_port: int = typer.Option(1234, "--gdb-port", help="GDB port on crosvm (used with gdb_run.sh starts)"),
    use_adb: bool = typer.Option(False, "--use-adb", help="Use ADB to push binary instead of SCP"),
    adb_port: int = typer.Option(6520, "--adb-port", help="ADB port for the Cuttlefish instance"),
    timeout: int = typer.Option(120, "--timeout", help="Execution timeout in seconds"),
    remote_dir: str = typer.Option("/data/local/tmp", "--remote-dir", help="Remote directory to push binary to"),
) -> None:
    """Manually verify an exploit binary on a target device.

    Deploys the binary to the device via SSH/ADB, runs it with a UID-checking
    wrapper, and reports whether privilege escalation occurred.

    Example::

        syzploit verify-exploit ./analysis_CVE-2023-20938/exploit \\
            --ssh-host cuttlefish2 --no-persistent --setup-tunnels --instance 5 \\
            --start-cmd "cd /home/jack/challenge-4/challenge-4.1 && ./run.sh 5" \\
            --stop-cmd "cd /home/jack/challenge-4/challenge-4.1 && ./stop.sh 5"
    """
    from ..infra.verification import verify_exploit

    binary_path = Path(binary).resolve()
    if not binary_path.exists():
        console.print(f"[red]Binary not found: {binary_path}[/]")
        raise typer.Exit(1)

    use_adb_resolved = use_adb or (instance is not None)
    is_persistent = persistent if persistent is not None else True

    # Show computed ADB port
    from ..infra.verification import _calc_adb_port
    resolved_adb_port = _calc_adb_port(instance, adb_port)

    console.print(f"[bold]═══ Manual Exploit Verification ═══[/]")
    console.print(f"  Binary:    {binary_path}")
    console.print(f"  SSH host:  {ssh_host}:{ssh_port} (build host)")
    console.print(f"  Instance:  {instance or '(none)'}")
    console.print(f"  Persistent: {is_persistent}")
    console.print(f"  ADB:       {use_adb_resolved} (port {resolved_adb_port})")
    console.print(f"  Tunnels:   {setup_tunnels}")
    # Show GDB info when start command looks like a GDB launch
    actual_start = exploit_start_cmd or start_cmd
    if actual_start and "gdb" in actual_start.lower():
        console.print(f"  GDB:       [bold yellow]enabled[/] (port {gdb_port})")
    console.print()

    result = verify_exploit(
        str(binary_path),
        ssh_host=ssh_host,
        ssh_port=ssh_port,
        ssh_user=ssh_user,
        ssh_key=ssh_key,
        instance=instance,
        start_cmd=start_cmd or "",
        stop_cmd=stop_cmd or "",
        exploit_start_cmd=exploit_start_cmd or "",
        gdb_port=gdb_port,
        setup_tunnels=setup_tunnels,
        persistent=is_persistent,
        timeout=timeout,
        remote_dir=remote_dir,
        use_adb=use_adb_resolved,
        adb_port=adb_port,
    )

    # Pretty-print results
    console.print(f"\n[bold]═══ Verification Result ═══[/]")
    if result["success"]:
        console.print(f"  [bold green]✓ EXPLOIT SUCCEEDED — PRIVILEGE ESCALATION CONFIRMED[/]")
    else:
        console.print(f"  [bold red]✗ EXPLOIT DID NOT ACHIEVE PRIVILEGE ESCALATION[/]")

    console.print(f"  UID before:         {result.get('uid_before', '?')}")
    console.print(f"  UID after:          {result.get('uid_after', '?')}")
    console.print(f"  Privilege escalated: {result.get('privilege_escalated', False)}")
    console.print(f"  Crash occurred:     {result.get('crash_occurred', False)}")
    console.print(f"  Device stable:      {result.get('device_stable', True)}")
    if result.get("crash_pattern"):
        console.print(f"  Crash pattern:      {result['crash_pattern']}")
    if result.get("failure_reason"):
        console.print(f"  Failure reason:     {result['failure_reason']}")
    if result.get("feedback"):
        console.print(f"\n  [dim]Feedback:[/] {result['feedback'][:500]}")

    # Show exploit output and dmesg
    if result.get("exploit_output"):
        console.print(f"\n[bold]═══ Exploit Output (last 2000 chars) ═══[/]")
        console.print(result["exploit_output"][-2000:])
    if result.get("dmesg_new"):
        console.print(f"\n[bold]═══ New dmesg entries ═══[/]")
        console.print(result["dmesg_new"][-2000:])


@app.command(name="verify-reproducer")
def verify_reproducer_cmd(
    binary: str = typer.Argument(help="Path to the compiled reproducer binary"),
    # Infrastructure
    ssh_host: str = typer.Option(..., "--ssh-host", help="SSH host for target device"),
    ssh_port: int = typer.Option(22, "--ssh-port", help="SSH port"),
    ssh_user: str = typer.Option("root", "--ssh-user", help="SSH user"),
    ssh_key: Optional[str] = typer.Option(None, "--ssh-key", help="SSH private key path"),
    instance: Optional[int] = typer.Option(None, "--instance", help="Cuttlefish instance number"),
    persistent: Optional[bool] = typer.Option(None, "--persistent/--no-persistent", help="Keep VM running"),
    setup_tunnels: bool = typer.Option(False, "--setup-tunnels", help="Set up ADB/SSH tunnels"),
    start_cmd: Optional[str] = typer.Option(None, "--start-cmd", help="Command to start the VM"),
    stop_cmd: Optional[str] = typer.Option(None, "--stop-cmd", help="Command to stop the VM"),
    gdb_port: int = typer.Option(1234, "--gdb-port", help="GDB port on crosvm (used with gdb_run.sh starts)"),
    use_adb: bool = typer.Option(False, "--use-adb", help="Use ADB to push binary instead of SCP"),
    adb_port: int = typer.Option(6520, "--adb-port", help="ADB port"),
    timeout: int = typer.Option(60, "--timeout", help="Execution timeout in seconds"),
    remote_dir: str = typer.Option("/data/local/tmp", "--remote-dir", help="Remote directory"),
    expected_crash: Optional[str] = typer.Option(None, "--expected-crash", help="Expected crash type (KASAN, BUG, etc.)"),
) -> None:
    """Manually verify a reproducer binary on a target device.

    Deploys the binary, runs it, captures dmesg before/after, and checks
    whether a kernel crash was triggered.

    Example::

        syzploit verify-reproducer ./analysis_CVE-2023-20938/reproducer \\
            --ssh-host cuttlefish2 --no-persistent --instance 5 \\
            --start-cmd "cd /home/jack/challenge-4/challenge-4.1 && ./run.sh 5" \\
            --stop-cmd "cd /home/jack/challenge-4/challenge-4.1 && ./stop.sh 5"
    """
    from ..infra.verification import verify_reproducer

    binary_path = Path(binary).resolve()
    if not binary_path.exists():
        console.print(f"[red]Binary not found: {binary_path}[/]")
        raise typer.Exit(1)

    use_adb_resolved = use_adb or (instance is not None)
    is_persistent = persistent if persistent is not None else True

    from ..infra.verification import _calc_adb_port
    resolved_adb_port = _calc_adb_port(instance, adb_port)

    console.print(f"[bold]═══ Manual Reproducer Verification ═══[/]")
    console.print(f"  Binary:    {binary_path}")
    console.print(f"  SSH host:  {ssh_host}:{ssh_port} (build host)")
    console.print(f"  Instance:  {instance or '(none)'}")
    console.print(f"  ADB:       {use_adb_resolved} (port {resolved_adb_port})")
    console.print(f"  Persistent: {is_persistent}")
    console.print()

    result = verify_reproducer(
        str(binary_path),
        ssh_host=ssh_host,
        ssh_port=ssh_port,
        ssh_user=ssh_user,
        ssh_key=ssh_key,
        instance=instance,
        expected_crash_type=expected_crash or "",
        start_cmd=start_cmd or "",
        stop_cmd=stop_cmd or "",
        gdb_port=gdb_port,
        setup_tunnels=setup_tunnels,
        persistent=is_persistent,
        timeout=timeout,
        remote_dir=remote_dir,
        use_adb=use_adb_resolved,
        adb_port=adb_port,
    )

    # Pretty-print
    console.print(f"\n[bold]═══ Verification Result ═══[/]")
    if result.get("crash_triggered"):
        console.print(f"  [bold green]✓ CRASH TRIGGERED — reproducer works![/]")
    else:
        console.print(f"  [bold red]✗ NO CRASH — reproducer did not trigger the vulnerability[/]")

    console.print(f"  Crash triggered:  {result.get('crash_triggered', False)}")
    console.print(f"  Crash type match: {result.get('crash_type_match', False)}")
    console.print(f"  Device stable:    {result.get('device_stable', True)}")
    if result.get("matched_functions"):
        console.print(f"  Matched functions: {', '.join(result['matched_functions'])}")
    if result.get("failure_reason"):
        console.print(f"  Failure reason:   {result['failure_reason']}")
    if result.get("feedback"):
        console.print(f"\n  [dim]Feedback:[/] {result['feedback'][:500]}")

    # Show crash log
    if result.get("crash_log_excerpt"):
        console.print(f"\n[bold]═══ Crash log ═══[/]")
        console.print(result["crash_log_excerpt"][-2000:])


# ═════════════════════════════════════════════════════════════════════
#  Helpers
# ═════════════════════════════════════════════════════════════════════


def _print_root_cause(rca) -> None:
    """Pretty-print a RootCauseAnalysis."""
    console.print("\n[bold]═══ Root Cause Analysis ═══[/]")
    console.print(f"  Summary: {rca.summary}")
    console.print(f"  Vuln type: {rca.vulnerability_type.value}")
    console.print(f"  Function: {rca.vulnerable_function}")
    console.print(f"  Subsystem: {rca.affected_subsystem}")
    console.print(f"  Score: {rca.exploitability_score}/100")
    console.print(f"  Confidence: {rca.confidence.value}")
    if rca.root_cause_description:
        console.print(f"  Root cause: {rca.root_cause_description[:200]}")
    if rca.trigger_conditions:
        console.print(f"  Triggers: {', '.join(rca.trigger_conditions[:5])}")
    if rca.affected_structs:
        console.print(f"  Structs: {', '.join(rca.affected_structs[:5])}")
    if rca.syscalls:
        console.print(f"  Syscalls: {', '.join(rca.syscalls[:5])}")


def _print_agent_result(ctx) -> None:
    """Pretty-print the final TaskContext summary."""
    console.print("\n[bold]═══ Result ═══[/]")
    console.print(f"  Run ID: {ctx.run_id}")
    if ctx.root_cause:
        console.print(f"  Root cause: {ctx.root_cause.summary}")
        console.print(f"  Vuln type: {ctx.root_cause.vulnerability_type.value}")
        console.print(f"  Score: {ctx.root_cause.exploitability_score}/100")
    if ctx.feasibility:
        console.print(f"  Feasibility: {ctx.feasibility.verdict}")
    if ctx.reproducer and ctx.reproducer.success:
        console.print(f"  Reproducer: {ctx.reproducer.binary_path}")
    if ctx.exploit_result and ctx.exploit_result.success:
        console.print(f"  Exploit: {ctx.exploit_result.binary_path}")
    if ctx.errors:
        console.print(f"  Errors: {len(ctx.errors)}")
        for e in ctx.errors[-5:]:
            console.print(f"    - {e[:100]}")


def _print_execution_trace(ctx) -> None:
    """Print a compact summary of the execution trace (tool sequence + timing)."""
    trace = getattr(ctx, "execution_trace", None)
    if trace is None:
        return

    console.print(f"\n[bold]═══ Execution Trace (run {trace.run_id}) ═══[/]")
    console.print(f"  Mode: {trace.mode}")
    console.print(f"  Outcome: {trace.final_outcome}")
    console.print(f"  Total steps: {trace.total_steps}")
    console.print(f"  Total time: {trace.total_duration_ms:.0f}ms")

    if trace.tool_sequence:
        seq = " → ".join(trace.tool_sequence)
        console.print(f"  Tool sequence: {seq}")

    if trace.steps:
        table = Table(show_header=True, header_style="bold")
        table.add_column("#", style="dim", width=3)
        table.add_column("Tool", min_width=16)
        table.add_column("Duration", justify="right", width=10)
        table.add_column("OK", width=3)
        table.add_column("Changed", min_width=20)
        table.add_column("Reason", max_width=50)

        for s in trace.steps:
            table.add_row(
                str(s.step),
                s.tool,
                f"{s.duration_ms:.0f}ms",
                "✓" if s.success else "✗",
                ", ".join(s.state_changed) if s.state_changed else "—",
                (s.reason[:50] + "…") if len(s.reason) > 50 else s.reason,
            )
        console.print(table)


def _print_report_paths(ctx) -> None:
    """List the JSON report files written to the work directory."""
    work_dir = getattr(ctx, "work_dir", None)
    if not work_dir:
        return
    work_dir = Path(work_dir)
    if not work_dir.exists():
        return
    report_files = (
        sorted(work_dir.glob("*_report.json"))
        + sorted(work_dir.glob("execution_trace_*.json"))
        + sorted(work_dir.glob("pipeline_summary.json"))
    )
    if not report_files:
        return
    console.print("\n[bold]═══ Reports ═══[/]")
    for f in report_files:
        console.print(f"  📄 {f}")


def main() -> None:
    """Entry-point registered in pyproject.toml."""
    app()
