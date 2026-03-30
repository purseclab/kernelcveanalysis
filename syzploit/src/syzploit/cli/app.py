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
    reference_exploit: Optional[str] = typer.Option(None, "--reference-exploit", help="Path to a reference exploit file or directory to guide generation"),
    extra_context: Optional[str] = typer.Option(None, "--extra-context", help="Free-form text or file path with additional context for the LLM"),
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
    static: bool = typer.Option(False, "--static", help="Static-only mode: skip all VM/ADB/SSH steps (no boot, no reproducer/exploit verification on target)"),
    replay: Optional[str] = typer.Option(None, "--replay", help="Replay a previous run from its execution_trace JSON (skips LLM calls, re-executes tools/GDB/ADB)"),
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

    # Enable output.log capture — tees ALL console + subprocess output
    if output_dir:
        from ..core.log import enable_file_logging
        log_path = enable_file_logging(output_dir)
        console.print(f"  [dim]Logging to {log_path}[/]")

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

    # Populate reference exploit and extra context
    if reference_exploit:
        ref_path = Path(reference_exploit).resolve()
        if ref_path.exists():
            ctx.reference_exploit_path = str(ref_path)
        else:
            console.print(f"[yellow]Warning: --reference-exploit path not found: {reference_exploit}[/]")
    if extra_context:
        # If it looks like a file path and the file exists, read it
        ec_path = Path(extra_context)
        if ec_path.exists() and ec_path.is_file():
            ctx.extra_context = ec_path.read_text()[:50000]
            console.print(f"  Loaded extra context from {ec_path} ({len(ctx.extra_context)} chars)")
        else:
            ctx.extra_context = extra_context

    if replay:
        # Replay mode: read tool sequence from a saved trace and
        # re-execute each tool WITHOUT querying the LLM for decisions.
        # GDB, ADB, compile, and verify steps still run live.
        replay_path = Path(replay)
        if not replay_path.exists():
            console.print(f"[red]Replay trace not found: {replay}[/]")
            raise typer.Exit(1)
        import json as _json
        trace_data = _json.loads(replay_path.read_text())
        # Extract tool sequence from trace
        steps = trace_data.get("steps", [])
        if not steps:
            # Try nested format
            steps = trace_data.get("data", {}).get("steps", [])
        tool_sequence = [
            {"tool": s["tool"], "reason": s.get("reason", "replay"), "kwargs": s.get("kwargs", {})}
            for s in steps
            if s.get("tool") not in ("done", "stop", "reflect")
        ]
        console.print(
            f"[bold cyan]REPLAY MODE[/] — replaying {len(tool_sequence)} "
            f"tools from {replay_path.name} (GDB/ADB/compile run live)"
        )
        ag = Agent(
            goal=goal or "Replay previous run",
            cfg=cfg,
            replay_sequence=tool_sequence,
        )
    else:
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
    _print_llm_usage()
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
    skip_verify: bool = typer.Option(False, "--skip-verify", help="Skip verification stage (deploy + run on target)"),
    # Input context
    blog_url: Optional[List[str]] = typer.Option(None, "--blog-url", help="Blog / write-up URL(s) for context (repeatable)"),
    reference_exploit: Optional[str] = typer.Option(None, "--reference-exploit", help="Path to a reference exploit file or directory to guide generation"),
    extra_context: Optional[str] = typer.Option(None, "--extra-context", help="Free-form text or file path with additional context for the LLM"),
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

    # Populate reference exploit and extra context
    if reference_exploit:
        ref_path = Path(reference_exploit).resolve()
        if ref_path.exists():
            ctx.reference_exploit_path = str(ref_path)
        else:
            console.print(f"[yellow]Warning: --reference-exploit path not found: {reference_exploit}[/]")
    if extra_context:
        ec_path = Path(extra_context)
        if ec_path.exists() and ec_path.is_file():
            ctx.extra_context = ec_path.read_text()[:50000]
            console.print(f"  Loaded extra context from {ec_path} ({len(ctx.extra_context)} chars)")
        else:
            ctx.extra_context = extra_context

    result = run_pipeline(
        input_value,
        skip_analysis=skip_analysis,
        skip_reproducer=skip_reproducer,
        skip_exploit=skip_exploit,
        skip_verify=skip_verify,
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
def investigate(
    cve_id: str = typer.Argument(help="CVE identifier (e.g., CVE-2023-20938)"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Write investigation JSON to file"),
    blog_url: Optional[List[str]] = typer.Option(None, "--blog-url", help="Blog / write-up URL(s) for extra context (repeatable)"),
    no_blogs: bool = typer.Option(False, "--no-blogs", help="Skip blog scraping"),
    no_source: bool = typer.Option(False, "--no-source", help="Skip kernel source fetching"),
    max_blogs: int = typer.Option(5, "--max-blogs", help="Maximum blog posts to scrape"),
    model: Optional[str] = typer.Option(None, "--model", "-m", help="LLM model"),
    debug: bool = typer.Option(False, "--debug", help="Enable debug output"),
) -> None:
    """Investigate a CVE: scrape exploits, blogs, patches, and source code.

    Performs comprehensive web scraping and analysis for a given CVE,
    searching for existing exploits, blog write-ups, patch notes, and
    pulling the affected kernel source code automatically.

    Example::

        syzploit investigate CVE-2023-20938
        syzploit investigate CVE-2024-36971 -o investigation.json
    """
    from ..analysis.investigate import investigate_cve as _investigate

    cfg = _build_config(llm_model=model, debug=debug)
    report = _investigate(
        cve_id,
        cfg=cfg,
        scrape_blogs=not no_blogs,
        fetch_source=not no_source,
        max_blogs=max_blogs,
        blog_urls=list(blog_url) if blog_url else None,
    )

    # Print the root cause if available
    if report.root_cause:
        _print_root_cause(report.root_cause)

    # Print exploit references
    if report.exploit_references:
        console.print(f"\n[bold]═══ Existing Exploits ({len(report.exploit_references)}) ═══[/]")
        for ref in report.exploit_references:
            console.print(f"  [{ref.source}] {ref.title}")
            console.print(f"    {ref.url}")
            if ref.description:
                console.print(f"    {ref.description[:100]}")
            if ref.stars:
                console.print(f"    ★ {ref.stars}")

    # Print patch info
    if report.patch_info:
        console.print(f"\n[bold]═══ Patches ({len(report.patch_info)}) ═══[/]")
        for patch in report.patch_info:
            console.print(f"  {patch.commit_hash[:12] or '(no hash)'} [{patch.patch_source}]")
            console.print(f"    {patch.commit_url}")
            if patch.files_changed:
                console.print(f"    Files: {', '.join(patch.files_changed[:5])}")

    # Print source contexts
    if report.source_contexts:
        console.print(f"\n[bold]═══ Source Code ({len(report.source_contexts)}) ═══[/]")
        for src in report.source_contexts:
            label = f"{src.file_path}"
            if src.function_name:
                label += f":{src.function_name}"
            console.print(f"  {label} ({len(src.source_code)} chars)")

    if output:
        out_path = Path(output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(report.to_dict(), indent=2, default=str))
        console.print(f"\n  Written to {out_path}")


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
    # Infrastructure — all options fall back to Config / .env defaults
    ssh_host: Optional[str] = typer.Option(None, "--ssh-host", help="SSH host (env: SYZPLOIT_SSH_HOST)"),
    ssh_port: Optional[int] = typer.Option(None, "--ssh-port", help="SSH port (env: SYZPLOIT_SSH_PORT)"),
    ssh_user: str = typer.Option("root", "--ssh-user", help="SSH user"),
    ssh_key: Optional[str] = typer.Option(None, "--ssh-key", help="SSH private key path"),
    instance: Optional[int] = typer.Option(None, "--instance", help="Cuttlefish instance (env: SYZPLOIT_INSTANCE)"),
    persistent: Optional[bool] = typer.Option(None, "--persistent/--no-persistent", help="Keep VM running (env: SYZPLOIT_PERSISTENT)"),
    setup_tunnels: Optional[bool] = typer.Option(None, "--setup-tunnels/--no-setup-tunnels", help="Set up ADB/SSH tunnels (env: SYZPLOIT_SETUP_TUNNELS)"),
    start_cmd: Optional[str] = typer.Option(None, "--start-cmd", help="Command to start the VM (env: SYZPLOIT_START_CMD)"),
    stop_cmd: Optional[str] = typer.Option(None, "--stop-cmd", help="Command to stop the VM (env: SYZPLOIT_STOP_CMD)"),
    exploit_start_cmd: Optional[str] = typer.Option(None, "--exploit-start-cmd", help="VM start command without GDB (env: SYZPLOIT_EXPLOIT_START_CMD)"),
    gdb_port: Optional[int] = typer.Option(None, "--gdb-port", help="GDB port on crosvm (env: SYZPLOIT_GDB_PORT)"),
    use_adb: bool = typer.Option(False, "--use-adb", help="Use ADB to push binary instead of SCP"),
    adb_port: Optional[int] = typer.Option(None, "--adb-port", help="ADB port (env: SYZPLOIT_ADB_PORT)"),
    timeout: int = typer.Option(120, "--timeout", help="Execution timeout in seconds"),
    remote_dir: str = typer.Option("/data/local/tmp", "--remote-dir", help="Remote directory to push binary to"),
    # GDB monitoring
    kallsyms_path: Optional[str] = typer.Option(None, "--kallsyms-path", help="Path to kallsyms file for GDB monitoring"),
    vmlinux_path: Optional[str] = typer.Option(None, "--vmlinux-path", help="Path to vmlinux for GDB symbols"),
) -> None:
    """Manually verify an exploit binary on a target device.

    Deploys the binary to the device via SSH/ADB, runs it with a UID-checking
    wrapper, and reports whether privilege escalation occurred.

    All infrastructure options can be set via environment variables or .env
    file so you only need to pass the binary path.

    Example (minimal, with .env configured)::

        syzploit verify-exploit ./analysis_CVE-2023-20938/exploit

    Example (all flags)::

        syzploit verify-exploit ./exploit \\
            --ssh-host cuttlefish2 --no-persistent --setup-tunnels --instance 5 \\
            --start-cmd "cd /home/jack/challenge-4/challenge-4.1 && ./gdb_run.sh 5" \\
            --stop-cmd "cd /home/jack/challenge-4/challenge-4.1 && ./stop.sh 5" \\
            --exploit-start-cmd "cd /home/jack/challenge-4/challenge-4.1 && ./run.sh 5" \\
            --gdb-port 1234 --use-adb --adb-port 6524 --timeout 120
    """
    from ..infra.verification import verify_exploit

    # Load config from .env — CLI flags override config values
    cfg = _build_config()

    # Resolve each option: CLI flag > Config > hardcoded default
    ssh_host_r = ssh_host or cfg.ssh_host
    ssh_port_r = ssh_port if ssh_port is not None else cfg.ssh_port
    instance_r = instance if instance is not None else cfg.instance
    setup_tunnels_r = setup_tunnels if setup_tunnels is not None else cfg.setup_tunnels
    start_cmd_r = start_cmd or cfg.start_cmd
    stop_cmd_r = stop_cmd or cfg.stop_cmd
    exploit_start_cmd_r = exploit_start_cmd or cfg.exploit_start_cmd
    gdb_port_r = gdb_port if gdb_port is not None else cfg.gdb_port
    adb_port_r = adb_port if adb_port is not None else cfg.adb_port
    is_persistent = persistent if persistent is not None else cfg.persistent
    kallsyms_r = kallsyms_path or cfg.kallsyms_path
    vmlinux_r = vmlinux_path or cfg.vmlinux_path

    # Auto-detect kallsyms from work directory (sibling of binary)
    if not kallsyms_r:
        for candidate in [
            Path(binary).resolve().parent / "kallsyms",
            Path(binary).resolve().parent.parent / "kallsyms",
        ]:
            if candidate.exists():
                kallsyms_r = str(candidate)
                break

    binary_path = Path(binary).resolve()
    if not binary_path.exists():
        console.print(f"[red]Binary not found: {binary_path}[/]")
        raise typer.Exit(1)

    use_adb_resolved = use_adb or (instance_r is not None)

    # Show computed ADB port
    from ..infra.verification import _calc_adb_port
    resolved_adb_port = _calc_adb_port(instance_r, adb_port_r)

    console.print(f"[bold]═══ Manual Exploit Verification ═══[/]")
    console.print(f"  Binary:    {binary_path}")
    console.print(f"  SSH host:  {ssh_host_r}:{ssh_port_r} (build host)")
    console.print(f"  Instance:  {instance_r or '(none)'}")
    console.print(f"  Persistent: {is_persistent}")
    console.print(f"  ADB:       {use_adb_resolved} (port {resolved_adb_port})")
    console.print(f"  Tunnels:   {setup_tunnels_r}")
    # Show GDB info when start command looks like a GDB launch
    actual_start = exploit_start_cmd_r or start_cmd_r
    if actual_start and "gdb" in actual_start.lower():
        console.print(f"  GDB:       [bold yellow]enabled[/] (port {gdb_port_r})")
    if kallsyms_r:
        console.print(f"  Kallsyms:  {kallsyms_r}")
    if vmlinux_r:
        console.print(f"  Vmlinux:   {vmlinux_r}")
    console.print()

    result = verify_exploit(
        str(binary_path),
        ssh_host=ssh_host_r,
        ssh_port=ssh_port_r,
        ssh_user=ssh_user,
        ssh_key=ssh_key,
        instance=instance_r,
        start_cmd=start_cmd_r or "",
        stop_cmd=stop_cmd_r or "",
        exploit_start_cmd=exploit_start_cmd_r or "",
        gdb_port=gdb_port_r,
        setup_tunnels=setup_tunnels_r,
        persistent=is_persistent,
        timeout=timeout,
        remote_dir=remote_dir,
        use_adb=use_adb_resolved,
        adb_port=adb_port_r,
        kallsyms_path=kallsyms_r,
        vmlinux_path=vmlinux_r,
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


def _print_llm_usage() -> None:
    """Print token usage statistics for the run."""
    try:
        from ..core.llm import LLMClient
        usage = LLMClient.get_usage_summary()
        if usage.get("total_calls", 0) == 0:
            return
        console.print("\n[bold]═══ LLM Usage ═══[/]")
        console.print(f"  Total calls: {usage['total_calls']}")
        console.print(
            f"  Total tokens: {usage['total_tokens']:,} "
            f"(prompt: {usage['total_prompt_tokens']:,}, "
            f"completion: {usage['total_completion_tokens']:,})"
        )
        for model, stats in usage.get("by_model", {}).items():
            console.print(
                f"  {model}: {stats['calls']} calls, "
                f"{stats['prompt_tokens'] + stats['completion_tokens']:,} tokens"
            )
    except Exception:
        pass


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


# ═════════════════════════════════════════════════════════════════════
#  Hunt (autonomous CVE hunting mode)
# ═════════════════════════════════════════════════════════════════════


@app.command()
def hunt(
    kernel_version: str = typer.Argument(help="Target kernel version (e.g. 5.10.107)"),
    # Target
    arch: str = typer.Option("arm64", "--arch", "-a", help="Target architecture (arm64/x86_64)"),
    platform: str = typer.Option("android", "--platform", "-p", help="Target platform (linux/android)"),
    output_dir: Optional[str] = typer.Option(None, "--output-dir", "-o", help="Output base directory"),
    max_targets: int = typer.Option(10, "--max-targets", "-n", help="Maximum CVEs to attempt"),
    max_iterations: int = typer.Option(20, "--max-iterations", help="Soft cap for agent iterations (continues past this until exploit is verified, hard cap at 2x)"),
    goal: Optional[str] = typer.Option(None, "--goal", "-g", help="Custom goal for each agent run"),
    # Discovery options
    skip_discovery: bool = typer.Option(False, "--resume", help="Resume from previous hunt_candidates.json"),
    # Infrastructure
    ssh_host: Optional[str] = typer.Option(None, "--ssh-host", help="SSH host for Cuttlefish / QEMU"),
    ssh_port: int = typer.Option(22, "--ssh-port", help="SSH port"),
    instance: Optional[int] = typer.Option(None, "--instance", help="Cuttlefish instance number"),
    persistent: Optional[bool] = typer.Option(None, "--persistent/--no-persistent", help="Keep VM running"),
    setup_tunnels: bool = typer.Option(False, "--setup-tunnels", help="Set up ADB/SSH tunnels"),
    start_cmd: Optional[str] = typer.Option(None, "--start-cmd", help="Command to start the VM"),
    stop_cmd: Optional[str] = typer.Option(None, "--stop-cmd", help="Command to stop the VM"),
    exploit_start_cmd: Optional[str] = typer.Option(None, "--exploit-start-cmd", help="VM start for exploit testing"),
    gdb_port: int = typer.Option(1234, "--gdb-port", help="GDB port on crosvm"),
    kernel_image: Optional[str] = typer.Option(None, "--kernel-image", help="Path to kernel Image"),
    # LLM
    model: Optional[str] = typer.Option(None, "--model", "-m", help="LLM model"),
    decision_model: Optional[str] = typer.Option(None, "--decision-model", help="Model for agent routing"),
    analysis_model: Optional[str] = typer.Option(None, "--analysis-model", help="Model for analysis"),
    codegen_model: Optional[str] = typer.Option(None, "--codegen-model", help="Model for code generation"),
    planning_model: Optional[str] = typer.Option(None, "--planning-model", help="Model for planning"),
    debug: bool = typer.Option(False, "--debug", help="Enable debug output"),
) -> None:
    """Autonomous CVE hunter — discover and exploit kernel vulnerabilities.

    Searches NVD, Android bulletins, GitHub, and PoC aggregators for CVEs
    affecting the target kernel. Ranks by exploitability, then runs the
    full agent pipeline on each, creating a per-CVE work directory.

    Example:
        syzploit hunt 5.10.107 --platform android --max-targets 5
    """
    from ..orchestrator.hunter import HunterOrchestrator

    cfg = _build_config(
        llm_model=model,
        llm_decision_model=decision_model,
        llm_analysis_model=analysis_model,
        llm_codegen_model=codegen_model,
        llm_planning_model=planning_model,
        debug=debug,
    )

    hunter = HunterOrchestrator(
        kernel_version=kernel_version,
        platform=platform,
        arch=arch,
        max_targets=max_targets,
        max_iterations_per_target=max_iterations,
        output_dir=Path(output_dir) if output_dir else None,
        cfg=cfg,
        ssh_host=ssh_host or "",
        ssh_port=ssh_port,
        instance=instance,
        start_cmd=start_cmd or "",
        stop_cmd=stop_cmd or "",
        exploit_start_cmd=exploit_start_cmd or "",
        gdb_port=gdb_port,
        setup_tunnels=setup_tunnels,
        persistent=persistent if persistent is not None else False,
        kernel_image=kernel_image or "",
        goal=goal or "",
    )

    results = hunter.run(skip_discovery=skip_discovery)

    # Final tally
    successes = sum(1 for r in results if r["outcome"] == "exploit_success")
    if successes:
        console.print(
            f"\n[bold green]🎯 {successes} exploit(s) succeeded![/]"
        )
    else:
        console.print(
            f"\n[bold yellow]No successful exploits this run. "
            f"Review individual analysis directories for partial results.[/]"
        )


@app.command(name="analyze-app")
def analyze_app_cmd(
    apk_path: str = typer.Argument(help="Path to APK file or package name on device"),
    output_dir: Optional[str] = typer.Option(None, "--output-dir", "-o", help="Output directory"),
    device: Optional[str] = typer.Option(None, "--device", "-d", help="ADB device serial (e.g. localhost:6538)"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Analyze an Android APK for security vulnerabilities."""
    from ..android.app_analyzer import analyze_apk, pull_apk_from_device

    apk_file = apk_path

    # If it looks like a package name (contains dots, no file extension), pull from device
    if "." in apk_path and not apk_path.endswith(".apk") and device:
        console.print(f"Pulling APK for {apk_path} from {device}...")
        pulled = pull_apk_from_device(apk_path, f"/tmp/{apk_path}.apk",
                                       adb_port=int(device.split(":")[-1]))
        if pulled:
            apk_file = pulled
        else:
            console.print(f"[red]Failed to pull APK for {apk_path}[/]")
            raise typer.Exit(1)

    console.print(f"\n[bold]═══ Analyzing {Path(apk_file).name} ═══[/]")
    result = analyze_apk(apk_file)

    # Display results
    console.print(f"  Package: {result.package_name}")
    console.print(f"  Version: {result.version_name} ({result.version_code})")
    console.print(f"  SDK: min={result.min_sdk}, target={result.target_sdk}")
    console.print(f"  Debuggable: {result.debuggable}")
    console.print(f"  Permissions: {len(result.permissions)} ({len(result.dangerous_permissions)} dangerous)")
    console.print(f"  Components: {len(result.components)} ({len(result.exported_components)} exported)")
    console.print(f"  Native Libraries: {len(result.native_libraries)}")

    if result.vulnerabilities:
        console.print(f"\n[bold]═══ Vulnerabilities ({len(result.vulnerabilities)}) ═══[/]")
        # Group by severity
        for sev in ("critical", "high", "medium", "low", "info"):
            vulns = [v for v in result.vulnerabilities if v.severity == sev]
            if not vulns:
                continue
            color = {"critical": "red", "high": "red", "medium": "yellow",
                     "low": "cyan", "info": "dim"}.get(sev, "white")
            for v in vulns:
                console.print(f"  [{color}][{sev.upper()}][/{color}] {v.name}")
                if sev in ("critical", "high"):
                    console.print(f"    {v.description[:120]}")

    # Save results
    if output_dir:
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)
        report_path = out / "app_analysis_report.json"
        report_path.write_text(json.dumps(result.to_dict(), indent=2))
        console.print(f"\n  📄 Report saved: {report_path}")

    if json_output:
        print(json.dumps(result.to_dict(), indent=2))


@app.command(name="decompile-app")
def decompile_app_cmd(
    apk_path: str = typer.Argument(help="Path to APK file"),
    output_dir: str = typer.Option("./decompiled", "--output-dir", "-o", help="Output directory"),
) -> None:
    """Decompile an Android APK to Java source code."""
    from ..android.decompiler import decompile_apk

    console.print(f"[bold]Decompiling {Path(apk_path).name}…[/]")
    result = decompile_apk(apk_path, output_dir)
    if result:
        java_count = sum(1 for _ in Path(result).rglob("*.java"))
        console.print(f"  [green]Source extracted: {result} ({java_count} files)[/]")
    else:
        console.print(f"  [red]Decompilation failed[/]")


@app.command(name="scan-app")
def scan_app_cmd(
    source_dir: str = typer.Argument(help="Path to decompiled source directory"),
    mode: str = typer.Option("static", "--mode", "-m", help="Scan mode: static, llm, hybrid"),
    focus: Optional[str] = typer.Option(None, "--focus", "-f", help="Focus areas (comma-separated: crypto,webview,ipc,storage,network,auth)"),
    output_dir: Optional[str] = typer.Option(None, "--output-dir", "-o", help="Output directory"),
) -> None:
    """Scan decompiled Android app source for vulnerabilities."""
    from ..android.vuln_scanner import scan_static, scan_with_llm, scan_hybrid

    focus_areas = focus.split(",") if focus else None

    console.print(f"[bold]Scanning {source_dir} (mode: {mode})…[/]")

    if mode == "static":
        vulns = scan_static(source_dir)
    elif mode == "llm":
        cfg = _build_config()
        vulns = scan_with_llm(source_dir, focus_areas=focus_areas, cfg=cfg)
    elif mode == "hybrid":
        cfg = _build_config()
        vulns = scan_hybrid(source_dir, cfg=cfg, focus_areas=focus_areas)
    else:
        console.print(f"[red]Unknown mode: {mode}[/]")
        raise typer.Exit(1)

    # Display results
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    vulns.sort(key=lambda v: severity_order.get(v.severity, 5))

    console.print(f"\n[bold]═══ Vulnerabilities ({len(vulns)}) ═══[/]")
    for v in vulns:
        color = {"critical": "red", "high": "red", "medium": "yellow",
                 "low": "cyan", "info": "dim"}.get(v.severity, "white")
        console.print(f"  [{color}][{v.severity.upper()}][/{color}] {v.name}")
        if v.evidence:
            for line in v.evidence.strip().splitlines()[:2]:
                console.print(f"    {line[:120]}")

    if output_dir:
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)
        report = [v.to_dict() for v in vulns]
        (out / "vuln_scan_report.json").write_text(json.dumps(report, indent=2))
        console.print(f"\n  📄 Report saved: {out / 'vuln_scan_report.json'}")


@app.command(name="frida-hook")
def frida_hook_cmd(
    package_name: str = typer.Argument(help="Target app package name"),
    script: str = typer.Option("ssl_pinning_bypass", "--script", "-s",
                               help="Script name or path to .js file"),
    device: str = typer.Option("localhost:6538", "--device", "-d", help="ADB device serial"),
    timeout: int = typer.Option(30, "--timeout", "-t", help="Script execution timeout (seconds)"),
    list_scripts: bool = typer.Option(False, "--list", help="List available built-in scripts"),
) -> None:
    """Run a Frida hook script on an Android app."""
    from ..android.frida_tools import (
        run_adb_frida_script, get_frida_script, list_frida_scripts,
    )

    if list_scripts:
        console.print("[bold]Available Frida scripts:[/]")
        for name in list_frida_scripts():
            console.print(f"  - {name}")
        return

    # Load script
    if Path(script).exists():
        script_code = Path(script).read_text()
        console.print(f"Loaded script from {script}")
    else:
        script_code = get_frida_script(script)
        if not script_code:
            console.print(f"[red]Unknown script: {script}[/]")
            console.print(f"Available: {', '.join(list_frida_scripts())}")
            raise typer.Exit(1)
        console.print(f"Using built-in script: {script}")

    console.print(f"[bold]Hooking {package_name} on {device}…[/]")
    result = run_adb_frida_script(package_name, script_code, device, timeout=timeout)

    if result.success:
        console.print(f"[green]Script executed successfully ({result.duration_ms}ms)[/]")
    else:
        console.print(f"[red]Script failed ({result.duration_ms}ms)[/]")
        for err in result.errors:
            console.print(f"  Error: {err[:200]}")

    if result.hooked_calls:
        console.print(f"\n[bold]Hooked calls ({len(result.hooked_calls)}):[/]")
        for call in result.hooked_calls[:20]:
            console.print(f"  {json.dumps(call, default=str)}")

    if result.messages:
        console.print(f"\nMessages ({len(result.messages)}):")
        for msg in result.messages[:10]:
            console.print(f"  {json.dumps(msg, default=str)}")


@app.command(name="test-intents")
def test_intents_cmd(
    apk_path: str = typer.Argument(help="Path to APK file to analyze and test"),
    device: str = typer.Option("localhost:6538", "--device", "-d", help="ADB device serial"),
    output_dir: Optional[str] = typer.Option(None, "--output-dir", "-o", help="Output directory"),
) -> None:
    """Test exported components of an Android app via crafted intents."""
    from ..android.app_analyzer import analyze_apk
    from ..android.intent_crafter import test_exported_components

    console.print(f"[bold]Analyzing {Path(apk_path).name}…[/]")
    analysis = analyze_apk(apk_path)

    if not analysis.exported_components:
        console.print("[yellow]No exported components found[/]")
        return

    console.print(f"Found {len(analysis.exported_components)} exported components")
    console.print(f"[bold]Testing on {device}…[/]\n")

    adb_port = int(device.split(":")[-1]) if ":" in device else 5555
    # Find ADB binary — check common locations
    import shutil
    adb_bin = shutil.which("adb") or ""
    if not adb_bin:
        for candidate in [
            Path.cwd() / "adb",
            Path(__file__).parent.parent.parent.parent / "adb",  # syzploit/adb
            Path("/home/gl055/research/ingots/kernelcveanalysis/syzploit/adb"),
        ]:
            if candidate.exists():
                adb_bin = str(candidate)
                break
    if not adb_bin:
        adb_bin = "adb"  # fallback to PATH
    results = test_exported_components(
        analysis.package_name,
        [c.to_dict() for c in analysis.exported_components],
        adb_serial=device,
        adb_binary=adb_bin,
    )

    # Display results
    for r in results:
        status = "[green]OK[/]" if r.success else "[red]FAIL[/]"
        console.print(f"  {status} [{r.intent_type}] {r.component}")
        if r.output and r.success:
            for line in r.output.strip().splitlines()[:3]:
                console.print(f"    → {line[:120]}")

    if output_dir:
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)
        report = {"package": analysis.package_name, "results": [r.to_dict() for r in results]}
        (out / "intent_test_report.json").write_text(json.dumps(report, indent=2))
        console.print(f"\n  📄 Report saved: {out / 'intent_test_report.json'}")


@app.command(name="audit-device")
def audit_device_cmd(
    # Target
    ssh_host: str = typer.Option("", "--ssh-host", help="SSH host for Cuttlefish/QEMU"),
    instance: int = typer.Option(18, "--instance", help="Cuttlefish instance number"),
    # VM management
    start_cmd: str = typer.Option("", "--start-cmd", help="Command to start VM with GDB"),
    stop_cmd: str = typer.Option("", "--stop-cmd", help="Command to stop VM"),
    exploit_start_cmd: str = typer.Option("", "--exploit-start-cmd", help="VM start command without GDB"),
    kernel_image: str = typer.Option("", "--kernel-image", help="Path to kernel Image on remote host"),
    # Kernel
    kernel_cve: Optional[str] = typer.Option(None, "--kernel-cve", "-k", help="Kernel CVE to analyze (e.g. CVE-2023-20938)"),
    # Apps
    include_system: bool = typer.Option(True, "--system/--no-system", help="Include system apps"),
    max_apps: int = typer.Option(0, "--max-apps", help="Max apps to analyze (0=all)"),
    deep_scan: int = typer.Option(3, "--deep-scan", help="Deep-scan top N riskiest apps"),
    fuzz: bool = typer.Option(True, "--fuzz/--no-fuzz", help="Fuzz during deep scan"),
    traffic: bool = typer.Option(True, "--traffic/--no-traffic", help="Capture traffic"),
    # LLM
    model: Optional[str] = typer.Option(None, "--model", "-m", help="LLM model for kernel analysis"),
    # APKs to install
    install_apks: Optional[List[str]] = typer.Option(None, "--install-apk", help="APK file(s) to install before scanning (repeatable)"),
    # Output
    output_dir: str = typer.Option("./device_audit", "--output-dir", "-o", help="Output directory"),
) -> None:
    """Full device security audit — kernel CVE analysis + all app scanning in one command.

    Example:
        syzploit audit-device --ssh-host INGOTS-ARM --instance 18
            --kernel-cve CVE-2023-20938
            --start-cmd "cd /path && ./gdb_run.sh 18"
            --stop-cmd "cd /path && ./stop.sh 18"
            --exploit-start-cmd "cd /path && ./run.sh 18"
            --kernel-image /path/to/kernel/Image
            --model openrouter/anthropic/claude-sonnet-4.6
    """
    from ..android.full_audit import run_full_audit, FullAuditConfig

    config = FullAuditConfig(
        ssh_host=ssh_host,
        instance=instance,
        start_cmd=start_cmd,
        stop_cmd=stop_cmd,
        exploit_start_cmd=exploit_start_cmd,
        kernel_image=kernel_image,
        kernel_cve=kernel_cve or "",
        include_system_apps=include_system,
        max_apps=max_apps,
        deep_scan_top=deep_scan,
        fuzz=fuzz,
        traffic=traffic,
        traffic_duration=10,
        model=model or "",
        output_dir=output_dir,
        llm_cfg=_build_config(model=model) if model else None,
        install_apks=list(install_apks) if install_apks else [],
    )

    run_full_audit(config)


@app.command(name="scan-device")
def scan_device_cmd(
    device: str = typer.Option("localhost:6537", "--device", "-d", help="ADB device serial"),
    output_dir: str = typer.Option("./device_audit", "--output-dir", "-o", help="Output directory"),
    include_system: bool = typer.Option(True, "--system/--no-system", help="Include system apps"),
    max_apps: int = typer.Option(0, "--max-apps", help="Max apps to analyze (0=all)"),
    deep_scan: int = typer.Option(3, "--deep-scan", help="Deep-scan top N riskiest apps (0=skip)"),
    fuzz: bool = typer.Option(True, "--fuzz/--no-fuzz", help="Fuzz during deep scan"),
    traffic: bool = typer.Option(True, "--traffic/--no-traffic", help="Capture traffic during deep scan"),
    kernel_cve: Optional[str] = typer.Option(None, "--kernel-cve", help="Kernel CVE for hybrid analysis"),
    kernel_exploit: Optional[str] = typer.Option(None, "--kernel-exploit", help="Kernel exploit binary for hybrid chain"),
) -> None:
    """Autonomous full-device security scan — analyzes kernel + all installed apps.

    One command does everything: pulls all APKs, analyzes each for vulnerabilities,
    ranks by risk score, deep-dives the riskiest apps (fuzz, traffic, exploit gen),
    and optionally chains with a kernel CVE for hybrid analysis.
    """
    from ..android.device_scanner import scan_device, full_device_audit

    import shutil
    adb_bin = shutil.which("adb") or ""
    if not adb_bin:
        for c in [Path.cwd() / "adb", Path(__file__).parent.parent.parent.parent / "adb"]:
            if c.exists():
                adb_bin = str(c)
                break
    if not adb_bin:
        adb_bin = "adb"

    console.print(f"\n[bold]═══ Syzploit Device Security Scanner ═══[/]")
    console.print(f"  Device: {device}")
    console.print(f"  System apps: {'yes' if include_system else 'no'}")
    if max_apps:
        console.print(f"  Max apps: {max_apps}")
    console.print(f"  Deep scan: top {deep_scan} apps")
    if kernel_cve:
        console.print(f"  Kernel CVE: {kernel_cve}")

    if deep_scan > 0:
        result = full_device_audit(
            serial=device, adb_bin=adb_bin, output_dir=output_dir,
            include_system=include_system, max_apps=max_apps,
            deep_scan_top=deep_scan, fuzz=fuzz, traffic=traffic,
            kernel_cve=kernel_cve or "",
            kernel_exploit_path=kernel_exploit or "",
        )
    else:
        result = scan_device(
            serial=device, adb_bin=adb_bin, output_dir=output_dir,
            include_system=include_system, max_apps=max_apps,
        )

    if result.apps_with_vulns:
        console.print(
            f"\n[bold yellow]{result.apps_with_vulns} apps have vulnerabilities "
            f"({result.total_critical} critical, {result.total_high} high)[/]"
        )
    else:
        console.print("\n[green]No significant vulnerabilities found[/]")


@app.command(name="app-agent")
def app_agent_cmd(
    apk_path: str = typer.Argument(help="Path to APK file"),
    output_dir: str = typer.Option("./app_analysis", "--output-dir", "-o", help="Output directory"),
    device: str = typer.Option("localhost:6537", "--device", "-d", help="ADB device serial"),
    scan_mode: str = typer.Option("static", "--scan-mode", help="Scan mode: static, llm, hybrid"),
    fuzz: bool = typer.Option(True, "--fuzz/--no-fuzz", help="Enable IPC fuzzing"),
    traffic: bool = typer.Option(True, "--traffic/--no-traffic", help="Enable traffic capture"),
    verify: bool = typer.Option(True, "--verify/--no-verify", help="Verify generated exploits"),
    traffic_duration: int = typer.Option(15, "--traffic-duration", help="Traffic capture duration (sec)"),
    model: Optional[str] = typer.Option(None, "--model", "-m", help="LLM model (for hybrid/llm scan)"),
    kernel_cve: Optional[str] = typer.Option(None, "--kernel-cve", help="Kernel CVE for hybrid exploit chain"),
    kernel_exploit: Optional[str] = typer.Option(None, "--kernel-exploit", help="Path to kernel exploit binary for hybrid chain"),
) -> None:
    """Run the full agentic app security analysis pipeline."""
    from ..android.app_agent import run_app_agent, AppAgentConfig

    import shutil
    adb_bin = shutil.which("adb") or ""
    if not adb_bin:
        for c in [Path.cwd() / "adb", Path(__file__).parent.parent.parent.parent / "adb"]:
            if c.exists():
                adb_bin = str(c)
                break
    if not adb_bin:
        adb_bin = "adb"

    cfg = None
    if model and scan_mode in ("llm", "hybrid"):
        cfg = _build_config(model=model)

    config = AppAgentConfig(
        apk_path=apk_path,
        output_dir=output_dir,
        adb_serial=device,
        adb_binary=adb_bin,
        scan_mode=scan_mode,
        fuzz=fuzz,
        capture_traffic=traffic,
        traffic_duration=traffic_duration,
        verify_exploits=verify,
        llm_cfg=cfg,
        kernel_cve=kernel_cve or "",
        kernel_exploit_path=kernel_exploit or "",
    )

    console.print(f"\n[bold]═══ Syzploit App Security Agent ═══[/]")
    console.print(f"  APK: {Path(apk_path).name}")
    console.print(f"  Device: {device}")
    console.print(f"  Scan mode: {scan_mode}")
    console.print(f"  Fuzz: {fuzz}, Traffic: {traffic}, Verify: {verify}")

    result = run_app_agent(config)

    if result.errors:
        console.print(f"\n[yellow]Completed with {len(result.errors)} error(s)[/]")


@app.command(name="fuzz-app")
def fuzz_app_cmd(
    apk_path: str = typer.Argument(help="Path to APK file"),
    device: str = typer.Option("localhost:6537", "--device", "-d", help="ADB device serial"),
    max_per_component: int = typer.Option(20, "--max", help="Max fuzz tests per component"),
    output_dir: Optional[str] = typer.Option(None, "--output-dir", "-o", help="Output directory"),
) -> None:
    """Fuzz exported components of an Android app."""
    from ..android.app_analyzer import analyze_apk
    from ..android.ipc_fuzzer import fuzz_exported_components

    console.print(f"[bold]Analyzing {Path(apk_path).name}…[/]")
    analysis = analyze_apk(apk_path)

    if not analysis.exported_components:
        console.print("[yellow]No exported components found[/]")
        return

    import shutil
    adb_bin = shutil.which("adb") or ""
    if not adb_bin:
        for c in [Path.cwd() / "adb", Path(__file__).parent.parent.parent.parent / "adb"]:
            if c.exists():
                adb_bin = str(c)
                break
    if not adb_bin:
        adb_bin = "adb"

    console.print(f"Fuzzing {len(analysis.exported_components)} exported components on {device}…\n")
    report = fuzz_exported_components(
        analysis.package_name,
        [c.to_dict() for c in analysis.exported_components],
        adb_serial=device, adb_binary=adb_bin,
        max_tests_per_component=max_per_component,
    )

    console.print(f"\n[bold]═══ Fuzz Results ═══[/]")
    console.print(f"  Total tests: {report.total_tests}")
    console.print(f"  Crashes: [red]{report.crashes}[/]")
    console.print(f"  Interesting: [yellow]{report.interesting}[/]")

    # Show interesting results
    for r in report.results:
        if r.crashed or r.success:
            color = "red" if r.crashed else "yellow"
            console.print(f"  [{color}]{'CRASH' if r.crashed else 'INTERESTING'}[/{color}] "
                         f"[{r.component_type}] {r.component}: {r.payload[:60]}")

    if output_dir:
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)
        (out / "fuzz_report.json").write_text(json.dumps(report.to_dict(), indent=2))
        console.print(f"\n  📄 Report saved: {out / 'fuzz_report.json'}")


@app.command(name="exploit-app")
def exploit_app_cmd(
    apk_path: str = typer.Argument(help="Path to APK file"),
    device: str = typer.Option("localhost:6537", "--device", "-d", help="ADB device serial"),
    verify: bool = typer.Option(True, "--verify/--no-verify", help="Verify exploits after generation"),
    output_dir: Optional[str] = typer.Option(None, "--output-dir", "-o", help="Output directory"),
) -> None:
    """Generate and optionally verify exploits for an Android app."""
    from ..android.app_analyzer import analyze_apk
    from ..android.vuln_scanner import scan_static
    from ..android.exploit_generator import generate_all_exploits, save_exploits

    console.print(f"[bold]═══ Exploit Generation Pipeline ═══[/]\n")

    # Step 1: Analyze
    console.print(f"[bold]Step 1:[/] Analyzing {Path(apk_path).name}…")
    analysis = analyze_apk(apk_path)
    console.print(f"  Package: {analysis.package_name}")
    console.print(f"  Vulnerabilities from manifest: {len(analysis.vulnerabilities)}")

    # Step 2: Generate exploits
    console.print(f"\n[bold]Step 2:[/] Generating exploit scripts…")

    import shutil
    adb_bin = shutil.which("adb") or ""
    if not adb_bin:
        for c in [Path.cwd() / "adb", Path(__file__).parent.parent.parent.parent / "adb"]:
            if c.exists():
                adb_bin = str(c)
                break
    if not adb_bin:
        adb_bin = "adb"

    exploits = generate_all_exploits(
        analysis.vulnerabilities,
        package_name=analysis.package_name,
        adb_serial=device,
        adb_binary=adb_bin,
    )
    console.print(f"  Generated {len(exploits)} exploit scripts")

    for e in exploits:
        console.print(f"    [{e.script_type}] {e.name}: {e.target_vuln}")

    # Step 3: Save
    if output_dir:
        out = Path(output_dir) / "exploits"
        saved = save_exploits(exploits, str(out))
        console.print(f"\n  Saved {len(saved)} files to {out}/")

    # Step 4: Verify
    if verify and exploits:
        console.print(f"\n[bold]Step 3:[/] Verifying exploits on {device}…")
        from ..android.app_verify import verify_all_exploits
        results = verify_all_exploits(
            exploits, analysis.package_name,
            adb_serial=device, adb_binary=adb_bin,
        )
        for r in results:
            status = "[green]SUCCESS[/]" if r.success else "[dim]no impact[/]"
            console.print(f"    {status} {r.exploit_name} ({r.duration_ms}ms)")
            for ind in r.indicators[:3]:
                console.print(f"      → {ind[:100]}")

        if output_dir:
            out = Path(output_dir)
            (out / "verify_results.json").write_text(
                json.dumps([r.to_dict() for r in results], indent=2)
            )

    console.print(f"\n[bold]Done.[/]")


@app.command(name="capture-traffic")
def capture_traffic_cmd(
    package_name: str = typer.Argument(help="Target app package name"),
    device: str = typer.Option("localhost:6537", "--device", "-d", help="ADB device serial"),
    duration: int = typer.Option(15, "--duration", "-t", help="Capture duration (seconds)"),
    output_dir: Optional[str] = typer.Option(None, "--output-dir", "-o", help="Output directory"),
) -> None:
    """Capture and analyze network traffic from an Android app."""
    from ..android.traffic_capture import capture_app_traffic, get_connections

    import shutil
    adb_bin = shutil.which("adb") or ""
    if not adb_bin:
        for c in [Path.cwd() / "adb", Path(__file__).parent.parent.parent.parent / "adb"]:
            if c.exists():
                adb_bin = str(c)
                break
    if not adb_bin:
        adb_bin = "adb"

    console.print(f"[bold]Capturing traffic for {package_name} ({duration}s)…[/]")
    result = capture_app_traffic(package_name, duration, device, adb_bin)

    console.print(f"\n[bold]═══ Traffic Analysis ═══[/]")
    console.print(f"  Connections: {len(result.connections)}")
    console.print(f"  URLs found: {len(result.urls_found)}")
    console.print(f"  API endpoints: {len(result.api_endpoints)}")
    console.print(f"  Cleartext URLs: {len(result.cleartext_urls)}")

    for conn in result.connections[:10]:
        console.print(f"  {conn.state:12s} {conn.local_addr}:{conn.local_port} → "
                      f"{conn.remote_addr}:{conn.remote_port} (uid={conn.uid})")

    if result.cleartext_urls:
        console.print(f"\n  [red]Cleartext HTTP URLs:[/]")
        for url in result.cleartext_urls[:5]:
            console.print(f"    {url}")

    if output_dir:
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)
        (out / "traffic_report.json").write_text(json.dumps(result.to_dict(), indent=2))
        console.print(f"\n  📄 Report saved: {out / 'traffic_report.json'}")


def main() -> None:
    """Entry-point registered in pyproject.toml."""
    app()
