"""
analysis package for syzkall: re-embedded crash analyzer code.

This package contains a copy of the `crash_analyzer` module so the
syzkall harness can use it as an integrated, local dependency without
needing to manipulate sys.path at runtime.
"""

from .crash_analyzer import *  # re-export core functions (analyze, etc.)
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeRemainingColumn, MofNCompleteColumn
import csv
import json
import shutil
import os
import re
import sys
import traceback
import time
from . import crash_analyzer as analyzer
from ..SyzVerify.dynamic import DynamicAnalysisConfig, run_dynamic_analysis as verify_run_da
from ..SyzVerify.bug_db import SyzkallBugDatabase
import json as _json

__all__ = ["analyze", "parse_crash_log", "stronger_heuristics"]


def analyze_bug(bug_id: str, kernel_name: str, qemu: bool, source_image: Path, source_disk: Path, 
                dynamic_analysis: bool, gdb_port: int, arch: str, output_dir: Path = None,
                skip_static: bool = False, ignore_exploitability: bool = False, reuse_dir: Path = None):
    """
    Comprehensive analysis of a single bug with both static and optional dynamic analysis.
    
    Args:
        bug_id: The syzkaller bug ID to analyze
        kernel_name: Name of the kernel (e.g., 'android-5-10')
        qemu: Whether to use QEMU (True) or Cuttlefish (False)
        source_image: Path to kernel image for QEMU
        source_disk: Path to disk image for QEMU
        dynamic_analysis: Enable GDB-based dynamic analysis
        gdb_port: Port for GDB remote debugging
        output_dir: Directory to save analysis results (defaults to bug-specific dir)
    """
    
    console = Console()
    db = SyzkallBugDatabase(kernel_name)
    
    # Get bug metadata
    metadata = db.get_bug_metadata(bug_id)
    if metadata is None:
        console.print(f"[red]Invalid bug ID: {bug_id}[/red]")
        return
    
    # Setup output directory
    if output_dir is None:
        output_dir = Path(f"analysis_{bug_id}")
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    console.print(f"[bold cyan]Analyzing Bug {bug_id}[/bold cyan]")
    console.print(f"Description: {metadata.description}")
    console.print(f"Output directory: {output_dir}")
    
    # Prepare reproducer artifacts (download/generate C, compile binary)
    c_repro_src = None
    try:
        # Prefer provided C reproducer URL
        if getattr(metadata, 'c_repro_url', None):
            p = metadata.save_c_repro()
            if p and Path(p).exists():
                c_repro_src = str(p)
        # Fallback: generate from syz if available
        if not c_repro_src and getattr(metadata, 'syz_repro_url', None):
            p = metadata.generate_c_repro(arch)
            if p and Path(p).exists():
                c_repro_src = str(p)
    except Exception:
        # Non-fatal; static/dynamic can still proceed if other data exists
        c_repro_src = None

    # Step 1: Static Analysis
    static_result = None
    if skip_static:
        console.print("\n[bold yellow]Step 1: Static Analysis (skipped; reusing prior results)[/bold yellow]")
        # Try to load prior static results from output_dir or reuse_dir
        src_dir = Path(reuse_dir) if reuse_dir else output_dir
        try:
            static_path = Path(src_dir) / "static_analysis.json"
            if static_path.exists():
                with static_path.open('r') as f:
                    static_result = _json.load(f)
                console.print(f"[green]✓[/green] Loaded prior static results: {static_path}")
            else:
                console.print(f"[yellow]No static_analysis.json in {src_dir}; proceeding without static context[/yellow]")
        except Exception as e:
            console.print(f"[yellow]Failed to load prior static results: {e}[/yellow]")
    else:
        console.print("\n[bold yellow]Step 1: Static Analysis[/bold yellow]")
        try:
            # Use prepared C reproducer if present; otherwise pass expected path (may not exist)
            repro_src_for_static = c_repro_src or str(metadata.artifact_path(f'repro_{arch}.c'))
            static_result = analyzer.analyze(
                metadata.crash_report,
                repro_src_for_static,
                None,
                None
            )
            
            static_output = output_dir / "static_analysis.json"
            with open(static_output, 'w') as f:
                _json.dump(static_result, f, indent=2)
            console.print(f"[green]✓[/green] Static analysis complete: {static_output}")
            
            # Print key findings (robust to list/dict formats)
            parsed_llm = (static_result.get("llm_analysis", {}) or {}).get('openai_llm', {})
            parsed_llm = (parsed_llm.get('parsed', {}) if isinstance(parsed_llm, dict) else {})
            # Overview block
            if isinstance(parsed_llm, dict) and 'overview' in parsed_llm:
                ov = parsed_llm.get('overview')
                if isinstance(ov, list) and ov:
                    ov = ov[0]
                if isinstance(ov, dict):
                    console.print(f"  Exploitability: {ov.get('exploitability', 'unknown')}")
                    console.print(f"  Rationale: {ov.get('rationale', 'unknown')}")
                    console.print(f"  Primitive Capabilities: {ov.get('primitive_capabilities', 'unknown')}")
            # Postconditions block
            if isinstance(parsed_llm, dict) and 'postconditions' in parsed_llm:
                pc = parsed_llm.get('postconditions')
                if isinstance(pc, list):
                    # try to print kernel impact from first element if dict
                    ki = None
                    if pc and isinstance(pc[0], dict):
                        ki = pc[0].get('kernel_impact')
                    console.print(f"  Kernel Impact: {ki if ki is not None else 'unknown'}")
                elif isinstance(pc, dict):
                    console.print(f"  Kernel Impact: {pc.get('kernel_impact', 'unknown')}")
        except Exception as e:
            console.print(f"[red]✗[/red] Static analysis failed: {e}")
            traceback.print_exc()
            static_result = None
    
    # Step 2: test the reproducer with syzverify reproducer
    console.print("\n[bold yellow]Step 2: Test Reproducer[/bold yellow]")
    # Try to compile the reproducer for dynamic runs
    repro_binary_path = None
    try:
        if c_repro_src and Path(c_repro_src).exists():
            repro_binary_path = str(metadata.compile_repro(arch))
            if repro_binary_path and Path(repro_binary_path).exists():
                console.print(f"[green]✓[/green] Reproducer compiled: {repro_binary_path}")
    except Exception as e:
        console.print(f"[yellow]Failed to compile reproducer: {e}[/yellow]")
    
    
    # Step 3: Dynamic Analysis (gated by exploitability rating)
    # Guard against None static_result and use fallback path if available
    generic_repro_path = None
    if static_result and isinstance(static_result, dict):
        try:
            generic_repro_path = (static_result.get("reproducer", {}) or {}).get('source_path')
        except Exception:
            generic_repro_path = None
    if not generic_repro_path:
        fallback = Path(c_repro_src) if c_repro_src else metadata.artifact_path(f'repro_{arch}.c')
        if fallback and fallback.exists():
            generic_repro_path = str(fallback)

    # Extract exploitability rating from static_result (LLM overview) robustly
    exploitability = None
    try:
        if isinstance(static_result, dict):
            parsed_llm = (static_result.get("llm_analysis", {}) or {}).get('openai_llm', {})
            parsed_llm = (parsed_llm.get('parsed', {}) if isinstance(parsed_llm, dict) else {})
            ov = parsed_llm.get('overview') if isinstance(parsed_llm, dict) else None
            if isinstance(ov, list) and ov:
                ov = ov[0]
            if isinstance(ov, dict):
                val = ov.get('exploitability')
                if isinstance(val, str):
                    exploitability = val.strip().lower()
    except Exception:
        exploitability = None

    dynamic_result = None
    should_run_dynamic = bool(dynamic_analysis) and ((exploitability in {"medium", "high"}) or bool(ignore_exploitability))
    if should_run_dynamic:
        console.print("\n[bold yellow]Step 2: Dynamic Analysis with GDB[/bold yellow]")
        print(f"[DEBUG] dynamic_analysis enabled: {dynamic_analysis}")
        print(f"[DEBUG] qemu: {qemu}, source_image: {source_image}, source_disk: {source_disk}, arch: {arch}")
        if not generic_repro_path:
            console.print("[yellow]Skipping dynamic analysis: no reproducer source path available[/yellow]")
        else:
            try:
                # Run SyzVerify dynamic analysis to produce instrumentation results
                vm_type = 'qemu' if qemu else 'cuttlefish'
                da_config = DynamicAnalysisConfig(
                    vm_type=vm_type,
                    kernel_image=str(source_image) if source_image else None,
                    kernel_disk=str(source_disk) if source_disk else None,
                    bzimage_path=str(source_image) if source_image else None,
                    gdb_port=gdb_port,
                    timeout=360,
                    tmp_scope_dir=str(output_dir)
                )
                # Ensure we have a compiled binary
                repro_binary = repro_binary_path or str(metadata.artifact_path('repro'))
                if not Path(repro_binary).exists() and c_repro_src and Path(c_repro_src).exists():
                    try:
                        repro_binary = str(metadata.compile_repro(arch))
                    except Exception:
                        pass
                parsed_crash = analyzer.parse_crash_log(metadata.crash_report)
                da_result = verify_run_da(str(repro_binary), parsed_crash, da_config)

                # Integrate dynamic results into analyzer output
                dynamic_result = analyzer.analyze(
                    metadata.crash_report,
                    generic_repro_path,
                    None,
                    dynamic_results=da_result
                )

                dynamic_output = output_dir / "dynamic_analysis.json"
                with open(dynamic_output, 'w') as f:
                    _json.dump(dynamic_result, f, indent=2)
                console.print(f"[green]✓[/green] Dynamic analysis complete: {dynamic_output}")

                # Optional robust post-processing for vulnerability signals
                try:
                    from ..SyzVerify import post_process as _pp
                    pp_out = dynamic_output.with_name(dynamic_output.stem + "_post.json")
                    pp_res = _pp.analyze(str(dynamic_output), str(pp_out))
                    console.print(f"  Post-processing summary: confidence={pp_res.get('confidence', 0)} uaf={pp_res.get('summary', {}).get('uaf', 0)} invalid-access={pp_res.get('summary', {}).get('invalid-access', 0)} double-free={pp_res.get('summary', {}).get('double_free_count', 0)}")
                    console.print(f"  Post-processed results: {pp_out}")
                except Exception as e:
                    console.print(f"[yellow]Post-processing failed: {e}[/yellow]")

                # Print key findings if present
                dyn = dynamic_result.get('dynamic_analysis') if isinstance(dynamic_result, dict) else None
                if isinstance(dyn, dict):
                    console.print(f"  Events detected: {len(dyn.get('events', []))}")
                    console.print(f"  Allocations tracked: {len(dyn.get('allocations', {}))}")
                    console.print(f"  Vulnerabilities: {len(dyn.get('vulnerabilities_detected', []))}")
            except Exception as e:
                console.print(f"[red]✗[/red] Dynamic analysis failed: {e}")
                traceback.print_exc()
                dynamic_result = None
    else:
        if dynamic_analysis:
            console.print("[yellow]Skipping dynamic analysis due to low exploitability rating[/yellow]")
            console.print(f"  Exploitability: {exploitability or 'unknown'} (required: medium/high)")
    
    # Step 4: Generate enhanced C trigger with LLM
    # console.print("\n[bold yellow]Step 4: Generate Enhanced C Trigger[/bold yellow]")
    # try:
    #     if static_result and 'postcondition' in static_result:
    #         # Generate trigger using LLM with both static and dynamic context
    #         trigger_output = output_dir / "enhanced_trigger.c"
            
    #         # Read original reproducer if available
    #         original_repro = None
    #         if repro_path and Path(repro_path).exists():
    #             with open(repro_path, 'r') as f:
    #                 original_repro = f.read()
            
    #         # Generate enhanced trigger
    #         enhanced_trigger = analyzer.generate_llm_trigger_c(
    #             original_repro_c=original_repro,
    #             postcondition=static_result['postcondition'],
    #             static_analysis=static_result,
    #             dynamic_analysis=dynamic_result,
    #             crash_log=metadata.crash_report
    #         )
            
    #         with open(trigger_output, 'w') as f:
    #             f.write(enhanced_trigger)
    #         console.print(f"[green]✓[/green] Enhanced trigger generated: {trigger_output}")
    # except Exception as e:
    #     console.print(f"[red]✗[/red] Trigger generation failed: {e}")
    #     traceback.print_exc()
    
    # Step 5: Generate comprehensive report
    console.print("\n[bold yellow]Step 5: Generate Report[/bold yellow]")
    try:
        report_output = output_dir / "analysis_report.md"
        
        with open(report_output, 'w') as f:
            f.write(f"# Analysis Report: Bug {bug_id}\n\n")
            f.write(f"**Description:** {metadata.description}\n\n")
            f.write(f"**Analysis Date:** {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            f.write("## Static Analysis\n\n")
            if static_result and 'postcondition' in static_result:
                pc = static_result['postcondition']
                f.write(f"- **Classification:** {pc.get('classification', 'unknown')}\n")
                f.write(f"- **Confidence:** {pc.get('confidence', 'unknown')}\n")
                f.write(f"- **Score:** {pc.get('score', 0)}/100\n")
                f.write(f"- **IP Control:** {pc.get('ip_control', False)}\n")
                f.write(f"- **Arbitrary Read:** {pc.get('arbitrary_read', False)}\n")
                f.write(f"- **Arbitrary Write:** {pc.get('arbitrary_write', False)}\n\n")
            
            if dynamic_analysis and dynamic_result:
                f.write("## Dynamic Analysis\n\n")
                if 'memory_accesses' in dynamic_result:
                    f.write(f"- **Memory Accesses:** {len(dynamic_result['memory_accesses'])}\n")
                if 'register_states' in dynamic_result:
                    f.write(f"- **Register States:** {len(dynamic_result['register_states'])}\n")
                if 'data_flow' in dynamic_result:
                    f.write(f"- **Data Flow Edges:** {len(dynamic_result.get('data_flow', []))}\n")
                f.write("\n")
            
            f.write("## Files Generated\n\n")
            f.write(f"- Static analysis: `static_analysis.json`\n")
            if dynamic_analysis:
                f.write(f"- Dynamic analysis: `dynamic_analysis.json`\n")
            f.write(f"- Enhanced trigger: `enhanced_trigger.c`\n")
            f.write(f"- This report: `analysis_report.md`\n")
        
        console.print(f"[green]✓[/green] Report generated: {report_output}")
    except Exception as e:
        console.print(f"[red]✗[/red] Report generation failed: {e}")
    
    console.print(f"\n[bold green]Analysis complete! Results in: {output_dir}[/bold green]")