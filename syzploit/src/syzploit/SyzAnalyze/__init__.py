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
from ..SyzVerify.bug_db import SyzkallBugDatabase
import json as _json

__all__ = ["analyze", "parse_crash_log", "stronger_heuristics"]


def analyze_bug(bug_id: str, kernel_name: str, qemu: bool, source_image: Path, source_disk: Path, 
                dynamic_analysis: bool, gdb_port: int, arch: str, output_dir: Path = None):
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
    
    # Step 1: Static Analysis
    console.print("\n[bold yellow]Step 1: Static Analysis[/bold yellow]")
    try:
        static_result = analyzer.analyze(
            metadata.crash_report, 
            metadata.artifact_path(f'repro_{arch}.c'),
            None,
            dynamic_analysis=False,
            kernel_image=str(source_image) if source_image else None
        )
        
        static_output = output_dir / "static_analysis.json"
        with open(static_output, 'w') as f:
            _json.dump(static_result, f, indent=2)
        console.print(f"[green]✓[/green] Static analysis complete: {static_output}")
        
        # Print key findings
        if 'overview' in static_result.get("llm_analysis", {}).get('openai_llm', {}).get('parsed', {}):
            pc = static_result.get("llm_analysis", {}).get('openai_llm', {}).get('parsed', {}).get('overview', {})
            console.print(f"  Exploitability: {pc.get('exploitability', 'unknown')}")
            console.print(f"  Rationale: {pc.get('rationale', 'unknown')}")
            console.print(f"  Primitive Capabilities: {pc.get('primitive_capabilities', 'unknown')}")
        if 'postconditions' in static_result.get("llm_analysis", {}).get('openai_llm', {}).get('parsed', {}):
            pc = static_result.get("llm_analysis", {}).get('openai_llm', {}).get('parsed', {}).get('postconditions', {})
            console.print(f"  Kernel Impact: {pc.get('kernel_impact', 'unknown')}")
    except Exception as e:
        console.print(f"[red]✗[/red] Static analysis failed: {e}")
        traceback.print_exc()
        static_result = None
    
    # Step 2: test the reproducer with syzverify reproducer
    console.print("\n[bold yellow]Step 2: Test Reproducer[/bold yellow]")
    
    
    # Step 3: Dynamic Analysis (if enabled)
    generic_repro_path = static_result.get("reproducer", {}).get('source_path', {})
    dynamic_result = None
    if dynamic_analysis:
        console.print("\n[bold yellow]Step 2: Dynamic Analysis with GDB[/bold yellow]")
        print(f"[DEBUG] dynamic_analysis enabled: {dynamic_analysis}")
        print(f"[DEBUG] qemu: {qemu}, source_image: {source_image}, source_disk: {source_disk}, arch: {arch}")
        try:
            dynamic_result = analyzer.analyze(
                metadata.crash_report,
                generic_repro_path,
                None,
                dynamic_analysis=True,
                gdb_port=gdb_port,
                kernel_image=str(source_image) if source_image else None
            )
            
            dynamic_output = output_dir / "dynamic_analysis.json"
            with open(dynamic_output, 'w') as f:
                _json.dump(dynamic_result, f, indent=2)
            console.print(f"[green]✓[/green] Dynamic analysis complete: {dynamic_output}")
            
            # Print key findings
            if 'dynamic_analysis' in dynamic_result and dynamic_result['dynamic_analysis']:
                dyn = dynamic_result['dynamic_analysis']
                if isinstance(dyn, dict):
                    console.print(f"  Events detected: {len(dyn.get('events', []))}")
                    console.print(f"  Allocations tracked: {len(dyn.get('allocations', {}))}")
                    console.print(f"  Vulnerabilities: {len(dyn.get('vulnerabilities_detected', []))}")
        except Exception as e:
            console.print(f"[red]✗[/red] Dynamic analysis failed: {e}")
            traceback.print_exc()
            dynamic_result = None
    
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