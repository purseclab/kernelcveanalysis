# Pulls bugs from syzkaller syzbot and filters for interesting looking ones

import csv
import json
import os
import re
import subprocess
import sys
import time
import traceback
from pathlib import Path

from rich.console import Console
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeRemainingColumn,
)
from rich.table import Table

from ..SyzAnalyze import crash_analyzer as precondition_analyzer
from ..utils.adb import calculate_adb_port
from .bug_db import SyzkallBugDatabase
from .cuttlefish import CuttlefishConfig
from .dynamic import DynamicAnalysisConfig, run_dynamic_analysis as verify_run_da
from .run_bug import (
    test_repro_crashes,
    wait_for_connection,
    test_repro_crashes_qemu,
    test_repro_crashes_cuttlefish_gdb,
    test_repro_crashes_cuttlefish_kernel_gdb,
    CUTTLEFISH_KERNEL_GDB_PORT,
    verify_exploit_privilege_escalation,
    test_exploit_on_device,
    test_exploit_from_source,
    compile_exploit,
    test_repro_with_cuttlefish_controller,
    extract_and_save_runtime_symbols,
    ensure_device_ready,
)
from .scrape import pull_bugs

def pull(kernel_name: str, apply_filter: bool = True):
    db = SyzkallBugDatabase(kernel_name)

    try:
        pull_bugs(db, kernel_name, apply_filter=apply_filter)
    finally:
        db.close()

def query(kernel_name: str):
    db = SyzkallBugDatabase(kernel_name)
    bugs = db.get_all_bugs()

    for bug in bugs:
        # print(bug.description)
        # print(bug.kernel_name)
        # if 'android' not in bug.kernel_name:
        #     continue
        print(f'{bug.bug_id}: {bug.title} ({bug.crash_time})')


def collect_stats(kernel_name: str, outfile: Path):
    db = SyzkallBugDatabase(kernel_name)
    console = Console()
    table = Table(title="Syzkaller Bug Test Results")
    table.add_column("Bug ID", style="cyan", no_wrap=True)
    table.add_column("Reported Crash", style="magenta")
    table.add_column("Crash Type", style="magenta")
    table.add_column("Syzcall", justify="center")
    table.add_column("File", justify="center")
    table.add_column("Function", justify="center", style="red")
    table.add_column("Line Number", justify="center", style="red")

    bugs = db.get_all_bugs()
    if not bugs:
        console.print("[red]No bugs found in the database.[/red]")
        return
    outfile_csv_name = outfile + '.csv'
    outfile_csv = []
    outfile_json_name = outfile + '.json'
    outfile_json = []

    for bug in bugs:
        metadata = db.get_bug_metadata(bug.bug_id)
        if metadata is None:
            table.add_row(bug.bug_id, "Invalid ID", "❌", "❌", "❌", "❌", "❌")
            outfile_json.append({"bug_id": bug.bug_id, "error": "Invalid ID"})
            outfile_csv.append([bug.bug_id, "Invalid ID", "❌", "❌", "❌", "❌", "❌"])
            continue

        description = metadata.description

        # parse the crash message to get the crash type, file, function, and syscall
        result = parse_crash_summary(metadata.crash_report)
        repro_path = metadata.save_syz_repro()
        try:
            all_syscalls, last_syscall = extract_last_syscall(repro_path)
        except:
            last_syscall = "unknown"

        bug_url = f"https://syzkaller.appspot.com/bug?id={bug.bug_id}"
        table.add_row(str(bug.bug_id), bug_url, result["crash_type"], last_syscall, result["file"], result["function"], str(result["line_number"]))
        outfile_csv.append([bug.bug_id, bug_url, result["crash_type"], last_syscall, result["file"], result["function"], str(result["line_number"])])
        outfile_json.append({
            "bug_id": bug.bug_id,
            "bug_url": bug_url,
            "crash_type": result["crash_type"],
            "syscall": last_syscall,
            "file": result["file"],
            "function": result["function"],
            "line_number": result["line_number"]})

    console.print(table)
    # === WRITE CSV RESULTS ===
    with open(outfile_csv_name, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Bug ID", "Report URL", "Crash Type", "Syscall", "File", "Function", "Line Number"])
        writer.writerows(outfile_csv)
    # === WRITE JSON RESULTS ===
    with open(outfile_json_name, mode="w", encoding="utf-8") as f:
        json.dump(outfile_json, f, indent=2)

    console.print(f"[green]Results saved to:[/green]")
    console.print(f"  [bold]{outfile_csv_name}[/bold]")
    console.print(f"  [bold]{outfile_json_name}[/bold]")


def test_all(
    local: bool, 
    arch: str, 
    kernel_name: str, 
    qemu: bool, 
    root: bool, 
    source_image: Path, 
    source_disk: Path, 
    source: bool, 
    outdir_name: str, 
    dynamic_analysis: bool = False, 
    gdb_port: int = 1234, 
    kernel_gdb: bool = False, 
    vmlinux_path: str = None, 
    kernel_gdb_port: int = 1234,
    # New Cuttlefish-specific options
    use_cuttlefish_controller: bool = False,
    ssh_host: str = "localhost",
    ssh_port: int = 22,
    ssh_user: str = None,
    ssh_key: str = None,
    adb_port: int = 6520,
    instance: int = None,
    persistent: bool = True,
    already_running: bool = True,
    setup_tunnels: bool = False,
    extract_runtime_symbols: bool = True,
    demo: bool = False,
    start_cmd: str = None,
    stop_cmd: str = None,
    runtime_logs_dir: str = None,
    # Connectivity check options
    pre_check_device: bool = True,
    pre_check_wait: int = 60,
    # LLM fix options
    use_llm_fix: bool = True,
):
    """
    Test all bugs in the database.
    
    Args:
        local: Whether to run locally
        arch: Target architecture (arm64, x86_64)
        kernel_name: Name of the kernel in the database
        qemu: Whether to use QEMU instead of Cuttlefish
        root: Whether to run as root
        source_image: Path to kernel image
        source_disk: Path to disk image
        source: Whether to download source assets
        outdir_name: Output directory name
        dynamic_analysis: Enable userspace GDB analysis
        gdb_port: Port for userspace gdbserver
        kernel_gdb: Enable kernel-side GDB analysis (requires Cuttlefish with --gdb_port)
        vmlinux_path: Path to vmlinux file for kernel symbols
        kernel_gdb_port: Port for kernel GDB stub (default: 1234)
        
        # Cuttlefish Controller Options:
        use_cuttlefish_controller: Use CuttlefishController for testing
        ssh_host: SSH host for Cuttlefish (can be ~/.ssh/config alias)
        ssh_port: SSH port
        ssh_user: SSH user (optional, uses ssh config if not set)
        ssh_key: SSH key path (optional, uses ssh config if not set)
        adb_port: ADB port for Cuttlefish device
        instance: Cuttlefish instance number (auto-calculates ADB port)
        persistent: Keep Cuttlefish running between tests
        already_running: Cuttlefish is already running
        setup_tunnels: Set up SSH tunnels for remote access
        extract_runtime_symbols: Extract kallsyms from running VM for accurate breakpoints
        demo: Demo mode - generate sample data if GDB tracing fails
        start_cmd: Command to start Cuttlefish (run once at beginning if not already_running)
        stop_cmd: Command to stop Cuttlefish (run once at end)
        runtime_logs_dir: Path to cuttlefish runtime logs directory
        
        # Connectivity check options:
        pre_check_device: Check device connectivity before each test (default: True)
        pre_check_wait: Max seconds to wait if device offline (default: 60)
    """
    db = SyzkallBugDatabase(kernel_name)
    console = Console()

    # Helper function to restart the instance after a crash
    def restart_instance():
        """Stop and restart the instance after a crash."""
        if not stop_cmd or not start_cmd:
            console.print("[yellow]No stop_cmd/start_cmd provided, cannot restart instance[/yellow]")
            return False
        
        console.print(f"[yellow]Restarting instance due to crash...[/yellow]")
        
        # Stop the instance
        console.print(f"[yellow]Stopping instance with command:[/yellow] {stop_cmd}")
        try:
            if ssh_host and ssh_host != 'localhost':
                stop_result = subprocess.run(
                    ['ssh', ssh_host, stop_cmd],
                    capture_output=True,
                    text=True,
                    timeout=120
                )
            else:
                stop_result = subprocess.run(
                    stop_cmd,
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=120
                )
            if stop_result.returncode != 0:
                console.print(f"[red]Warning: Stop command exited with code {stop_result.returncode}[/red]")
            else:
                console.print(f"[green]Instance stopped successfully[/green]")
        except subprocess.TimeoutExpired:
            console.print("[red]Stop command timed out after 2 minutes[/red]")
        except Exception as e:
            console.print(f"[red]Failed to stop instance: {e}[/red]")
        
        # Wait a bit before restarting
        console.print("[yellow]Waiting 5 seconds before restart...[/yellow]")
        time.sleep(5)
        
        # Start the instance
        console.print(f"[yellow]Starting instance with command:[/yellow] {start_cmd}")
        try:
            if ssh_host and ssh_host != 'localhost':
                start_result = subprocess.run(
                    ['ssh', ssh_host, start_cmd],
                    capture_output=True,
                    text=True,
                    timeout=300
                )
            else:
                start_result = subprocess.run(
                    start_cmd,
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=300
                )
            if start_result.returncode != 0:
                console.print(f"[red]Warning: Start command exited with code {start_result.returncode}[/red]")
            else:
                console.print(f"[green]Instance started successfully[/green]")
        except subprocess.TimeoutExpired:
            console.print("[red]Start command timed out after 5 minutes[/red]")
            return False
        except Exception as e:
            console.print(f"[red]Failed to start instance: {e}[/red]")
            return False
        
        # Wait for stabilization
        console.print("[yellow]Waiting 30 seconds for instance to stabilize...[/yellow]")
        time.sleep(30)
        return True

    bugs = db.get_all_bugs()
    if not bugs:
        console.print("[red]No bugs found in the database.[/red]")
        return

    results = []
    crashing_bugs = []
    unique_outcomes = []
    crash_summary = {}
    crash_type_summary = {}
    syscall_summary = {}
    exceptions = []

    base_dir = os.path.join(os.getcwd(), outdir_name)
    os.makedirs(base_dir, exist_ok=True)
    if root:
        rootstr = "_root"
    else:
        rootstr = ""
    crashes_dir = os.path.join(base_dir, f"{kernel_name}{rootstr}_crashes")
    os.makedirs(crashes_dir, exist_ok=True)
    if source:
        sources_dir = os.path.join(base_dir, f"{kernel_name}_sources")
        os.makedirs(sources_dir, exist_ok=True)


    # summary_path = os.path.join(base_dir, f"{kernel_name}_summary.txt")
    crash_report_path = os.path.join(base_dir, f"{kernel_name}{rootstr}_crash_analysis.json")
    unique_report_path = os.path.join(base_dir, f"{kernel_name}{rootstr}_unique_outcomes.json")
    crash_summary_path = os.path.join(base_dir, f"{kernel_name}{rootstr}_crash_summary.json")
    # make a log folder if it doesn't exist at the base dir
    log_dir = os.path.join(base_dir, f"logs{rootstr}")
    os.makedirs(log_dir, exist_ok=True)

    compiled_count = 0
    crashed_root_count = 0
    crashed_unroot_count = 0
    unique_outcomes_root_count = 0
    unique_outcomes_unroot_count = 0
    last_run = "❌"
    start_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    previous_source_image = None
    previous_source_disk = None
    download_succeeded = True
    used_assets = "no"
    
    # Start Cuttlefish if start_cmd is provided and not already running
    if start_cmd and not already_running:
        console.print(f"[yellow]Starting Cuttlefish with command:[/yellow] {start_cmd}")
        try:
            if ssh_host and ssh_host != 'localhost':
                # Run start command on remote host
                start_result = subprocess.run(
                    ['ssh', ssh_host, start_cmd],
                    capture_output=True,
                    text=True,
                    timeout=300  # 5 min timeout for boot
                )
            else:
                # Run start command locally
                start_result = subprocess.run(
                    start_cmd,
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=300
                )
            if start_result.returncode != 0:
                console.print(f"[red]Warning: Start command exited with code {start_result.returncode}[/red]")
                console.print(f"  stderr: {start_result.stderr[:500]}")
            else:
                console.print(f"[green]Cuttlefish started successfully[/green]")
            # Wait for Cuttlefish to stabilize
            console.print("[yellow]Waiting 30 seconds for Cuttlefish to stabilize...[/yellow]")
            time.sleep(30)
        except subprocess.TimeoutExpired:
            console.print("[red]Start command timed out after 5 minutes[/red]")
        except Exception as e:
            console.print(f"[red]Failed to start Cuttlefish: {e}[/red]")

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        MofNCompleteColumn(),
        TimeRemainingColumn(),
        transient=True
    ) as progress:
        task = progress.add_task("Testing bugs...", total=len(bugs))

        for idx, bug in enumerate(bugs, 1):
            # Update progress bar once at start of each bug
            progress.update(task, description=f"[{idx}/{len(bugs)}] Bug {bug.bug_id[:12]}")
            
            metadata = db.get_bug_metadata(bug.bug_id)
            if metadata is None:
                row = [str(bug.bug_id), "Invalid ID", "❌", "N/A", "yes" if not root else "no", "N/A"]
                results.append(row)
                console.print(f"  [{idx}/{len(bugs)}] Bug {bug.bug_id}: [red]Invalid ID[/red]")
                progress.advance(task)
                continue

            description = metadata.description

            try:
                repro_path = metadata.compile_repro(arch, use_llm_fix=use_llm_fix)
                compiled = "✅"
                compiled_count += 1
            except Exception as e:
                compiled = "❌"
                repro_path = None
                print(f"Error compiling repro for bug {bug.bug_id}: {e}")

            crashed = "❌"
            crash_log_path = None
            gdb_results = None
            uaf_detected = False
            oob_detected = False
            
            # Pre-check device connectivity before running this bug's reproducer
            if pre_check_device and repro_path and not qemu:
                try:
                    device_ready = ensure_device_ready(
                        max_wait=pre_check_wait,
                        ssh_host=ssh_host if ssh_host != 'localhost' else None,
                        stop_cmd=stop_cmd,
                        start_cmd=start_cmd,
                        verbose=True,
                        instance=instance,
                        adb_port=adb_port,
                    )
                    if not device_ready:
                        console.print(f"  [{idx}/{len(bugs)}] Bug {bug.bug_id}: [yellow]SKIPPED - device not ready[/yellow]")
                        row = [str(bug.bug_id), description[:40], compiled, "SKIPPED", "yes" if not root else "no", "N/A"]
                        results.append(row)
                        progress.advance(task)
                        continue
                except KeyboardInterrupt:
                    console.print("[red]Test run aborted by user[/red]")
                    break
            
            if repro_path:
                try:
                    if qemu:
                        if source:
                            source_disk, source_image = bug.download_artifacts(sources_dir)
                            if source_disk is None or source_image is None:
                                download_succeeded = False
                                if previous_source_disk and previous_source_image:
                                    source_disk = previous_source_disk
                                    source_image = previous_source_image
                                    used_assets = "no (used previous)"
                            else:
                                download_succeeded = True
                                used_assets = "yes"
                        v, t = test_repro_crashes_qemu(repro_path, local, bug.bug_id, log_dir, root, source_image, source_disk)
                    elif use_cuttlefish_controller:
                        # Use CuttlefishController with runtime symbol extraction
                        parsed_crash = parse_crash_summary(metadata.crash_report) if metadata.crash_report else None
                        
                        # Calculate ADB port from instance number
                        actual_adb_port = adb_port
                        if instance is not None:
                            actual_adb_port = calculate_adb_port(instance)
                        
                        # Create Cuttlefish configuration
                        cf_config = CuttlefishConfig(
                            ssh_host=ssh_host,
                            ssh_port=ssh_port,
                            ssh_user=ssh_user,
                            ssh_key_path=ssh_key,
                            persistent=persistent,
                            already_running=already_running,
                            gdb_port=kernel_gdb_port,
                            adb_port=actual_adb_port,
                            enable_gdb=kernel_gdb or dynamic_analysis,
                            setup_tunnels=setup_tunnels,
                            vmlinux_path=vmlinux_path,
                            extract_symbols=extract_runtime_symbols,
                        )
                        
                        v, t, gdb_results = test_repro_with_cuttlefish_controller(
                            repro_path=str(repro_path),
                            bug_id=bug.bug_id,
                            cuttlefish_config=cf_config,
                            parsed_crash=parsed_crash,
                            log_dir=log_dir,
                            root=root,
                            timeout=120,
                            arch=arch,
                            vmlinux_path=vmlinux_path,
                            demo=demo,
                        )
                        
                        # Check for UAF/OOB in GDB results
                        if gdb_results:
                            events = gdb_results.get("events", [])
                            for event in events:
                                if event.get("type") == "uaf_detected" or "use-after-free" in str(event).lower():
                                    uaf_detected = True
                                if event.get("type") == "oob_detected" or "out-of-bounds" in str(event).lower():
                                    oob_detected = True
                            
                            # Save GDB results
                            gdb_out = os.path.join(log_dir, f"cuttlefish_gdb_{bug.bug_id}.json")
                            with open(gdb_out, 'w', encoding='utf-8') as gf:
                                json.dump(gdb_results, gf, indent=2)
                    else:
                        # Parse crash for GDB instrumentation
                        parsed_crash = parse_crash_summary(metadata.crash_report) if metadata.crash_report else None
                        
                        # Use kernel GDB if enabled (takes precedence)
                        if kernel_gdb:
                            v, t, gdb_results = test_repro_crashes_cuttlefish_kernel_gdb(
                                repro_path=repro_path,
                                bug_id=bug.bug_id,
                                vmlinux_path=vmlinux_path,
                                kernel_gdb_port=kernel_gdb_port,
                                parsed_crash=parsed_crash,
                                log_dir=log_dir,
                                root=root,
                                arch=arch
                            )
                            # Save kernel GDB results
                            if gdb_results:
                                gdb_out = os.path.join(log_dir, f"kernel_gdb_analysis_{bug.bug_id}.json")
                                with open(gdb_out, 'w', encoding='utf-8') as gf:
                                    json.dump(gdb_results, gf, indent=2)
                        # Use userspace GDB analysis if dynamic_analysis is enabled
                        elif dynamic_analysis:
                            v, t, gdb_results = test_repro_crashes_cuttlefish_gdb(
                                repro_path, local, bug.bug_id, log_dir, root,
                                parsed_crash=parsed_crash,
                                gdb_port=gdb_port,
                                arch=arch
                            )
                            # Save GDB results alongside other outputs
                            if gdb_results:
                                gdb_out = os.path.join(log_dir, f"gdb_analysis_{bug.bug_id}.json")
                                with open(gdb_out, 'w', encoding='utf-8') as gf:
                                    json.dump(gdb_results, gf, indent=2)
                        else:
                            v, t = test_repro_crashes(repro_path, local, bug.bug_id, log_dir, root)
                    if v and (t==1 or t==3):
                        crashed = "💥"+str(t)
                        if root:
                            crashed_root_count += 1
                        else:
                            crashed_unroot_count += 1
                        crash_subdir = os.path.join(crashes_dir, f"bug_{bug.bug_id}")
                        os.makedirs(crash_subdir, exist_ok=True)

                        os.system(f'cp {os.path.dirname(repro_path)}/* {crash_subdir}')
                        
                        try:
                            crashing_file, crashing_line, crash_type = extract_crash_locations(metadata.crash_report)
                        except Exception as e:
                            crashing_file = "unknown"
                            crash_type = "unknown"
                            crashing_line = 0
                            exceptions.append(f"Error extracting crash locations for bug {bug.bug_id}: {e}")
                        try:
                            all_syscalls, last_syscall = extract_last_syscall(os.path.join(os.path.dirname(repro_path),"repro.syz"))
                        except:
                            last_syscall = "unknown"
                        
                        # Create README with bug info (after extracting crash details)
                        syzbot_link = f"https://syzkaller.appspot.com/bug?extid={bug.bug_id}"
                        readme_content = f"""# Bug {bug.bug_id}

## Description
{description}

## Syzbot Link
{syzbot_link}

## Bug ID
{bug.bug_id}

## Architecture
{arch}

## Crash Type
{crash_type}

## Crash Location
- **File:** {crashing_file}
- **Line:** {crashing_line}

## Triggering Syscall
{last_syscall}

## Reproducer
The compiled reproducer for {arch} is included in this folder.

## Files
- `repro.syz` - Syzkaller reproducer script
- `repro.c` - C reproducer source  
- `repro_{arch}` - Compiled reproducer binary
"""
                        readme_path = os.path.join(crash_subdir, "README.md")
                        with open(readme_path, 'w', encoding='utf-8') as rf:
                            rf.write(readme_content)

                        crash_type_summary[crash_type] = crash_type_summary.get(crash_type, 0) + 1
                        syscall_summary[last_syscall] = syscall_summary.get(last_syscall, 0) + 1

                        print("ADDING CRASH",  bug.bug_id, crashed)
                        crashing_bugs.append({
                            "bug_id": bug.bug_id,
                            "description": description,
                            "repro_path": os.path.join(crash_subdir, os.path.basename(repro_path)),
                            "file": crashing_file,
                            "line" : crashing_line,
                            "crash_type": crash_type,
                            "rooted": root,
                            "syscall": last_syscall,
                            "used_assets": used_assets,
                            "uaf_detected": uaf_detected,
                            "oob_detected": oob_detected,
                            "gdb_results": gdb_results,
                        })
                        # Attempt to run precondition analysis (non-fatal)
                        try:
                            # analyze() returns dict with parsed/snippets/evidence/classification/exploitability/llm_analysis
                            # Force dynamic analysis to always use SyzVerify dynamic module and GDB script
                            analysis = precondition_analyzer.analyze(
                                metadata.crash_report,
                                f'{repro_path}_{arch}.c',
                                None,
                                dynamic_analysis=True,
                                gdb_port=gdb_port,
                                kernel_image=str(source_image) if source_image else None
                            )
                            outname = os.path.join(crash_subdir, f'precondition_analysis_{bug.bug_id}.json')
                            os.makedirs(os.path.dirname(outname), exist_ok=True)
                            with open(outname, 'w', encoding='utf-8') as pf:
                                json.dump(analysis, pf, indent=2)
                        except Exception as e:
                            exceptions.append(f"precondition analysis failed for {bug.bug_id}: {e}")
                        # Optional: run dynamic GDB analysis to verify preconditions
                        if dynamic_analysis and source_image:
                            try:
                                # Build config based on environment
                                vm_type = 'qemu' if qemu else 'cuttlefish'
                                da_config = DynamicAnalysisConfig(
                                    vm_type=vm_type,
                                    kernel_image=str(source_image),
                                    gdb_port=gdb_port,
                                    timeout=360
                                )
                                # Use compiled binary path (metadata.compile_repro returns binary path)
                                repro_binary = repro_path
                                parsed_crash = parse_crash_summary(metadata.crash_report)
                                print("[STEP D] Running dynamic GDB analysis to verify preconditions...")
                                da_result = verify_run_da(str(repro_binary), parsed_crash, da_config)
                                # Save dynamic analysis result
                                da_out = os.path.join(crash_subdir, f"dynamic_analysis_{bug.bug_id}.json")
                                with open(da_out, 'w', encoding='utf-8') as f:
                                    json.dump(da_result, f, indent=2)
                                print(f"[+] Dynamic analysis written to: {da_out}")
                            except Exception as e:
                                exceptions.append(f"dynamic analysis failed for {bug.bug_id}: {e}")

                        # Restart instance after crash if stop_cmd and start_cmd are provided
                        console.print(f"  [{idx}/{len(bugs)}] Bug {bug.bug_id}: [red]💥 CRASHED[/red] ({crash_type})")
                        if not qemu and stop_cmd and start_cmd:
                            restart_instance()
                        elif not qemu:
                            print("crashed happened, waiting for connection...")
                            wait_for_connection()
                            print("crashed happened, done")
                    elif not v and t==2:
                        crashed = "⚠️"+str(t)
                        print("WARNING: No crash, but repro may not work as expected",  bug.bug_id, crashed)
                    # elif v and t==2 and not root:
                    #     crashed = "⚠️"+str(t)+(" root" if root else "")
                    #     if root:
                    #         unique_outcomes_root_count += 1
                    #     else:
                    #         unique_outcomes_unroot_count += 1
                    #     crash_subdir = os.path.join(crashes_dir, f"bug_{bug.bug_id}")
                    #     os.makedirs(crash_subdir, exist_ok=True)
                    #     os.system(f'cp {os.path.dirname(repro_path)}/* {crash_subdir}')
                    #     try:
                    #         crashing_file, crashing_line, crash_type = extract_crash_locations(metadata.crash_report)
                    #     except Exception as e:
                    #         crashing_file = "unknown"
                    #         crash_type = "unknown"
                    #         crashing_line = 0
                    #         exceptions.append(f"Error extracting crash locations for bug {bug.bug_id}: {e}")
                    #     try:
                    #         all_syscalls, last_syscall = extract_last_syscall(os.path.join(os.path.dirname(repro_path),"repro.syz"))
                    #     except:
                    #         last_syscall = "unknown"

                    #     crash_type_summary[crash_type] = crash_type_summary.get(crash_type, 0) + 1
                    #     syscall_summary[last_syscall] = syscall_summary.get(last_syscall, 0) + 1
                    #     print("ADDING UNIQUE OUTCOME",  bug.bug_id, crashed)
                    #     unique_outcomes.append({
                    #         "bug_id": bug.bug_id,
                    #         "description": description,
                    #         "repro_path": os.path.join(crash_subdir, os.path.basename(repro_path)),
                    #         "file": crashing_file,
                    #         "line" : crashing_line,
                    #         "crash_type": crash_type,
                    #         "rooted": root,
                    #         "syscall": last_syscall
                    #     })

                    #     print("unqique outcome happened, waiting for connection...")
                    #     wait_for_connection()
                    #     print("unique outcome happened, done")
                    #     break

                except Exception as e:
                    # Print full traceback (with filenames & line numbers) to stdout
                    print("❌ Exception caught, full details below:", file=sys.stdout)
                    traceback.print_exc(file=sys.stdout)
                    crashed = "❌"
            last_run = crashed
            if download_succeeded:
                previous_source_disk = source_disk
                previous_source_image = source_image
            row = [str(bug.bug_id), description, compiled, crashed, "yes" if not root else "no", used_assets]
            results.append(row)
            # Log progress for non-crash cases (crashes already logged above)
            if "💥" not in crashed and "SKIPPED" not in str(crashed):
                status_icon = "✅" if compiled == "✅" else "❌"
                console.print(f"  [{idx}/{len(bugs)}] Bug {bug.bug_id}: {status_icon} compiled={compiled} crashed={crashed}")
            progress.advance(task)


    end_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    run_time = time.mktime(time.strptime(end_time, "%Y-%m-%d %H:%M:%S")) - time.mktime(time.strptime(start_time, "%Y-%m-%d %H:%M:%S"))

    # Calculate UAF/OOB counts from crashing bugs
    uaf_count = sum(1 for bug in crashing_bugs if bug.get("uaf_detected", False))
    oob_count = sum(1 for bug in crashing_bugs if bug.get("oob_detected", False))

    # === WRITE CRASH ANALYSIS ===
    crash_summary = {
        "kernel_name": kernel_name,
        "total_bugs": len(results),
        "compiled_count": compiled_count,
        "crashed_root_count": crashed_root_count,
        "crashed_unroot_count": crashed_unroot_count,
        "unique_outcomes_root_count": unique_outcomes_root_count,
        "unique_outcomes_unroot_count": unique_outcomes_unroot_count,
        "uaf_detected_count": uaf_count,
        "oob_detected_count": oob_count,
        "runtime": run_time,
        "crash_type_summary": crash_type_summary,
        "syscall_summary": syscall_summary
    }
    with open(crash_summary_path, 'w', encoding='utf-8') as f:
        json.dump(crash_summary, f, indent=2)

    with open(unique_report_path, 'w', encoding='utf-8') as f:
        json.dump(unique_outcomes, f, indent=2)

    with open(crash_report_path, 'w', encoding='utf-8') as f:
        json.dump(crashing_bugs, f, indent=2)

    # === WRITE CSV RESULTS ===
    csv_path = os.path.join(base_dir, f"{kernel_name}{rootstr}_results.csv")
    with open(csv_path, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Bug ID", "Description", "Compiled", "Crash Occurred", "Non-Root", "Used Assets"])
        writer.writerows(results)

    # === WRITE JSON RESULTS ===
    json_path = os.path.join(base_dir, f"{kernel_name}{rootstr}_results.json")
    json_data = [
        {
            "bug_id": bug_id,
            "description": desc,
            "compiled": compiled,
            "crashed": crashed,
            "rooted": root,
            "used_assets": used_assets
        }
        for bug_id, desc, compiled, crashed, root, used_assets in results
    ]
    with open(json_path, mode="w", encoding="utf-8") as f:
        json.dump(json_data, f, indent=2)

    # === PRINT SUMMARY ===
    console.print("\n" + "=" * 60)
    console.print("[bold cyan]=== TEST RUN SUMMARY ===[/bold cyan]")
    console.print("=" * 60)
    console.print(f"  [bold]Kernel:[/bold] {kernel_name}")
    console.print(f"  [bold]Mode:[/bold] {'root' if root else 'non-root'}")
    console.print(f"  [bold]Total bugs tested:[/bold] {len(results)}")
    console.print(f"  [bold]Compiled successfully:[/bold] {compiled_count}")
    if root:
        console.print(f"  [bold red]Crashes (root):[/bold red] {crashed_root_count}")
    else:
        console.print(f"  [bold red]Crashes (non-root):[/bold red] {crashed_unroot_count}")
    console.print(f"  [bold]Runtime:[/bold] {run_time:.1f} seconds")
    
    # Print crash type breakdown
    if crash_type_summary:
        console.print(f"\n[bold yellow]Crash Types:[/bold yellow]")
        for crash_type, count in sorted(crash_type_summary.items(), key=lambda x: -x[1]):
            console.print(f"    {crash_type}: {count}")
    
    # Print syscall breakdown
    if syscall_summary:
        console.print(f"\n[bold yellow]Triggering Syscalls:[/bold yellow]")
        for syscall, count in sorted(syscall_summary.items(), key=lambda x: -x[1]):
            console.print(f"    {syscall}: {count}")
    
    # List crashing bugs
    if crashing_bugs:
        console.print(f"\n[bold red]Crashing Bugs ({len(crashing_bugs)}):[/bold red]")
        for bug in crashing_bugs:
            console.print(f"    - {bug['bug_id']}: {bug['description'][:50]}... ({bug.get('crash_type', 'unknown')})")
    
    # Print UAF/OOB detection summary
    if uaf_count > 0 or oob_count > 0:
        console.print(f"\n[bold yellow]=== GDB Memory Analysis Summary ===[/bold yellow]")
        console.print(f"  [red]UAF (Use-After-Free) detected:[/red] {uaf_count}")
        console.print(f"  [red]OOB (Out-of-Bounds) detected:[/red] {oob_count}")
        
        # List bugs with UAF/OOB
        uaf_bugs = [bug for bug in crashing_bugs if bug.get("uaf_detected", False)]
        oob_bugs = [bug for bug in crashing_bugs if bug.get("oob_detected", False)]
        
        if uaf_bugs:
            console.print(f"\n[bold red]Bugs with UAF detected:[/bold red]")
            for bug in uaf_bugs:
                console.print(f"    - {bug['bug_id']}: {bug['description'][:60]}...")
        
        if oob_bugs:
            console.print(f"\n[bold red]Bugs with OOB detected:[/bold red]")
            for bug in oob_bugs:
                console.print(f"    - {bug['bug_id']}: {bug['description'][:60]}...")
    
    console.print(f"\n[green]Results saved to:[/green]")
    console.print(f"  [bold]{csv_path}[/bold]")
    console.print(f"  [bold]{json_path}[/bold]")
    console.print(f"  [bold]{crash_summary_path}[/bold]")
    console.print(f"  [bold]{crash_report_path}[/bold]")
    console.print("=" * 60)
    
    if exceptions:
        console.print(f"\n[yellow]Exceptions encountered ({len(exceptions)}):[/yellow]")
        for exc in exceptions[:10]:  # Limit to first 10
            console.print(f"  - {exc}")
    
    # Stop Cuttlefish if stop_cmd is provided
    if stop_cmd:
        console.print(f"[yellow]Stopping Cuttlefish with command:[/yellow] {stop_cmd}")
        try:
            if ssh_host and ssh_host != 'localhost':
                # Run stop command on remote host
                stop_result = subprocess.run(
                    ['ssh', ssh_host, stop_cmd],
                    capture_output=True,
                    text=True,
                    timeout=120  # 2 min timeout for stop
                )
            else:
                # Run stop command locally
                stop_result = subprocess.run(
                    stop_cmd,
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=120
                )
            if stop_result.returncode != 0:
                console.print(f"[red]Warning: Stop command exited with code {stop_result.returncode}[/red]")
                console.print(f"  stderr: {stop_result.stderr[:500]}")
            else:
                console.print(f"[green]Cuttlefish stopped successfully[/green]")
        except subprocess.TimeoutExpired:
            console.print("[red]Stop command timed out after 2 minutes[/red]")
        except Exception as e:
            console.print(f"[red]Failed to stop Cuttlefish: {e}[/red]")



def extract_last_syscall(syz_file_path: str):
    syscalls = []

    with open(syz_file_path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            match = re.match(r'^([a-zA-Z0-9_]+)(\$[a-zA-Z0-9_]+)?\s*\(', line)
            if match:
                base_syscall = match.group(1)
                syscalls.append(base_syscall)

    last_syscall = syscalls[-1] if syscalls else None
    return syscalls, last_syscall


def extract_crash_type(crash_line: str, idx: int = 0) -> str:
    crash_type = ""
    for j in range(idx + 1, len(crash_line)):
        if crash_line[j] == 'in':
            break
        if crash_type:
            crash_type += ' '
        crash_type += crash_line[j].strip()
    return crash_type.strip()



"""
general protection fault, probably for non-canonical address 0xdffffc0000000001: 0000 [#1] PREEMPT SMP KASAN
KASAN: null-ptr-deref in range [0x0000000000000008-0x000000000000000f]
CPU: 0 PID: 289 Comm: syz-executor840 Not tainted 5.10.234-syzkaller-00157-ge0b88ee5f09c #0
Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS Google 02/12/2025
RIP: 0010:dir_rename fs/incfs/vfs.c:1394 [inline]
RIP: 0010:dir_rename_wrap+0xf7/0x570 fs/incfs/vfs.c:85
===================== OR =====================
BUG: KASAN: slab-out-of-bounds in ext4_read_inline_data fs/ext4/inline.c:209 [inline]
BUG: KASAN: slab-out-of-bounds in ext4_read_inline_dir+0x435/0xd90 fs/ext4/inline.c:1515
Read of size 68 at addr ffff88810f5446d3 by task syz-executor/355

CPU: 0 PID: 355 Comm: syz-executor Not tainted 5.10.239-syzkaller #0
Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS Google 05/07/2025
Call Trace:

"""

def parse_crash_summary(log: str):
    """
    Parse a crash log for summary information (type, function, file, line).
    
    This is a simpler parser than SyzAnalyze.crash_analyzer.parse_crash_log,
    which returns detailed frame and object information.
    
    Use this for quick display/logging. Use crash_analyzer.parse_crash_log
    for full analysis.
    """
    result = {
        "crash_type": "",
        "function": "",
        "file": "",
        "line_number": ""
    }

    # Case 1: BUG: style crash
    bug_re = re.compile(
        r'(?m)^(?!.*\[inline\]).*BUG:\s*(KASAN|UBSAN|KMSAN):\s*([^\n]+?)\s+in\s+([^\s]+)\s+([^:]+):(\d+)',
        re.MULTILINE
    )

    m = bug_re.search(log)
    if m:
        result["crash_type"] = f"{m.group(2)}".strip().split(' in ')[0]
        result["function"]   = m.group(3).strip().split('+')[0]
        result["file"]       = m.group(4).strip()
        result["line_number"] = int(m.group(5))
        return result

    # Case 2: KASAN: … with RIP fallback
    m = re.search(r'KASAN:\s*([^\n]+)', log)
    if m:
        result["crash_type"] = m.group(1).strip().split(' in ')[0]
    else:
        m = re.search(r'^(.*fault.*)', log, re.MULTILINE)
        if m:
            result["crash_type"] = m.group(1).strip()

    # RIP: function+offset file:line
    bug2_re = re.compile(r'RIP:.*?([a-zA-Z0-9_]+)\+.*? ([^ ]+):(\d+)(?!\s*\[inline\])', re.MULTILINE)
    m = bug2_re.search(log)
    if m:
        result["function"] = m.group(1).split('+')[0]
        result["file"] = m.group(2)
        result["line_number"] = int(m.group(3))

    return result


def extract_crash_locations(log_text: str):
    """
    Extract the first N crash entries after a line of ====.
    Looks for lines like:
    'BUG: KASAN: ... in <func> <file>:<line> [inline]'
    """
    log_lines = log_text.split("\n")
    start = 0
    end = -1
    for idx, line in enumerate(log_lines):
        line = line.strip()
        if line.startswith('====') and start == 0:
            start = idx
        if line == '':
            end = idx - 1
        if line.startswith("CPU") and end == -1:
            end = idx - 2
    if end < start or end >= len(log_lines):
        return "", 0, "end index out of range"
    # entries = []
    crashing_file = ""
    crash_type = ""
    crashing_line = 0
    for i in range(start +1, end):
        line = log_lines[i].split(' ')
        if line[-1] == '[inline]':
            continue
        else:
            file_line1 = next((word for word in line if '.c:' in word), None)
            file1, line1_num = (file_line1.split(':') if file_line1 else (None, None))
            crashing_file = file1
            crashing_line = line1_num
            for idx, word in enumerate(line):
                # TODO: make this more robust
                # currently this just looks at memory bugs from KASAN, UBSAN, and KMSAN
                # it then determines the type of the crash from all words starting after the colon afer the bug type
                # all the way until the word 'in'
                if 'KASAN:' in word:
                    crash_type = extract_crash_type(line, idx)
                elif 'UBSAN:' in word:
                    crash_type = extract_crash_type(line, idx)
                elif 'KMSAN:' in word:
                    crash_type = extract_crash_type(line, idx)
            break

    return crashing_file, crashing_line, crash_type

def test(id: str, local: bool, arch: str, root: bool, kernel_name: str, qemu: bool, source_disk: Path, source_image: Path, outdir_name: str, dynamic_analysis: bool = False, gdb_port: int = 1234, kernel_gdb: bool = False, vmlinux_path: str = None, kernel_gdb_port: int = 1234, demo: bool = False):
    """
    Test a single bug.
    
    Args:
        id: Bug ID to test
        local: Whether to run locally
        arch: Target architecture (arm64, x86_64)
        root: Whether to run as root
        kernel_name: Name of the kernel in the database
        qemu: Whether to use QEMU instead of Cuttlefish
        source_disk: Path to disk image
        source_image: Path to kernel image
        outdir_name: Output directory name
        dynamic_analysis: Enable userspace GDB analysis
        gdb_port: Port for userspace gdbserver
        kernel_gdb: Enable kernel-side GDB analysis (requires Cuttlefish with --gdb_port)
        vmlinux_path: Path to vmlinux file for kernel symbols
        kernel_gdb_port: Port for kernel GDB stub (default: 1234)
        demo: Demo mode - generate sample data if real GDB tracing fails
    """
    db = SyzkallBugDatabase(kernel_name)
    metadata = db.get_bug_metadata(id)
    if metadata is None:
        print('Invalid bug id supplied')
        return
    
    print(f'Compiling {metadata.description}...')
    repro_path = metadata.compile_repro(arch)
    if qemu:
        v, t = test_repro_crashes_qemu(repro_path, local, id, outdir_name, root, source_image, source_disk)
    else:
        # Parse crash for GDB instrumentation
        parsed_crash = parse_crash_summary(metadata.crash_report) if metadata.crash_report else None
        
        # Use kernel GDB if enabled (takes precedence)
        if kernel_gdb:
            v, t, gdb_results = test_repro_crashes_cuttlefish_kernel_gdb(
                repro_path=repro_path,
                bug_id=id,
                vmlinux_path=vmlinux_path,
                kernel_gdb_port=kernel_gdb_port,
                parsed_crash=parsed_crash,
                log_dir=outdir_name,
                root=root,
                arch=arch
            )
            # Save kernel GDB results
            if gdb_results:
                gdb_out = os.path.join(outdir_name, f"kernel_gdb_analysis_{id}.json")
                os.makedirs(os.path.dirname(gdb_out) if os.path.dirname(gdb_out) else '.', exist_ok=True)
                with open(gdb_out, 'w', encoding='utf-8') as gf:
                    json.dump(gdb_results, gf, indent=2)
                print(f"[+] Kernel GDB analysis saved to: {gdb_out}")
        # Use userspace GDB analysis if dynamic_analysis is enabled
        elif dynamic_analysis:
            v, t, gdb_results = test_repro_crashes_cuttlefish_gdb(
                repro_path, local, id, outdir_name, root,
                parsed_crash=parsed_crash,
                gdb_port=gdb_port,
                arch=arch
            )
            # Save GDB results
            if gdb_results:
                gdb_out = os.path.join(outdir_name, f"gdb_analysis_{id}.json")
                os.makedirs(os.path.dirname(gdb_out) if os.path.dirname(gdb_out) else '.', exist_ok=True)
                with open(gdb_out, 'w', encoding='utf-8') as gf:
                    json.dump(gdb_results, gf, indent=2)
                print(f"[+] GDB analysis saved to: {gdb_out}")
        else:
            v, t = test_repro_crashes(repro_path, local, id, outdir_name, root)
    if v:
        print('Crash occured')
    else:
        print('No crash occured')
    # Optional dynamic GDB analysis to verify preconditions around memory regions
    if dynamic_analysis and source_image:
        try:
            vm_type = 'qemu' if qemu else 'cuttlefish'
            da_config = DynamicAnalysisConfig(
                vm_type=vm_type,
                kernel_image=str(source_image),
                kernel_disk=str(source_disk),
                bzimage_path=str(source_image),
                gdb_port=gdb_port,
                timeout=360
            )
            repro_binary = repro_path
            parsed_crash = parse_crash_summary(metadata.crash_report)
            print("[STEP D] Running dynamic GDB analysis to verify preconditions...")
            da_result = verify_run_da(str(repro_binary), parsed_crash, da_config)
            outname = os.path.join(outdir_name, f"dynamic_analysis_{id}.json")
            os.makedirs(os.path.dirname(outname), exist_ok=True)
            with open(outname, 'w', encoding='utf-8') as of:
                json.dump(da_result, of, indent=2)
            print(f"[+] Dynamic analysis written to: {outname}")
        except Exception as e:
            print(f"[!] Dynamic analysis failed: {e}")


