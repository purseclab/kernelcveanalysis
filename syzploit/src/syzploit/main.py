from pathlib import Path
from typing import Optional
from typing_extensions import Annotated

from dotenv import load_dotenv
import typer
from . import SyzVerify
from . import SyzAnalyze
from . import Synthesizer
from .SyzVerify.bug_db import SyzkallBugDatabase
from .SyzVerify.run_bug import test_repro_crashes, test_repro_crashes_qemu, test_repro_with_cuttlefish_controller
from .SyzVerify.cuttlefish import CuttlefishConfig, create_config_from_args
import json
import os

app = typer.Typer(help="Syzkall/Syzbot tooling for pulling, testing, and analyzing bugs.")


# TODO: decide if this will even be apart of kexploit
@app.command()
def pull(
    syzkall_kernel: Annotated[str, typer.Option(help='Kernel name to pull bugs for')] = 'android-5-10',
):
    """Pull bugs from syzbot for a given kernel version"""
    SyzVerify.pull(syzkall_kernel)


@app.command()
def pull_bug(
    bug_id: Annotated[str, typer.Argument(help='Bug ID to pull from syzbot')],
    syzkall_kernel: Annotated[str, typer.Option(help='Kernel name for database')] = 'android-5-10',
    force: Annotated[bool, typer.Option(help='Re-download even if already in database')] = False,
):
    """
    Pull a single bug directly from syzbot by its ID.
    
    This is faster than pulling all bugs when you only need one specific bug.
    The bug ID is the hex string from the syzbot URL (e.g., 283ce5a46486d6acdbaf).
    
    Examples:
        syzploit pull-bug 283ce5a46486d6acdbaf
        syzploit pull-bug 283ce5a46486d6acdbaf --force
    """
    from .SyzVerify.scrape import pull_single_bug
    
    db = SyzkallBugDatabase(syzkall_kernel)
    metadata = pull_single_bug(db, bug_id, force=force)
    
    if metadata:
        typer.echo(f"[✓] Bug pulled successfully:")
        typer.echo(f"    ID: {metadata.bug_id}")
        typer.echo(f"    Title: {metadata.title}")
        typer.echo(f"    Kernel: {metadata.kernel_name}")
        typer.echo(f"    C Repro: {'Yes' if metadata.c_repro_url else 'No'}")
        typer.echo(f"    Syz Repro: {'Yes' if metadata.syz_repro_url else 'No'}")
    else:
        typer.echo(f"[!] Failed to pull bug {bug_id}")
        raise typer.Exit(code=1)


# Probably temprorary command
@app.command()
def query(
    syzkall_kernel: Annotated[str, typer.Option(help='Kernel name to pull bugs for')] = 'android-5-10',
):
    """Query downloaded syzbot database for bugs"""
    SyzVerify.query(syzkall_kernel)

# Probably temprorary command
@app.command()
def test(
    bug_id: Annotated[str, typer.Argument(help='Bug ID to test')],
    local: Annotated[bool, typer.Option(help='Use local cuttlefish instance')] = True,
    root: Annotated[bool, typer.Option(help='Run repro as root user in VM')] = True,
    arch: Annotated[str, typer.Option(help='Architecture of kernel to test bugs on')] = 'x86_64',
    syzkall_kernel: Annotated[str, typer.Option(help='Kernel name to pull bugs for')] = 'android-5-10',
    qemu: Annotated[bool, typer.Option(help='Use QEMU VM instead of cuttlefish')]=False,
    source_image: Annotated[Path, typer.Option(help='Path to source image')] = None,
    source_disk: Annotated[Path, typer.Option(help='Path to source disk')] = None,
    outdir_name: Annotated[Optional[str], typer.Option(help='Output directory name for crash artifacts')] = "syzkall_crashes",
    dynamic_analysis: Annotated[bool, typer.Option(help='Enable GDB-based dynamic analysis')] = False,
    gdb_port: Annotated[int, typer.Option(help='GDB port for dynamic analysis')] = 1234,
):
    """Test a specific bug from syzbot"""
    SyzVerify.test(bug_id, local, arch, root, syzkall_kernel, qemu, source_disk, source_image, outdir_name, dynamic_analysis, gdb_port)

# Probably temprorary command
@app.command()
def testall(
    local: Annotated[bool, typer.Option(help='Use local cuttlefish instance')] = False,
    arch: Annotated[str, typer.Option(help='Architecture of kernel to test bugs on')] = 'x86_64',
    syzkall_kernel: Annotated[str, typer.Option(help='Kernel name to pull bugs for')] = 'android-5-10',
    qemu: Annotated[bool, typer.Option(help='Use QEMU VM instead of cuttlefish')]=False,
    source_image: Annotated[Path, typer.Option(help='Path to source image')] = None,
    source_disk: Annotated[Path, typer.Option(help='Path to source disk')] = None,
    source: Annotated[bool, typer.Option(help='Test bugs from syzbot source image')] = False,
    root: Annotated[bool, typer.Option(help='Run repro as root user in VM')] = False,
    outdir_name: Annotated[Optional[str], typer.Option(help='Output directory name for crash artifacts')] = "syzkall_crashes",
    dynamic_analysis: Annotated[bool, typer.Option(help='Enable GDB-based dynamic analysis')] = False,
    gdb_port: Annotated[int, typer.Option(help='GDB port for dynamic analysis')] = 1234,
):
    """Test all bugs from syzbot for a given kernel version"""
    SyzVerify.test_all(local, arch, syzkall_kernel, qemu, root, source_image, source_disk, source, outdir_name, dynamic_analysis, gdb_port)

# Probably temprorary command
@app.command()
def collectstats(
    syzkall_kernel: Annotated[str, typer.Option(help='Kernel name to pull bugs for')] = 'android-5-10',
    outfile: Annotated[str, typer.Option(help='Output file to write stats to')] = 'syzkall_stats',
):
    """ Collect stats on bugs from syzbot """
    SyzVerify.collect_stats(syzkall_kernel, outfile)


@app.command()
def test_cuttlefish(
    bug_id: Annotated[str, typer.Argument(help='Bug ID to test')],
    syzkall_kernel: Annotated[str, typer.Option(help='Kernel name for bug')] = 'android-5-10',
    arch: Annotated[str, typer.Option(help='Architecture (arm64/x86_64)')] = 'arm64',
    root: Annotated[bool, typer.Option(help='Run reproducer as root')] = True,
    # Cuttlefish instance settings
    ssh_host: Annotated[str, typer.Option(help='SSH host for Cuttlefish (can be a ~/.ssh/config alias)')] = 'localhost',
    ssh_port: Annotated[int, typer.Option(help='SSH port for Cuttlefish')] = 22,
    ssh_user: Annotated[Optional[str], typer.Option(help='SSH user (optional, uses ssh config if not set)')] = None,
    ssh_key: Annotated[Optional[str], typer.Option(help='SSH key path (optional, uses ssh config if not set)')] = None,
    ssh_password: Annotated[Optional[str], typer.Option(help='SSH password (if no key)')] = None,
    # Persistence mode
    persistent: Annotated[bool, typer.Option(help='Persistent mode (keep Cuttlefish running)')] = True,
    already_running: Annotated[bool, typer.Option(help='Cuttlefish is already running')] = True,
    start_cmd: Annotated[Optional[str], typer.Option(help='Command to start Cuttlefish (non-persistent)')] = None,
    stop_cmd: Annotated[Optional[str], typer.Option(help='Command to stop Cuttlefish (non-persistent)')] = None,
    # Connection settings
    instance: Annotated[Optional[int], typer.Option(help='Cuttlefish instance number (auto-calculates ADB port: 6520 + instance - 1)')] = None,
    gdb_port: Annotated[int, typer.Option(help='Crosvm kernel GDB port')] = 1234,
    adb_port: Annotated[int, typer.Option(help='ADB port for Cuttlefish device (overridden by --instance)')] = 6520,
    dynamic_analysis: Annotated[bool, typer.Option(help='Enable GDB-based dynamic analysis (alias for --enable-gdb)')] = True,
    setup_tunnels: Annotated[bool, typer.Option(help='Set up SSH tunnels for remote ADB/GDB access')] = False,
    # Cuttlefish runtime logs
    runtime_logs_dir: Annotated[Optional[str], typer.Option(help='Path to cuttlefish runtime logs dir (e.g., ~/cuttlefish/cuttlefish_runtime.5/logs). If not set, inferred from start command')] = None,
    # Kernel symbol extraction options
    kernel_image: Annotated[Optional[str], typer.Option(help='Path to kernel Image file (local or remote). Used to extract vmlinux with symbols via vmlinux-to-elf')] = None,
    vmlinux_path: Annotated[Optional[str], typer.Option(help='Path to vmlinux with debug symbols (local). If not set and --kernel-image is provided, vmlinux will be auto-extracted')] = None,
    system_map: Annotated[Optional[str], typer.Option(help='Path to System.map for symbol resolution. Use this if you have a pre-generated System.map (e.g., from /proc/kallsyms)')] = None,
    remote_vmlinux_path: Annotated[Optional[str], typer.Option(help='DEPRECATED: Path to vmlinux on remote server (GDB now runs locally via tunnel)')] = None,
    extract_symbols: Annotated[bool, typer.Option(help='Auto-extract vmlinux from kernel Image using vmlinux-to-elf')] = True,
    # Other options
    timeout: Annotated[int, typer.Option(help='Test timeout in seconds')] = 120,
    output_dir: Annotated[Optional[Path], typer.Option(help='Output directory for logs')] = None,
):
    """
    Test a bug reproducer on Cuttlefish with support for persistent and non-persistent modes.
    
    PERSISTENT MODE (default):
    - Use when Cuttlefish is already running or should stay up between tests
    - Set --persistent --already-running for an already-booted instance
    - Set --persistent --no-already-running with --start-cmd to boot once and keep running
    
    NON-PERSISTENT MODE:
    - Use when Cuttlefish should start/stop for each test
    - Set --no-persistent with --start-cmd and --stop-cmd
    
    SYMBOL EXTRACTION:
    - Provide --kernel-image to auto-extract vmlinux with symbols using vmlinux-to-elf
    - This enables proper symbol resolution for GDB breakpoints and backtraces
    - The kernel Image can be local or remote (downloaded via SSH if remote)
    - Alternatively, provide --vmlinux-path directly if you already have vmlinux
    
    Examples:
        # Test on already-running local Cuttlefish with auto symbol extraction
        syzploit test-cuttlefish abc123 --persistent --already-running --gdb-port 1234 \\
            --kernel-image ./package/kernel/Image
        
        # Test on remote Cuttlefish via SSH with symbol extraction
        syzploit test-cuttlefish abc123 --ssh-host cuttlefish2 --setup-tunnels \\
            --instance 5 --kernel-image /home/user/cuttlefish/package/kernel/Image \\
            --start-cmd "cd ~/cuttlefish && ./gdb_run.sh 5" \\
            --stop-cmd "cd ~/cuttlefish && ./stop.sh 5"
        
        # Test with pre-extracted vmlinux
        syzploit test-cuttlefish abc123 --persistent --already-running \\
            --vmlinux-path ./symbols/vmlinux
    """
    from .SyzVerify.scrape import pull_single_bug
    
    # Initialize DB and get bug metadata
    db = SyzkallBugDatabase(syzkall_kernel)
    md = db.get_bug_metadata(bug_id)
    if md is None:
        typer.echo(f"[+] Bug {bug_id} not in local database, pulling from syzbot...")
        md = pull_single_bug(db, bug_id)
        if md is None:
            typer.echo(f"[!] Failed to pull bug {bug_id} from syzbot")
            raise typer.Exit(code=1)
        typer.echo(f"[+] Successfully pulled: {md.title}")
    
    # Compile reproducer
    typer.echo(f"[+] Compiling reproducer for {arch}...")
    repro_bin = md.compile_repro(arch)
    typer.echo(f"[+] Reproducer binary: {repro_bin}")
    
    # Calculate ADB port from instance number if provided
    # Cuttlefish instance ports: base 6520 + (instance - 1)
    # Instance 1 -> 6520, Instance 5 -> 6524
    actual_adb_port = adb_port
    if instance is not None:
        actual_adb_port = 6520 + (instance - 1)
        typer.echo(f"[+] Instance {instance}: using ADB port {actual_adb_port}")
    
    # Create Cuttlefish configuration
    config = CuttlefishConfig(
        ssh_host=ssh_host,
        ssh_port=ssh_port,
        ssh_user=ssh_user,
        ssh_password=ssh_password,
        ssh_key_path=ssh_key,
        persistent=persistent,
        already_running=already_running,
        start_command=start_cmd,
        stop_command=stop_cmd,
        gdb_port=gdb_port,
        adb_port=actual_adb_port,
        enable_gdb=dynamic_analysis,
        setup_tunnels=setup_tunnels,
        # Cuttlefish runtime logs directory
        cuttlefish_runtime_logs=runtime_logs_dir,
        # Kernel symbol extraction
        kernel_image_path=kernel_image,
        vmlinux_path=vmlinux_path,
        system_map_path=system_map,
        extract_symbols=extract_symbols,
    )
    
    # Determine output directory
    log_dir = str(output_dir) if output_dir else f"cuttlefish_test_{bug_id}"
    
    # Get parsed crash info if available (optional attribute)
    parsed_crash = None
    if hasattr(md, 'crash_parser_results') and md.crash_parser_results:
        parsed_crash = md.crash_parser_results
    
    # Run test
    typer.echo(f"[+] Running test with Cuttlefish controller...")
    typer.echo(f"[+] Mode: {'persistent' if persistent else 'non-persistent'}")
    typer.echo(f"[+] Dynamic analysis (GDB): {'enabled' if dynamic_analysis else 'disabled'}")
    typer.echo(f"[+] SSH tunnels: {'enabled' if setup_tunnels else 'disabled'}")
    if kernel_image:
        typer.echo(f"[+] Kernel Image: {kernel_image}")
    if vmlinux_path:
        typer.echo(f"[+] vmlinux: {vmlinux_path}")
    if system_map:
        typer.echo(f"[+] System.map: {system_map}")
    
    crashed, crash_type, results = test_repro_with_cuttlefish_controller(
        repro_path=str(repro_bin),
        bug_id=bug_id,
        cuttlefish_config=config,
        parsed_crash=parsed_crash,
        log_dir=log_dir,
        root=root,
        timeout=timeout,
        arch=arch,
        vmlinux_path=vmlinux_path,
        remote_vmlinux_path=remote_vmlinux_path,
    )
    
    # Report results
    if crashed:
        typer.echo(f"[✓] CRASH DETECTED (type: {crash_type})")
    else:
        typer.echo(f"[!] No crash detected")
    
    typer.echo(f"[+] Results saved to: {log_dir}")

@app.command()
def analyze(
    bug_id: Annotated[str, typer.Argument(help='Bug ID to analyze')],
    syzkall_kernel: Annotated[str, typer.Option(help='Kernel name for bug')] = 'android-5-10',
    qemu: Annotated[bool, typer.Option(help='Use QEMU VM')] = False,
    source_image: Annotated[Path, typer.Option(help='Path to kernel image')] = None,
    source_disk: Annotated[Path, typer.Option(help='Path to disk image')] = None,
    dynamic_analysis: Annotated[bool, typer.Option(help='Enable GDB-based dynamic analysis')] = True,
    gdb_port: Annotated[int, typer.Option(help='GDB port')] = 1234,
    arch: Annotated[str, typer.Option(help='Architecture of kernel to analyze')] = 'x86_64',
    output_dir: Annotated[Optional[Path], typer.Option(help='Output directory for analysis results')] = None,
    skip_static: Annotated[bool, typer.Option(help='Skip static analysis and reuse prior results')] = False,
    ignore_exploitability: Annotated[bool, typer.Option(help='Run dynamic even if static exploitability is low/unknown')] = False,
    dynamic_only: Annotated[bool, typer.Option(help='Convenience flag: skip static and ignore exploitability gating')] = False,
):
    """Analyze a specific bug with static and optional dynamic analysis"""
    if dynamic_only:
        skip_static = True
        ignore_exploitability = True
    SyzAnalyze.analyze_bug(
        bug_id,
        syzkall_kernel,
        qemu,
        source_image,
        source_disk,
        dynamic_analysis,
        gdb_port,
        arch,
        output_dir,
        skip_static=skip_static,
        ignore_exploitability=ignore_exploitability,
        reuse_dir=output_dir,
    )


@app.command()
def pipeline_cuttlefish(
    bug_id: Annotated[str, typer.Argument(help='Bug ID for end-to-end pipeline')],
    syzkall_kernel: Annotated[str, typer.Option(help='Kernel name for bug')] = 'android-5-10',
    arch: Annotated[str, typer.Option(help='Architecture (arm64/x86_64)')] = 'arm64',
    root: Annotated[bool, typer.Option(help='Run reproducer as root')] = True,
    # Cuttlefish instance settings
    ssh_host: Annotated[str, typer.Option(help='SSH host for Cuttlefish (can be a ~/.ssh/config alias)')] = 'localhost',
    ssh_port: Annotated[int, typer.Option(help='SSH port for Cuttlefish')] = 22,
    ssh_user: Annotated[Optional[str], typer.Option(help='SSH user (optional, uses ssh config if not set)')] = None,
    ssh_key: Annotated[Optional[str], typer.Option(help='SSH key path (optional, uses ssh config if not set)')] = None,
    ssh_password: Annotated[Optional[str], typer.Option(help='SSH password (if no key)')] = None,
    # Persistence mode
    persistent: Annotated[bool, typer.Option(help='Persistent mode (keep Cuttlefish running)')] = True,
    already_running: Annotated[bool, typer.Option(help='Cuttlefish is already running')] = True,
    start_cmd: Annotated[Optional[str], typer.Option(help='Command to start Cuttlefish (non-persistent)')] = None,
    stop_cmd: Annotated[Optional[str], typer.Option(help='Command to stop Cuttlefish (non-persistent)')] = None,
    # Connection settings
    instance: Annotated[Optional[int], typer.Option(help='Cuttlefish instance number (auto-calculates ADB port: 6520 + instance - 1)')] = None,
    gdb_port: Annotated[int, typer.Option(help='Crosvm kernel GDB port')] = 1234,
    adb_port: Annotated[int, typer.Option(help='ADB port for Cuttlefish device (overridden by --instance)')] = 6520,
    dynamic_analysis: Annotated[bool, typer.Option(help='Enable GDB-based dynamic analysis')] = True,
    setup_tunnels: Annotated[bool, typer.Option(help='Set up SSH tunnels for remote ADB/GDB access')] = False,
    # Cuttlefish runtime logs
    runtime_logs_dir: Annotated[Optional[str], typer.Option(help='Path to cuttlefish runtime logs dir')] = None,
    # Kernel symbol extraction options
    kernel_image: Annotated[Optional[str], typer.Option(help='Path to kernel Image file (local or remote)')] = None,
    vmlinux_path: Annotated[Optional[str], typer.Option(help='Path to vmlinux with debug symbols')] = None,
    system_map: Annotated[Optional[str], typer.Option(help='Path to System.map for symbol resolution')] = None,
    extract_symbols: Annotated[bool, typer.Option(help='Auto-extract vmlinux from kernel Image')] = True,
    # Pipeline options
    skip_static: Annotated[bool, typer.Option(help='Skip static analysis')] = False,
    ignore_exploitability: Annotated[bool, typer.Option(help='Run dynamic even if exploitability is low')] = False,
    goal: Annotated[str, typer.Option(help='Exploit goal for synthesis')] = 'privilege_escalation',
    platform: Annotated[Optional[str], typer.Option(help='Target platform: linux, android, or generic')] = None,
    timeout: Annotated[int, typer.Option(help='Test timeout in seconds')] = 120,
    output_dir: Annotated[Optional[Path], typer.Option(help='Output directory for logs')] = None,
):
    """
    Full pipeline with Cuttlefish: analyze crash, run dynamic analysis, and synthesize exploit.
    
    Combines the functionality of test_cuttlefish + analyze + synthesize into a single command
    that properly passes crash stack trace information from static analysis to dynamic analysis.
    
    Steps:
    1) Static analysis (LLM-based crash analysis)
    2) Parse crash log to extract stack trace functions
    3) Run reproducer with GDB breakpoints on stack trace functions
    4) Collect alloc/free events and function hits
    5) Post-process for UAF/OOB detection
    6) Synthesize exploit plan (optional)
    
    Example:
        syzploit pipeline-cuttlefish abc123 --ssh-host cuttlefish2 --setup-tunnels \\
            --instance 5 --kernel-image /home/user/cuttlefish/package/kernel/Image
    """
    from .SyzAnalyze import crash_analyzer as analyzer
    from .SyzVerify.scrape import pull_single_bug
    
    # Initialize DB and get bug metadata
    db = SyzkallBugDatabase(syzkall_kernel)
    md = db.get_bug_metadata(bug_id)
    if md is None:
        typer.echo(f"[+] Bug {bug_id} not in local database, pulling from syzbot...")
        md = pull_single_bug(db, bug_id)
        if md is None:
            typer.echo(f"[!] Failed to pull bug {bug_id} from syzbot")
            raise typer.Exit(code=1)
        typer.echo(f"[+] Successfully pulled: {md.title}")
    
    # Setup output directory
    if output_dir is None:
        output_dir = Path(f"analysis_{bug_id}")
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    typer.echo(f"[+] Pipeline for Bug {bug_id}")
    typer.echo(f"[+] Output directory: {output_dir}")
    
    summary = {"bug_id": bug_id, "steps": {}}
    
    # Step 1: Static Analysis to get crash info
    typer.echo("\n[STEP 1] Static Analysis...")
    parsed_crash = None
    static_result = None
    
    if not skip_static:
        try:
            # Parse crash log to get frames
            parsed_crash = analyzer.parse_crash_log(md.crash_report)
            
            # Get crash stack functions
            crash_stack_funcs = []
            if parsed_crash:
                seen = set()
                for frame in parsed_crash.get('frames', [])[:10]:
                    func = frame.get('func', '')
                    if func:
                        base_func = func.split('+')[0].split('.')[0].strip()
                        if base_func and base_func not in seen:
                            seen.add(base_func)
                            crash_stack_funcs.append(base_func)
            
            typer.echo(f"[+] Parsed {len(parsed_crash.get('frames', []))} stack frames")
            typer.echo(f"[+] Crash stack functions: {crash_stack_funcs[:5]}...")
            
            # Prepare reproducer
            c_repro_src = None
            if getattr(md, 'c_repro_url', None):
                p = md.save_c_repro()
                if p and Path(p).exists():
                    c_repro_src = str(p)
            if not c_repro_src and getattr(md, 'syz_repro_url', None):
                p = md.generate_c_repro(arch)
                if p and Path(p).exists():
                    c_repro_src = str(p)
            
            # Run static analysis
            if c_repro_src:
                static_result = analyzer.analyze(md.crash_report, c_repro_src, None, None)
                static_output = output_dir / "static_analysis.json"
                import json
                with open(static_output, 'w') as f:
                    json.dump(static_result, f, indent=2)
                typer.echo(f"[+] Static analysis saved: {static_output}")
                summary["steps"]["static"] = {"success": True, "frames": len(crash_stack_funcs)}
            else:
                typer.echo("[!] No reproducer source available for static analysis")
                summary["steps"]["static"] = {"success": False, "error": "no reproducer"}
        except Exception as e:
            typer.echo(f"[!] Static analysis failed: {e}")
            summary["steps"]["static"] = {"success": False, "error": str(e)}
    else:
        typer.echo("[+] Skipping static analysis (--skip-static)")
        # Try to load prior results
        static_path = output_dir / "static_analysis.json"
        if static_path.exists():
            import json
            with open(static_path) as f:
                static_result = json.load(f)
            parsed_crash = static_result  # May contain frames
            typer.echo(f"[+] Loaded prior static results: {static_path}")
    
    # Ensure we have parsed_crash for dynamic analysis
    if parsed_crash is None:
        try:
            parsed_crash = analyzer.parse_crash_log(md.crash_report)
        except Exception:
            parsed_crash = {}
    
    # Step 2: Compile reproducer
    typer.echo("\n[STEP 2] Compiling reproducer...")
    try:
        repro_bin = md.compile_repro(arch)
        typer.echo(f"[+] Reproducer binary: {repro_bin}")
        summary["steps"]["compile"] = {"success": True, "binary": str(repro_bin)}
    except Exception as e:
        typer.echo(f"[!] Failed to compile reproducer: {e}")
        summary["steps"]["compile"] = {"success": False, "error": str(e)}
        raise typer.Exit(code=1)
    
    # Step 3: Dynamic analysis with Cuttlefish
    typer.echo("\n[STEP 3] Dynamic Analysis with Cuttlefish...")
    
    # Calculate ADB port from instance number if provided
    actual_adb_port = adb_port
    if instance is not None:
        actual_adb_port = 6520 + (instance - 1)
        typer.echo(f"[+] Instance {instance}: using ADB port {actual_adb_port}")
    
    # Create Cuttlefish configuration
    config = CuttlefishConfig(
        ssh_host=ssh_host,
        ssh_port=ssh_port,
        ssh_user=ssh_user,
        ssh_password=ssh_password,
        ssh_key_path=ssh_key,
        persistent=persistent,
        already_running=already_running,
        start_command=start_cmd,
        stop_command=stop_cmd,
        gdb_port=gdb_port,
        adb_port=actual_adb_port,
        enable_gdb=dynamic_analysis,
        setup_tunnels=setup_tunnels,
        cuttlefish_runtime_logs=runtime_logs_dir,
        kernel_image_path=kernel_image,
        vmlinux_path=vmlinux_path,
        system_map_path=system_map,
        extract_symbols=extract_symbols,
    )
    
    log_dir = str(output_dir)
    
    typer.echo(f"[+] Mode: {'persistent' if persistent else 'non-persistent'}")
    typer.echo(f"[+] Dynamic analysis (GDB): {'enabled' if dynamic_analysis else 'disabled'}")
    typer.echo(f"[+] SSH tunnels: {'enabled' if setup_tunnels else 'disabled'}")
    if kernel_image:
        typer.echo(f"[+] Kernel Image: {kernel_image}")
    if system_map:
        typer.echo(f"[+] System.map: {system_map}")
    
    try:
        crashed, crash_type, results = test_repro_with_cuttlefish_controller(
            repro_path=str(repro_bin),
            bug_id=bug_id,
            cuttlefish_config=config,
            parsed_crash=parsed_crash,
            log_dir=log_dir,
            root=root,
            timeout=timeout,
            arch=arch,
            vmlinux_path=vmlinux_path,
        )
        
        if crashed:
            typer.echo(f"[✓] CRASH DETECTED (type: {crash_type})")
        else:
            typer.echo(f"[!] No crash detected")
        
        summary["steps"]["dynamic"] = {
            "success": True,
            "crashed": crashed,
            "crash_type": crash_type,
        }
    except Exception as e:
        typer.echo(f"[!] Dynamic analysis failed: {e}")
        summary["steps"]["dynamic"] = {"success": False, "error": str(e)}
    
    # Step 4: Post-process results
    typer.echo("\n[STEP 4] Post-processing results...")
    try:
        from .SyzVerify import post_process as pp
        dynamic_json = output_dir / "dynamic_analysis.json"
        if dynamic_json.exists():
            pp_out = output_dir / "dynamic_analysis_post.json"
            pp_res = pp.analyze(str(dynamic_json), str(pp_out))
            typer.echo(f"[+] Post-processing: confidence={pp_res.get('confidence', 0)}")
            typer.echo(f"[+] UAF={pp_res.get('summary', {}).get('uaf', 0)} OOB={pp_res.get('summary', {}).get('invalid-access', 0)}")
            summary["steps"]["post_process"] = {"success": True, "confidence": pp_res.get('confidence', 0)}
        else:
            typer.echo("[!] No dynamic_analysis.json found to post-process")
            summary["steps"]["post_process"] = {"success": False, "error": "no dynamic results"}
    except Exception as e:
        typer.echo(f"[!] Post-processing failed: {e}")
        summary["steps"]["post_process"] = {"success": False, "error": str(e)}
    
    # Step 5: Synthesize (optional)
    if goal:
        typer.echo("\n[STEP 5] Synthesizing exploit plan...")
        try:
            res = Synthesizer.synthesize(
                bug_id=str(bug_id),
                goal=str(goal),
                analysis_dir=str(output_dir),
                vmlinux_path=str(vmlinux_path) if vmlinux_path else None,
                platform=platform or "android",
                verbose=False,
                debug=False,
            )
            typer.echo(f"[+] Synthesis completed")
            summary["steps"]["synthesize"] = {"success": True}
        except Exception as e:
            typer.echo(f"[!] Synthesis failed: {e}")
            summary["steps"]["synthesize"] = {"success": False, "error": str(e)}
    
    # Save pipeline summary
    import json
    summary_path = output_dir / "pipeline_summary.json"
    with open(summary_path, 'w') as f:
        json.dump(summary, f, indent=2)
    typer.echo(f"\n[+] Pipeline summary saved: {summary_path}")
    typer.echo(f"[+] Results in: {output_dir}")


@app.command()
def synthesize(
    bug_id: Annotated[str, typer.Argument(help='Bug ID to synthesize exploit for')],
    goal: Annotated[str, typer.Option(help='Desired exploit goal (e.g., privilege_escalation, root_shell, container_escape)')] = 'privilege_escalation',
    platform: Annotated[Optional[str], typer.Option(help='Target platform: linux, android, or generic (auto-detect if not set)')] = None,
    kernel_research_path: Annotated[Optional[Path], typer.Option(help='Path to google/kernel-research repo')] = None,
    analysis_dir: Annotated[Optional[Path], typer.Option(help='Path to analysis_<bug_id> directory')] = None,
    vmlinux_path: Annotated[Optional[Path], typer.Option(help='Path to vmlinux for gadget analysis')] = None,
    verbose: Annotated[bool, typer.Option(help='Print planner output')] = False,
    debug: Annotated[bool, typer.Option(help='Enable debug output')] = False,
    time_limit: Annotated[int, typer.Option(help='Planner time limit in seconds')] = 300,
):
    """Synthesize an exploit plan using SyzAnalyze + kernelXDK primitives.
    
    Supports Linux kernel and Android kernel exploitation. Platform is auto-detected
    from analysis data if not specified.
    """
    res = Synthesizer.synthesize(
        bug_id=str(bug_id),
        goal=str(goal),
        kernel_research_path=str(kernel_research_path) if kernel_research_path else None,
        analysis_dir=str(analysis_dir) if analysis_dir else None,
        vmlinux_path=str(vmlinux_path) if vmlinux_path else None,
        platform=platform,
        verbose=verbose,
        debug=debug,
        time_limit=time_limit,
    )
    # Save a summary in the analysis directory
    try:
        ad = res.get('plan', {}).get('target_info', {}).get('analysis_dir')
        if ad:
            out = Path(ad) / 'synth_summary.json'
            with out.open('w') as f:
                import json
                json.dump(res, f, indent=2)
            typer.echo(f"[+] Synthesizer summary -> {out}")
        else:
            typer.echo("[+] Synthesizer completed; no analysis_dir available to write summary.")
    except Exception:
        typer.echo("[+] Synthesizer completed.")

@app.command(name="chainreactor_run")
def chainreactor_run(
    analysis_dir: Annotated[Path, typer.Argument(help='Path to analysis_<bug_id> directory with pddl')],
    chainreactor_path: Annotated[Path, typer.Option(help='Path to ucsb-seclab/chainreactor repo')],
    verbose: Annotated[bool, typer.Option(help='Print solver stdout/stderr')] = True,
):
    """Run ChainReactor on previously generated PDDL without rerunning dynamic analysis.

    Expects domain.pddl and problem.pddl under <analysis_dir>/pddl.
    """
    try:
        from .Synthesizer.chainreactor_integration import ChainReactor
        pddl_dir = analysis_dir / 'pddl'
        domain = pddl_dir / 'domain.pddl'
        problem = pddl_dir / 'problem.pddl'
        if not domain.exists() or not problem.exists():
            typer.echo(f"[!] Missing PDDL: {domain} or {problem}")
            raise typer.Exit(code=2)
        cr = ChainReactor(str(chainreactor_path))
        typer.echo(f"[INFO] Using domain: {domain}")
        typer.echo(f"[INFO] Using problem: {problem}")
        res = cr.solve_with_pddl(str(domain), str(problem), str(pddl_dir))
        # write summary next to PDDL
        summary = pddl_dir / 'solve_summary.json'
        with summary.open('w') as f:
            import json
            json.dump(res, f, indent=2)
        if verbose:
            stdout = (res.get('stdout') or '').strip()
            stderr = (res.get('stderr') or '').strip()
            if stdout:
                typer.echo("[SOLVER STDOUT]\n" + stdout)
            if stderr:
                typer.echo("[SOLVER STDERR]\n" + stderr)
        ok = bool(res.get('success'))
        plans = res.get('plans') or []
        hint = res.get('hint')
        if hint:
            typer.echo(f"[HINT] {hint}")
        if ok:
            typer.echo(f"[✓] ChainReactor succeeded. Plans: {len(plans)}. Outputs in {pddl_dir}")
        else:
            typer.echo(f"[!] ChainReactor failed. See {summary} for details.")
    except Exception as e:
        typer.echo(f"[!] chainreactor_run failed: {e}")


@app.command()
def pipeline(
    bug_id: Annotated[str, typer.Argument(help='Bug ID for end-to-end pipeline')],
    syzkall_kernel: Annotated[str, typer.Option(help='Kernel name for bug')] = 'android-5-10',
    qemu: Annotated[bool, typer.Option(help='Use QEMU VM')] = False,
    local: Annotated[bool, typer.Option(help='Use local cuttlefish instance')] = True,
    root: Annotated[bool, typer.Option(help='Run repro/exploit as root in VM')]=True,
    arch: Annotated[str, typer.Option(help='Architecture of kernel to analyze/run')]='x86_64',
    source_image: Annotated[Optional[Path], typer.Option(help='Path to kernel image (QEMU)')] = None,
    source_disk: Annotated[Optional[Path], typer.Option(help='Path to disk image (QEMU)')] = None,
    dynamic_analysis: Annotated[bool, typer.Option(help='Enable GDB-based dynamic analysis during analysis')] = True,
    gdb_port: Annotated[int, typer.Option(help='GDB port for dynamic analysis')] = 1234,
    goal: Annotated[str, typer.Option(help='Exploit goal for synthesis')] = 'privilege_escalation',
    platform: Annotated[Optional[str], typer.Option(help='Target platform: linux, android, or generic')] = None,
    debug: Annotated[bool, typer.Option(help='Enable debug output')] = False,
    verbose: Annotated[bool, typer.Option(help='Print planner output')] = False,
):
    """Run the full pipeline: verify crash with SyzVerify, analyze with SyzAnalyze,
    test generated primitive, run Synthesizer, and finally verify the generated exploit.

    Steps:
    1) Compile + run reproducer to confirm crash
    2) Perform static (+optional dynamic) analysis
    3) Compile + run generated primitive C (if available)
    4) Synthesize exploit plan (optionally via ChainReactor)
    5) Run final exploit artifact if available
    """
    # Initialize DB and pull metadata
    db = SyzkallBugDatabase(syzkall_kernel)
    md = db.get_bug_metadata(bug_id)
    if md is None:
        typer.echo(f"[!] Invalid bug id: {bug_id}")
        raise typer.Exit(code=1)

    summary = {
        "bug_id": bug_id,
        "kernel": syzkall_kernel,
        "steps": {},
    }

    # Step 1: Compile and run original reproducer
    typer.echo("[STEP 1] Compiling reproducible binary from syzkaller repro...")
    repro_bin = md.compile_repro(arch)
    typer.echo(f"[INFO] Reproducer binary: {repro_bin}")
    try:
        if qemu:
            if not source_image or not source_disk:
                typer.echo("[!] QEMU selected but source_image/source_disk not provided")
                raise typer.Exit(code=2)
            v, t = test_repro_crashes_qemu(repro_bin, local, bug_id, 'syzkall_crashes', root, source_image, source_disk)
        else:
            v, t = test_repro_crashes(repro_bin, local, bug_id, 'syzkall_crashes', root)
        summary["steps"]["repro_run"] = {"crashed": bool(v), "type": t}
        if v:
            typer.echo("[✓] Crash detected with original repro")
        else:
            typer.echo("[!] No crash detected with original repro")
    except Exception as e:
        summary["steps"]["repro_run"] = {"error": str(e)}
        typer.echo(f"[!] Error running original repro: {e}")

    # Step 2: Analysis (static + optional dynamic)
    analysis_dir = Path(f"analysis_{bug_id}")
    typer.echo("[STEP 2] Running SyzAnalyze (static + optional dynamic)...")
    try:
        SyzAnalyze.analyze_bug(
            bug_id=bug_id,
            kernel_name=syzkall_kernel,
            qemu=qemu,
            source_image=source_image,
            source_disk=source_disk,
            dynamic_analysis=dynamic_analysis,
            gdb_port=gdb_port,
            arch=arch,
            output_dir=analysis_dir,
        )
        summary["steps"]["analyze"] = {"output_dir": str(analysis_dir)}
    except Exception as e:
        summary["steps"]["analyze"] = {"error": str(e)}
        typer.echo(f"[!] Analysis failed: {e}")

    # Decide whether to proceed based on static exploitability rating
    proceed_steps = False
    exploit_rating = None
    try:
        static_path = analysis_dir / 'static_analysis.json'
        if static_path.exists():
            with static_path.open('r') as sf:
                sdata = json.load(sf)
            parsed_llm = (sdata.get('llm_analysis', {}) or {}).get('openai_llm', {})
            parsed_llm = (parsed_llm.get('parsed', {}) if isinstance(parsed_llm, dict) else {})
            ov = parsed_llm.get('overview') if isinstance(parsed_llm, dict) else None
            if isinstance(ov, list) and ov:
                ov = ov[0]
            if isinstance(ov, dict):
                val = ov.get('exploitability')
                if isinstance(val, str):
                    exploit_rating = val.strip().lower()
            proceed_steps = exploit_rating in {'medium', 'high'}
    except Exception:
        proceed_steps = False

    # Step 3: Test generated primitive C (if present)
    typer.echo("[STEP 3] Testing generated primitive from analysis outputs...")
    primitive_result = {"attempted": False}
    try:
        if not proceed_steps:
            primitive_result["note"] = f"skipped due to exploitability rating: {exploit_rating or 'unknown'}"
        else:
            static_path = analysis_dir / 'static_analysis.json'
            if static_path.exists():
                with static_path.open('r') as sf:
                    sdata = json.load(sf)
                # Look for a generated reproducer source path
                repro_src = (sdata.get('reproducer', {}) or {})
                repro_src = repro_src.get('source_path') if isinstance(repro_src, dict) else None
                if repro_src and Path(repro_src).exists():
                    primitive_result["attempted"] = True
                    primitive_bin = analysis_dir / 'primitive'
                    compile_script = Path.cwd() / f"compile_{arch}.sh"
                    os.system(f'"{compile_script}" "{Path(repro_src).absolute()}" "{primitive_bin.absolute()}"')
                    if primitive_bin.exists():
                        if qemu:
                            v2, t2 = test_repro_crashes_qemu(primitive_bin, local, bug_id, str(analysis_dir), root, source_image, source_disk)
                        else:
                            v2, t2 = test_repro_crashes(primitive_bin, local, bug_id, str(analysis_dir), root)
                        primitive_result.update({"crashed": bool(v2), "type": t2, "binary": str(primitive_bin)})
                        typer.echo("[✓] Primitive run complete")
                    else:
                        primitive_result["error"] = "primitive binary not created"
                else:
                    primitive_result["note"] = "no generated reproducer source found"
            else:
                primitive_result["note"] = "static_analysis.json not found"
    except Exception as e:
        primitive_result["error"] = str(e)
        typer.echo(f"[!] Primitive test failed: {e}")
    summary["steps"]["primitive_run"] = primitive_result

    # Step 4: Synthesis (gated)
    if proceed_steps:
        typer.echo("[STEP 4] Running Synthesizer to build exploit plan...")
        synth_res = Synthesizer.synthesize(
            bug_id=bug_id,
            goal=goal,
            kernel_research_path=None,
            analysis_dir=str(analysis_dir),
            vmlinux_path=None,
            platform=platform,  # Can be None for auto-detect
            debug=debug,
            verbose=verbose,
        )
        summary["steps"]["synthesis"] = {"result": synth_res}
        typer.echo("[✓] Synthesis completed")
    else:
        summary["steps"]["synthesis"] = {"note": f"skipped due to exploitability rating: {exploit_rating or 'unknown'}"}
        typer.echo("[!] Skipping synthesis due to low exploitability rating")

    # Step 5: Final exploit run if artifact exists (gated)
    typer.echo("[STEP 5] Attempting final exploit run from synth_output...")
    final_result = {"attempted": False}
    try:
        if proceed_steps:
            outdir = Path(analysis_dir) / 'synth_output'
            if outdir.exists():
                # Find any executable file in synth_output
                exec_candidate = None
                for p in outdir.iterdir():
                    try:
                        mode_exec = os.access(p, os.X_OK)
                    except Exception:
                        mode_exec = False
                    if p.is_file() and mode_exec:
                        exec_candidate = p
                        break
                if exec_candidate:
                    final_result["attempted"] = True
                    if qemu:
                        v3, t3 = test_repro_crashes_qemu(exec_candidate, local, bug_id, str(outdir), root, source_image, source_disk)
                    else:
                        v3, t3 = test_repro_crashes(exec_candidate, local, bug_id, str(outdir), root)
                    final_result.update({"crashed": bool(v3), "type": t3, "binary": str(exec_candidate)})
                    typer.echo("[✓] Final exploit run complete")
                else:
                    final_result["note"] = "no executable artifact found in synth_output"
            else:
                final_result["note"] = "synth_output directory not found"
        else:
            final_result["note"] = f"skipped due to exploitability rating: {exploit_rating or 'unknown'}"
    except Exception as e:
        final_result["error"] = str(e)
        typer.echo(f"[!] Final exploit run failed: {e}")
    summary["steps"]["final_run"] = final_result

    # Save summary
    out = analysis_dir / 'pipeline_summary.json'
    with out.open('w') as f:
        json.dump(summary, f, indent=2)
    typer.echo(f"[+] Pipeline summary -> {out}")

def main():
    load_dotenv()
    app()

if __name__ == "__main__":
    main()
