from pathlib import Path
from typing import Optional
from typing_extensions import Annotated

import typer
from . import SyzVerify
from . import SyzAnalyze
from . import Synthesizer
from .SyzVerify.bug_db import SyzkallBugDatabase
from .utils.env import load_env
from .SyzVerify.run_bug import test_repro_crashes, test_repro_crashes_qemu, test_repro_with_cuttlefish_controller, verify_exploit_with_cuttlefish_controller
from .SyzVerify.cuttlefish import CuttlefishConfig, create_config_from_args
import json
import os

app = typer.Typer(help="Syzkall/Syzbot tooling for pulling, testing, and analyzing bugs.")


# TODO: decide if this will even be apart of kexploit
@app.command()
def pull(
    syzkall_kernel: Annotated[str, typer.Option(help='Kernel name to pull bugs for')] = 'android-5-10',
    all_bugs: Annotated[bool, typer.Option('--all', help='Pull all bugs without filtering for memory unsafety')] = False,
):
    """Pull bugs from syzbot for a given kernel version"""
    SyzVerify.pull(syzkall_kernel, apply_filter=not all_bugs)


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
    # Kernel GDB options
    kernel_gdb: Annotated[bool, typer.Option(help='Enable kernel GDB tracing for allocation tracking')] = False,
    kernel_gdb_port: Annotated[int, typer.Option(help='Kernel GDB port (crosvm)')] = 1234,
    vmlinux_path: Annotated[Optional[str], typer.Option(help='Path to vmlinux with debug symbols')] = None,
    # CuttlefishController options (use_cuttlefish_controller mode)
    use_cuttlefish_controller: Annotated[bool, typer.Option(help='Use CuttlefishController for Cuttlefish with runtime symbol extraction')] = False,
    ssh_host: Annotated[str, typer.Option(help='SSH host for Cuttlefish (can be a ~/.ssh/config alias)')] = 'localhost',
    ssh_port: Annotated[int, typer.Option(help='SSH port for Cuttlefish')] = 22,
    ssh_user: Annotated[Optional[str], typer.Option(help='SSH user (optional, uses ssh config if not set)')] = None,
    ssh_key: Annotated[Optional[str], typer.Option(help='SSH key path (optional, uses ssh config if not set)')] = None,
    adb_port: Annotated[int, typer.Option(help='ADB port for Cuttlefish device')] = 6520,
    instance: Annotated[Optional[int], typer.Option(help='Cuttlefish instance number (auto-calculates ADB port: 6520 + instance - 1)')] = None,
    persistent: Annotated[bool, typer.Option(help='Persistent mode (keep Cuttlefish running)')] = True,
    already_running: Annotated[bool, typer.Option(help='Cuttlefish is already running')] = True,
    setup_tunnels: Annotated[bool, typer.Option(help='Set up SSH tunnels for remote ADB/GDB access')] = False,
    extract_runtime_symbols: Annotated[bool, typer.Option(help='Extract kallsyms from running VM at runtime for accurate symbol addresses')] = True,
    # Lifecycle commands (for non-already-running mode)
    start_cmd: Annotated[Optional[str], typer.Option(help='Command to start Cuttlefish (run once at beginning if --no-already-running)')] = None,
    stop_cmd: Annotated[Optional[str], typer.Option(help='Command to stop Cuttlefish (run once at end)')] = None,
    runtime_logs_dir: Annotated[Optional[str], typer.Option(help='Path to cuttlefish runtime logs dir (e.g., ~/cuttlefish/cuttlefish_runtime.5/logs)')] = None,
    # LLM fix options
    use_llm_fix: Annotated[bool, typer.Option('--llm-fix/--no-llm-fix', help='Use LLM to fix compilation errors (uses cached fixes if available)')] = True,
):
    """
    Test all bugs from syzbot for a given kernel version.
    
    CUTTLEFISH CONTROLLER MODE (--use-cuttlefish-controller):
    - Uses CuttlefishController for advanced Cuttlefish management
    - Extracts runtime kallsyms from running VM for accurate breakpoint addresses
    - Enables GDB-based memory analysis (UAF/OOB detection)
    - Outputs crashes and analysis results with GDB traces
    
    Example:
        # Test all bugs with runtime symbol extraction on Cuttlefish
        syzploit testall --use-cuttlefish-controller --already-running --gdb-port 1234 \\
            --vmlinux-path ./vmlinux --extract-runtime-symbols
        
        # Boot Cuttlefish once at start, test all bugs, stop at end
        syzploit testall --use-cuttlefish-controller --persistent --no-already-running \\
            --ssh-host INGOTS-ARM --setup-tunnels --instance 20 \\
            --start-cmd "cd ~/cuttlefish && ./gdb_run.sh 20" \\
            --stop-cmd "cd ~/cuttlefish && ./stop.sh 20" \\
            --syzkall-kernel upstream --arch arm64
    """
    SyzVerify.test_all(
        local=local,
        arch=arch,
        kernel_name=syzkall_kernel,
        qemu=qemu,
        root=root,
        source_image=source_image,
        source_disk=source_disk,
        source=source,
        outdir_name=outdir_name,
        dynamic_analysis=dynamic_analysis,
        gdb_port=gdb_port,
        kernel_gdb=kernel_gdb,
        kernel_gdb_port=kernel_gdb_port,
        vmlinux_path=vmlinux_path,
        use_cuttlefish_controller=use_cuttlefish_controller,
        ssh_host=ssh_host,
        ssh_port=ssh_port,
        ssh_user=ssh_user,
        ssh_key=ssh_key,
        adb_port=adb_port,
        instance=instance,
        persistent=persistent,
        already_running=already_running,
        setup_tunnels=setup_tunnels,
        extract_runtime_symbols=extract_runtime_symbols,
        start_cmd=start_cmd,
        stop_cmd=stop_cmd,
        runtime_logs_dir=runtime_logs_dir,
        use_llm_fix=use_llm_fix,
    )


@app.command()
def testall_both(
    arch: Annotated[str, typer.Option(help='Architecture of kernel to test bugs on')] = 'x86_64',
    syzkall_kernel: Annotated[str, typer.Option(help='Kernel name to pull bugs for')] = 'android-5-10',
    outdir_name: Annotated[str, typer.Option(help='Base output directory name (will append _root and _nonroot)')] = "android-5.10_crashes",
    # CuttlefishController options
    use_cuttlefish_controller: Annotated[bool, typer.Option(help='Use CuttlefishController for Cuttlefish with runtime symbol extraction')] = False,
    ssh_host: Annotated[str, typer.Option(help='SSH host for Cuttlefish (can be a ~/.ssh/config alias)')] = 'localhost',
    instance: Annotated[Optional[int], typer.Option(help='Cuttlefish instance number')] = None,
    persistent: Annotated[bool, typer.Option(help='Persistent mode (keep Cuttlefish running)')] = True,
    already_running: Annotated[bool, typer.Option(help='Cuttlefish is already running')] = True,
    setup_tunnels: Annotated[bool, typer.Option(help='Set up SSH tunnels for remote ADB/GDB access')] = False,
    extract_runtime_symbols: Annotated[bool, typer.Option(help='Extract kallsyms from running VM (only if GDB enabled)')] = False,
    start_cmd: Annotated[Optional[str], typer.Option(help='Command to start Cuttlefish')] = None,
    stop_cmd: Annotated[Optional[str], typer.Option(help='Command to stop Cuttlefish')] = None,
    runtime_logs_dir: Annotated[Optional[str], typer.Option(help='Path to cuttlefish runtime logs dir')] = None,
    # GDB options
    enable_gdb: Annotated[bool, typer.Option('--gdb/--no-gdb', help='Enable GDB analysis (slower but more detailed)')] = False,
    # Connectivity check options
    pre_check_device: Annotated[bool, typer.Option('--pre-check/--no-pre-check', help='Check device connectivity before each test')] = True,
    pre_check_wait: Annotated[int, typer.Option(help='Max seconds to wait for device if offline')] = 60,
    # LLM fix options
    use_llm_fix: Annotated[bool, typer.Option('--llm-fix/--no-llm-fix', help='Use LLM to fix compilation errors (uses cached fixes if available)')] = True,
):
    """
    Test all bugs TWICE - once as root and once as non-root.
    
    This runs testall with --root first, then with --no-root, using separate
    output directories for each run.
    
    By default, GDB is disabled for faster execution. Use --gdb to enable
    GDB-based dynamic analysis.
    
    A pre-execution device connectivity check is performed before each test.
    If the device is offline, it waits up to --pre-check-wait seconds, then
    offers options to restart or skip.
    
    Example (fast mode without GDB):
        syzploit testall-both --use-cuttlefish-controller --arch arm64 \\
            --ssh-host INGOTS-ARM --setup-tunnels --instance 20 --persistent \\
            --already-running \\
            --start-cmd "cd ~/cuttlefish && HOME=/home/osboxes nohup ./gdb_run.sh 20 &" \\
            --stop-cmd "cd ~/cuttlefish && ./stop.sh 20"
    
    Example (with GDB analysis):
        syzploit testall-both --use-cuttlefish-controller --arch arm64 \\
            --ssh-host INGOTS-ARM --setup-tunnels --instance 20 --persistent \\
            --no-already-running --gdb --extract-runtime-symbols \\
            --start-cmd "cd ~/cuttlefish && ./gdb_run.sh 20" \\
            --stop-cmd "cd ~/cuttlefish && ./stop.sh 20" \\
            --runtime-logs-dir ~/cuttlefish/cuttlefish_runtime.20/logs
    """
    import typer
    
    gdb_mode = "with GDB analysis" if enable_gdb else "without GDB (fast mode)"
    typer.echo("=" * 60)
    typer.echo(f"PHASE 1: Testing all bugs as ROOT ({gdb_mode})")
    typer.echo("=" * 60)
    
    SyzVerify.test_all(
        local=False,
        arch=arch,
        kernel_name=syzkall_kernel,
        qemu=False,
        root=True,  # ROOT
        source_image=None,
        source_disk=None,
        source=False,
        outdir_name=f"{outdir_name}_root",
        dynamic_analysis=enable_gdb,
        gdb_port=1234,
        kernel_gdb=enable_gdb,
        kernel_gdb_port=1234,
        vmlinux_path=None,
        use_cuttlefish_controller=use_cuttlefish_controller,
        ssh_host=ssh_host,
        ssh_port=22,
        ssh_user=None,
        ssh_key=None,
        adb_port=6520,
        instance=instance,
        persistent=persistent,
        already_running=already_running,
        setup_tunnels=setup_tunnels,
        extract_runtime_symbols=extract_runtime_symbols if enable_gdb else False,
        start_cmd=start_cmd,
        stop_cmd=stop_cmd,  # Pass stop_cmd to allow restart on crash
        runtime_logs_dir=runtime_logs_dir,
        pre_check_device=pre_check_device,
        pre_check_wait=pre_check_wait,
        use_llm_fix=use_llm_fix,
    )
    
    typer.echo("")
    typer.echo("=" * 60)
    typer.echo(f"PHASE 2: Testing all bugs as NON-ROOT ({gdb_mode})")
    typer.echo("=" * 60)
    
    SyzVerify.test_all(
        local=False,
        arch=arch,
        kernel_name=syzkall_kernel,
        qemu=False,
        root=False,  # NON-ROOT
        source_image=None,
        source_disk=None,
        source=False,
        outdir_name=f"{outdir_name}_nonroot",
        dynamic_analysis=enable_gdb,
        gdb_port=1234,
        kernel_gdb=enable_gdb,
        kernel_gdb_port=1234,
        vmlinux_path=None,
        use_cuttlefish_controller=use_cuttlefish_controller,
        ssh_host=ssh_host,
        ssh_port=22,
        ssh_user=None,
        ssh_key=None,
        adb_port=6520,
        instance=instance,
        persistent=persistent,
        already_running=True,  # Already running from first phase
        setup_tunnels=setup_tunnels,
        extract_runtime_symbols=extract_runtime_symbols if enable_gdb else False,
        start_cmd=start_cmd,  # Pass start_cmd to allow restart on crash
        stop_cmd=stop_cmd,  # Stop at end and allow restart on crash
        runtime_logs_dir=runtime_logs_dir,
        pre_check_device=pre_check_device,
        pre_check_wait=pre_check_wait,
        use_llm_fix=use_llm_fix,
    )
    
    typer.echo("")
    typer.echo("=" * 60)
    typer.echo("BOTH PHASES COMPLETE")
    typer.echo(f"  Root results:     {outdir_name}_root/")
    typer.echo(f"  Non-root results: {outdir_name}_nonroot/")
    typer.echo("=" * 60)


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
    start_cmd: Annotated[Optional[str], typer.Option(help='Command to start Cuttlefish with GDB (e.g. ./gdb_run.sh)')] = None,
    run_cmd: Annotated[Optional[str], typer.Option(help='Command to start Cuttlefish WITHOUT GDB (e.g. ./run.sh). Used for symbol extraction.')] = None,
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
    extract_runtime_symbols: Annotated[bool, typer.Option(help='Extract kallsyms from running VM at runtime for accurate symbol addresses')] = True,
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
    
    # Auto-derive run_cmd from start_cmd if not explicitly provided
    actual_run_cmd = run_cmd
    if not actual_run_cmd and start_cmd and 'gdb_run' in start_cmd:
        actual_run_cmd = start_cmd.replace('gdb_run', 'run')
    
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
        run_command=actual_run_cmd,
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
        extract_runtime_symbols=extract_runtime_symbols,
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
    start_cmd: Annotated[Optional[str], typer.Option(help='Command to start Cuttlefish with GDB (e.g. ./gdb_run.sh)')] = None,
    run_cmd: Annotated[Optional[str], typer.Option(help='Command to start Cuttlefish WITHOUT GDB (e.g. ./run.sh). Used for symbol extraction. Auto-derived from --start-cmd if not set.')] = None,
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
    extract_runtime_symbols: Annotated[bool, typer.Option(help='Extract kallsyms from running VM at runtime for accurate symbol addresses')] = True,
    # Pipeline options
    skip_static: Annotated[bool, typer.Option(help='Skip static analysis')] = False,
    ignore_exploitability: Annotated[bool, typer.Option(help='Run dynamic even if exploitability is low')] = False,
    goal: Annotated[str, typer.Option(help='Exploit goal for synthesis')] = 'privilege_escalation',
    platform: Annotated[Optional[str], typer.Option(help='Target platform: linux, android, or generic')] = None,
    timeout: Annotated[int, typer.Option(help='Test timeout in seconds')] = 120,
    output_dir: Annotated[Optional[Path], typer.Option(help='Output directory for logs')] = None,
    # Exploit verification
    verify_exploit: Annotated[bool, typer.Option('--verify/--no-verify', help='Verify exploit for privilege escalation at the end')] = True,
    # Exploit verification start command (non-GDB)
    exploit_start_cmd: Annotated[Optional[str], typer.Option(help='Command to start Cuttlefish for exploit verification (without GDB). If provided, used instead of start_cmd for Step 6')] = None,
):
    """
    Full pipeline with Cuttlefish: analyze crash, run dynamic analysis, synthesize exploit, and verify.
    
    Combines the functionality of test_cuttlefish + analyze + synthesize + verify into a single command
    that properly passes crash stack trace information from static analysis to dynamic analysis.
    
    Steps:
    1) Static analysis (LLM-based crash analysis)
    2) Parse crash log to extract stack trace functions
    3) Run reproducer with GDB breakpoints on stack trace functions
    4) Collect alloc/free events and function hits
    5) Post-process for UAF/OOB detection
    6) Synthesize exploit plan
    7) Verify exploit achieves privilege escalation
    
    EXPLOIT VERIFICATION:
    Use --exploit-start-cmd to provide a separate start command for exploit verification (Step 6).
    This is useful when your main --start-cmd starts the instance with GDB support (slower boot),
    but for exploit verification you want to start without GDB for faster testing.
    
    Example:
        # Normal run with GDB tracing
        syzploit pipeline-cuttlefish abc123 --ssh-host cuttlefish2 --setup-tunnels \\
            --instance 5 --kernel-image /home/user/cuttlefish/package/kernel/Image
        
        # Full pipeline with separate start commands for GDB tracing vs exploit verification
        syzploit pipeline-cuttlefish abc123 --ssh-host INGOTS-ARM --setup-tunnels --instance 20 \\
            --start-cmd "cd ~/challenge-4 && ./gdb_run.sh 20" \\
            --exploit-start-cmd "cd ~/challenge-4 && ./run.sh 20"
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
    
    # Auto-derive run_cmd from start_cmd if not explicitly provided
    # Replace gdb_run.sh with run.sh for the non-GDB symbol extraction boot
    actual_run_cmd = run_cmd
    if not actual_run_cmd and start_cmd and 'gdb_run' in start_cmd:
        actual_run_cmd = start_cmd.replace('gdb_run', 'run')
        typer.echo(f"[+] Auto-derived --run-cmd: {actual_run_cmd}")
    
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
        run_command=actual_run_cmd,
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
        extract_runtime_symbols=extract_runtime_symbols,
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
            confidence = pp_res.get('confidence', 0)
            uaf_count = pp_res.get('summary', {}).get('uaf', 0)
            oob_count = pp_res.get('summary', {}).get('invalid-access', 0)
            
            typer.echo(f"[+] Post-processing: confidence={confidence}")
            typer.echo(f"[+] UAF={uaf_count} OOB={oob_count}")
            
            # Highlight UAF detection
            if uaf_count > 0:
                typer.echo(f"[✓] USE-AFTER-FREE DETECTED: {uaf_count} UAF event(s) found!")
                
            # Show vulnerabilities detected
            vulns = pp_res.get('vulnerabilities_detected', [])
            if vulns:
                typer.echo(f"[+] Vulnerabilities detected:")
                for vuln in vulns:
                    typer.echo(f"    - {vuln.get('type', 'unknown')}: {vuln.get('count', 0)} instance(s)")
            
            summary["steps"]["post_process"] = {
                "success": True, 
                "confidence": confidence,
                "uaf_count": uaf_count,
                "oob_count": oob_count,
                "vulnerabilities": vulns,
            }
        else:
            typer.echo("[!] No dynamic_analysis.json found to post-process")
            summary["steps"]["post_process"] = {"success": False, "error": "no dynamic results"}
    except Exception as e:
        typer.echo(f"[!] Post-processing failed: {e}")
        summary["steps"]["post_process"] = {"success": False, "error": str(e)}
    
    # Step 5: Synthesize (optional)
    exploit_path = None
    if goal:
        typer.echo("\n[STEP 5] Synthesizing exploit plan...")
        try:
            from .Synthesizer.exploit_generator import generate_exploit
            
            # Use the same exploit generator as generate-exploit command
            # This has better LLM prompts that produce actual exploitation steps
            result = generate_exploit(
                analysis_dir=str(output_dir),
                target_arch=arch,
                kernel_version="",  # Auto-detect
                output_dir=str(output_dir),
                skip_llm=False,
                model="gpt-5",
                use_existing_plan=True,  # Use existing plan if available
                use_reference=False,
            )
            
            if result.get('success'):
                typer.echo(f"[+] Exploit generated successfully!")
                typer.echo(f"    Vulnerability: {result.get('vulnerability_type')}")
                typer.echo(f"    Target: {result.get('target_struct')}")
                typer.echo(f"    Technique: {result.get('technique')}")
                typer.echo(f"    Steps: {len(result.get('steps', []))}")
                for step in result.get('steps', []):
                    typer.echo(f"      - {step}")
                summary["steps"]["synthesize"] = {
                    "success": True,
                    "vulnerability_type": result.get('vulnerability_type'),
                    "technique": result.get('technique'),
                    "steps": result.get('steps', []),
                }
                
                # Find the generated exploit binary or source
                outputs = result.get('outputs', {})
                if outputs.get('exploit'):
                    exploit_path = outputs['exploit']
                    typer.echo(f"[+] Generated exploit: {exploit_path}")
            else:
                typer.echo(f"[!] Exploit generation failed")
                summary["steps"]["synthesize"] = {"success": False, "error": "generation failed"}
            
            # Also check for compiled binary in synth_output
            synth_output = output_dir / 'synth_output'
            if synth_output.exists() and not exploit_path:
                for p in synth_output.iterdir():
                    if p.is_file() and os.access(p, os.X_OK):
                        exploit_path = str(p)
                        typer.echo(f"[+] Found compiled exploit: {exploit_path}")
                        break
            
            # Also check the analysis_dir directly for exploit.c
            if not exploit_path:
                for p in output_dir.glob("exploit*.c"):
                    typer.echo(f"[+] Found generated exploit source: {p}")
                    break
        except Exception as e:
            typer.echo(f"[!] Synthesis failed: {e}")
            import traceback
            typer.echo(f"[!] Traceback: {traceback.format_exc()}")
            summary["steps"]["synthesize"] = {"success": False, "error": str(e)}
    
    # Step 6: Verify exploit (optional)
    if verify_exploit:
        typer.echo("\n[STEP 6] Verifying exploit for privilege escalation...")
        
        if exploit_path:
            # typer.echo(f"[+] Exploit binary: {exploit_path}")
            
            # Create a separate config for exploit verification
            # If exploit_start_cmd is provided, use it instead of start_cmd (no GDB needed)
            verify_config = CuttlefishConfig(
                ssh_host=ssh_host,
                ssh_port=ssh_port,
                ssh_user=ssh_user,
                ssh_password=ssh_password,
                ssh_key_path=ssh_key,
                persistent=persistent,
                already_running=already_running,
                start_command=exploit_start_cmd if exploit_start_cmd else start_cmd,
                stop_command=stop_cmd,
                gdb_port=gdb_port,
                adb_port=actual_adb_port,
                enable_gdb=False,  # No GDB needed for exploit verification
                setup_tunnels=setup_tunnels,
                cuttlefish_runtime_logs=runtime_logs_dir,
                kernel_image_path=None,  # No kernel symbols needed
                vmlinux_path=None,
                system_map_path=None,
                extract_symbols=False,
                extract_runtime_symbols=False,
            )
            
            # Use CuttlefishController-based verification (same approach as test_repro)
            verify_result = verify_exploit_with_cuttlefish_controller(
                exploit_path=exploit_path,
                cuttlefish_config=verify_config,
                log_dir=str(output_dir / 'verification'),
                timeout=timeout,
            )
            
            if verify_result.get('success'):
                typer.echo("\n[✓] EXPLOIT VERIFICATION PASSED")
                typer.echo("    Privilege escalation achieved!")
                typer.echo(f"    Initial UID: {verify_result.get('initial_uid')}")
                typer.echo(f"    Final UID: {verify_result.get('final_uid')}")
                summary["steps"]["verify"] = {"success": True, "initial_uid": verify_result.get('initial_uid'), "final_uid": verify_result.get('final_uid')}
            else:
                typer.echo("\n[✗] EXPLOIT VERIFICATION FAILED")
                if verify_result.get('error'):
                    typer.echo(f"    Error: {verify_result['error']}")
                if verify_result.get('crash_occurred'):
                    typer.echo("    Note: A crash was detected during execution")
                summary["steps"]["verify"] = {"success": False, "error": verify_result.get('error', 'unknown')}
        else:
            typer.echo("[!] No exploit binary found to verify")
            summary["steps"]["verify"] = {"success": False, "error": "no exploit binary"}
    
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
    # Exploit verification options
    verify_exploit: Annotated[bool, typer.Option('--verify/--no-verify', help='Verify synthesized exploit on device')] = False,
    arch: Annotated[str, typer.Option(help='Architecture for compilation (arm64/x86_64)')] = 'arm64',
    ssh_host: Annotated[Optional[str], typer.Option(help='SSH host for Cuttlefish')] = None,
    instance: Annotated[Optional[int], typer.Option(help='Cuttlefish instance number')] = None,
    start_cmd: Annotated[Optional[str], typer.Option(help='Command to start Cuttlefish')] = None,
    stop_cmd: Annotated[Optional[str], typer.Option(help='Command to stop Cuttlefish')] = None,
):
    """Synthesize an exploit plan using SyzAnalyze + kernelXDK primitives.
    
    Supports Linux kernel and Android kernel exploitation. Platform is auto-detected
    from analysis data if not specified.
    
    Use --verify to test the synthesized exploit on a device after synthesis.
    This will:
    1. Stop the instance (clean state)
    2. Start the instance (fresh boot)
    3. Push the compiled exploit
    4. Run as non-root user
    5. Verify privilege escalation to root
    
    Example with verification:
        syzploit synthesize abc123 --verify --arch arm64 \\
            --ssh-host INGOTS-ARM --instance 20 \\
            --start-cmd "cd ~/cuttlefish && ./gdb_run.sh 20" \\
            --stop-cmd "cd ~/cuttlefish && ./stop.sh 20"
    """
    from .SyzVerify.run_bug import test_exploit_on_device
    
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
    ad = None
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
    
    # Verify exploit if requested
    if verify_exploit:
        typer.echo("\n[VERIFY] Testing synthesized exploit on device...")
        
        # Find the compiled exploit
        exploit_path = None
        if ad:
            synth_output = Path(ad) / 'synth_output'
            if synth_output.exists():
                # Look for executable in synth_output
                for p in synth_output.iterdir():
                    if p.is_file() and os.access(p, os.X_OK):
                        exploit_path = str(p)
                        break
                # Also check for exploit_*.c and compile it
                if not exploit_path:
                    for p in synth_output.glob('exploit_*.c'):
                        compiled = synth_output / f'exploit_{arch}'
                        compile_script = Path.cwd() / f"compile_{arch}.sh"
                        if compile_script.exists():
                            os.system(f'"{compile_script}" "{p}" "{compiled}"')
                            if compiled.exists():
                                exploit_path = str(compiled)
                                break
            
            # Also check analysis dir root for exploit files
            if not exploit_path:
                analysis_path = Path(ad)
                for p in analysis_path.glob('exploit_*.c'):
                    compiled = analysis_path / f'exploit_{arch}'
                    compile_script = Path.cwd() / f"compile_{arch}.sh"
                    if compile_script.exists():
                        os.system(f'"{compile_script}" "{p}" "{compiled}"')
                        if compiled.exists():
                            exploit_path = str(compiled)
                            break
        
        if not exploit_path:
            typer.echo("[!] No exploit binary found to verify. Check synth_output directory.")
        else:
            typer.echo(f"[+] Found exploit: {exploit_path}")
            
            verify_result = test_exploit_on_device(
                exploit_path=exploit_path,
                arch=arch,
                ssh_host=ssh_host,
                instance=instance,
                start_cmd=start_cmd,
                stop_cmd=stop_cmd,
                log_dir=str(Path(ad) / 'verification') if ad else None,
            )
            
            if verify_result.get('success'):
                typer.echo("[✓] EXPLOIT VERIFICATION PASSED - Privilege escalation achieved!")
            else:
                typer.echo("[!] Exploit verification failed")
                if verify_result.get('error'):
                    typer.echo(f"    Error: {verify_result['error']}")


@app.command(name="test-exploit")
def test_exploit(
    exploit_path: Annotated[Path, typer.Argument(help='Path to compiled exploit binary')],
    arch: Annotated[str, typer.Option(help='Architecture (arm64/x86_64)')] = 'arm64',
    ssh_host: Annotated[Optional[str], typer.Option(help='SSH host for Cuttlefish')] = None,
    ssh_port: Annotated[int, typer.Option(help='SSH port')] = 22,
    adb_port: Annotated[int, typer.Option(help='ADB port')] = 6520,
    instance: Annotated[Optional[int], typer.Option(help='Cuttlefish instance number')] = None,
    start_cmd: Annotated[Optional[str], typer.Option(help='Command to start Cuttlefish')] = None,
    stop_cmd: Annotated[Optional[str], typer.Option(help='Command to stop Cuttlefish')] = None,
    timeout: Annotated[int, typer.Option(help='Exploit execution timeout in seconds')] = 120,
    log_dir: Annotated[Optional[Path], typer.Option(help='Directory to save logs')] = None,
    persistent: Annotated[bool, typer.Option('--persistent/--no-persistent', help='Persistent mode - assume instance is running, keep it running')] = False,
    gdb_port: Annotated[int, typer.Option(help='GDB port for Crosvm kernel')] = 1234,
    setup_tunnels: Annotated[bool, typer.Option(help='Set up SSH tunnels for remote access')] = False,
):
    """
    Test an exploit binary for privilege escalation on a Cuttlefish device.
    
    This command:
    1. Stops the instance (if stop_cmd provided) - skipped if --persistent
    2. Starts the instance (if start_cmd provided) - skipped if --persistent
    3. Pushes the exploit to the device
    4. Runs the exploit as a non-root user
    5. Verifies if privilege escalation to root was achieved
    
    Examples:
        # Test on already-running instance (persistent mode)
        syzploit test-exploit ./exploit_arm64 --instance 20 --persistent
        
        # Full cycle with stop/start
        syzploit test-exploit ./exploit_arm64 --ssh-host INGOTS-ARM --instance 20 \\
            --start-cmd "cd ~/cuttlefish && ./gdb_run.sh 20" \\
            --stop-cmd "cd ~/cuttlefish && ./stop.sh 20"
    """
    from .SyzVerify.run_bug import test_exploit_on_device
    
    if not exploit_path.exists():
        typer.echo(f"[!] Exploit binary not found: {exploit_path}")
        raise typer.Exit(code=1)
    
    result = test_exploit_on_device(
        exploit_path=str(exploit_path),
        arch=arch,
        ssh_host=ssh_host,
        ssh_port=ssh_port,
        adb_port=adb_port,
        instance=instance,
        start_cmd=start_cmd,
        stop_cmd=stop_cmd,
        timeout=timeout,
        log_dir=str(log_dir) if log_dir else None,
        persistent=persistent,
        gdb_port=gdb_port,
        setup_tunnels=setup_tunnels,
    )
    
    if result.get('success'):
        typer.echo("\n[✓] EXPLOIT VERIFICATION PASSED")
        typer.echo("    Privilege escalation achieved!")
        typer.echo(f"    Initial UID: {result.get('initial_uid')}")
        typer.echo(f"    Final UID: {result.get('final_uid')}")
    else:
        typer.echo("\n[✗] EXPLOIT VERIFICATION FAILED")
        if result.get('error'):
            typer.echo(f"    Error: {result['error']}")
        if result.get('crash_occurred'):
            typer.echo("    Note: A crash was detected during execution")
        raise typer.Exit(code=1)


@app.command(name="test-exploit-source")
def test_exploit_source(
    source_path: Annotated[Path, typer.Argument(help='Path to exploit C source file')],
    arch: Annotated[str, typer.Option(help='Architecture (arm64/x86_64)')] = 'arm64',
    ssh_host: Annotated[Optional[str], typer.Option(help='SSH host for Cuttlefish')] = None,
    ssh_port: Annotated[int, typer.Option(help='SSH port')] = 22,
    adb_port: Annotated[int, typer.Option(help='ADB port')] = 6520,
    instance: Annotated[Optional[int], typer.Option(help='Cuttlefish instance number')] = None,
    start_cmd: Annotated[Optional[str], typer.Option(help='Command to start Cuttlefish')] = None,
    stop_cmd: Annotated[Optional[str], typer.Option(help='Command to stop Cuttlefish')] = None,
    timeout: Annotated[int, typer.Option(help='Exploit execution timeout in seconds')] = 120,
    log_dir: Annotated[Optional[Path], typer.Option(help='Directory to save logs')] = None,
    persistent: Annotated[bool, typer.Option('--persistent/--no-persistent', help='Persistent mode - assume instance is running, keep it running')] = False,
    output_binary: Annotated[Optional[Path], typer.Option(help='Path for compiled binary output')] = None,
):
    """
    Compile and test an exploit C source file for privilege escalation.
    
    This command:
    1. Compiles the C source file for the target architecture
    2. Stops the instance (clean state) - skipped if --persistent
    3. Starts the instance (fresh boot) - skipped if --persistent  
    4. Pushes the compiled exploit to the device
    5. Runs the exploit as a non-root user
    6. Verifies if privilege escalation to root was achieved
    7. Stops the instance - skipped if --persistent
    
    PERSISTENT MODE (--persistent):
    Use when the instance is already running and you want to keep it running.
    This skips stop/start steps and just pushes + runs + verifies.
    
    NON-PERSISTENT MODE (default):
    Full cycle: stop -> start -> test -> stop
    Ensures clean state for each test.
    
    Examples:
        # Compile and test on already-running instance (persistent)
        syzploit test-exploit-source ./exploit.c --arch arm64 --instance 20 --persistent
        
        # Full cycle with stop/start (non-persistent)
        syzploit test-exploit-source ./exploit.c --arch arm64 \\
            --ssh-host INGOTS-ARM --instance 20 \\
            --start-cmd "cd ~/cuttlefish && ./gdb_run.sh 20" \\
            --stop-cmd "cd ~/cuttlefish && ./stop.sh 20"
        
        # Specify output binary path
        syzploit test-exploit-source ./my_exploit.c --output-binary ./my_exploit_arm64
    """
    from .SyzVerify.run_bug import test_exploit_from_source
    
    if not source_path.exists():
        typer.echo(f"[!] Source file not found: {source_path}")
        raise typer.Exit(code=1)
    
    result = test_exploit_from_source(
        source_path=str(source_path),
        arch=arch,
        ssh_host=ssh_host,
        ssh_port=ssh_port,
        adb_port=adb_port,
        instance=instance,
        start_cmd=start_cmd,
        stop_cmd=stop_cmd,
        timeout=timeout,
        log_dir=str(log_dir) if log_dir else None,
        persistent=persistent,
        output_binary=str(output_binary) if output_binary else None,
    )
    
    if not result.get('compiled'):
        typer.echo("\n[✗] COMPILATION FAILED")
        if result.get('error'):
            typer.echo(f"    Error: {result['error']}")
        raise typer.Exit(code=1)
    
    verification = result.get('verification', {})
    if verification.get('success'):
        typer.echo("\n[✓] EXPLOIT VERIFICATION PASSED")
        typer.echo("    Privilege escalation achieved!")
        typer.echo(f"    Binary: {result.get('binary_path')}")
        typer.echo(f"    Initial UID: {verification.get('initial_uid')}")
        typer.echo(f"    Final UID: {verification.get('final_uid')}")
    else:
        typer.echo("\n[✗] EXPLOIT VERIFICATION FAILED")
        typer.echo(f"    Binary: {result.get('binary_path')}")
        if verification.get('error'):
            typer.echo(f"    Error: {verification['error']}")
        if verification.get('crash_occurred'):
            typer.echo("    Note: A crash was detected during execution")
        raise typer.Exit(code=1)



@app.command(name="generate-exploit")
def generate_exploit_cmd(
    analysis_dir: Annotated[Path, typer.Argument(help='Path to analysis directory with static_analysis.json')],
    arch: Annotated[str, typer.Option(help='Target architecture (arm64/x86_64)')] = 'arm64',
    kernel_version: Annotated[str, typer.Option(help='Target kernel version (for offset selection)')] = '',
    output_dir: Annotated[Optional[Path], typer.Option(help='Output directory (defaults to analysis_dir)')] = None,
    skip_llm: Annotated[bool, typer.Option('--skip-llm', help='Skip LLM generation, produce stubs only')] = False,
    template_only: Annotated[bool, typer.Option('--template-only', help='Generate only the template, no function implementations')] = False,
    model: Annotated[str, typer.Option(help='LLM model to use')] = 'gpt-5',
    use_existing_plan: Annotated[bool, typer.Option('--use-existing-plan/--new-plan', help='Use llm_planner_output.json if it exists')] = True,
    use_reference: Annotated[bool, typer.Option('--use-reference', help='Use reference implementations from badbinder (no LLM)')] = False,
):
    """
    Generate an exploit from vulnerability analysis.
    
    This command uses LLM to dynamically analyze the vulnerability and create
    an exploitation plan. It performs three stages:
    
    1. ANALYZE: LLM analyzes static_analysis.json to understand the vulnerability
       (or loads llm_planner_output.json if --use-existing-plan)
    2. PLAN: Generate exploitation plan with steps  
    3. IMPLEMENT: LLM generates function implementations
    
    Examples:
        # Generate full exploit with LLM assistance
        syzploit generate-exploit ./analysis_abc123 --arch arm64
        
        # Use existing plan from llm_planner_output.json
        syzploit generate-exploit ./analysis_abc123 --use-existing-plan
        
        # Generate template only (for manual implementation)
        syzploit generate-exploit ./analysis_abc123 --template-only
        
        # Generate with stubs (no LLM for function bodies)
        syzploit generate-exploit ./analysis_abc123 --skip-llm
        
        # Force new LLM plan even if llm_planner_output.json exists
        syzploit generate-exploit ./analysis_abc123 --new-plan
        
        # Use reference implementations from badbinder (no LLM needed)
        syzploit generate-exploit ./analysis_abc123 --use-reference
    
    Output files:
        - exploit_plan.json: Exploitation plan with steps
        - exploit_template.c: Code skeleton with stubs
        - exploit.c: Full implementation (if not --template-only)
    """
    from .Synthesizer.exploit_generator import (
        generate_exploit,
        ExploitGenerator,
    )
    
    # Validate analysis_dir
    if not analysis_dir.exists():
        typer.echo(f"[!] Analysis directory not found: {analysis_dir}")
        raise typer.Exit(code=1)
    
    static_analysis = analysis_dir / "static_analysis.json"
    if not static_analysis.exists():
        typer.echo(f"[!] static_analysis.json not found in {analysis_dir}")
        typer.echo("    Run 'syzploit analyze' first to generate vulnerability analysis.")
        raise typer.Exit(code=1)
    
    # Check for existing plan
    existing_plan = analysis_dir / "llm_planner_output.json"
    if use_existing_plan and existing_plan.exists():
        typer.echo(f"[*] Found existing plan: {existing_plan}")
    
    # Generate exploit
    typer.echo(f"[*] Generating exploit from: {analysis_dir}")
    typer.echo(f"    Architecture: {arch}")
    typer.echo(f"    Model: {model}")
    if kernel_version:
        typer.echo(f"    Kernel: {kernel_version}")
    
    if template_only:
        # Generate just the template (with existing plan support)
        import json
        from .Synthesizer.exploit_generator import ExploitPlan as GenExploitPlan
        
        generator = ExploitGenerator(model=model)
        
        # Load analysis
        with open(static_analysis) as f:
            analysis_data = json.load(f)
        
        # Try to use existing plan
        plan = None
        if use_existing_plan and existing_plan.exists():
            typer.echo("[*] Loading existing plan...")
            try:
                with open(existing_plan) as f:
                    plan_data = json.load(f)
                steps = []
                for step_name in plan_data.get("steps", []):
                    steps.append({
                        "name": step_name,
                        "description": step_name.replace("_", " "),
                        "requires": [],
                        "provides": [],
                    })
                plan = GenExploitPlan(
                    vulnerability_type=plan_data.get("vulnerability_type", "unknown"),
                    target_struct=plan_data.get("target_struct", "unknown"),
                    slab_cache="kmalloc-512",
                    technique=plan_data.get("exploitation_technique", ""),
                    steps=steps,
                    target_arch=arch,
                    target_kernel=kernel_version,
                )
            except Exception as e:
                typer.echo(f"[!] Failed to load existing plan: {e}")
        
        if plan is None:
            typer.echo("[*] Generating new plan with LLM...")
            plan = generator.generate_plan(
                analysis_data=analysis_data,
                target_arch=arch,
                kernel_version=kernel_version,
            )
        
        template = generator.generate_template(plan)
        
        out_dir = output_dir or analysis_dir
        template_path = out_dir / "exploit_template.c"
        with open(template_path, 'w') as f:
            f.write(template)
        
        plan_path = out_dir / "exploit_plan.json"
        plan_data = {
            "vulnerability_type": plan.vulnerability_type,
            "target_struct": plan.target_struct,
            "technique": plan.technique,
            "steps": [s["name"] for s in plan.steps],
        }
        with open(plan_path, 'w') as f:
            json.dump(plan_data, f, indent=2)
        
        typer.echo(f"\n[✓] Template generated:")
        typer.echo(f"    Vulnerability: {plan.vulnerability_type}")
        typer.echo(f"    Target: {plan.target_struct}")
        typer.echo(f"    Technique: {plan.technique}")
        typer.echo(f"    Steps: {len(plan.steps)}")
        for s in plan.steps:
            typer.echo(f"      - {s['name']}")
        typer.echo(f"    Plan: {plan_path}")
        typer.echo(f"    Template: {template_path}")
        return
    
    # Full generation
    result = generate_exploit(
        analysis_dir=str(analysis_dir),
        target_arch=arch,
        kernel_version=kernel_version,
        output_dir=str(output_dir) if output_dir else None,
        skip_llm=skip_llm,
        model=model,
        use_existing_plan=use_existing_plan,
        use_reference=use_reference,
    )
    
    if result.get('success'):
        typer.echo(f"\n[✓] Exploit generated successfully!")
        typer.echo(f"    Vulnerability: {result.get('vulnerability_type')}")
        typer.echo(f"    Target: {result.get('target_struct')}")
        typer.echo(f"    Technique: {result.get('technique')}")
        typer.echo(f"    Steps: {len(result.get('steps', []))}")
        for step in result.get('steps', []):
            typer.echo(f"      - {step}")
        for key, path in result.get('outputs', {}).items():
            typer.echo(f"    {key}: {path}")
    else:
        typer.echo(f"\n[!] Exploit generation failed")
        raise typer.Exit(code=1)



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
    setup_tunnels: Annotated[bool, typer.Option(help='Set up SSH tunnels for remote ADB/GDB access')] = False,
    goal: Annotated[str, typer.Option(help='Exploit goal for synthesis')] = 'privilege_escalation',
    platform: Annotated[Optional[str], typer.Option(help='Target platform: linux, android, or generic')] = None,
    debug: Annotated[bool, typer.Option(help='Enable debug output')] = False,
    verbose: Annotated[bool, typer.Option(help='Print planner output')] = False,
    # Exploit verification options
    verify_exploit: Annotated[bool, typer.Option('--verify/--no-verify', help='Verify synthesized exploit achieves privilege escalation')] = False,
    ssh_host: Annotated[Optional[str], typer.Option(help='SSH host for Cuttlefish (for verification)')] = None,
    instance: Annotated[Optional[int], typer.Option(help='Cuttlefish instance number (for verification)')] = None,
    start_cmd: Annotated[Optional[str], typer.Option(help='Command to start Cuttlefish (for verification)')] = None,
    stop_cmd: Annotated[Optional[str], typer.Option(help='Command to stop Cuttlefish (for verification)')] = None,
):
    """Run the full pipeline: verify crash with SyzVerify, analyze with SyzAnalyze,
    test generated primitive, run Synthesizer, and finally verify the generated exploit.

    Steps:
    1) Compile + run reproducer to confirm crash
    2) Perform static (+optional dynamic) analysis
    3) Compile + run generated primitive C (if available)
    4) Synthesize exploit plan (optionally via ChainReactor)
    5) Run final exploit artifact if available
    6) Verify privilege escalation (if --verify)
    
    Use --verify to add a final verification step that:
    - Stops the instance (clean slate)
    - Starts the instance (fresh boot)
    - Runs the exploit as non-root
    - Verifies privilege escalation to root
    
    Example with verification:
        syzploit pipeline abc123 --verify --arch arm64 \\
            --ssh-host INGOTS-ARM --instance 20 \\
            --start-cmd "cd ~/cuttlefish && ./gdb_run.sh 20" \\
            --stop-cmd "cd ~/cuttlefish && ./stop.sh 20"
    """
    from .SyzVerify.run_bug import test_exploit_on_device
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

    # Step 6: Verify privilege escalation (if --verify)
    if verify_exploit:
        typer.echo("[STEP 6] Verifying exploit achieves privilege escalation...")
        verify_result = {"attempted": False}
        
        # Find exploit binary
        exploit_path = None
        if proceed_steps:
            outdir = Path(analysis_dir) / 'synth_output'
            if outdir.exists():
                for p in outdir.iterdir():
                    if p.is_file() and os.access(p, os.X_OK):
                        exploit_path = str(p)
                        break
                # Try compiling if only source exists
                if not exploit_path:
                    for p in outdir.glob('exploit_*.c'):
                        compiled = outdir / f'exploit_{arch}'
                        compile_script = Path.cwd() / f"compile_{arch}.sh"
                        if compile_script.exists():
                            os.system(f'"{compile_script}" "{p}" "{compiled}"')
                            if compiled.exists():
                                exploit_path = str(compiled)
                                break
            
            # Also check analysis dir root
            if not exploit_path:
                for p in analysis_dir.glob('exploit_*.c'):
                    compiled = analysis_dir / f'exploit_{arch}'
                    compile_script = Path.cwd() / f"compile_{arch}.sh"
                    if compile_script.exists():
                        os.system(f'"{compile_script}" "{p}" "{compiled}"')
                        if compiled.exists():
                            exploit_path = str(compiled)
                            break
        
        if exploit_path:
            verify_result["attempted"] = True
            typer.echo(f"[INFO] Testing exploit: {exploit_path}")
            
            try:
                result = test_exploit_on_device(
                    exploit_path=exploit_path,
                    arch=arch,
                    ssh_host=ssh_host,
                    instance=instance,
                    start_cmd=start_cmd,
                    stop_cmd=stop_cmd,
                    log_dir=str(analysis_dir / 'verification'),
                    gdb_port=gdb_port,
                    setup_tunnels=setup_tunnels,
                )
                
                verify_result["success"] = result.get("success", False)
                verify_result["privilege_escalated"] = result.get("privilege_escalated", False)
                verify_result["initial_uid"] = result.get("initial_uid")
                verify_result["final_uid"] = result.get("final_uid")
                verify_result["crash_occurred"] = result.get("crash_occurred", False)
                
                if result.get("success"):
                    typer.echo("[✓] EXPLOIT VERIFICATION PASSED - Privilege escalation achieved!")
                else:
                    typer.echo("[!] Exploit verification failed - privilege escalation not achieved")
                    
            except Exception as e:
                verify_result["error"] = str(e)
                typer.echo(f"[!] Verification failed: {e}")
        else:
            verify_result["note"] = "no exploit binary found"
            typer.echo("[!] No exploit binary found to verify")
        
        summary["steps"]["verification"] = verify_result
    
    # Save summary
    out = analysis_dir / 'pipeline_summary.json'
    with out.open('w') as f:
        json.dump(summary, f, indent=2)
    typer.echo(f"[+] Pipeline summary -> {out}")
    
    # Print final summary
    typer.echo("\n" + "=" * 60)
    typer.echo("PIPELINE SUMMARY")
    typer.echo("=" * 60)
    for step_name, step_data in summary["steps"].items():
        if isinstance(step_data, dict):
            if step_data.get("success") or step_data.get("crashed"):
                typer.echo(f"  {step_name}: ✓")
            elif step_data.get("error"):
                typer.echo(f"  {step_name}: ✗ ({step_data['error'][:50]}...)")
            elif step_data.get("note"):
                typer.echo(f"  {step_name}: - ({step_data['note'][:50]})")
            else:
                typer.echo(f"  {step_name}: ?")
    typer.echo("=" * 60)

def main():
    load_env()
    app()

if __name__ == "__main__":
    main()
