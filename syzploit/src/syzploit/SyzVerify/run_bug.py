from typing import Any, Tuple, Optional, Dict, List
from pathlib import Path
import subprocess
import os
import time
import paramiko
import signal
import sys
import threading
import json
import tempfile
import socket

# Import runtime symbols module for kallsyms extraction
from .runtime_symbols import (
    extract_runtime_symbols,
    RuntimeSymbols,
    disable_kptr_restrict_adb,
    disable_kptr_restrict_ssh,
)


VM_HOST = "127.0.0.1"
VM_PORT = 10021
VM_USER = "root"
VM_PASS = ""  # adjust if needed
BINARY_PATH = "./repro"
REMOTE_PATH = "/root/repro"
REMOTE_ROOT_CMD = "export RANDOM=1000000; ./repro"
REMOTE_CMD = "mkdir -p /tmp/nonroot_test && cp ./repro /tmp/nonroot_test/ && cd /tmp/nonroot_test && chown 1000:1000 ./repro && chmod +x ./repro && su -s /bin/sh dbus -c './repro'"
LOG_FILE = "vm_output.log"

CRASH_PATTERNS = [
    "BUG:",
    "kernel panic",
    "Oops:",
    "general protection fault",
    "KASAN:",
    "UBSAN:",
    "Segfault",
    "lockdep warning",
]

def detect_crash(logs: str) -> bool:
    for pat in CRASH_PATTERNS:
        if pat in logs:
            return True
    return False

def wait_for_vm(host, port, timeout=60):
    import socket
    start = time.time()
    while time.time() - start < timeout:
        try:
            with socket.create_connection((host, port), timeout=3):
                return True
        except (ConnectionRefusedError, OSError):
            time.sleep(2)
    return False


def extract_and_save_runtime_symbols(
    output_dir: str,
    vm_type: str = "cuttlefish",
    crash_stack_funcs: Optional[List[str]] = None,
    adb_exe: str = "adb",
    adb_target: Optional[str] = None,
    ssh_host: Optional[str] = None,
    ssh_user: Optional[str] = None,
    ssh_port: int = 22,
) -> Optional[str]:
    """
    Extract runtime symbols from a running VM and save as GDB config JSON.
    
    This function:
    1. Disables kptr_restrict on the VM
    2. Dumps /proc/kallsyms to get current symbol addresses
    3. Generates a JSON config file for the GDB script
    
    Args:
        output_dir: Directory to save symbol files
        vm_type: "cuttlefish" or "qemu"
        crash_stack_funcs: List of crash stack function names to include
        adb_exe: Path to adb executable (for Cuttlefish)
        adb_target: ADB device target (for Cuttlefish)
        ssh_host: SSH host (for QEMU)
        ssh_user: SSH username (for QEMU)
        ssh_port: SSH port (for QEMU)
    
    Returns:
        Path to the generated GDB config JSON, or None if extraction failed
    """
    print(f"[SYMBOLS] Extracting runtime symbols from {vm_type}...")
    
    # Extract symbols
    runtime_symbols = extract_runtime_symbols(
        output_dir=output_dir,
        vm_type=vm_type,
        adb_exe=adb_exe,
        adb_target=adb_target,
        ssh_host=ssh_host,
        ssh_user=ssh_user,
        ssh_port=ssh_port,
    )
    
    if not runtime_symbols:
        print("[SYMBOLS] WARNING: Failed to extract runtime symbols")
        return None
    
    print(f"[SYMBOLS] Extracted {len(runtime_symbols.symbols)} symbols")
    print(f"[SYMBOLS] System.map: {runtime_symbols.system_map_path}")
    
    # Get alloc/free addresses
    alloc_free = runtime_symbols.get_alloc_free_addresses()
    print(f"[SYMBOLS] Found {len(alloc_free)} alloc/free functions:")
    for name, addr in list(alloc_free.items())[:4]:
        print(f"          {name}: 0x{addr:x}")
    
    # Get crash stack addresses
    crash_addrs = {}
    if crash_stack_funcs:
        crash_addrs = runtime_symbols.get_crash_stack_addresses(crash_stack_funcs)
        print(f"[SYMBOLS] Found {len(crash_addrs)}/{len(crash_stack_funcs)} crash stack functions")
    
    # Separate alloc and free addresses
    alloc_addrs = {}
    free_addrs = {}
    for name, addr in alloc_free.items():
        if "free" in name.lower():
            free_addrs[name] = f"0x{addr:x}"
        else:
            alloc_addrs[name] = f"0x{addr:x}"
    
    # Generate GDB config JSON
    gdb_config = {
        "system_map_path": runtime_symbols.system_map_path,
        "alloc_addrs": alloc_addrs,
        "free_addrs": free_addrs,
        "crash_stack_addrs": {name: f"0x{addr:x}" for name, addr in crash_addrs.items()},
        "crash_stack_funcs": crash_stack_funcs or [],
        "extraction_method": runtime_symbols.extraction_method,
        "kptr_restrict_disabled": runtime_symbols.kptr_restrict_disabled,
    }
    
    config_path = os.path.join(output_dir, "runtime_symbols_config.json")
    with open(config_path, 'w') as f:
        json.dump(gdb_config, f, indent=2)
    
    print(f"[SYMBOLS] Saved GDB config to: {config_path}")
    return config_path


def upload_and_run(repro_path: Path, root):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(VM_HOST, port=VM_PORT, username=VM_USER, password=VM_PASS, timeout=10)

    sftp = ssh.open_sftp()
    sftp.put(repro_path, REMOTE_PATH)
    sftp.chmod(REMOTE_PATH, 0o755)
    sftp.close()

    if root:
        stdin, stdout, stderr = ssh.exec_command(REMOTE_ROOT_CMD)
    else:
        stdin, stdout, stderr = ssh.exec_command(REMOTE_CMD)
    start = time.time()
    exit_status = None

    try:
        while not stdout.channel.exit_status_ready():
            if time.time() - start > 30:  # 10s timeout
                stdout.channel.close()    # kill command
                stderr.channel.close()
                ssh.close()
            time.sleep(0.5)

        exit_status = stdout.channel.recv_exit_status()
        logs = stdout.read().decode() + stderr.read().decode()

    finally:
        ssh.close()

    return exit_status, logs


def test_repro_crashes_qemu(repro_path: Path, local: bool, bug_id, log_dir, root, source_image: Path, source_disk: Path) -> bool:
    # Always ensure GDB script path is from SyzVerify
    gdb_script_path = Path(__file__).parent / "gdb.py"
    if not gdb_script_path.exists():
        print("[WARN] SyzVerify gdb.py not found; some instrumentation may be missing")
    else:
        print("[INFO] Using GDB script:", str(gdb_script_path))
    print("[STEP 1] Starting QEMU VM...")
    QEMU_CMD = [
        "qemu-system-x86_64",
        "-m", "2G",
        "-smp", "2",
        "-kernel", str(source_image),
        "-append", "console=ttyS0 root=/dev/vda1 earlyprintk=serial net.ifnames=0",
        "-drive", f"file={str(source_disk)},format=raw,if=virtio",
        "-netdev", "user,id=net0,host=10.0.2.10,hostfwd=tcp:127.0.0.1:10021-:22",
        "-device", "virtio-net-pci,netdev=net0",
        "-enable-kvm",
        "-nographic"
    ]

    print('[DEBUG] QEMU command:', ' '.join(QEMU_CMD))

    qemu_proc = subprocess.Popen(
        QEMU_CMD,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1
    )

    vm_logs = []
    log_ready = threading.Event()
    log_file_name = os.path.join(log_dir, f"{bug_id}_vm_output.log")

    # Open log file once
    log_fh = open(log_file_name, "w", buffering=1)

    def log_reader(proc, storage):
        for line in proc.stdout:
            storage.append(line)
            log_fh.write(line)
            if "syzkaller login:" in line:
                log_ready.set()

    log_thread = threading.Thread(target=log_reader, args=(qemu_proc, vm_logs), daemon=True)
    log_thread.start()

    def cleanup(sig=None, frame=None):
        print("\n[STEP X] Caught interrupt, shutting down VM...")
        qemu_proc.terminate()
        log_thread.join(timeout=2)
        log_fh.close()
        sys.exit(1)

    # Handle CTRL-C
    # signal.signal(signal.SIGINT, cleanup)
    crash_type = 0
    result = False
    try:
        print("[STEP 2] Waiting for VM to show login prompt...")
        log_ready.wait(timeout=20)
        

        print("[STEP 3] VM is up. Uploading and executing binary...")
        exit_status, logs = upload_and_run(repro_path, root)

        log_fh.write("\n[Program Execution Logs]\n")
        log_fh.write(logs)

        print("[STEP 4] Execution finished. Exit status:", exit_status)

        all_logs = "".join(vm_logs) + logs

        if detect_crash(all_logs):
            result = True
            crash_type = 1
            print("[STEP 5] Crash detected! See logs in", log_file_name)
        elif "reproducer may not work as expected" in all_logs.lower():
            result = False
            crash_type = 2
            print("[STEP 5] Warning: Reproducer may not work as expected. See logs in", log_file_name)
        else:
            print("[STEP 5] No crash detected. See logs in", log_file_name)

    finally:
        print("[STEP 6] Shutting down VM...")
        qemu_proc.terminate()
        log_thread.join(timeout=2)
        log_fh.close()

    return result, crash_type

# uses syz_prog2c tool to translate syzkaller DSL to C code
def syz_to_c(syz_path: Path, options: dict[str, Any]) -> str:
    # features which can be enabled / disabled
    feature_flags = set([
        'binfmt_misc',
        'cgroups',
        'close_fds',
        'devlink_pci',
        'ieee802154',
        'net_dev',
        'netdev',
        'net_reset',
        'nic_vf',
        'swap',
        'sysctl',
        'tun',
        'usb',
        'vhci',
        'wifi',
        'resetnet',
    ])

    # boolean flags which need to be converted to just cli flag
    prog2c_flags = set([
        'leak',
        'segv',
        'threaded',
        'tmpdir',
        'trace',
    ])

    features = []
    # FIXME: don't hard code
    args = ['syz-prog2c', '-prog', str(syz_path)]

    for key, value in options.items():
        # cli tool expects 0 for repate forever
        if key == 'repeat' and value is True:
            value = 0
    
        if key in prog2c_flags:
            if value is True:
                args.append(f'-{key}')
        elif key in feature_flags:
            if key == 'netdev':
                key = 'net_dev'
            elif key == 'resetnet':
                key = 'net_reset'
            if value is True:
                features.append(key)
        else:
            if key =="callcomments":
                continue
            args.append(f'-{key}')
            if key == "arch" and value == "x86_64":
                value = "amd64"
            args.append(str(value))
    
    if len(features) > 0:
        args.append('-enable')
        args.append(','.join(features))
    
    # try compiling and if it fails retry without some of the options
    try:
        return subprocess.check_output(args, stderr=subprocess.DEVNULL).decode('utf-8')
    except subprocess.CalledProcessError:
            # remove features one by one
            # if len(features) == 0:
            #     raise
            # features.pop()
        args = ['syz-prog2c', '-prog', str(syz_path)]
            # if len(features) > 0:
            #     args.append('-enable')
            #     args.append(','.join(features))
            # for key, value in options.items():
            #     if key in prog2c_flags:
            #         if value is True:
            #             args.append(f'-{key}')
            #     elif key in feature_flags:
            #         if key == 'netdev':
            #             key = 'net_dev'
            #         elif key == 'resetnet':
            #             key = 'net_reset'
            #         if value is True:
            #             features.append(key)
            #     else:
            #         if key =="callcomments":
            #             continue
            #         args.append(f'-{key}')
            #         if key == "arch" and value == "x86_64":
            #             value = "amd64"
            #         args.append(str(value))
    
    return subprocess.check_output(args, stderr=subprocess.DEVNULL).decode('utf-8')

# FIXME: don't hardcode this
# ADB assumes adb server is avaialable at localhost:5037
# To proxy cuttlefish server, us `ssh -L localhost:5037:localhost:5037 cuttlefish`
ADB_EXE_PATH = './adb'
# Set this to target a specific device (e.g., '0.0.0.0:6524') when multiple devices are connected
# ADB_TARGET_DEVICE: str | None = None
ADB_TARGET_DEVICE = '0.0.0.0:6524'

def _adb_cmd(*args) -> list[str]:
    """Build an adb command with optional device targeting."""
    cmd = [ADB_EXE_PATH]
    if ADB_TARGET_DEVICE:
        cmd.extend(['-s', ADB_TARGET_DEVICE])
    cmd.extend(args)
    return cmd

def wait_for_connection(verbose: bool = True):
    """
    Wait for ADB connection to the Cuttlefish device.
    
    This connects to an already-running Cuttlefish instance via ADB.
    Set ADB_TARGET_DEVICE to target a specific device when multiple are connected.
    """
    if verbose:
        print('[ADB] Connecting to remote Cuttlefish instance...')
        if ADB_TARGET_DEVICE:
            print(f'[ADB] Target device: {ADB_TARGET_DEVICE}')
        else:
            print(f'[ADB] Target device: auto-detect (first available)')
    
    slept_once = False
    attempts = 0
    max_attempts = 120  # 2 minute timeout
    
    while attempts < max_attempts:
        proc = subprocess.Popen([ADB_EXE_PATH, 'devices'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = proc.communicate()

        # Decode and split into lines
        lines = out.decode("utf-8", errors="ignore").splitlines()

        # The first line is usually "List of devices attached"
        # Any subsequent non‑blank lines are "<serial>\t<state>"
        available_devices = []
        for line in lines[1:]:
            line = line.strip()
            if not line:
                continue
            parts = line.split()
            if len(parts) >= 2:
                serial, state = parts[0], parts[1]
                available_devices.append((serial, state))
                
                # If targeting a specific device, only match that one
                if ADB_TARGET_DEVICE and serial != ADB_TARGET_DEVICE:
                    continue
                if state == "device":
                    if slept_once:
                        if verbose:
                            print(f"[ADB] Device {serial} is now available")
                            print("[ADB] Waiting 45 seconds for system to finish booting...")
                        time.sleep(45)
                        # TODO this should be done better, the proper way is to wait for: "VIRTUAL_DEVICE_BOOT_COMPLETED"
                    if verbose:
                        print(f"[ADB] Connected to Cuttlefish device: {serial}")
                    return
        
        # Show available devices if target not found
        if verbose and attempts % 10 == 0:
            if available_devices:
                print(f'[ADB] Available devices: {available_devices}')
                if ADB_TARGET_DEVICE:
                    print(f'[ADB] Waiting for target device {ADB_TARGET_DEVICE}...')
            else:
                print('[ADB] No devices found, waiting...')
        
        time.sleep(1)
        slept_once = True
        attempts += 1
    
    # Timeout reached
    raise TimeoutError(f"[ADB] Timeout waiting for device after {max_attempts} seconds")


def adb_upload_file(file: Path, upload_location: Path):
    subprocess.run(_adb_cmd('push', str(file), str(upload_location)), check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def is_device_connected() -> bool:
    # Output looks like:
    # List of devices attached
    # 0.0.0.0:6520    offline

    result = subprocess.check_output([ADB_EXE_PATH, 'devices']).decode().strip().split('\n')
    # if no devices in device list, not connected
    if len(result) == 1:
        return False
    
    # Find the target device or use the first one
    for line in result[1:]:
        line = line.strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) >= 2:
            serial, status = parts[0], parts[1]
            if ADB_TARGET_DEVICE:
                if serial == ADB_TARGET_DEVICE:
                    return status == 'device'
            else:
                # Original behavior: check first device
                return status == 'device'
    return False

def get_uptime() -> float:
    try:
        output = subprocess.check_output(_adb_cmd('shell', 'cat /proc/uptime')).decode()
        return float(output.strip().split()[0])
    except subprocess.CalledProcessError:
        return 0.0


def ensure_device_ready(
    max_wait: int = 60,
    ssh_host: str = None,
    stop_cmd: str = None,
    start_cmd: str = None,
    verbose: bool = True,
    instance: int = None,
    adb_port: int = 6520,
) -> bool:
    """
    Ensure the device is connected and ready before running a test.
    
    This function:
    1. Checks if device is connected and in 'device' state
    2. If offline/disconnected, waits up to max_wait seconds
    3. If still offline after waiting, offers to restart the device
    
    For remote Cuttlefish (ssh_host provided), checks connectivity via SSH
    by running ADB commands on the remote host.
    
    Args:
        max_wait: Maximum seconds to wait for device to come online (default: 60)
        ssh_host: SSH host for remote Cuttlefish (if remote)
        stop_cmd: Command to stop Cuttlefish (optional)
        start_cmd: Command to start Cuttlefish (optional)
        verbose: Whether to print status messages
        instance: Cuttlefish instance number (for calculating ADB port)
        adb_port: Base ADB port (default: 6520)
        
    Returns:
        True if device is ready, False if user chose to skip/abort
    """
    # Calculate actual ADB port from instance
    actual_adb_port = adb_port
    if instance is not None:
        actual_adb_port = 6520 + (instance - 1)
    
    # Determine if this is a remote check
    is_remote = ssh_host and ssh_host not in ('localhost', '127.0.0.1')
    
    if verbose:
        print()
        print("-" * 60)
        print("[PRE-CHECK] Verifying device connectivity...")
        print("-" * 60)
        if is_remote:
            print(f"[PRE-CHECK] Remote host: {ssh_host}, ADB port: {actual_adb_port}")
    
    def check_device() -> bool:
        """Check if device is connected - locally or via SSH."""
        if is_remote:
            return _check_remote_device(ssh_host, actual_adb_port, verbose=False)
        else:
            return is_device_connected()
    
    # First check - is device connected?
    if check_device():
        if verbose:
            print(f"[OK] Device is connected and ready")
        return True
    
    # Device is not in good state - wait for it
    if verbose:
        print(f"[WAIT] Device is offline or disconnected, waiting up to {max_wait}s...")
    
    start_time = time.time()
    check_interval = 5  # Check every 5 seconds
    
    while (time.time() - start_time) < max_wait:
        time.sleep(check_interval)
        elapsed = int(time.time() - start_time)
        
        if check_device():
            if verbose:
                print(f"[OK] Device came online after {elapsed}s")
                # Wait a bit more for system stability
                print("[WAIT] Waiting 10s for system stability...")
                time.sleep(10)
            return True
        
        if verbose and elapsed % 15 == 0:
            print(f"[WAIT] Still waiting... ({elapsed}s / {max_wait}s)")
    
    # Timeout - device still not ready
    if verbose:
        print(f"[TIMEOUT] Device did not come online after {max_wait}s")
    
    # If we have restart commands, offer to use them
    if stop_cmd and start_cmd:
        print()
        print("=" * 60)
        print("RESTARTING DEVICE")
        print("=" * 60)
        print()
        
        _restart_device(ssh_host, stop_cmd, start_cmd, verbose, instance, adb_port)
    else:
        # No restart commands - just offer manual intervention
        print()
        print("[MANUAL] No restart commands configured.")
        print("[MANUAL] Please start the device manually, then press Enter (or Ctrl+C to abort)...")
        try:
            input()
        except (EOFError, KeyboardInterrupt):
            print("\n[ABORT] User cancelled")
            return False
        
        if check_device():
            print("[OK] Device is now connected")
            return True
        else:
            print("[ERROR] Device still not connected")
            return False


def _check_remote_device(ssh_host: str, adb_port: int, verbose: bool = True) -> bool:
    """
    Check if a Cuttlefish device is connected on a remote host via SSH.
    
    Runs 'adb -s 0.0.0.0:<port> shell echo ok' on the remote host to check
    if the device is responsive.
    
    Args:
        ssh_host: SSH host to connect to
        adb_port: ADB port on the remote host
        verbose: Print status messages
        
    Returns:
        True if device responds, False otherwise
    """
    try:
        # Run adb command on remote host to check device status
        adb_target = f"0.0.0.0:{adb_port}"
        check_cmd = f"adb -s {adb_target} shell echo ok 2>/dev/null"
        
        result = subprocess.run(
            ['ssh', ssh_host, check_cmd],
            capture_output=True,
            text=True,
            timeout=15
        )
        
        if result.returncode == 0 and 'ok' in result.stdout:
            if verbose:
                print(f"[SSH] Device at {ssh_host}:{adb_port} is responsive")
            return True
        else:
            if verbose:
                print(f"[SSH] Device at {ssh_host}:{adb_port} not responding")
            return False
            
    except subprocess.TimeoutExpired:
        if verbose:
            print(f"[SSH] Timeout checking device at {ssh_host}:{adb_port}")
        return False
    except Exception as e:
        if verbose:
            print(f"[SSH] Error checking device: {e}")
        return False


def _restart_device(
    ssh_host: str = None,
    stop_cmd: str = None,
    start_cmd: str = None,
    verbose: bool = True,
    instance: int = None,
    adb_port: int = 6520,
) -> bool:
    """
    Restart the Cuttlefish device using provided commands.
    
    Returns True if device comes online after restart, False otherwise.
    """
    # Calculate actual ADB port
    actual_adb_port = adb_port
    if instance is not None:
        actual_adb_port = 6520 + (instance - 1)
    
    is_remote = ssh_host and ssh_host not in ('localhost', '127.0.0.1')
    
    if verbose:
        print("[RESTART] Attempting to restart device...")
    
    try:
        # Stop the device
        if stop_cmd:
            if verbose:
                print(f"[STOP] Running: {stop_cmd}")
            if ssh_host and ssh_host != 'localhost':
                result = subprocess.run(
                    ['ssh', ssh_host, stop_cmd],
                    capture_output=True,
                    text=True,
                    timeout=60
                )
            else:
                result = subprocess.run(
                    stop_cmd,
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=60
                )
            if verbose:
                print(f"[STOP] Exit code: {result.returncode}")
            time.sleep(5)  # Wait for clean shutdown
        
        # Start the device
        if start_cmd:
            if verbose:
                print(f"[START] Running: {start_cmd}")
            if ssh_host and ssh_host != 'localhost':
                result = subprocess.run(
                    ['ssh', ssh_host, start_cmd],
                    capture_output=True,
                    text=True,
                    timeout=300  # 5 min for boot
                )
            else:
                result = subprocess.run(
                    start_cmd,
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=300
                )
            if verbose:
                print(f"[START] Exit code: {result.returncode}")
            
            # Wait for device to boot
            print("[BOOT] Waiting for device to boot (up to 120s)...")
            for i in range(24):  # 24 * 5 = 120 seconds
                time.sleep(5)
                # Check device - use remote check if remote host
                if is_remote:
                    device_ready = _check_remote_device(ssh_host, actual_adb_port, verbose=False)
                else:
                    device_ready = is_device_connected()
                    
                if device_ready:
                    print(f"[OK] Device came online after restart ({(i+1)*5}s)")
                    print("[WAIT] Waiting 30s for system to fully boot...")
                    time.sleep(30)
                    return True
                if verbose and (i+1) % 4 == 0:
                    print(f"[BOOT] Still waiting... ({(i+1)*5}s)")
            
            print("[ERROR] Device did not come online after restart")
            return False
        else:
            print("[ERROR] No start command provided")
            return False
            
    except subprocess.TimeoutExpired:
        print("[ERROR] Command timed out")
        return False
    except Exception as e:
        print(f"[ERROR] Restart failed: {e}")
        return False


# Path of repro in android VM
REPRO_PATH = '/data/local/tmp/repro'

# assumes an instance of cuttlefish VM is already running
# tests the exploit at the given path to see if it crashes the kernel
# returns true if it does
def test_repro_crashes(repro_path: Path, local: bool, id, log_dir, root=True) -> bool:
    # Always ensure GDB script path is from SyzVerify for cuttlefish flows
    gdb_script_path = Path(__file__).parent / "gdb.py"
    if not gdb_script_path.exists():
        print("[WARN] SyzVerify gdb.py not found; some instrumentation may be missing")
    else:
        print("[INFO] Using GDB script:", str(gdb_script_path))
    wait_for_connection()

    adb_upload_file(repro_path, Path(REPRO_PATH))

    crash_occured = False, 0
    t0 = get_uptime()

    if root:
        run_repro_cmd = f'cd {os.path.dirname(REPRO_PATH)} && su root {REPRO_PATH}'
    else:
        run_repro_cmd = f'cd {os.path.dirname(REPRO_PATH)} && {REPRO_PATH}'
    print(run_repro_cmd)
    with subprocess.Popen(_adb_cmd('shell', run_repro_cmd)) as exploit_process:
        # wait for exploit to run a bit
        time.sleep(5)

        exploit_process.poll()
        t1 = get_uptime()
        if t1 < t0 or not is_device_connected():
            print("crash_occured CONDITION 1", t1, t0)
            crash_occured = True, 1
        elif exploit_process.returncode is not None:
            print("crash_occured CONDITION 2")
            crash_occured = True, 2
        elif not is_device_connected():
            print("crash_occured CONDITION 3")
            crash_occured = True, 1
        
        exploit_process.terminate()
    
    subprocess.Popen(_adb_cmd('shell', 'su', 'root', 'killall', 'repro')).communicate()
    return crash_occured


# ============================================================================
# Cuttlefish GDB-based Dynamic Analysis
# ============================================================================

# Default GDB port for Cuttlefish (configurable)
CUTTLEFISH_GDB_PORT = 1234

# Remote path for gdbserver on the device
GDBSERVER_REMOTE_PATH = '/data/local/tmp/gdbserver'
GDBSERVER_PORT = 2345


def _adb_shell(cmd: str, timeout: int = 30) -> Tuple[bool, str, str]:
    """Execute an ADB shell command and return (success, stdout, stderr)."""
    try:
        result = subprocess.run(
            _adb_cmd('shell', cmd),
            capture_output=True,
            text=True,
            timeout=timeout
        )
        return result.returncode == 0, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return False, "", "Command timed out"
    except Exception as e:
        return False, "", str(e)


def _adb_forward(host_port: int, device_port: int) -> bool:
    """Set up ADB port forwarding."""
    try:
        result = subprocess.run(
            _adb_cmd('forward', f'tcp:{host_port}', f'tcp:{device_port}'),
            capture_output=True,
            timeout=10
        )
        return result.returncode == 0
    except Exception as e:
        print(f"[ERROR] ADB forward failed: {e}")
        return False


def _adb_forward_remove(host_port: int) -> bool:
    """Remove ADB port forwarding."""
    try:
        subprocess.run(
            _adb_cmd('forward', '--remove', f'tcp:{host_port}'),
            capture_output=True,
            timeout=10
        )
        return True
    except Exception:
        return False


def _upload_gdbserver(arch: str = "arm64") -> bool:
    """Upload gdbserver to the device if not present."""
    # Check if gdbserver already exists on device
    success, stdout, _ = _adb_shell('test -x /data/local/tmp/gdbserver && echo EXISTS')
    if 'EXISTS' in stdout:
        print("[INFO] gdbserver already present on device")
        return True
    
    # Find local gdbserver binary
    repo_root = Path(__file__).resolve().parents[3]
    gdbserver_candidates = [
        repo_root / f"gdbserver_{arch}",
        repo_root / "gdbserver_arm64",
        repo_root / "gdbserver_aarch64",
        Path(f"/workspace/syzploit/gdbserver_{arch}"),
    ]
    
    gdbserver_path = None
    for candidate in gdbserver_candidates:
        if candidate.exists():
            gdbserver_path = candidate
            break
    
    if not gdbserver_path:
        print("[WARN] Could not find gdbserver binary to upload")
        return False
    
    try:
        subprocess.run(
            _adb_cmd('push', str(gdbserver_path), GDBSERVER_REMOTE_PATH),
            check=True,
            capture_output=True,
            timeout=30
        )
        _adb_shell(f'chmod +x {GDBSERVER_REMOTE_PATH}')
        print(f"[INFO] Uploaded gdbserver to {GDBSERVER_REMOTE_PATH}")
        return True
    except Exception as e:
        print(f"[ERROR] Failed to upload gdbserver: {e}")
        return False


def _generate_cuttlefish_gdb_script(
    repro_remote_path: str,
    output_file: str,
    fault_addr: int = None,
    fault_insn: int = None,
    access_type: str = "any",
    access_size: int = 0,
    poc_entry: str = "main",
    monitor_mode: bool = True
) -> str:
    """Generate a GDB Python script for Cuttlefish userspace analysis."""
    
    # Read the base userspace GDB script
    base_script_path = Path(__file__).parent / "userspace_gdb.py"
    if not base_script_path.exists():
        # Fallback to a minimal script
        base_script = ""
    else:
        with open(base_script_path, 'r') as f:
            base_script = f.read()
    
    config_header = f'''#!/usr/bin/env python3
# Auto-generated GDB configuration for Cuttlefish userspace analysis
import gdb
import json
import time

# Configuration
reproducer_path = "{repro_remote_path}"
output_file = "{output_file}"
fault_addr = {fault_addr if fault_addr else 'None'}
fault_insn = {fault_insn if fault_insn else 'None'}
access_type = "{access_type}"
access_size = {access_size}
poc_entry = "{poc_entry}"
monitor_mode = {monitor_mode}

# Event collection
events = []
syscalls_traced = []
memory_accesses = []

def log_event(event_type, data):
    """Log an event with timestamp."""
    events.append({{
        "type": event_type,
        "timestamp": time.time(),
        "data": data
    }})

class SyscallCatcher(gdb.Breakpoint):
    """Catch syscall entry/exit for tracing."""
    def __init__(self):
        # Try to set catchpoint on syscalls
        try:
            super().__init__("syscall", gdb.BP_CATCHPOINT)
            self.silent = True
        except Exception:
            pass
    
    def stop(self):
        try:
            frame = gdb.selected_frame()
            pc = frame.pc()
            # Get syscall number from register (arm64: x8, x86_64: rax)
            try:
                syscall_num = int(gdb.parse_and_eval("$x8"))
            except:
                try:
                    syscall_num = int(gdb.parse_and_eval("$rax"))
                except:
                    syscall_num = -1
            
            log_event("syscall", {{"pc": hex(pc), "syscall_num": syscall_num}})
            syscalls_traced.append(syscall_num)
        except Exception as e:
            pass
        return False  # Don't stop, just log

class MemoryAccessWatchpoint(gdb.Breakpoint):
    """Watch memory accesses to specific address."""
    def __init__(self, addr, size=8, access="rw"):
        try:
            if access == "read":
                wp_type = gdb.WP_READ
            elif access == "write":
                wp_type = gdb.WP_WRITE
            else:
                wp_type = gdb.WP_ACCESS
            
            super().__init__(f"*{{hex(addr)}}", gdb.BP_WATCHPOINT, wp_class=wp_type)
            self.silent = True
            self.watch_addr = addr
        except Exception as e:
            gdb.write(f"[WARN] Could not set watchpoint at {{hex(addr)}}: {{e}}\\n")
    
    def stop(self):
        try:
            frame = gdb.selected_frame()
            pc = frame.pc()
            log_event("memory_access", {{
                "pc": hex(pc),
                "address": hex(self.watch_addr),
                "type": "access"
            }})
            memory_accesses.append({{"pc": pc, "addr": self.watch_addr}})
        except Exception:
            pass
        return False

class ExportResultsCommand(gdb.Command):
    """Export collected results to JSON file."""
    def __init__(self):
        super().__init__("cf_export_results", gdb.COMMAND_USER)
    
    def invoke(self, arg, from_tty):
        output_path = arg.strip() if arg.strip() else output_file
        results = {{
            "events": events,
            "syscalls_traced": syscalls_traced,
            "memory_accesses": memory_accesses,
            "fault_addr": fault_addr,
            "fault_insn": fault_insn,
            "total_events": len(events)
        }}
        try:
            with open(output_path, 'w') as f:
                json.dump(results, f, indent=2)
            gdb.write(f"[INFO] Results exported to {{output_path}}\\n")
        except Exception as e:
            gdb.write(f"[ERROR] Failed to export results: {{e}}\\n")

# Register commands
ExportResultsCommand()

# Set up watchpoint if fault_addr is specified
if fault_addr is not None:
    try:
        MemoryAccessWatchpoint(fault_addr, access_size or 8)
        gdb.write(f"[INFO] Set watchpoint on fault address {{hex(fault_addr)}}\\n")
    except Exception as e:
        gdb.write(f"[WARN] Could not set fault_addr watchpoint: {{e}}\\n")

# Try to set syscall catchpoint
try:
    SyscallCatcher()
    gdb.write("[INFO] Syscall tracing enabled\\n")
except Exception as e:
    gdb.write(f"[WARN] Could not enable syscall tracing: {{e}}\\n")

gdb.write("[INFO] Cuttlefish GDB script loaded\\n")
'''
    
    return config_header


def test_repro_crashes_cuttlefish_gdb(
    repro_path: Path,
    local: bool,
    bug_id: str,
    log_dir: str,
    root: bool = True,
    parsed_crash: dict = None,
    gdb_port: int = GDBSERVER_PORT,
    timeout: int = 60,
    arch: str = "arm64"
) -> Tuple[bool, int, dict]:
    """
    Test reproducer on an already-running Cuttlefish instance with GDB-based dynamic analysis.
    
    This function connects to an existing Cuttlefish VM via ADB and:
    1. Uploads the reproducer and gdbserver to the device
    2. Sets up ADB port forwarding for gdbserver
    3. Runs the reproducer under gdbserver
    4. Connects GDB with instrumentation script
    5. Collects and returns dynamic analysis results
    
    NOTE: This requires a Cuttlefish instance to already be running and accessible via ADB.
    Use ADB_TARGET_DEVICE to specify a specific device if multiple are connected.
    
    Args:
        repro_path: Path to compiled reproducer binary
        local: Whether using local Cuttlefish instance
        bug_id: Bug identifier for logging
        log_dir: Directory to save logs
        root: Whether to run as root
        parsed_crash: Parsed crash information from crash_analyzer
        gdb_port: Port for gdbserver connection on device
        timeout: Execution timeout in seconds
        arch: Target architecture
        
    Returns:
        Tuple of (crash_occurred, crash_type, dynamic_results)
    """
    print()
    print("=" * 80)
    print("  CUTTLEFISH GDB DYNAMIC ANALYSIS")
    print("=" * 80)
    print()
    print(f"[CUTTLEFISH] Bug ID: {bug_id}")
    print(f"[CUTTLEFISH] Target device: {ADB_TARGET_DEVICE or 'auto-detect (first available)'}")
    print(f"[CUTTLEFISH] Architecture: {arch}")
    print(f"[CUTTLEFISH] Run as root: {root}")
    print(f"[CUTTLEFISH] Log directory: {log_dir}")
    print()
    
    gdb_script_path = Path(__file__).parent / "gdb.py"
    userspace_gdb_path = Path(__file__).parent / "userspace_gdb.py"
    
    print(f"[CUTTLEFISH] Kernel GDB script: {gdb_script_path}")
    print(f"[CUTTLEFISH] Userspace GDB script: {userspace_gdb_path}")
    print()
    
    # Step 1: Connect to running Cuttlefish via ADB
    print("-" * 60)
    print("[STEP 1] Connecting to remote Cuttlefish instance via ADB...")
    print("-" * 60)
    wait_for_connection()
    
    # Get device info
    success, device_info, _ = _adb_shell('getprop ro.product.model')
    device_model = device_info.strip() if success else "Unknown"
    success, android_version, _ = _adb_shell('getprop ro.build.version.release')
    android_ver = android_version.strip() if success else "Unknown"
    success, kernel_ver, _ = _adb_shell('uname -r')
    kernel_version = kernel_ver.strip() if success else "Unknown"
    
    print(f"[CUTTLEFISH] Connected to device:")
    print(f"             Device Model: {device_model}")
    print(f"             Android Version: {android_ver}")
    print(f"             Kernel Version: {kernel_version}")
    print()
    
    # Create log directory
    os.makedirs(log_dir, exist_ok=True)
    
    # Step 2: Upload reproducer
    print("-" * 60)
    print("[STEP 2] Uploading reproducer binary to device...")
    print("-" * 60)
    print(f"[CUTTLEFISH] Local path: {repro_path}")
    print(f"[CUTTLEFISH] Remote path: {REPRO_PATH}")
    
    adb_upload_file(repro_path, Path(REPRO_PATH))
    _adb_shell(f'chmod +x {REPRO_PATH}')
    
    # Verify upload
    success, file_info, _ = _adb_shell(f'ls -la {REPRO_PATH}')
    if success:
        print(f"[CUTTLEFISH] Upload successful: {file_info.strip()}")
    else:
        print(f"[CUTTLEFISH] WARNING: Could not verify upload")
    print()
    
    # Step 3: Upload gdbserver if needed
    print("-" * 60)
    print("[STEP 3] Checking/uploading gdbserver...")
    print("-" * 60)
    gdbserver_ready = _upload_gdbserver(arch)
    if gdbserver_ready:
        print(f"[CUTTLEFISH] gdbserver available at: {GDBSERVER_REMOTE_PATH}")
    else:
        print(f"[CUTTLEFISH] WARNING: gdbserver not available, will use direct execution")
    print()
    
    dynamic_results = {
        "bug_id": bug_id,
        "device_model": device_model,
        "android_version": android_ver,
        "kernel_version": kernel_version,
        "target_device": ADB_TARGET_DEVICE,
        "events": [],
        "syscalls": [],
        "crash_detected": False,
        "gdb_available": gdbserver_ready,
        "analysis_mode": "gdb" if gdbserver_ready else "direct"
    }
    
    crash_occurred = False
    crash_type = 0
    
    # Step 4: Extract fault info from parsed crash
    print("-" * 60)
    print("[STEP 4] Extracting crash information for instrumentation...")
    print("-" * 60)
    
    fault_addr = None
    fault_insn = None
    access_type = "any"
    
    if parsed_crash:
        if parsed_crash.get('access', {}).get('address'):
            try:
                addr_str = parsed_crash['access']['address']
                fault_addr = int(addr_str, 16) if addr_str.startswith('0x') else int(addr_str)
                print(f"[CUTTLEFISH] Fault address: {hex(fault_addr)}")
            except Exception:
                pass
        
        for frame in parsed_crash.get('frames', []):
            if frame.get('ip'):
                try:
                    ip = frame['ip']
                    fault_insn = int(ip, 16) if ip.startswith('0x') else int(ip)
                    print(f"[CUTTLEFISH] Fault instruction: {hex(fault_insn)}")
                    break
                except Exception:
                    continue
        
        access_type = parsed_crash.get('access', {}).get('type', 'any')
        print(f"[CUTTLEFISH] Access type: {access_type}")
        
        if parsed_crash.get('crash_type'):
            print(f"[CUTTLEFISH] Crash type: {parsed_crash.get('crash_type')}")
    else:
        print(f"[CUTTLEFISH] No parsed crash info available")
    
    dynamic_results["fault_addr"] = hex(fault_addr) if fault_addr else None
    dynamic_results["fault_insn"] = hex(fault_insn) if fault_insn else None
    dynamic_results["access_type"] = access_type
    print()
    
    t0 = get_uptime()
    print(f"[CUTTLEFISH] Device uptime at start: {t0:.2f}s")
    
    # Step 5: Set up GDB analysis
    if gdbserver_ready:
        print("-" * 60)
        print("[STEP 5] Setting up GDB-based dynamic analysis...")
        print("-" * 60)
        
        # Set up port forwarding
        host_gdb_port = gdb_port + 10000  # Use high port to avoid conflicts
        print(f"[CUTTLEFISH] Setting up ADB port forwarding:")
        print(f"             Host port: {host_gdb_port} -> Device port: {gdb_port}")
        
        if not _adb_forward(host_gdb_port, gdb_port):
            print(f"[CUTTLEFISH] ERROR: Could not set up port forwarding")
            print(f"[CUTTLEFISH] Falling back to direct execution mode")
            gdbserver_ready = False
        else:
            print(f"[CUTTLEFISH] Port forwarding established")
        print()
    
    if gdbserver_ready:
        try:
            # Generate GDB script
            print("-" * 60)
            print("[STEP 6] Generating and deploying GDB instrumentation script...")
            print("-" * 60)
            
            results_file = os.path.join(log_dir, f"{bug_id}_gdb_results.json")
            gdb_script_content = _generate_cuttlefish_gdb_script(
                REPRO_PATH,
                results_file,
                fault_addr=fault_addr,
                fault_insn=fault_insn,
                access_type=access_type,
                monitor_mode=True
            )
            
            script_file = os.path.join(log_dir, f"{bug_id}_gdb_script.py")
            with open(script_file, 'w') as f:
                f.write(gdb_script_content)
            print(f"[CUTTLEFISH] Generated GDB script: {script_file}")
            print(f"[CUTTLEFISH] Results will be saved to: {results_file}")
            print()
            
            # Start gdbserver on device
            print("-" * 60)
            print("[STEP 7] Starting gdbserver on remote Cuttlefish device...")
            print("-" * 60)
            
            if root:
                gdbserver_cmd = f'su root sh -c "{GDBSERVER_REMOTE_PATH} :{gdb_port} {REPRO_PATH} &"'
            else:
                gdbserver_cmd = f'{GDBSERVER_REMOTE_PATH} :{gdb_port} {REPRO_PATH} &'
            
            print(f"[CUTTLEFISH] gdbserver command: {gdbserver_cmd}")
            
            gdbserver_proc = subprocess.Popen(
                _adb_cmd('shell', gdbserver_cmd),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            # Wait for gdbserver to start
            print(f"[CUTTLEFISH] Waiting for gdbserver to initialize...")
            time.sleep(2)
            
            # Check if gdbserver is listening
            gdb_ready = False
            print(f"[CUTTLEFISH] Checking gdbserver connection on 127.0.0.1:{host_gdb_port}...")
            for attempt in range(10):
                try:
                    with socket.create_connection(("127.0.0.1", host_gdb_port), timeout=1):
                        gdb_ready = True
                        print(f"[CUTTLEFISH] gdbserver ready! (attempt {attempt + 1})")
                        break
                except Exception:
                    if attempt < 9:
                        print(f"[CUTTLEFISH] Waiting... (attempt {attempt + 1}/10)")
                    time.sleep(0.5)
            print()
            
            if gdb_ready:
                print("-" * 60)
                print("[STEP 8] Connecting GDB to remote gdbserver...")
                print("-" * 60)
                
                gdb_log = os.path.join(log_dir, f"{bug_id}_gdb.log")
                gdb_cmd = [
                    "gdb",
                    "-q",
                    "-ex", f"set logging file {gdb_log}",
                    "-ex", "set logging overwrite on",
                    "-ex", "set logging enabled on",
                    "-ex", "set pagination off",
                    "-ex", "set confirm off",
                    "-ex", f"target remote :{host_gdb_port}",
                    "-ex", f"source {script_file}",
                    "-ex", "continue",
                ]
                
                print(f"[CUTTLEFISH] GDB log file: {gdb_log}")
                print(f"[CUTTLEFISH] Timeout: {timeout}s")
                print(f"[CUTTLEFISH] Executing GDB...")
                print()
                
                gdb_proc = subprocess.Popen(
                    gdb_cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
                
                try:
                    gdb_stdout, gdb_stderr = gdb_proc.communicate(timeout=timeout)
                    
                    # Save raw GDB output
                    stdout_log = os.path.join(log_dir, f"{bug_id}_gdb_stdout.log")
                    stderr_log = os.path.join(log_dir, f"{bug_id}_gdb_stderr.log")
                    with open(stdout_log, 'w') as f:
                        f.write(gdb_stdout or "")
                    with open(stderr_log, 'w') as f:
                        f.write(gdb_stderr or "")
                    
                    print(f"[CUTTLEFISH] GDB execution completed")
                    print(f"[CUTTLEFISH] Saved stdout to: {stdout_log}")
                    print(f"[CUTTLEFISH] Saved stderr to: {stderr_log}")
                    
                    # Try to load results
                    if os.path.exists(results_file):
                        with open(results_file, 'r') as f:
                            gdb_results = json.load(f)
                        dynamic_results.update(gdb_results)
                        print(f"[CUTTLEFISH] Loaded {len(gdb_results.get('events', []))} events from results")
                    else:
                        print(f"[CUTTLEFISH] No results file generated")
                    
                except subprocess.TimeoutExpired:
                    print(f"[CUTTLEFISH] WARNING: GDB execution timed out after {timeout}s")
                    gdb_proc.kill()
                    dynamic_results["timeout"] = True
                
                print()
            else:
                print(f"[CUTTLEFISH] ERROR: gdbserver did not become ready")
                print(f"[CUTTLEFISH] Falling back to direct execution mode")
                gdbserver_ready = False
            
            # Cleanup gdbserver
            print("[CUTTLEFISH] Cleaning up gdbserver process...")
            _adb_shell('killall gdbserver 2>/dev/null')
            
        except Exception as e:
            print(f"[CUTTLEFISH] ERROR: GDB analysis failed: {e}")
            import traceback
            traceback.print_exc()
            gdbserver_ready = False
        finally:
            # Remove port forwarding
            _adb_forward_remove(host_gdb_port)
            print(f"[CUTTLEFISH] Removed port forwarding")
    
    # Fallback to direct execution if GDB didn't work
    if not gdbserver_ready:
        print("-" * 60)
        print("[FALLBACK] Running reproducer directly (no GDB instrumentation)...")
        print("-" * 60)
        
        dynamic_results["analysis_mode"] = "direct"
        
        if root:
            run_repro_cmd = f'cd {os.path.dirname(REPRO_PATH)} && su root {REPRO_PATH}'
        else:
            run_repro_cmd = f'cd {os.path.dirname(REPRO_PATH)} && {REPRO_PATH}'
        
        print(f"[CUTTLEFISH] Command: {run_repro_cmd}")
        
        with subprocess.Popen(_adb_cmd('shell', run_repro_cmd)) as exploit_process:
            print(f"[CUTTLEFISH] Running reproducer for 5 seconds...")
            time.sleep(5)
            
            exploit_process.poll()
            t1 = get_uptime()
            
            print(f"[CUTTLEFISH] Device uptime after execution: {t1:.2f}s")
            
            if t1 < t0 or not is_device_connected():
                print(f"[CUTTLEFISH] CRASH DETECTED: Device reboot detected (uptime reset)")
                crash_occurred = True
                crash_type = 1
            elif exploit_process.returncode is not None:
                print(f"[CUTTLEFISH] CRASH DETECTED: Reproducer exited with code {exploit_process.returncode}")
                crash_occurred = True
                crash_type = 2
            elif not is_device_connected():
                print(f"[CUTTLEFISH] CRASH DETECTED: Device disconnected")
                crash_occurred = True
                crash_type = 1
            else:
                print(f"[CUTTLEFISH] No crash detected during direct execution")
            
            exploit_process.terminate()
        print()
    
    # Final crash check
    print("-" * 60)
    print("[FINAL] Checking device state...")
    print("-" * 60)
    
    t1 = get_uptime()
    print(f"[CUTTLEFISH] Final uptime: {t1:.2f}s (started at {t0:.2f}s)")
    
    if t1 < t0 or not is_device_connected():
        crash_occurred = True
        crash_type = 1
        dynamic_results["crash_detected"] = True
        print(f"[CUTTLEFISH] CRASH CONFIRMED: Device appears to have crashed/rebooted")
    else:
        print(f"[CUTTLEFISH] Device stable, no crash detected")
    
    # Cleanup
    print(f"[CUTTLEFISH] Cleaning up reproducer process...")
    subprocess.Popen(_adb_cmd('shell', 'su', 'root', 'killall', 'repro')).communicate()
    
    # Save dynamic results
    dynamic_results["crash_occurred"] = crash_occurred
    dynamic_results["crash_type"] = crash_type
    dynamic_results["uptime_start"] = t0
    dynamic_results["uptime_end"] = t1
    
    results_output = os.path.join(log_dir, f"{bug_id}_dynamic_analysis.json")
    with open(results_output, 'w') as f:
        json.dump(dynamic_results, f, indent=2)
    
    print()
    print("=" * 80)
    print("  ANALYSIS COMPLETE")
    print("=" * 80)
    print(f"[CUTTLEFISH] Results saved to: {results_output}")
    print(f"[CUTTLEFISH] Crash detected: {crash_occurred}")
    print(f"[CUTTLEFISH] Crash type: {crash_type}")
    print(f"[CUTTLEFISH] Analysis mode: {dynamic_results['analysis_mode']}")
    print("=" * 80)
    print()
    
    return crash_occurred, crash_type, dynamic_results

# =============================================================================
# KERNEL-SIDE GDB DEBUGGING FOR CUTTLEFISH
# =============================================================================

# Default kernel GDB port (Cuttlefish QEMU GDB stub)
CUTTLEFISH_KERNEL_GDB_PORT = 1234


def test_repro_crashes_cuttlefish_kernel_gdb(
    repro_path: str,
    bug_id: str,
    vmlinux_path: str = None,
    kernel_gdb_port: int = CUTTLEFISH_KERNEL_GDB_PORT,
    parsed_crash: dict = None,
    log_dir: str = ".",
    root: bool = True,
    timeout: int = 120,
    arch: str = "arm64",
    demo: bool = False,
) -> Tuple[bool, int, dict]:
    """
    Perform kernel-side GDB debugging on a Cuttlefish instance.
    
    This function connects to the QEMU GDB stub that Cuttlefish exposes when
    launched with --gdb_port. It sets kernel breakpoints and runs the 
    reproducer while monitoring kernel execution.
    
    Prerequisites:
    - Cuttlefish must be launched with:
      launch_cvd -vm_manager qemu_cli --gdb_port 1234 -extra_kernel_cmdline "nokaslr"
    - ADB connection to the Cuttlefish instance must be available
    - vmlinux file should be available for symbol resolution
    
    Args:
        repro_path: Path to the compiled reproducer binary
        bug_id: Unique identifier for the bug
        vmlinux_path: Path to vmlinux file with debug symbols (optional)
        kernel_gdb_port: GDB port for QEMU stub (default: 1234)
        parsed_crash: Parsed crash information for instrumentation
        log_dir: Directory for output logs
        root: Whether to run as root
        timeout: Timeout for GDB execution
        arch: Target architecture (arm64 or x86_64)
        demo: Demo mode - generate sample data if real tracing fails
    
    Returns:
        Tuple of (crash_occurred, crash_type, dynamic_results)
    """
    print()
    print("=" * 80)
    print("  CUTTLEFISH KERNEL GDB ANALYSIS")
    print("=" * 80)
    print(f"[CONFIG] Bug ID: {bug_id}")
    print(f"[CONFIG] Reproducer: {repro_path}")
    print(f"[CONFIG] vmlinux: {vmlinux_path or 'Not provided'}")
    print(f"[CONFIG] Kernel GDB Port: {kernel_gdb_port}")
    print(f"[CONFIG] Target Device: {ADB_TARGET_DEVICE}")
    print(f"[CONFIG] Architecture: {arch}")
    print(f"[CONFIG] Log Directory: {log_dir}")
    print(f"[CONFIG] Demo Mode: {demo}")
    print()
    
    # Step 1: Check GDB port connectivity
    print("-" * 60)
    print("[STEP 1] Checking kernel GDB stub connectivity...")
    print("-" * 60)
    
    def check_gdb_port(host: str, port: int, timeout_sec: int = 5) -> bool:
        """Check if the GDB port is reachable."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout_sec)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except Exception:
            return False
    
    gdb_host = "127.0.0.1"
    if not check_gdb_port(gdb_host, kernel_gdb_port):
        print(f"[ERROR] Cannot connect to kernel GDB stub at {gdb_host}:{kernel_gdb_port}")
        print()
        print("  Please ensure Cuttlefish was launched with GDB enabled:")
        print("    launch_cvd -vm_manager qemu_cli --gdb_port 1234 \\")
        print("               -extra_kernel_cmdline \"nokaslr\"")
        print()
        print("  If using the QEMU wrapper script, ensure -gdb flag is injected:")
        print("    args+=( -gdb tcp::1234 )")
        print()
        return False, 0, {"error": "GDB stub not reachable"}
    
    print(f"[KERNEL GDB] Connected to GDB stub at {gdb_host}:{kernel_gdb_port}")
    print()
    
    # Step 2: Connect to ADB and get device info
    print("-" * 60)
    print("[STEP 2] Connecting to Cuttlefish via ADB...")
    print("-" * 60)
    
    wait_for_connection()
    
    success, device_info, _ = _adb_shell('getprop ro.product.model')
    device_model = device_info.strip() if success else "Unknown"
    success, android_version, _ = _adb_shell('getprop ro.build.version.release')
    android_ver = android_version.strip() if success else "Unknown"
    success, kernel_ver, _ = _adb_shell('uname -r')
    kernel_version = kernel_ver.strip() if success else "Unknown"
    
    print(f"[CUTTLEFISH] Device Model: {device_model}")
    print(f"[CUTTLEFISH] Android Version: {android_ver}")
    print(f"[CUTTLEFISH] Kernel Version: {kernel_version}")
    print()
    
    # Step 3: Upload reproducer
    print("-" * 60)
    print("[STEP 3] Uploading reproducer to device...")
    print("-" * 60)
    
    adb_upload_file(repro_path, Path(REPRO_PATH))
    _adb_shell(f'chmod +x {REPRO_PATH}')
    print(f"[CUTTLEFISH] Reproducer uploaded to {REPRO_PATH}")
    print()
    
    # Create log directory
    os.makedirs(log_dir, exist_ok=True)
    
    # Step 4: Extract fault information
    print("-" * 60)
    print("[STEP 4] Extracting crash information for kernel instrumentation...")
    print("-" * 60)
    
    fault_addr = None
    fault_insn = None
    access_type = "any"
    access_size = 0
    
    if parsed_crash:
        # Extract fault address
        if parsed_crash.get('access', {}).get('address'):
            try:
                addr_str = parsed_crash['access']['address']
                fault_addr = int(addr_str, 16) if addr_str.startswith('0x') else int(addr_str)
                print(f"[KERNEL GDB] Fault address: {hex(fault_addr)}")
            except Exception:
                pass
        
        # Extract faulting instruction
        for frame in parsed_crash.get('frames', []):
            if frame.get('ip'):
                try:
                    ip = frame['ip']
                    fault_insn = int(ip, 16) if ip.startswith('0x') else int(ip)
                    print(f"[KERNEL GDB] Fault instruction: {hex(fault_insn)}")
                    break
                except Exception:
                    continue
        
        access_type = parsed_crash.get('access', {}).get('type', 'any')
        access_size = parsed_crash.get('access', {}).get('size', 0)
        print(f"[KERNEL GDB] Access type: {access_type}, size: {access_size}")
    
    if not fault_addr and not fault_insn:
        print("[KERNEL GDB] No specific fault info, will use general monitoring")
    print()
    
    # Step 5: Generate kernel GDB script
    print("-" * 60)
    print("[STEP 5] Generating kernel GDB instrumentation script...")
    print("-" * 60)
    
    gdb_script = _generate_cuttlefish_kernel_gdb_script(
        bug_id=bug_id,
        output_file=os.path.join(log_dir, f"{bug_id}_kernel_events.json"),
        fault_addr=fault_addr,
        fault_insn=fault_insn,
        access_type=access_type,
        access_size=access_size,
        vmlinux_path=vmlinux_path,
        arch=arch
    )
    
    gdb_script_path = os.path.join(log_dir, f"{bug_id}_kernel_gdb_script.py")
    with open(gdb_script_path, 'w') as f:
        f.write(gdb_script)
    print(f"[KERNEL GDB] Script saved to: {gdb_script_path}")
    print()
    
    # Initialize results
    dynamic_results = {
        "bug_id": bug_id,
        "device_model": device_model,
        "android_version": android_ver,
        "kernel_version": kernel_version,
        "target_device": ADB_TARGET_DEVICE,
        "kernel_gdb_port": kernel_gdb_port,
        "vmlinux_path": vmlinux_path,
        "analysis_mode": "kernel_gdb",
        "events": [],
        "crash_detected": False
    }
    
    crash_occurred = False
    crash_type = 0
    
    t0 = get_uptime()
    print(f"[CUTTLEFISH] Device uptime before test: {t0:.2f}s")
    
    # Step 6: Run kernel GDB analysis
    print("-" * 60)
    print("[STEP 6] Running kernel GDB analysis...")
    print("-" * 60)
    
    # Generate GDB commands file
    gdb_commands_path = os.path.join(log_dir, f"{bug_id}_kernel_gdb_commands.txt")
    gdb_commands = _generate_kernel_gdb_commands(
        gdb_host=gdb_host,
        gdb_port=kernel_gdb_port,
        vmlinux_path=vmlinux_path,
        gdb_script_path=gdb_script_path,
        repro_trigger_cmd=f"{REPRO_PATH}" if not root else f"su root {REPRO_PATH}",
        arch=arch
    )
    with open(gdb_commands_path, 'w') as f:
        f.write(gdb_commands)
    
    # Select appropriate GDB binary
    if arch == "arm64" or arch == "aarch64":
        gdb_binary = "gdb-multiarch"
        # Try aarch64-linux-gnu-gdb if gdb-multiarch not available
        try:
            subprocess.run(["which", "gdb-multiarch"], check=True, capture_output=True)
        except subprocess.CalledProcessError:
            gdb_binary = "aarch64-linux-gnu-gdb"
    else:
        gdb_binary = "gdb"
    
    print(f"[KERNEL GDB] Using GDB binary: {gdb_binary}")
    print(f"[KERNEL GDB] Commands file: {gdb_commands_path}")
    print()
    
    gdb_output_log = os.path.join(log_dir, f"{bug_id}_kernel_gdb_output.log")
    
    try:
        # Start reproducer in background on device
        print("[KERNEL GDB] Starting reproducer on device (background)...")
        
        if root:
            repro_cmd = f'cd {os.path.dirname(REPRO_PATH)} && nohup su root {REPRO_PATH} > /dev/null 2>&1 &'
        else:
            repro_cmd = f'cd {os.path.dirname(REPRO_PATH)} && nohup {REPRO_PATH} > /dev/null 2>&1 &'
        
        _adb_shell(repro_cmd)
        time.sleep(1)  # Give it time to start
        
        # Run GDB with the script
        print(f"[KERNEL GDB] Attaching GDB to kernel...")
        print(f"[KERNEL GDB] Timeout: {timeout}s")
        
        with open(gdb_output_log, 'w') as gdb_log:
            gdb_cmd = [
                gdb_binary,
                "-batch",
                "-nx",  # Don't read .gdbinit
                "-x", gdb_commands_path
            ]
            
            gdb_proc = subprocess.Popen(
                gdb_cmd,
                stdout=gdb_log,
                stderr=subprocess.STDOUT,
                text=True
            )
            
            try:
                gdb_proc.wait(timeout=timeout)
                print(f"[KERNEL GDB] GDB completed with exit code: {gdb_proc.returncode}")
            except subprocess.TimeoutExpired:
                print(f"[KERNEL GDB] GDB execution timed out after {timeout}s")
                gdb_proc.kill()
                dynamic_results["timeout"] = True
        
        print(f"[KERNEL GDB] Output saved to: {gdb_output_log}")
        
        # Read and parse the events file
        events_file = os.path.join(log_dir, f"{bug_id}_kernel_events.json")
        if os.path.exists(events_file):
            try:
                with open(events_file, 'r') as f:
                    events_data = json.load(f)
                    dynamic_results["events"] = events_data.get("events", [])
                    dynamic_results["allocations"] = events_data.get("allocations", {})
                    print(f"[KERNEL GDB] Captured {len(dynamic_results['events'])} events")
            except Exception as e:
                print(f"[KERNEL GDB] Warning: Could not parse events file: {e}")
        
    except Exception as e:
        print(f"[KERNEL GDB] Error during analysis: {e}")
        import traceback
        traceback.print_exc()
        dynamic_results["error"] = str(e)
    finally:
        # Cleanup: kill reproducer
        print("[KERNEL GDB] Cleaning up reproducer process...")
        _adb_shell('killall repro 2>/dev/null')
    
    print()
    
    # Step 7: Check for crash
    print("-" * 60)
    print("[STEP 7] Checking device state...")
    print("-" * 60)
    
    # Give the device a moment to stabilize
    time.sleep(2)
    
    t1 = get_uptime()
    print(f"[CUTTLEFISH] Uptime after test: {t1:.2f}s (started at {t0:.2f}s)")
    
    if t1 < t0 or not is_device_connected():
        crash_occurred = True
        crash_type = 1
        dynamic_results["crash_detected"] = True
        print(f"[CUTTLEFISH] CRASH DETECTED: Device rebooted or disconnected")
    else:
        # Check dmesg for kernel errors
        success, dmesg_output, _ = _adb_shell('dmesg | tail -100')
        if success:
            for pattern in CRASH_PATTERNS:
                if pattern in dmesg_output:
                    print(f"[CUTTLEFISH] CRASH PATTERN DETECTED in dmesg: {pattern}")
                    crash_occurred = True
                    crash_type = 2
                    dynamic_results["crash_detected"] = True
                    dynamic_results["crash_pattern"] = pattern
                    break
        
        if not crash_occurred:
            print(f"[CUTTLEFISH] Device stable, no crash detected")
    
    # Save results
    dynamic_results["crash_occurred"] = crash_occurred
    dynamic_results["crash_type"] = crash_type
    dynamic_results["uptime_start"] = t0
    dynamic_results["uptime_end"] = t1
    
    results_output = os.path.join(log_dir, f"{bug_id}_kernel_dynamic_analysis.json")
    with open(results_output, 'w') as f:
        json.dump(dynamic_results, f, indent=2)
    
    print()
    print("=" * 80)
    print("  KERNEL GDB ANALYSIS COMPLETE")
    print("=" * 80)
    print(f"[RESULTS] Output: {results_output}")
    print(f"[RESULTS] Crash detected: {crash_occurred}")
    print(f"[RESULTS] Crash type: {crash_type}")
    print(f"[RESULTS] Events captured: {len(dynamic_results.get('events', []))}")
    print("=" * 80)
    print()
    
    return crash_occurred, crash_type, dynamic_results


def _generate_cuttlefish_kernel_gdb_script(
    bug_id: str,
    output_file: str,
    fault_addr: int = None,
    fault_insn: int = None,
    access_type: str = "any",
    access_size: int = 0,
    vmlinux_path: str = None,
    arch: str = "arm64"
) -> str:
    """Generate a GDB Python script for kernel-side Cuttlefish analysis."""
    
    # Read the base kernel GDB script if available
    base_script_path = Path(__file__).parent / "gdb.py"
    if base_script_path.exists():
        with open(base_script_path, 'r') as f:
            base_script = f.read()
        # Return the base script with config header prepended
        return f'''# Auto-generated kernel GDB configuration for Cuttlefish
# Bug ID: {bug_id}
# Architecture: {arch}

# Set GDB variables for the script
set $fault_addr = {fault_addr if fault_addr else 0}
set $fault_insn = {fault_insn if fault_insn else 0}
set $access_type = "{access_type}"
set $access_size = {access_size}
set $output_file = "{output_file}"

# Load the main kernel tracing script
source {base_script_path}
'''
    
    # Fallback: Generate minimal kernel tracing script
    return f'''#!/usr/bin/env python3
# Auto-generated kernel GDB script for Cuttlefish
# Bug ID: {bug_id}

import gdb
import json
import time

# Configuration
output_file = "{output_file}"
fault_addr = {fault_addr if fault_addr else 'None'}
fault_insn = {fault_insn if fault_insn else 'None'}
access_type = "{access_type}"
access_size = {access_size}
arch = "{arch}"

events = []
allocations = {{}}

def log_event(event_type, data):
    """Log an event with timestamp."""
    events.append({{
        "type": event_type,
        "timestamp": time.time(),
        "data": data
    }})
    gdb.write(f"[EVENT] {{event_type}}: {{data}}\\n")

def bt(max_frames=10):
    """Get backtrace as list of strings."""
    frames = []
    try:
        f = gdb.newest_frame()
        i = 0
        while f and i < max_frames:
            try:
                name = f.name() or "<unknown>"
            except Exception:
                name = "<unknown>"
            try:
                pc = f.pc()
            except Exception:
                pc = 0
            frames.append(f"{{name}} ({{hex(pc)}})")
            f = f.older()
            i += 1
    except Exception:
        pass
    return frames

class KernelPanicCatcher(gdb.Breakpoint):
    """Catch kernel panic."""
    def __init__(self):
        try:
            super().__init__("panic", gdb.BP_BREAKPOINT)
            self.silent = False
            gdb.write("[GDB] Set breakpoint on panic()\\n")
        except Exception as e:
            gdb.write(f"[GDB] Could not set panic breakpoint: {{e}}\\n")
    
    def stop(self):
        log_event("kernel_panic", {{"backtrace": bt()}})
        return True

class KernelOopsCatcher(gdb.Breakpoint):
    """Catch kernel oops."""
    def __init__(self):
        try:
            super().__init__("oops_enter", gdb.BP_BREAKPOINT)
            self.silent = False
            gdb.write("[GDB] Set breakpoint on oops_enter()\\n")
        except Exception as e:
            gdb.write(f"[GDB] Could not set oops breakpoint: {{e}}\\n")
    
    def stop(self):
        log_event("kernel_oops", {{"backtrace": bt()}})
        return True

class KASANCatcher(gdb.Breakpoint):
    """Catch KASAN reports."""
    def __init__(self):
        try:
            super().__init__("kasan_report", gdb.BP_BREAKPOINT)
            self.silent = False
            gdb.write("[GDB] Set breakpoint on kasan_report()\\n")
        except Exception as e:
            gdb.write(f"[GDB] Could not set KASAN breakpoint: {{e}}\\n")
    
    def stop(self):
        log_event("kasan_report", {{"backtrace": bt()}})
        return True

class AllocTracker(gdb.Breakpoint):
    """Track kmalloc allocations."""
    def __init__(self):
        try:
            super().__init__("__kmalloc", gdb.BP_BREAKPOINT)
            self.silent = True
            gdb.write("[GDB] Set breakpoint on __kmalloc()\\n")
        except Exception as e:
            gdb.write(f"[GDB] Could not set kmalloc breakpoint: {{e}}\\n")
    
    def stop(self):
        try:
            # Get size argument (first arg)
            size = gdb.parse_and_eval("$x0" if arch == "arm64" else "$rdi")
            log_event("kmalloc", {{"size": int(size), "backtrace": bt(5)}})
        except Exception:
            pass
        return False  # Don't stop

class FreeTracker(gdb.Breakpoint):
    """Track kfree calls."""
    def __init__(self):
        try:
            super().__init__("kfree", gdb.BP_BREAKPOINT)
            self.silent = True
            gdb.write("[GDB] Set breakpoint on kfree()\\n")
        except Exception as e:
            gdb.write(f"[GDB] Could not set kfree breakpoint: {{e}}\\n")
    
    def stop(self):
        try:
            # Get pointer argument
            ptr = gdb.parse_and_eval("$x0" if arch == "arm64" else "$rdi")
            log_event("kfree", {{"ptr": hex(int(ptr)), "backtrace": bt(5)}})
        except Exception:
            pass
        return False

def save_results():
    """Save collected events to file."""
    try:
        with open(output_file, 'w') as f:
            json.dump({{"events": events, "allocations": allocations}}, f, indent=2)
        gdb.write(f"[GDB] Saved {{len(events)}} events to {{output_file}}\\n")
    except Exception as e:
        gdb.write(f"[GDB] Failed to save results: {{e}}\\n")

# Set up breakpoints
gdb.write("[GDB] Setting up kernel instrumentation...\\n")

try:
    KernelPanicCatcher()
except Exception:
    pass

try:
    KernelOopsCatcher()
except Exception:
    pass

try:
    KASANCatcher()
except Exception:
    pass

try:
    AllocTracker()
except Exception:
    pass

try:
    FreeTracker()
except Exception:
    pass

# Install fault-specific watchpoint if address provided
if fault_addr:
    try:
        gdb.execute(f"watch *(unsigned long *){{hex(fault_addr)}}")
        gdb.write(f"[GDB] Set watchpoint on fault address {{hex(fault_addr)}}\\n")
    except Exception as e:
        gdb.write(f"[GDB] Could not set watchpoint: {{e}}\\n")

# Register exit handler
import atexit
atexit.register(save_results)

gdb.write("[GDB] Kernel instrumentation ready\\n")
gdb.write("[GDB] Continuing execution...\\n")
'''


def _generate_kernel_gdb_commands(
    gdb_host: str,
    gdb_port: int,
    vmlinux_path: str = None,
    gdb_script_path: str = None,
    repro_trigger_cmd: str = None,
    arch: str = "arm64"
) -> str:
    """Generate GDB command file for kernel debugging."""
    
    commands = []
    
    # Set architecture
    if arch == "arm64" or arch == "aarch64":
        commands.append("set architecture aarch64")
    else:
        commands.append("set architecture i386:x86-64")
    
    # Load vmlinux for symbols if provided
    if vmlinux_path and os.path.exists(vmlinux_path):
        commands.append(f"file {vmlinux_path}")
    
    # Connect to remote GDB stub
    commands.append(f"target remote {gdb_host}:{gdb_port}")
    
    # Disable pagination for batch mode
    commands.append("set pagination off")
    commands.append("set confirm off")
    
    # For ARM64, set up interrupt masking hook
    if arch == "arm64" or arch == "aarch64":
        commands.append("""
define hook-stop
    # Mask IRQ + FIQ to prevent interrupt interference
    set $cpsr = $cpsr | 0xc0
end
""")
    
    # Source the Python instrumentation script
    if gdb_script_path:
        commands.append(f"source {gdb_script_path}")
    
    # Continue execution and let breakpoints catch events
    commands.append("continue")
    
    # After timeout or crash, disconnect gracefully
    commands.append("disconnect")
    commands.append("quit")
    
    return "\n".join(commands)


# =============================================================================
# INTEGRATED CUTTLEFISH CONTROLLER FUNCTIONS
# =============================================================================

def test_repro_with_cuttlefish_controller(
    repro_path: str,
    bug_id: str,
    cuttlefish_config: 'CuttlefishConfig',
    parsed_crash: dict = None,
    log_dir: str = ".",
    root: bool = True,
    timeout: int = 120,
    arch: str = "arm64",
    vmlinux_path: str = None,
    remote_vmlinux_path: str = None,
    demo: bool = False,
) -> Tuple[bool, int, dict]:
    """
    Test a reproducer using the CuttlefishController with support for
    persistent and non-persistent modes.
    
    TWO-PHASE APPROACH (when extract_runtime_symbols is enabled):
    Phase 1: Boot VM (minimal GDB, just continue) -> Extract kallsyms -> Stop
    Phase 2: Generate GDB script with real addresses -> Restart -> Run reproducer
    
    This ensures we have accurate symbol addresses for hardware breakpoints
    since KASLR randomizes addresses on each boot.
    
    Args:
        repro_path: Path to the compiled reproducer binary
        bug_id: Unique identifier for the bug
        cuttlefish_config: CuttlefishConfig instance with connection settings
        parsed_crash: Parsed crash information for instrumentation
        log_dir: Directory for output logs
        root: Whether to run the reproducer as root
        timeout: Execution timeout in seconds
        arch: Target architecture (arm64/x86_64)
        vmlinux_path: Path to vmlinux with debug symbols (local, optional)
        remote_vmlinux_path: Path to vmlinux on remote server (for remote GDB)
        demo: Demo mode - generate sample data if GDB tracing fails
    
    Returns:
        Tuple of (crash_occurred, crash_type, dynamic_results)
    """
    from .cuttlefish import CuttlefishController, CuttlefishConfig
    
    # Create log directory and set log_file path in config
    # This ensures GDB logs and other controller logs go to the right place
    os.makedirs(log_dir, exist_ok=True)
    if not cuttlefish_config.log_file:
        cuttlefish_config.log_file = os.path.join(log_dir, "cuttlefish_controller.log")
    
    controller = CuttlefishController(cuttlefish_config)
    
    dynamic_results = {
        "bug_id": bug_id,
        "analysis_mode": "cuttlefish_controller",
        "persistent_mode": cuttlefish_config.persistent,
        "gdb_enabled": cuttlefish_config.enable_gdb,
        "arch": arch,
        "events": [],
        "crash_detected": False,
        # GDB log paths
        "gdb_session_log": os.path.join(log_dir, "gdb_session.log"),
        "gdb_stdout_log": os.path.join(log_dir, "gdb_stdout.log"),
        "gdb_stderr_log": os.path.join(log_dir, "gdb_stderr.log"),
    }
    
    crash_occurred = False
    crash_type = 0
    runtime_symbols = None
    runtime_config_path = None
    
    # Store original ADB settings to restore later
    global ADB_TARGET_DEVICE, ADB_EXE_PATH
    old_adb_target = ADB_TARGET_DEVICE
    old_adb_exe = ADB_EXE_PATH
    
    # Check if we should do two-phase symbol extraction
    do_runtime_extraction = getattr(cuttlefish_config, 'extract_runtime_symbols', True)
    
    try:
        # Print header
        print()
        print("=" * 80)
        print("  CUTTLEFISH CONTROLLER TEST")
        print("=" * 80)
        print(f"[CONFIG] Bug ID: {bug_id}")
        print(f"[CONFIG] Mode: {'persistent' if cuttlefish_config.persistent else 'non-persistent'}")
        print(f"[CONFIG] Already running: {cuttlefish_config.already_running}")
        print(f"[CONFIG] SSH: {cuttlefish_config.ssh_user or '(from ssh config)'}@{cuttlefish_config.ssh_host}:{cuttlefish_config.ssh_port}")
        print(f"[CONFIG] GDB enabled: {cuttlefish_config.enable_gdb}")
        print(f"[CONFIG] GDB port: {cuttlefish_config.gdb_port}")
        print(f"[CONFIG] ADB: {cuttlefish_config.adb_host}:{cuttlefish_config.adb_port}")
        print(f"[CONFIG] Runtime symbol extraction: {do_runtime_extraction}")
        print(f"[CONFIG] Log file: {controller.get_log_file_path()}")
        print()
        
        # ============================================================
        # PHASE 1: Boot VM and extract runtime symbols
        # ============================================================
        if do_runtime_extraction and cuttlefish_config.enable_gdb:
            print("=" * 60)
            print("  PHASE 1: Symbol Extraction")
            print("=" * 60)
            print()
            
            print("-" * 60)
            print("[PHASE 1.1] Starting Cuttlefish for symbol extraction...")
            print("-" * 60)
            
            # Use run_command (non-GDB, e.g. run.sh) for symbol extraction if available
            # This avoids the GDB stub pausing the kernel during a symbols-only boot
            phase1_cmd = cuttlefish_config.run_command or cuttlefish_config.start_command
            original_start = cuttlefish_config.start_command
            original_enable_gdb = cuttlefish_config.enable_gdb
            if phase1_cmd and phase1_cmd != cuttlefish_config.start_command:
                print(f"[INFO] Using non-GDB command for symbol extraction: {phase1_cmd}")
                cuttlefish_config.start_command = phase1_cmd
                cuttlefish_config.enable_gdb = False
            else:
                print("[INFO] GDB will just continue (no breakpoints yet)")
            
            # Start without GDB script - just boot and extract symbols
            if not controller.start(gdb_script_path=None, vmlinux_path=None, gdb_continue_only=True):
                print("[ERROR] Failed to start Cuttlefish for symbol extraction")
                dynamic_results["error"] = "Failed to start Cuttlefish (phase 1)"
                return False, 0, dynamic_results
            
            print("[OK] Cuttlefish booted for symbol extraction")
            print()
            
            # Configure ADB for phase 1
            ADB_TARGET_DEVICE = controller.get_adb_target()
            ADB_EXE_PATH = cuttlefish_config.adb_exe
            
            print(f"[CONFIG] Using ADB target: {ADB_TARGET_DEVICE}")
            print(f"[CONFIG] Using ADB executable: {ADB_EXE_PATH}")
            
            # Connect via SSH tunnel if needed
            if cuttlefish_config.setup_tunnels:
                print(f"[CONFIG] SSH tunnels enabled - connecting via tunneled ADB server")
                subprocess.run(
                    [ADB_EXE_PATH, "connect", ADB_TARGET_DEVICE],
                    capture_output=True, text=True, timeout=10
                )
            
            print("-" * 60)
            print("[PHASE 1.2] Extracting runtime symbols from running VM...")
            print("-" * 60)
            
            # Extract crash stack functions
            crash_stack_funcs = []
            if parsed_crash:
                frames_list = parsed_crash.get("stack_frames", parsed_crash.get("frames", []))
                for frame in frames_list:
                    func = frame.get("function", frame.get("func", ""))
                    if func and func not in crash_stack_funcs:
                        crash_stack_funcs.append(func)
                if parsed_crash.get("corrupted_function"):
                    crash_stack_funcs.insert(0, parsed_crash["corrupted_function"])
            
            runtime_config_path = extract_and_save_runtime_symbols(
                output_dir=log_dir,
                vm_type="cuttlefish",
                crash_stack_funcs=crash_stack_funcs,
                adb_exe=ADB_EXE_PATH,
                adb_target=ADB_TARGET_DEVICE,
            )
            
            if runtime_config_path:
                dynamic_results["runtime_symbols_config"] = runtime_config_path
                dynamic_results["symbols_source"] = "runtime_kallsyms"
                print(f"[OK] Runtime symbols extracted: {runtime_config_path}")
            else:
                print("[WARNING] Failed to extract runtime symbols")
                dynamic_results["symbols_source"] = "none"
            
            print()
            print("-" * 60)
            print("[PHASE 1.3] Stopping Cuttlefish instance...")
            print("-" * 60)
            
            # Restore ADB settings before stopping
            ADB_TARGET_DEVICE = old_adb_target
            ADB_EXE_PATH = old_adb_exe
            
            # Restore original start command for Phase 2 (GDB-enabled)
            cuttlefish_config.start_command = original_start
            cuttlefish_config.enable_gdb = original_enable_gdb
            
            # Stop the instance
            controller.stop()
            print("[OK] Instance stopped")
            print()
            
            # Wait for clean shutdown
            time.sleep(5)
            
            print("=" * 60)
            print("  PHASE 2: Run with GDB Breakpoints")
            print("=" * 60)
            print()
        
        # ============================================================
        # PHASE 2: Generate GDB script with extracted symbols and run
        # ============================================================
        
        print("-" * 60)
        print("[PHASE 2.1] Generating GDB script with runtime symbols...")
        print("-" * 60)
        
        gdb_script_path = None
        kernel_gdb = None
        
        if cuttlefish_config.enable_gdb:
            from .cuttlefish import CuttlefishKernelGDB
            
            kernel_gdb = CuttlefishKernelGDB(controller, log_dir)
            
            # Log parsed crash info
            if parsed_crash:
                print(f"[GDB] Parsed crash info available:")
                print(f"      - frames: {len(parsed_crash.get('frames', []))}")
                print(f"      - stack_frames: {len(parsed_crash.get('stack_frames', []))}")
                print(f"      - access: {parsed_crash.get('access', 'N/A')}")
                print(f"      - kind: {parsed_crash.get('kind', 'N/A')}")
            else:
                print(f"[GDB] WARNING: No parsed crash info available!")
            
            # Build breakpoints from parsed crash info
            breakpoints = []
            if parsed_crash:
                if "corrupted_function" in parsed_crash:
                    breakpoints.append({"function": parsed_crash["corrupted_function"]})
                frames_list = parsed_crash.get("stack_frames", parsed_crash.get("frames", []))
                for frame in frames_list[:5]:
                    func = frame.get("function", frame.get("func", ""))
                    if func:
                        breakpoints.append({"function": func})
                if breakpoints:
                    print(f"[GDB] Passing {len(breakpoints)} breakpoint hints to script generator")
            
            # Use runtime symbols config if we extracted it
            effective_vmlinux = kernel_gdb.vmlinux_path or vmlinux_path
            
            gdb_script_path = kernel_gdb.generate_kernel_gdb_script(
                bug_id=bug_id,
                breakpoints=breakpoints,
                vmlinux_path=effective_vmlinux,
                parsed_crash=parsed_crash,
                demo_mode=demo,
                runtime_symbols_config=runtime_config_path,  # Pass the extracted symbols
            )
            print(f"[GDB] Script generated: {gdb_script_path}")
            if runtime_config_path:
                print(f"[GDB] Using runtime symbols from: {runtime_config_path}")
            if demo:
                print(f"[GDB] DEMO MODE ENABLED - will generate sample data if tracing fails")
        
        print()
        print("-" * 60)
        print("[PHASE 2.2] Starting Cuttlefish with GDB breakpoints...")
        print("-" * 60)
        
        # For phase 2, we may need to reset the controller state for non-persistent mode
        if not cuttlefish_config.persistent:
            # Create a fresh controller for the second boot
            controller = CuttlefishController(cuttlefish_config)
        
        if not controller.start(gdb_script_path=gdb_script_path, vmlinux_path=vmlinux_path if cuttlefish_config.enable_gdb else None):
            print("[ERROR] Failed to start Cuttlefish with GDB")
            dynamic_results["error"] = "Failed to start Cuttlefish (phase 2)"
            return False, 0, dynamic_results
        
        dynamic_results["cuttlefish_started"] = True
        dynamic_results["log_file"] = controller.get_log_file_path()
        print("[OK] Cuttlefish is ready with GDB breakpoints")
        print()
        
        # Configure ADB again for phase 2
        ADB_TARGET_DEVICE = controller.get_adb_target()
        ADB_EXE_PATH = cuttlefish_config.adb_exe
        
        print(f"[CONFIG] Using ADB target: {ADB_TARGET_DEVICE}")
        print(f"[CONFIG] Using ADB executable: {ADB_EXE_PATH}")
        
        if cuttlefish_config.setup_tunnels:
            print(f"[CONFIG] SSH tunnels enabled - connecting via tunneled ADB server")
            connect_result = subprocess.run(
                [ADB_EXE_PATH, "connect", ADB_TARGET_DEVICE],
                capture_output=True, text=True, timeout=10
            )
            print(f"[ADB] Connect result: {connect_result.stdout.strip()}")
        
        # Get device info
        print("-" * 60)
        print("[PHASE 2.3] Getting device information...")
        print("-" * 60)
        
        wait_for_connection()
        
        success, device_info, _ = _adb_shell('getprop ro.product.model')
        device_model = device_info.strip() if success else "Unknown"
        success, android_version, _ = _adb_shell('getprop ro.build.version.release')
        android_ver = android_version.strip() if success else "Unknown"
        success, kernel_ver, _ = _adb_shell('uname -r')
        kernel_version = kernel_ver.strip() if success else "Unknown"
        
        print(f"[DEVICE] Model: {device_model}")
        print(f"[DEVICE] Android: {android_ver}")
        print(f"[DEVICE] Kernel: {kernel_version}")
        
        dynamic_results["device_model"] = device_model
        dynamic_results["android_version"] = android_ver
        dynamic_results["kernel_version"] = kernel_version
        print()
        
        # Upload reproducer
        print("-" * 60)
        print("[PHASE 2.4] Uploading reproducer...")
        print("-" * 60)
        
        adb_upload_file(repro_path, Path(REPRO_PATH))
        _adb_shell(f'chmod +x {REPRO_PATH}')
        print(f"[OK] Reproducer uploaded to {REPRO_PATH}")
        print()
        
        # Record uptime before test
        t0 = get_uptime()
        print(f"[DEVICE] Uptime before test: {t0:.2f}s")
        
        # Run reproducer
        if cuttlefish_config.enable_gdb:
            print("-" * 60)
            print("[PHASE 2.5] Running reproducer with GDB monitoring...")
            print("-" * 60)
            
            print("[GDB] GDB script loaded with runtime symbol addresses")
            print(f"[GDB] Script path: {gdb_script_path}")
            
            # Start reproducer in background
            print("[GDB] Starting reproducer on device...")
            if root:
                repro_cmd = f'cd {os.path.dirname(REPRO_PATH)} && nohup su root {REPRO_PATH} > /dev/null 2>&1 &'
            else:
                repro_cmd = f'cd {os.path.dirname(REPRO_PATH)} && nohup {REPRO_PATH} > /dev/null 2>&1 &'
            _adb_shell(repro_cmd)
            time.sleep(1)
            
            # Wait for execution
            print(f"[GDB] Waiting {timeout}s for reproducer execution...")
            time.sleep(min(timeout, 30))
            
            # Check for results
            if kernel_gdb:
                results_file = Path(log_dir) / f"{bug_id}_kernel_gdb_results.json"
                if results_file.exists():
                    with open(results_file, 'r') as f:
                        gdb_results = json.load(f)
                    dynamic_results.update(gdb_results)
                    print(f"[GDB] Results loaded from {results_file}")
                    if "events" in gdb_results:
                        print(f"[GDB] Captured {len(gdb_results['events'])} events")
                    dynamic_results["analysis_mode"] = "kernel_gdb"
                else:
                    print("[GDB] No results file found (GDB may still be running)")
                    dynamic_results["analysis_mode"] = "kernel_gdb_in_progress"
                
                kernel_gdb.cleanup()
        else:
            # Direct execution without GDB
            print("-" * 60)
            print("[PHASE 2.5] Running reproducer directly (no GDB)...")
            print("-" * 60)
            
            dynamic_results["analysis_mode"] = "direct"
            
            if root:
                run_repro_cmd = f'cd {os.path.dirname(REPRO_PATH)} && su root {REPRO_PATH}'
            else:
                run_repro_cmd = f'cd {os.path.dirname(REPRO_PATH)} && {REPRO_PATH}'
            
            print(f"[RUN] Command: {run_repro_cmd}")
            
            with subprocess.Popen(_adb_cmd('shell', run_repro_cmd)) as exploit_process:
                print(f"[RUN] Running for {min(5, timeout)}s...")
                time.sleep(min(5, timeout))
                exploit_process.poll()
                exploit_process.terminate()
        
        # Cleanup reproducer
        print()
        print("[CLEANUP] Stopping reproducer process...")
        _adb_shell('killall repro 2>/dev/null')
        
        # Check for crash
        print("-" * 60)
        print("[PHASE 2.6] Checking device state...")
        print("-" * 60)
        
        time.sleep(2)
        t1 = get_uptime()
        print(f"[DEVICE] Uptime after test: {t1:.2f}s (started at {t0:.2f}s)")
        
        if t1 < t0 or not is_device_connected():
            crash_occurred = True
            crash_type = 1
            dynamic_results["crash_detected"] = True
            print("[CRASH] Device rebooted or disconnected!")
        else:
            # Check dmesg for kernel errors
            success, dmesg_output, _ = _adb_shell('dmesg | tail -100')
            if success:
                for pattern in CRASH_PATTERNS:
                    if pattern in dmesg_output:
                        print(f"[CRASH] Pattern detected in dmesg: {pattern}")
                        crash_occurred = True
                        crash_type = 2
                        dynamic_results["crash_detected"] = True
                        dynamic_results["crash_pattern"] = pattern
                        break
            
            if not crash_occurred:
                print("[OK] Device stable, no crash detected")
        
        dynamic_results["crash_occurred"] = crash_occurred
        dynamic_results["crash_type"] = crash_type
        dynamic_results["uptime_start"] = t0
        dynamic_results["uptime_end"] = t1
        
        # Restore ADB settings
        ADB_TARGET_DEVICE = old_adb_target
        ADB_EXE_PATH = old_adb_exe
        
    except Exception as e:
        print(f"[ERROR] Test failed: {e}")
        import traceback
        traceback.print_exc()
        dynamic_results["error"] = str(e)
        
    finally:
        # Cleanup
        print()
        print("-" * 60)
        print("[CLEANUP] Cleaning up...")
        print("-" * 60)
        controller.cleanup()
        print("[OK] Cleanup complete")
    
    # Save results
    results_output = os.path.join(log_dir, f"{bug_id}_controller_results.json")
    with open(results_output, 'w') as f:
        json.dump(dynamic_results, f, indent=2)
    
    print()
    print("=" * 80)
    print("  TEST COMPLETE")
    print("=" * 80)
    print(f"[RESULTS] Output: {results_output}")
    print(f"[RESULTS] Crash detected: {crash_occurred}")
    print(f"[RESULTS] Crash type: {crash_type}")
    print(f"[RESULTS] Mode: {dynamic_results['analysis_mode']}")
    print(f"[RESULTS] Symbols source: {dynamic_results.get('symbols_source', 'unknown')}")
    print(f"[RESULTS] Detailed log: {controller.get_log_file_path()}")
    if cuttlefish_config.enable_gdb:
        print(f"[RESULTS] GDB session log: {dynamic_results.get('gdb_session_log')}")
    print("=" * 80)
    print()
    
    return crash_occurred, crash_type, dynamic_results


def verify_exploit_with_cuttlefish_controller(
    exploit_path: str,
    cuttlefish_config: 'CuttlefishConfig',
    log_dir: str = ".",
    timeout: int = 120,
    demo: bool = False,
) -> Dict[str, Any]:
    """
    Verify an exploit achieves privilege escalation using CuttlefishController.
    
    This mirrors the approach used in test_repro_with_cuttlefish_controller but
    is specifically designed for exploit verification:
    1. Push exploit to device
    2. Run exploit as non-root user (shell)
    3. Check if privilege escalation to root was achieved
    
    Args:
        exploit_path: Path to the compiled exploit binary
        cuttlefish_config: CuttlefishConfig instance with connection settings
        log_dir: Directory for output logs
        timeout: Execution timeout in seconds
        demo: Demo mode - simulate success for testing pipeline
        
    Returns:
        Dictionary with verification results
    """
    from .cuttlefish import CuttlefishController, CuttlefishConfig
    
    os.makedirs(log_dir, exist_ok=True)
    if not cuttlefish_config.log_file:
        cuttlefish_config.log_file = os.path.join(log_dir, "exploit_verification.log")
    
    controller = CuttlefishController(cuttlefish_config)
    
    result = {
        "exploit_path": exploit_path,
        "success": False,
        "initial_uid": None,
        "final_uid": None,
        "privilege_escalated": False,
        "crash_occurred": False,
        "error": None,
        "logs": [],
        "device_stable": True,
    }
    
    # Store original ADB settings to restore later
    global ADB_TARGET_DEVICE, ADB_EXE_PATH
    old_adb_target = ADB_TARGET_DEVICE
    old_adb_exe = ADB_EXE_PATH
    
    def log(msg: str):
        print(msg)
        result["logs"].append(msg)
    
    try:
        print()
        print("=" * 80)
        print("  EXPLOIT PRIVILEGE ESCALATION VERIFICATION")
        print("  (Using CuttlefishController)")
        print("=" * 80)
        print()
        
        log(f"[CONFIG] Exploit: {exploit_path}")
        log(f"[CONFIG] Mode: {'persistent' if cuttlefish_config.persistent else 'non-persistent'}")
        log(f"[CONFIG] Already running: {cuttlefish_config.already_running}")
        log(f"[CONFIG] SSH: {cuttlefish_config.ssh_host}:{cuttlefish_config.ssh_port}")
        log(f"[CONFIG] ADB: {cuttlefish_config.adb_host}:{cuttlefish_config.adb_port}")
        print()
        
        # Check exploit exists
        if not os.path.exists(exploit_path):
            result["error"] = f"Exploit binary not found: {exploit_path}"
            log(f"[ERROR] {result['error']}")
            return result
        
        # Step 1: Start Cuttlefish (if not already running)
        log("-" * 60)
        log("[STEP 1] Starting Cuttlefish instance...")
        log("-" * 60)
        
        # For exploit verification, we don't need GDB - just boot and run
        if not controller.start(gdb_script_path=None, vmlinux_path=None, gdb_continue_only=True):
            result["error"] = "Failed to start Cuttlefish instance"
            log(f"[ERROR] {result['error']}")
            return result
        
        log("[OK] Cuttlefish is ready")
        print()
        
        # Configure ADB
        ADB_TARGET_DEVICE = controller.get_adb_target()
        ADB_EXE_PATH = cuttlefish_config.adb_exe
        
        log(f"[CONFIG] Using ADB target: {ADB_TARGET_DEVICE}")
        log(f"[CONFIG] Using ADB executable: {ADB_EXE_PATH}")
        
        if cuttlefish_config.setup_tunnels:
            log("[CONFIG] Connecting via SSH tunneled ADB...")
            subprocess.run(
                [ADB_EXE_PATH, "connect", ADB_TARGET_DEVICE],
                capture_output=True, text=True, timeout=10
            )
        
        # Wait for device
        log("-" * 60)
        log("[STEP 2] Waiting for device connection...")
        log("-" * 60)
        
        wait_for_connection()
        log("[OK] Device connected")
        
        # Get device info
        success, device_info, _ = _adb_shell('getprop ro.product.model')
        device_model = device_info.strip() if success else "Unknown"
        log(f"[DEVICE] Model: {device_model}")
        
        # Record uptime before test
        t0 = get_uptime()
        log(f"[DEVICE] Uptime: {t0:.2f}s")
        print()
        
        # Step 3: Push exploit
        log("-" * 60)
        log("[STEP 3] Pushing exploit to device...")
        log("-" * 60)
        
        remote_exploit_path = "/data/local/tmp/exploit"
        adb_upload_file(exploit_path, Path(remote_exploit_path))
        log(f"[OK] Exploit pushed to {remote_exploit_path}")
        print()
        
        # Step 4: Check initial UID (as shell user)
        log("-" * 60)
        log("[STEP 4] Checking initial UID (as shell user)...")
        log("-" * 60)
        
        success, uid_output, _ = _adb_shell('id -u')
        if success:
            initial_uid = uid_output.strip()
            result["initial_uid"] = initial_uid
            log(f"[OK] Initial UID: {initial_uid} (should be non-zero)")
        else:
            log("[WARNING] Could not get initial UID")
            result["initial_uid"] = "unknown"
        print()
        
        # Step 5: Run exploit as shell user (non-root)
        log("-" * 60)
        log("[STEP 5] Running exploit as non-root user...")
        log("-" * 60)
        
        # Run the exploit and capture output
        # Don't use 'su root' - run as the default shell user to test privilege escalation
        exploit_cmd = f'cd /data/local/tmp && ./exploit'
        
        log(f"[RUN] Command: {exploit_cmd}")
        log(f"[RUN] Timeout: {timeout}s")
        
        try:
            success, exploit_output, exploit_stderr = _adb_shell(exploit_cmd, timeout=timeout)
            result["exploit_output"] = exploit_output
            result["exploit_stderr"] = exploit_stderr
            
            if exploit_output:
                log("[OUTPUT] Exploit stdout:")
                for line in exploit_output.strip().split('\n')[:20]:
                    log(f"  {line}")
            # if exploit_stderr:
            #     log("[OUTPUT] Exploit stderr:")
            #     for line in exploit_stderr.strip().split('\n')[:10]:
            #         log(f"  {line}")
        except Exception as e:
            log(f"[WARNING] Exploit execution error: {e}")
            result["exploit_output"] = ""
        
        print()
        
        # Step 6: Check if device crashed
        log("-" * 60)
        log("[STEP 6] Checking device stability...")
        log("-" * 60)
        
        time.sleep(2)
        t1 = get_uptime()
        
        if t1 < t0 or not is_device_connected():
            result["crash_occurred"] = True
            # result["device_stable"] = False
            # log(f"[CRASH] Device rebooted or disconnected! (uptime was {t0:.2f}s, now {t1:.2f}s)")
        else:
            log(f"[OK] Device stable (uptime: {t1:.2f}s)")
        print()
        
        # Step 7: Check final UID to see if we got root
        log("-" * 60)
        log("[STEP 7] Checking final UID after exploit...")
        log("-" * 60)
        
        # Try to get UID - if exploit spawned a root shell, check process
        success, final_uid_output, _ = _adb_shell('id -u')
        if success:
            final_uid = final_uid_output.strip()
            result["final_uid"] = final_uid
            log(f"[OK] Final UID: {final_uid}")
        else:
            log("[WARNING] Could not get final UID")
            result["final_uid"] = "unknown"
        
        # Also check if there's a root process from our exploit
        success, ps_output, _ = _adb_shell('ps -ef | grep exploit | grep -v grep')
        if success and ps_output.strip():
            log(f"[INFO] Exploit process status:")
            for line in ps_output.strip().split('\n')[:5]:
                log(f"  {line}")
                # Check if running as root (uid 0)
                if line.startswith('root ') or ' root ' in line:
                    log("[+] Found exploit process running as ROOT!")
                    result["final_uid"] = "0"
        
        # Parse exploit output for success indicators
        exploit_output = result.get("exploit_output", "")
        success_indicators = [
            "uid=0",
            "got root",
            "privilege escalation successful",
            "exploit succeeded",
            "now running as root",
            "euid=0",
        ]
        
        for indicator in success_indicators:
            if indicator.lower() in exploit_output.lower():
                log(f"[+] Success indicator found in output: '{indicator}'")
                result["privilege_escalated"] = True
                result["final_uid"] = "0"
                break
        
        # Determine overall success
        if result["final_uid"] == "0" or result["privilege_escalated"]:
            result["success"] = True
            result["privilege_escalated"] = True
            log("\n[✓] PRIVILEGE ESCALATION ACHIEVED!")
        elif result["crash_occurred"]:
            log("\n[!] Device crashed - exploit may have caused kernel panic")
        else:
            log("\n[✗] Privilege escalation not achieved")
        
        # Demo mode: simulate success if real verification failed
        # if demo and not result["success"]:
        #     log("\n[DEMO] Demo mode enabled - simulating successful privilege escalation")
        #     result["success"] = True
        #     result["privilege_escalated"] = True
        #     result["initial_uid"] = "2000"
        #     result["final_uid"] = "0"
        #     result["demo_mode"] = True
        
    except Exception as e:
        log(f"[ERROR] Verification failed: {e}")
        import traceback
        log(f"[TRACEBACK] {traceback.format_exc()}")
        result["error"] = str(e)
        
    finally:
        # Restore ADB settings
        ADB_TARGET_DEVICE = old_adb_target
        ADB_EXE_PATH = old_adb_exe
        
        # Cleanup
        log("\n[CLEANUP] Cleaning up...")
        controller.cleanup()
        log("[OK] Cleanup complete")
    
    # Save results
    results_file = os.path.join(log_dir, "exploit_verification_results.json")
    with open(results_file, 'w') as f:
        json.dump(result, f, indent=2)
    
    print()
    print("=" * 80)
    print("  VERIFICATION COMPLETE")
    print("=" * 80)
    print(f"[RESULT] Success: {result['success']}")
    print(f"[RESULT] Initial UID: {result['initial_uid']}")
    print(f"[RESULT] Final UID: {result['final_uid']}")
    print(f"[RESULT] Privilege escalated: {result['privilege_escalated']}")
    print(f"[RESULT] Device crashed: {result['crash_occurred']}")
    print(f"[RESULT] Results saved: {results_file}")
    print("=" * 80)
    print()
    
    return result


# ============================================================================
# Exploit Verification - Test Privilege Escalation
# ============================================================================

def _send_gdb_continue(
    ssh_host: Optional[str],
    gdb_port: int = 1234,
    setup_tunnels: bool = False,
    log_fn = None,
) -> bool:
    """
    Send GDB continue command to allow VM to boot.
    
    When using gdb_run.sh, the crosvm waits for GDB to connect and send
    the 'continue' command before the VM starts running.
    
    This function:
    1. Sets up SSH tunnel if needed
    2. Connects to the GDB stub
    3. Sends the continue command via GDB RSP protocol
    
    Returns True if continue command was sent successfully.
    """
    import socket
    import subprocess
    
    def log(msg: str):
        if log_fn:
            log_fn(msg)
        else:
            print(msg)
    
    def gdb_checksum(data: bytes) -> str:
        """Calculate GDB RSP checksum."""
        return f"{sum(data) % 256:02x}"
    
    def make_packet(cmd: str) -> bytes:
        """Create a GDB RSP packet."""
        data = cmd.encode()
        return f"${cmd}#{gdb_checksum(data)}".encode()
    
    tunnel_proc = None
    local_port = gdb_port
    
    try:
        # Set up SSH tunnel if remote and tunnels requested
        if ssh_host and ssh_host != 'localhost' and setup_tunnels:
            local_port = 11234 + (gdb_port % 1000)  # Use a different local port
            log(f"[GDB] Setting up SSH tunnel: localhost:{local_port} -> {ssh_host}:{gdb_port}")
            tunnel_cmd = [
                'ssh', '-N', '-L', f'{local_port}:localhost:{gdb_port}',
                ssh_host
            ]
            tunnel_proc = subprocess.Popen(tunnel_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            time.sleep(2)  # Wait for tunnel to establish
            gdb_host = 'localhost'
        elif ssh_host and ssh_host != 'localhost':
            # Remote but no tunnel - connect directly (may not work without tunnel)
            gdb_host = ssh_host
            local_port = gdb_port
        else:
            gdb_host = 'localhost'
        
        # Wait for GDB port to become available
        log(f"[GDB] Waiting for GDB stub at {gdb_host}:{local_port}...")
        max_wait = 30
        start_time = time.time()
        
        while time.time() - start_time < max_wait:
            try:
                sock = socket.create_connection((gdb_host, local_port), timeout=2)
                sock.close()
                log(f"[GDB] GDB port is open")
                break
            except (socket.timeout, ConnectionRefusedError, OSError):
                time.sleep(1)
        else:
            log(f"[GDB] Timeout waiting for GDB port")
            return False
        
        # Connect and send continue
        log(f"[GDB] Connecting to GDB stub at {gdb_host}:{local_port}...")
        sock = socket.create_connection((gdb_host, local_port), timeout=10)
        sock.settimeout(5)
        
        # Send ACK first to sync
        sock.send(b"+")
        time.sleep(0.2)
        
        # Send continue packet: $c#63
        continue_packet = make_packet("c")
        log(f"[GDB] Sending continue packet...")
        sock.send(continue_packet)
        
        # Wait briefly for ACK
        try:
            response = sock.recv(1)
            if response == b"+":
                log("[GDB] GDB stub acknowledged continue command")
            elif response == b"":
                # Empty response often means the stub continued and closed connection
                log("[GDB] Empty response received (VM likely continuing)")
            else:
                log(f"[GDB] Received response: {response}")
        except socket.timeout:
            log("[GDB] No ACK received (stub may have continued anyway)")
        
        sock.close()
        log("[GDB] Continue command sent successfully")
        return True
        
    except socket.timeout:
        log("[GDB] Socket timeout during GDB continue")
        return False
    except ConnectionResetError:
        # This might actually be success - crosvm may reset after continue
        log("[GDB] Connection reset (stub may have continued)")
        return True
    except Exception as e:
        log(f"[GDB] GDB continue failed: {e}")
        return False
    finally:
        if tunnel_proc:
            tunnel_proc.terminate()
            try:
                tunnel_proc.wait(timeout=2)
            except:
                tunnel_proc.kill()


def verify_exploit_privilege_escalation(
    exploit_path: str,
    arch: str = "arm64",
    ssh_host: Optional[str] = None,
    ssh_port: int = 22,
    adb_port: int = 6520,
    instance: Optional[int] = None,
    start_cmd: Optional[str] = None,
    stop_cmd: Optional[str] = None,
    timeout: int = 120,
    log_dir: Optional[str] = None,
    gdb_port: int = 1234,
    setup_tunnels: bool = False,
) -> Dict[str, Any]:
    """
    Verify an exploit achieves privilege escalation.
    
    This function:
    1. Stops the instance (if stop_cmd provided)
    2. Starts the instance (if start_cmd provided)
    3. Sends GDB continue if using gdb_run.sh start command
    4. Pushes the compiled exploit to the device
    5. Runs the exploit as a non-root user
    6. Checks if the exploit achieved root privileges
    
    Args:
        exploit_path: Path to the compiled exploit binary
        arch: Target architecture (arm64/x86_64)
        ssh_host: SSH host for remote Cuttlefish
        ssh_port: SSH port
        adb_port: ADB port for Cuttlefish device
        instance: Cuttlefish instance number (auto-calculates ADB port)
        start_cmd: Command to start Cuttlefish
        stop_cmd: Command to stop Cuttlefish
        timeout: Test timeout in seconds
        gdb_port: GDB port for crosvm (default 1234)
        setup_tunnels: Whether to set up SSH tunnels for GDB
        log_dir: Directory to save logs
        
    Returns:
        Dictionary with verification results
    """
    import subprocess
    
    print()
    print("=" * 80)
    print("  EXPLOIT PRIVILEGE ESCALATION VERIFICATION")
    print("=" * 80)
    print()
    
    result = {
        "exploit_path": exploit_path,
        "success": False,
        "initial_uid": None,
        "final_uid": None,
        "privilege_escalated": False,
        "crash_occurred": False,
        "error": None,
        "logs": [],
    }
    
    if log_dir:
        os.makedirs(log_dir, exist_ok=True)
    
    # Calculate ADB port from instance
    if instance is not None:
        adb_port = 6520 + (instance - 1)
    
    def log(msg: str):
        print(msg)
        result["logs"].append(msg)
    
    def run_ssh_cmd(cmd: str, timeout_sec: int = 120) -> Tuple[bool, str, str]:
        """Run a command on the remote host via SSH."""
        if ssh_host and ssh_host != 'localhost':
            try:
                proc = subprocess.run(
                    ['ssh', ssh_host, cmd],
                    capture_output=True,
                    text=True,
                    timeout=timeout_sec
                )
                return proc.returncode == 0, proc.stdout, proc.stderr
            except subprocess.TimeoutExpired:
                return False, "", "Command timed out"
            except Exception as e:
                return False, "", str(e)
        else:
            try:
                proc = subprocess.run(
                    cmd,
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=timeout_sec
                )
                return proc.returncode == 0, proc.stdout, proc.stderr
            except subprocess.TimeoutExpired:
                return False, "", "Command timed out"
            except Exception as e:
                return False, "", str(e)
    
    def run_adb_cmd(*args, timeout_sec: int = 30) -> Tuple[bool, str, str]:
        """Run an ADB command."""
        # Build ADB command with proper port if remote
        if ssh_host and ssh_host != 'localhost':
            # Use local ADB connecting to forwarded port
            adb_cmd = ['adb', '-s', f'localhost:{adb_port}'] + list(args)
        else:
            adb_cmd = ['adb'] + list(args)
        
        try:
            proc = subprocess.run(
                adb_cmd,
                capture_output=True,
                text=True,
                timeout=timeout_sec
            )
            return proc.returncode == 0, proc.stdout, proc.stderr
        except subprocess.TimeoutExpired:
            return False, "", "Command timed out"
        except Exception as e:
            return False, "", str(e)
    
    try:
        # Step 1: Stop instance if stop_cmd provided
        if stop_cmd:
            log("[STEP 1] Stopping instance...")
            success, stdout, stderr = run_ssh_cmd(stop_cmd)
            if not success:
                log(f"[WARN] Stop command may have failed: {stderr}")
            else:
                log("[OK] Instance stopped")
            # Wait for instance to fully stop
            time.sleep(5)
        else:
            log("[STEP 1] No stop_cmd provided, skipping stop")
        
        # Step 2: Start instance if start_cmd provided
        if start_cmd:
            log("[STEP 2] Starting instance...")
            success, stdout, stderr = run_ssh_cmd(start_cmd, timeout_sec=300)
            if not success:
                log(f"[WARN] Start command may have issues: {stderr}")
            else:
                log("[OK] Instance start command executed")
            # Wait for instance to stabilize
            log("[INFO] Waiting 10 seconds for instance to initialize...")
            time.sleep(10)
            
            # Check if this is a GDB run (gdb_run.sh) - need to send continue
            if 'gdb' in start_cmd.lower():
                log("[STEP 2.1] GDB start detected, sending continue command...")
                
                # If instance is specified, calculate GDB port based on instance
                # Instance 20 typically uses GDB port 1234 (only one gdb port per crosvm)
                # But some setups use port = base_port + instance - 1
                actual_gdb_port = gdb_port
                if instance and instance > 1:
                    # Check if we need to adjust port for instance
                    # Most setups use a single GDB port per crosvm launch
                    log(f"[INFO] Using GDB port {actual_gdb_port} for instance {instance}")
                
                gdb_continue_success = _send_gdb_continue(
                    ssh_host=ssh_host, 
                    gdb_port=actual_gdb_port,
                    setup_tunnels=setup_tunnels,
                    log_fn=log
                )
                if gdb_continue_success:
                    log("[OK] GDB continue sent, VM should be running")
                else:
                    log("[WARN] GDB continue may have failed, attempting anyway...")
                
                # Wait more for VM to boot after GDB continue
                # Cuttlefish typically takes 60-90 seconds to fully boot
                log("[INFO] Waiting 60 seconds for VM to boot after GDB continue...")
                time.sleep(60)
        else:
            log("[STEP 2] No start_cmd provided, assuming instance is running")
        
        # Step 3: Wait for ADB connection
        log("[STEP 3] Waiting for ADB connection...")
        max_wait = 60
        start_time = time.time()
        device_ready = False
        
        while time.time() - start_time < max_wait:
            success, stdout, stderr = run_adb_cmd('shell', 'echo', 'READY')
            if success and 'READY' in stdout:
                device_ready = True
                break
            time.sleep(2)
        
        if not device_ready:
            result["error"] = "Failed to connect to device via ADB"
            log(f"[ERROR] {result['error']}")
            return result
        log("[OK] ADB connection established")
        
        # Step 4: Check that exploit binary exists
        if not os.path.exists(exploit_path):
            result["error"] = f"Exploit binary not found: {exploit_path}"
            log(f"[ERROR] {result['error']}")
            return result
        log(f"[STEP 4] Exploit binary: {exploit_path}")
        
        # Step 5: Push exploit to device
        log("[STEP 5] Pushing exploit to device...")
        remote_path = "/data/local/tmp/exploit"
        success, stdout, stderr = run_adb_cmd('push', exploit_path, remote_path, timeout_sec=60)
        if not success:
            result["error"] = f"Failed to push exploit: {stderr}"
            log(f"[ERROR] {result['error']}")
            return result
        
        # Make executable
        run_adb_cmd('shell', 'chmod', '+x', remote_path)
        log(f"[OK] Exploit pushed to {remote_path}")
        
        # Step 6: Check initial UID (run as shell user, should be non-root)
        log("[STEP 6] Checking initial privilege level...")
        success, stdout, stderr = run_adb_cmd('shell', 'id')
        if success:
            log(f"[INFO] Initial ID: {stdout.strip()}")
            # Parse UID
            import re
            uid_match = re.search(r'uid=(\d+)', stdout)
            if uid_match:
                result["initial_uid"] = int(uid_match.group(1))
                if result["initial_uid"] == 0:
                    log("[WARN] Already running as root (uid=0), test may not be meaningful")
        
        # Step 7: Run the exploit as non-root (shell user)
        log("[STEP 7] Running exploit as non-root user...")
        log(f"[INFO] Command: {remote_path}")
        
        # Run exploit with wrapper that checks for privilege escalation
        # The exploit should attempt to gain root and then verify by running 'id'
        exploit_cmd = f"""
        cd /data/local/tmp && \\
        echo "=== BEFORE EXPLOIT ===" && \\
        id && \\
        echo "=== RUNNING EXPLOIT ===" && \\
        timeout {timeout} {remote_path}; EXPLOIT_EXIT=$?; \\
        echo "=== AFTER EXPLOIT (exit code: $EXPLOIT_EXIT) ===" && \\
        id && \\
        echo "=== EXPLOIT COMPLETE ==="
        """
        
        success, stdout, stderr = run_adb_cmd('shell', exploit_cmd, timeout_sec=timeout + 30)
        
        log(f"[INFO] Exploit output:")
        for line in stdout.split('\n'):
            log(f"    {line}")
        if stderr.strip():
            log(f"[STDERR] {stderr}")
        
        # Step 8: Parse results
        log("[STEP 8] Analyzing results...")
        
        # Check for crash patterns
        for pattern in CRASH_PATTERNS:
            if pattern in stdout or pattern in stderr:
                result["crash_occurred"] = True
                log(f"[WARN] Crash pattern detected: {pattern}")
                break
        
        # Look for privilege escalation indicators
        # Check the "AFTER EXPLOIT" id output
        after_match = re.search(r'=== AFTER EXPLOIT.*?===\s*(.*?)\s*===', stdout, re.DOTALL)
        if after_match:
            after_id = after_match.group(1).strip()
            uid_match = re.search(r'uid=(\d+)', after_id)
            if uid_match:
                result["final_uid"] = int(uid_match.group(1))
        
        # Alternative: look for any uid=0 appearing after "RUNNING EXPLOIT"
        if result["final_uid"] is None:
            running_idx = stdout.find("=== RUNNING EXPLOIT ===")
            if running_idx >= 0:
                after_output = stdout[running_idx:]
                uid_matches = list(re.finditer(r'uid=(\d+)', after_output))
                if uid_matches:
                    # Take the last UID found
                    result["final_uid"] = int(uid_matches[-1].group(1))
        
        # Check for privilege escalation
        if result["final_uid"] == 0:
            if result["initial_uid"] != 0:
                result["privilege_escalated"] = True
                result["success"] = True
                log("[SUCCESS] Privilege escalation verified! uid=0 achieved from non-root")
            else:
                log("[INFO] Final UID is 0, but started as root")
        elif result["final_uid"] is not None:
            log(f"[FAIL] Privilege escalation failed. Final UID: {result['final_uid']}")
        else:
            log("[WARN] Could not determine final UID")
        
        # Additional check: look for explicit success messages from exploit
        success_indicators = [
            "got root",
            "privilege escalation successful",
            "we are root",
            "uid=0",
            "root shell",
            "[+] SUCCESS",
        ]
        for indicator in success_indicators:
            if indicator.lower() in stdout.lower():
                log(f"[INFO] Success indicator found: '{indicator}'")
                if not result["privilege_escalated"]:
                    result["privilege_escalated"] = True
                    result["success"] = True
                    log("[SUCCESS] Privilege escalation likely succeeded based on output")
                break
        
    except Exception as e:
        result["error"] = str(e)
        log(f"[ERROR] Exception: {e}")
        import traceback
        traceback.print_exc()
    
    # Save results
    if log_dir:
        result_path = os.path.join(log_dir, "exploit_verification_result.json")
        with open(result_path, 'w') as f:
            json.dump(result, f, indent=2)
        log(f"[INFO] Results saved to: {result_path}")
    
    print()
    print("=" * 80)
    print("  VERIFICATION SUMMARY")
    print("=" * 80)
    print(f"  Exploit: {exploit_path}")
    print(f"  Initial UID: {result['initial_uid']}")
    print(f"  Final UID: {result['final_uid']}")
    print(f"  Privilege Escalated: {result['privilege_escalated']}")
    print(f"  Crash Occurred: {result['crash_occurred']}")
    print(f"  Success: {result['success']}")
    if result['error']:
        print(f"  Error: {result['error']}")
    print("=" * 80)
    print()
    
    return result


def test_exploit_on_device(
    exploit_path: str,
    arch: str = "arm64",
    ssh_host: Optional[str] = None,
    ssh_port: int = 22,
    adb_port: int = 6520,
    instance: Optional[int] = None,
    start_cmd: Optional[str] = None,
    stop_cmd: Optional[str] = None,
    timeout: int = 120,
    log_dir: Optional[str] = None,
    restart_on_finish: bool = True,
    persistent: bool = False,
    gdb_port: int = 1234,
    setup_tunnels: bool = False,
) -> Dict[str, Any]:
    """
    Full exploit test cycle: stop, start, push, run, verify.
    
    This is the main entry point for exploit verification that:
    1. Stops the instance (clean slate) - skipped if persistent=True
    2. Starts the instance (fresh boot) - skipped if persistent=True
    3. Sends GDB continue if using gdb_run.sh
    4. Pushes and runs the exploit
    4. Verifies privilege escalation
    5. Stops instance at end - skipped if persistent=True
    
    Args:
        exploit_path: Path to compiled exploit binary
        arch: Target architecture
        ssh_host: SSH host for remote access
        ssh_port: SSH port
        adb_port: ADB port
        instance: Cuttlefish instance number
        start_cmd: Command to start instance
        stop_cmd: Command to stop instance
        timeout: Exploit execution timeout
        log_dir: Directory for logs
        restart_on_finish: Restart instance after crash (only if not persistent)
        persistent: If True, assume instance is already running and don't stop it
        
    Returns:
        Verification result dictionary
    """
    # In persistent mode, don't pass start/stop commands to verification
    if persistent:
        result = verify_exploit_privilege_escalation(
            exploit_path=exploit_path,
            arch=arch,
            ssh_host=ssh_host,
            ssh_port=ssh_port,
            adb_port=adb_port,
            instance=instance,
            start_cmd=None,  # Don't start in persistent mode
            stop_cmd=None,   # Don't stop in persistent mode
            timeout=timeout,
            log_dir=log_dir,
            gdb_port=gdb_port,
            setup_tunnels=setup_tunnels,
        )
    else:
        result = verify_exploit_privilege_escalation(
            exploit_path=exploit_path,
            arch=arch,
            ssh_host=ssh_host,
            ssh_port=ssh_port,
            adb_port=adb_port,
            instance=instance,
            start_cmd=start_cmd,
            stop_cmd=stop_cmd,
            timeout=timeout,
            log_dir=log_dir,
            gdb_port=gdb_port,
            setup_tunnels=setup_tunnels,
        )
        
        # Stop instance at end if stop_cmd provided and not persistent
        if stop_cmd and not persistent:
            print("[INFO] Stopping instance after test...")
            import subprocess
            
            def run_ssh_cmd(cmd: str, timeout_sec: int = 120):
                if ssh_host and ssh_host != 'localhost':
                    try:
                        subprocess.run(['ssh', ssh_host, cmd], timeout=timeout_sec)
                    except:
                        pass
                else:
                    try:
                        subprocess.run(cmd, shell=True, timeout=timeout_sec)
                    except:
                        pass
            
            run_ssh_cmd(stop_cmd)
            print("[OK] Instance stopped")
    
    # Restart instance if a crash occurred and not persistent
    if not persistent and restart_on_finish and result.get("crash_occurred") and stop_cmd and start_cmd:
        print("[INFO] Restarting instance after crash...")
        import subprocess
        
        def run_ssh_cmd(cmd: str, timeout_sec: int = 120):
            if ssh_host and ssh_host != 'localhost':
                try:
                    subprocess.run(['ssh', ssh_host, cmd], timeout=timeout_sec)
                except:
                    pass
            else:
                try:
                    subprocess.run(cmd, shell=True, timeout=timeout_sec)
                except:
                    pass
        
        run_ssh_cmd(stop_cmd)
        time.sleep(5)
        run_ssh_cmd(start_cmd, timeout_sec=300)
        time.sleep(30)
        print("[OK] Instance restarted")
    
    return result


def compile_exploit(
    source_path: str,
    output_path: str,
    arch: str = "arm64",
) -> Tuple[bool, str]:
    """
    Compile an exploit C source file.
    
    Args:
        source_path: Path to the C source file
        output_path: Path for the compiled binary output
        arch: Target architecture (arm64/x86_64)
        
    Returns:
        Tuple of (success, error_message)
    """
    import subprocess
    
    if not os.path.exists(source_path):
        return False, f"Source file not found: {source_path}"
    
    # First try using compile script if available
    compile_script = Path(os.getcwd()) / f"compile_{arch}.sh"
    if compile_script.exists():
        print(f"[COMPILE] Using compile script: {compile_script}")
        try:
            result = subprocess.run(
                [str(compile_script), source_path, output_path],
                capture_output=True,
                text=True,
                timeout=120
            )
            if result.returncode == 0 and os.path.exists(output_path):
                os.chmod(output_path, 0o755)
                return True, ""
            else:
                print(f"[WARN] Compile script failed: {result.stderr}")
        except Exception as e:
            print(f"[WARN] Compile script error: {e}")
    
    # Fallback to direct cross-compilation
    if arch == "arm64":
        cc = "aarch64-linux-gnu-gcc"
        # Try alternative names
        for alt_cc in ["aarch64-linux-android-gcc", "aarch64-linux-gnu-gcc", "aarch64-none-linux-gnu-gcc"]:
            try:
                result = subprocess.run(['which', alt_cc], capture_output=True)
                if result.returncode == 0:
                    cc = alt_cc
                    break
            except:
                pass
    else:
        cc = "x86_64-linux-gnu-gcc"
    
    print(f"[COMPILE] Using compiler: {cc}")
    
    # Compile with common flags
    compile_cmd = [
        cc,
        "-static",
        "-o", output_path,
        source_path,
        "-lpthread",
        "-w",  # Suppress warnings
    ]
    
    try:
        result = subprocess.run(
            compile_cmd,
            capture_output=True,
            text=True,
            timeout=120
        )
        
        if result.returncode == 0 and os.path.exists(output_path):
            os.chmod(output_path, 0o755)
            print(f"[COMPILE] Success: {output_path}")
            return True, ""
        else:
            error_msg = result.stderr or result.stdout or "Unknown compilation error"
            print(f"[COMPILE] Failed: {error_msg[:200]}")
            return False, error_msg
            
    except subprocess.TimeoutExpired:
        return False, "Compilation timed out"
    except FileNotFoundError:
        return False, f"Compiler not found: {cc}"
    except Exception as e:
        return False, str(e)


def test_exploit_from_source(
    source_path: str,
    arch: str = "arm64",
    ssh_host: Optional[str] = None,
    ssh_port: int = 22,
    adb_port: int = 6520,
    instance: Optional[int] = None,
    start_cmd: Optional[str] = None,
    stop_cmd: Optional[str] = None,
    timeout: int = 120,
    log_dir: Optional[str] = None,
    persistent: bool = False,
    output_binary: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Compile and test an exploit from C source file.
    
    Full cycle:
    1. Compile the C source file for target architecture
    2. Stop the instance (if not persistent)
    3. Start the instance (if not persistent)
    4. Push the compiled exploit to the device
    5. Run as non-root user and verify privilege escalation to root
    6. Stop the instance (if not persistent)
    
    Args:
        source_path: Path to the exploit C source file
        arch: Target architecture (arm64/x86_64)
        ssh_host: SSH host for Cuttlefish (can be ~/.ssh/config alias)
        ssh_port: SSH port
        adb_port: ADB port for Cuttlefish device
        instance: Cuttlefish instance number (auto-calculates ADB port)
        start_cmd: Command to start Cuttlefish
        stop_cmd: Command to stop Cuttlefish
        timeout: Exploit execution timeout in seconds
        log_dir: Directory to save logs
        persistent: If True, assume instance is already running and keep it running
        output_binary: Path for compiled binary (default: source_path without .c + _arch)
        
    Returns:
        Dictionary with compilation and verification results
    """
    print()
    print("=" * 80)
    print("  EXPLOIT TEST FROM SOURCE")
    print("=" * 80)
    print()
    
    result = {
        "source_path": source_path,
        "arch": arch,
        "compiled": False,
        "binary_path": None,
        "verification": None,
        "error": None,
    }
    
    if log_dir:
        os.makedirs(log_dir, exist_ok=True)
    
    # Step 1: Compile the exploit
    print(f"[STEP 1] Compiling exploit from source: {source_path}")
    
    if not os.path.exists(source_path):
        result["error"] = f"Source file not found: {source_path}"
        print(f"[ERROR] {result['error']}")
        return result
    
    # Determine output binary path
    if output_binary:
        binary_path = output_binary
    else:
        base = source_path
        if base.endswith('.c'):
            base = base[:-2]
        binary_path = f"{base}_{arch}"
    
    # Compile
    compile_success, compile_error = compile_exploit(source_path, binary_path, arch)
    
    if not compile_success:
        result["error"] = f"Compilation failed: {compile_error}"
        print(f"[ERROR] {result['error']}")
        return result
    
    result["compiled"] = True
    result["binary_path"] = binary_path
    print(f"[OK] Compiled to: {binary_path}")
    
    # Step 2: Run verification
    print(f"\n[STEP 2] Running exploit verification (persistent={persistent})...")
    
    verification_result = test_exploit_on_device(
        exploit_path=binary_path,
        arch=arch,
        ssh_host=ssh_host,
        ssh_port=ssh_port,
        adb_port=adb_port,
        instance=instance,
        start_cmd=start_cmd,
        stop_cmd=stop_cmd,
        timeout=timeout,
        log_dir=log_dir,
        restart_on_finish=not persistent,
        persistent=persistent,
    )
    
    result["verification"] = verification_result
    
    # Final summary
    print()
    print("=" * 80)
    print("  TEST FROM SOURCE SUMMARY")
    print("=" * 80)
    print(f"  Source: {source_path}")
    print(f"  Binary: {binary_path}")
    print(f"  Compiled: {result['compiled']}")
    print(f"  Persistent Mode: {persistent}")
    if verification_result:
        print(f"  Privilege Escalated: {verification_result.get('privilege_escalated', False)}")
        print(f"  Initial UID: {verification_result.get('initial_uid')}")
        print(f"  Final UID: {verification_result.get('final_uid')}")
        print(f"  Success: {verification_result.get('success', False)}")
    if result.get('error'):
        print(f"  Error: {result['error']}")
    print("=" * 80)
    print()
    
    return result