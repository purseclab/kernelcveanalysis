from typing import Any, Tuple
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
    arch: str = "arm64"
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
) -> Tuple[bool, int, dict]:
    """
    Test a reproducer using the CuttlefishController with support for
    persistent and non-persistent modes.
    
    This function orchestrates:
    1. Starting Cuttlefish (if not already running/persistent)
    2. Uploading the reproducer via ADB
    3. Optionally attaching kernel GDB via crosvm
       - For remote Cuttlefish: GDB runs on remote server, results transferred back
       - For local Cuttlefish: GDB runs locally
    4. Running the reproducer and monitoring for crashes
    5. Stopping Cuttlefish (if non-persistent mode)
    
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
    
    Returns:
        Tuple of (crash_occurred, crash_type, dynamic_results)
    
    Example usage:
        from syzploit.SyzVerify.cuttlefish import CuttlefishConfig
        
        # Persistent mode - Cuttlefish already running
        config = CuttlefishConfig(
            persistent=True,
            already_running=True,
            gdb_port=1234,
            adb_port=6520,
        )
        
        # Non-persistent mode - start/stop for each test
        config = CuttlefishConfig(
            persistent=False,
            start_command="cd ~/cf && HOME=$PWD ./bin/launch_cvd --daemon",
            stop_command="cd ~/cf && HOME=$PWD ./bin/stop_cvd",
            gdb_port=1234,
            adb_port=6520,
        )
        
        crashed, crash_type, results = test_repro_with_cuttlefish_controller(
            repro_path="./repro",
            bug_id="bug123",
            cuttlefish_config=config,
        )
    """
    from .cuttlefish import CuttlefishController, CuttlefishConfig
    
    controller = CuttlefishController(cuttlefish_config)
    os.makedirs(log_dir, exist_ok=True)
    
    dynamic_results = {
        "bug_id": bug_id,
        "analysis_mode": "cuttlefish_controller",
        "persistent_mode": cuttlefish_config.persistent,
        "gdb_enabled": cuttlefish_config.enable_gdb,
        "arch": arch,
        "events": [],
        "crash_detected": False,
    }
    
    crash_occurred = False
    crash_type = 0
    
    try:
        # Step 1: Start/connect to Cuttlefish
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
        print(f"[CONFIG] Log file: {controller.get_log_file_path()}")
        print()
        
        print("-" * 60)
        print("[STEP 1] Starting/connecting to Cuttlefish...")
        print("-" * 60)
        
        # If GDB is enabled, generate the GDB script BEFORE starting
        # so that it can be loaded during kernel boot
        gdb_script_path = None
        kernel_gdb = None
        
        if cuttlefish_config.enable_gdb:
            from .cuttlefish import CuttlefishKernelGDB
            
            # Determine if this is a remote Cuttlefish instance
            is_remote = cuttlefish_config.ssh_host != "localhost" or cuttlefish_config.ssh_port != 22
            
            print("[GDB] Generating kernel GDB analysis script...")
            kernel_gdb = CuttlefishKernelGDB(controller, log_dir)
            
            # Log symbol extraction results
            if kernel_gdb.vmlinux_path:
                print(f"[GDB] Using vmlinux with symbols: {kernel_gdb.vmlinux_path}")
            if kernel_gdb.system_map_path:
                print(f"[GDB] Using System.map: {kernel_gdb.system_map_path}")
            
            # Generate breakpoints from parsed crash info
            breakpoints = []
            if parsed_crash:
                if "corrupted_function" in parsed_crash:
                    breakpoints.append({"function": parsed_crash["corrupted_function"]})
                if "stack_frames" in parsed_crash:
                    for frame in parsed_crash["stack_frames"][:5]:
                        if "function" in frame:
                            breakpoints.append({"function": frame["function"]})
            
            # Use auto-extracted vmlinux from kernel_gdb, or fallback to provided paths
            effective_vmlinux = kernel_gdb.vmlinux_path or (remote_vmlinux_path if is_remote else vmlinux_path)
            
            gdb_script_path = kernel_gdb.generate_kernel_gdb_script(
                bug_id=bug_id,
                breakpoints=breakpoints,
                vmlinux_path=effective_vmlinux,
            )
            print(f"[GDB] Script generated: {gdb_script_path}")
        else:
            effective_vmlinux = vmlinux_path
        
        if not controller.start(gdb_script_path=gdb_script_path, vmlinux_path=effective_vmlinux if cuttlefish_config.enable_gdb else None):
            print("[ERROR] Failed to start Cuttlefish")
            print(f"[INFO] Check detailed log: {controller.get_log_file_path()}")
            dynamic_results["error"] = "Failed to start Cuttlefish"
            dynamic_results["log_file"] = controller.get_log_file_path()
            return False, 0, dynamic_results
        
        dynamic_results["cuttlefish_started"] = True
        dynamic_results["log_file"] = controller.get_log_file_path()
        print("[OK] Cuttlefish is ready")
        print()
        
        # Step 2: Configure ADB to use the controller's settings
        global ADB_TARGET_DEVICE, ADB_EXE_PATH
        old_adb_target = ADB_TARGET_DEVICE
        old_adb_exe = ADB_EXE_PATH
        ADB_TARGET_DEVICE = controller.get_adb_target()
        
        # Use system adb (not ./adb) for controller-based tests
        ADB_EXE_PATH = cuttlefish_config.adb_exe
        
        print(f"[CONFIG] Using ADB target: {ADB_TARGET_DEVICE}")
        print(f"[CONFIG] Using ADB executable: {ADB_EXE_PATH}")
        
        # If using SSH tunnels, we need to connect to the device through the tunneled ADB server
        if cuttlefish_config.setup_tunnels:
            print(f"[CONFIG] SSH tunnels enabled - connecting via tunneled ADB server")
            # The tunnel forwards local 5037 to remote 5037
            # Device is at localhost:adb_port on the remote, accessible via tunneled server
            connect_result = subprocess.run(
                [ADB_EXE_PATH, "connect", ADB_TARGET_DEVICE],
                capture_output=True,
                text=True,
                timeout=10
            )
            print(f"[ADB] Connect result: {connect_result.stdout.strip()}")
        
        # Step 2.5: Extract kallsyms if vmlinux-to-elf failed
        if kernel_gdb and not kernel_gdb.system_map_path:
            print("[SYMBOLS] vmlinux extraction failed, trying kallsyms from running system...")
            if kernel_gdb.extract_kallsyms_after_boot(adb_target=ADB_TARGET_DEVICE):
                print(f"[SYMBOLS] Successfully extracted kallsyms: {kernel_gdb.system_map_path}")
                dynamic_results["symbols_source"] = "kallsyms"
            else:
                print("[SYMBOLS] Failed to extract kallsyms - debugging without symbols")
                dynamic_results["symbols_source"] = "none"
        elif kernel_gdb and kernel_gdb.system_map_path:
            dynamic_results["symbols_source"] = "vmlinux"
        
        # Step 3: Get device info
        print("-" * 60)
        print("[STEP 2] Getting device information...")
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
        
        # Step 4: Upload reproducer
        print("-" * 60)
        print("[STEP 3] Uploading reproducer...")
        print("-" * 60)
        
        adb_upload_file(repro_path, Path(REPRO_PATH))
        _adb_shell(f'chmod +x {REPRO_PATH}')
        print(f"[OK] Reproducer uploaded to {REPRO_PATH}")
        print()
        
        # Record uptime before test
        t0 = get_uptime()
        print(f"[DEVICE] Uptime before test: {t0:.2f}s")
        
        # Step 5: Run with GDB if enabled
        if cuttlefish_config.enable_gdb:
            print("-" * 60)
            print("[STEP 4] Running reproducer (GDB script loaded at boot)...")
            print("-" * 60)
            
            # GDB script was already loaded during boot (via controller.start())
            # Now we just run the reproducer and let the breakpoints trigger
            
            print("[GDB] GDB script was loaded during kernel boot")
            print(f"[GDB] Script path: {gdb_script_path}")
            
            # Start reproducer in background
            print("[GDB] Starting reproducer on device...")
            if root:
                repro_cmd = f'cd {os.path.dirname(REPRO_PATH)} && nohup su root {REPRO_PATH} > /dev/null 2>&1 &'
            else:
                repro_cmd = f'cd {os.path.dirname(REPRO_PATH)} && nohup {REPRO_PATH} > /dev/null 2>&1 &'
            _adb_shell(repro_cmd)
            time.sleep(1)
            
            # Wait for the timeout period to let the reproducer run
            # GDB is already attached and monitoring from boot
            print(f"[GDB] Waiting {timeout}s for reproducer execution...")
            time.sleep(min(timeout, 30))  # Wait a bit for reproducer to trigger
            
            # Check if there are results from the GDB session
            # The script should have saved results to a JSON file
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
                
                # Clean up remote resources if needed
                kernel_gdb.cleanup()
        
        else:
            # Direct execution without GDB
            print("-" * 60)
            print("[STEP 4] Running reproducer directly (no GDB)...")
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
        
        # Step 6: Check for crash
        print("-" * 60)
        print("[STEP 5] Checking device state...")
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
        # Step 7: Cleanup Cuttlefish
        print()
        print("-" * 60)
        print("[STEP 6] Cleaning up...")
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
    print(f"[RESULTS] Detailed log: {controller.get_log_file_path()}")
    print("=" * 80)
    print()
    
    return crash_occurred, crash_type, dynamic_results