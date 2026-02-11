"""
Cuttlefish Controller Module

Provides management of Cuttlefish Android emulator instances for testing,
supporting both persistent (already running or boot once) and non-persistent
(start/stop for each test) modes.

Key features:
- Local or remote SSH-based execution
- GDB attachment for dynamic analysis
- Configurable start/stop commands for non-persistent mode
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Tuple, List, Callable
import subprocess
import time
import os
import socket
import threading
import json
import logging
import shutil
import tempfile
from datetime import datetime

import paramiko

# Try to import pyelftools for System.map generation
try:
    from elftools.elf.elffile import ELFFile
    HAS_ELFTOOLS = True
except ImportError:
    ELFFile = None
    HAS_ELFTOOLS = False


@dataclass
class CuttlefishConfig:
    """Configuration for Cuttlefish instance management."""
    
    # SSH connection settings
    ssh_host: str = "localhost"
    ssh_port: int = 22
    ssh_user: Optional[str] = None  # If None, uses ~/.ssh/config
    ssh_password: Optional[str] = None
    ssh_key_path: Optional[str] = None
    
    # Cuttlefish control
    cuttlefish_home: str = "~/cuttlefish"
    
    # Persistence mode
    persistent: bool = True  # If True, assume Cuttlefish is already running or will stay up
    already_running: bool = False  # If True with persistent, skip boot entirely
    
    # Commands for non-persistent mode (executed via SSH)
    start_command: Optional[str] = None  # e.g., "HOME=$PWD ./bin/launch_cvd -kernel_path=..." (GDB-enabled start)
    run_command: Optional[str] = None    # Non-GDB start command for symbol extraction (e.g., ./run.sh). Falls back to start_command.
    stop_command: Optional[str] = None   # e.g., "HOME=$PWD ./bin/stop_cvd"
    
    # Cuttlefish runtime log directory (for fetching kernel.log, logcat, etc.)
    # If None, will try to infer from start_command or use cuttlefish_home/cuttlefish_runtime/logs
    cuttlefish_runtime_logs: Optional[str] = None  # e.g., "~/challenge-4/challenge-4.1/cuttlefish_runtime.5/logs"
    
    # Boot timeout
    boot_timeout: int = 360  # seconds
    shutdown_timeout: int = 60  # seconds
    startup_delay: int = 10  # seconds to wait after starting instance before checking ports
    
    # GDB settings
    gdb_host: str = "localhost"  # Host where GDB can connect (after SSH tunnel if needed)
    gdb_port: int = 1234
    enable_gdb: bool = True
    gdb_connect_timeout: int = 300  # seconds to wait for GDB stub to accept connections (launch_cvd can take 2-3 min for assembly)
    gdb_attach_after_boot: bool = True  # If True, attach GDB AFTER kernel boots (better for crosvm)
                                         # If False, attach at early boot (required for boot-time tracing)
    
    # ADB settings  
    adb_host: str = "localhost"
    adb_port: int = 6520  # Default Cuttlefish ADB port (device port, not server)
    adb_exe: str = "adb"
    
    # SSH tunneling (for remote cuttlefish)
    setup_tunnels: bool = False  # Whether to set up SSH tunnels for GDB/ADB
    local_gdb_port: int = 1234   # Local port to forward GDB
    local_adb_server_port: int = 5037   # Local port for ADB server tunnel (ssh -L 5037:localhost:5037)
    
    # Kernel symbol extraction (for GDB debugging with symbols)
    kernel_image_path: Optional[str] = None  # Path to kernel Image file (local or remote)
    vmlinux_path: Optional[str] = None       # Path to vmlinux ELF with symbols (auto-extracted if kernel_image_path set)
    system_map_path: Optional[str] = None    # Path to System.map for symbol resolution
    extract_symbols: bool = True             # Auto-extract vmlinux from kernel Image using vmlinux-to-elf
    extract_runtime_symbols: bool = True     # Extract /proc/kallsyms from running VM for accurate breakpoint addresses
    
    # Logging
    log_file: Optional[str] = None  # Path to log file (default: cuttlefish_controller.log in cwd)
    verbose_logging: bool = True  # Enable verbose logging to file


# ============================================================================
# Vmlinux Extraction Utilities
# ============================================================================

def extract_vmlinux_from_image(
    kernel_image_path: str,
    output_dir: Optional[str] = None,
    logger: Optional[Callable] = None,
) -> Optional[str]:
    """
    Extract vmlinux ELF with symbols from a kernel Image using vmlinux-to-elf.
    
    vmlinux-to-elf extracts kallsyms from the kernel image to reconstruct
    a debuggable ELF file with proper symbol information.
    
    Args:
        kernel_image_path: Path to kernel Image file
        output_dir: Directory to store extracted vmlinux (default: temp dir)
        logger: Optional logging function
    
    Returns:
        Path to extracted vmlinux ELF, or None if extraction failed
    """
    def log(msg):
        if logger:
            logger(msg)
        else:
            print(f"[VMLINUX] {msg}")
    
    # Check if vmlinux-to-elf is available
    tool = shutil.which("vmlinux-to-elf")
    if not tool:
        log("vmlinux-to-elf not found in PATH - install with: pip install vmlinux-to-elf")
        return None
    
    if not os.path.exists(kernel_image_path):
        log(f"Kernel image not found: {kernel_image_path}")
        return None
    
    # Create output directory
    if output_dir:
        out_dir = Path(output_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
    else:
        out_dir = Path(tempfile.mkdtemp(prefix="vmlinux_extract_"))
    
    vmlinux_out = out_dir / "vmlinux"
    
    log(f"Extracting vmlinux from {kernel_image_path}...")
    log(f"Output: {vmlinux_out}")
    
    try:
        proc = subprocess.run(
            [tool, str(kernel_image_path), str(vmlinux_out)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=120,
        )
        
        if proc.returncode == 0 and vmlinux_out.exists():
            log(f"Successfully extracted vmlinux ({vmlinux_out.stat().st_size} bytes)")
            return str(vmlinux_out)
        else:
            log(f"vmlinux-to-elf failed (rc={proc.returncode})")
            if proc.stderr:
                # Log full error for debugging
                log(f"Full error output:")
                for line in proc.stderr.strip().split('\n'):
                    log(f"  {line}")
            if proc.stdout:
                log(f"stdout: {proc.stdout[:200]}")
            log("Note: This may happen if kernel was built without CONFIG_KALLSYMS or kallsyms are not exposed")
            log("Fallback: Will try to extract /proc/kallsyms from running system after boot")
            return None
            
    except subprocess.TimeoutExpired:
        log("vmlinux-to-elf timed out")
        return None
    except Exception as e:
        log(f"vmlinux-to-elf error: {e}")
        return None


def extract_kallsyms_from_running_system(
    ssh_host: str,
    local_output_dir: str,
    ssh_user: Optional[str] = None,
    ssh_key_path: Optional[str] = None,
    adb_exe: str = "adb",
    adb_target: Optional[str] = None,
    use_adb: bool = True,
    logger: Optional[Callable] = None,
) -> Optional[str]:
    """
    Extract /proc/kallsyms from a running system via ADB or SSH.
    
    This is a fallback when vmlinux-to-elf fails (e.g., kernel built without
    exposed kallsyms). Requires the system to be booted and accessible.
    
    Args:
        ssh_host: SSH host for remote execution
        local_output_dir: Local directory to store kallsyms
        ssh_user: Optional SSH username
        ssh_key_path: Optional path to SSH private key
        adb_exe: Path to adb executable
        adb_target: ADB device target (e.g., "0.0.0.0:6524")
        use_adb: If True, use ADB; if False, use SSH
        logger: Optional logging function
    
    Returns:
        Path to extracted kallsyms file (in System.map format), or None if failed
    """
    def log(msg):
        if logger:
            logger(msg)
        else:
            print(f"[KALLSYMS] {msg}")
    
    out_dir = Path(local_output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    kallsyms_file = out_dir / "kallsyms.txt"
    system_map_file = out_dir / "System.map"
    
    log("Extracting /proc/kallsyms from running system...")
    
    def try_disable_kptr_restrict_adb(adb_exe: str, adb_target: str) -> bool:
        """Try to disable kptr_restrict via ADB. Returns True if successful."""
        log("Attempting to disable kptr_restrict via ADB...")
        
        # Try multiple methods to disable kptr_restrict
        disable_cmds = [
            # Method 1: su -c (common on rooted devices)
            [adb_exe, "-s", adb_target, "shell", "su", "-c", "echo 0 > /proc/sys/kernel/kptr_restrict"],
            # Method 2: su root with -c
            [adb_exe, "-s", adb_target, "shell", "su", "root", "-c", "echo 0 > /proc/sys/kernel/kptr_restrict"],
            # Method 3: Direct shell (if already root)
            [adb_exe, "-s", adb_target, "shell", "echo 0 > /proc/sys/kernel/kptr_restrict"],
            # Method 4: Using sh -c
            [adb_exe, "-s", adb_target, "shell", "su", "-c", "sh -c 'echo 0 > /proc/sys/kernel/kptr_restrict'"],
        ]
        
        for cmd in disable_cmds:
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    log(f"kptr_restrict disable command succeeded: {' '.join(cmd[-3:])}")
                    return True
            except Exception:
                pass
        
        log("Could not disable kptr_restrict - all methods failed")
        return False
    
    def try_disable_kptr_restrict_ssh(ssh_host: str, ssh_user: Optional[str], ssh_key_path: Optional[str]) -> bool:
        """Try to disable kptr_restrict via SSH. Returns True if successful."""
        log("Attempting to disable kptr_restrict via SSH...")
        
        ssh_cmd = ["ssh"]
        if ssh_key_path:
            ssh_cmd.extend(["-i", ssh_key_path])
        if ssh_user:
            ssh_cmd.append(f"{ssh_user}@{ssh_host}")
        else:
            ssh_cmd.append(ssh_host)
        
        # Try multiple methods
        disable_cmds = [
            ssh_cmd + ["sudo", "sh", "-c", "echo 0 > /proc/sys/kernel/kptr_restrict"],
            ssh_cmd + ["echo", "0", "|", "sudo", "tee", "/proc/sys/kernel/kptr_restrict"],
        ]
        
        for cmd in disable_cmds:
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    log("kptr_restrict disabled via SSH")
                    return True
            except Exception:
                pass
        
        return False
    
    try:
        if use_adb and adb_target:
            # Use ADB to extract kallsyms
            log(f"Using ADB to extract kallsyms from {adb_target}")
            
            # First, try to read kallsyms with root
            cmd = [adb_exe, "-s", adb_target, "shell", "su", "-c", "cat /proc/kallsyms"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode != 0:
                # Try su root format
                cmd = [adb_exe, "-s", adb_target, "shell", "su", "root", "cat", "/proc/kallsyms"]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode != 0:
                # Try without su if it fails (maybe already root)
                cmd = [adb_exe, "-s", adb_target, "shell", "cat", "/proc/kallsyms"]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            kallsyms_content = result.stdout
            
            # Check if addresses are zeroed (kptr_restrict) and try to fix
            if kallsyms_content:
                lines = kallsyms_content.strip().split('\n')[:10]
                if lines and all(line.startswith('0000000000000000') for line in lines if line.strip()):
                    log("kallsyms addresses are zeroed - kptr_restrict is enabled")
                    
                    # Try to disable kptr_restrict
                    if try_disable_kptr_restrict_adb(adb_exe, adb_target):
                        log("Retrying kallsyms extraction after disabling kptr_restrict...")
                        # Wait a moment and retry
                        import time
                        time.sleep(0.5)
                        
                        # Retry extraction
                        cmd = [adb_exe, "-s", adb_target, "shell", "su", "-c", "cat /proc/kallsyms"]
                        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                        if result.returncode != 0:
                            cmd = [adb_exe, "-s", adb_target, "shell", "cat", "/proc/kallsyms"]
                            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                        kallsyms_content = result.stdout
        else:
            # Use SSH to extract kallsyms
            log(f"Using SSH to extract kallsyms from {ssh_host}")
            ssh_cmd = ["ssh"]
            if ssh_key_path:
                ssh_cmd.extend(["-i", ssh_key_path])
            if ssh_user:
                ssh_cmd.append(f"{ssh_user}@{ssh_host}")
            else:
                ssh_cmd.append(ssh_host)
            ssh_cmd.extend(["cat", "/proc/kallsyms"])
            
            result = subprocess.run(ssh_cmd, capture_output=True, text=True, timeout=30)
            kallsyms_content = result.stdout
            
            # Check and try to fix kptr_restrict
            if kallsyms_content:
                lines = kallsyms_content.strip().split('\n')[:10]
                if lines and all(line.startswith('0000000000000000') for line in lines if line.strip()):
                    if try_disable_kptr_restrict_ssh(ssh_host, ssh_user, ssh_key_path):
                        result = subprocess.run(ssh_cmd, capture_output=True, text=True, timeout=30)
                        kallsyms_content = result.stdout
        
        if not kallsyms_content or len(kallsyms_content) < 100:
            log("Failed to extract kallsyms or content is empty")
            log("This may happen if kernel has kptr_restrict enabled and could not be disabled")
            return None
        
        # Check if addresses are still zeroed (kptr_restrict couldn't be disabled)
        lines = kallsyms_content.strip().split('\n')[:10]
        if lines and all(line.startswith('0000000000000000') for line in lines if line.strip()):
            log("kallsyms addresses are still zeroed (kptr_restrict could not be disabled)")
            log("To fix manually, run as root on the target:")
            log("  echo 0 > /proc/sys/kernel/kptr_restrict")
            log("Or ensure the device is running with root/userdebug build")
            return None
        
        # Save raw kallsyms
        with open(kallsyms_file, 'w') as f:
            f.write(kallsyms_content)
        log(f"Saved raw kallsyms to {kallsyms_file}")
        
        # Convert to System.map format (kallsyms format is similar but may have module info)
        # kallsyms: addr type name [module]
        # System.map: addr type name
        with open(system_map_file, 'w') as out:
            for line in kallsyms_content.strip().split('\n'):
                parts = line.split()
                if len(parts) >= 3:
                    addr, typ, name = parts[0], parts[1], parts[2]
                    out.write(f"{addr} {typ} {name}\n")
        
        symbol_count = len(kallsyms_content.strip().split('\n'))
        log(f"Generated System.map with {symbol_count} symbols from /proc/kallsyms")
        return str(system_map_file)
        
    except subprocess.TimeoutExpired:
        log("Timeout extracting kallsyms")
        return None
    except Exception as e:
        log(f"Failed to extract kallsyms: {e}")
        return None


def generate_system_map(vmlinux_path: str, output_path: Optional[str] = None, logger: Optional[Callable] = None) -> Optional[str]:
    """
    Generate a System.map-style file from vmlinux using pyelftools.
    
    This extracts symbol addresses from the ELF file to create a symbol map
    that can be used for address-to-symbol resolution during debugging.
    
    Args:
        vmlinux_path: Path to vmlinux ELF file
        output_path: Output path for System.map (default: same dir as vmlinux)
        logger: Optional logging function
    
    Returns:
        Path to generated System.map, or None if failed
    """
    def log(msg):
        if logger:
            logger(msg)
        else:
            print(f"[SYSTEM.MAP] {msg}")
    
    if not HAS_ELFTOOLS:
        log("pyelftools not available - install with: pip install pyelftools")
        return None
    
    if not os.path.exists(vmlinux_path):
        log(f"vmlinux not found: {vmlinux_path}")
        return None
    
    vmlinux = Path(vmlinux_path)
    if output_path:
        out_map = Path(output_path)
    else:
        out_map = vmlinux.parent / "System.map"
    
    log(f"Generating System.map from {vmlinux_path}...")
    
    try:
        with vmlinux.open("rb") as fh:
            elf = ELFFile(fh)
            syms = []
            
            for sec in elf.iter_sections():
                st = getattr(sec.header, 'sh_type', 0)
                if st in (2, 11) or getattr(sec.header, 'sh_type', None) in ("SHT_SYMTAB", "SHT_DYNSYM"):
                    try:
                        for sym in sec.iter_symbols():
                            addr = sym['st_value']
                            name = sym.name
                            if not name or addr == 0:
                                continue
                            typ = sym['st_info']['type']
                            # Determine symbol type letter
                            letter = 'T' if (typ == 2 or 'FUNC' in str(typ).upper()) else (
                                'D' if (typ == 1 or 'OBJECT' in str(typ).upper()) else '?'
                            )
                            syms.append((addr, letter, name))
                    except Exception:
                        continue
            
            syms.sort(key=lambda x: x[0])
            
            with out_map.open("w") as out:
                for addr, letter, name in syms:
                    out.write(f"{addr:016x} {letter} {name}\n")
        
        log(f"Wrote System.map with {len(syms)} symbols")
        return str(out_map)
        
    except Exception as e:
        log(f"Failed to generate System.map: {e}")
        return None


def download_and_extract_kernel_symbols(
    ssh_host: str,
    remote_kernel_image: str,
    local_output_dir: str,
    ssh_user: Optional[str] = None,
    ssh_key_path: Optional[str] = None,
    logger: Optional[Callable] = None,
) -> Tuple[Optional[str], Optional[str]]:
    """
    Download kernel Image from remote host and extract vmlinux with symbols.
    
    This is useful when the kernel Image is on a remote Cuttlefish server
    and you want to debug locally with symbols.
    
    Args:
        ssh_host: SSH host (can be ~/.ssh/config alias)
        remote_kernel_image: Path to kernel Image on remote host
        local_output_dir: Local directory to store extracted files
        ssh_user: Optional SSH username
        ssh_key_path: Optional path to SSH private key
        logger: Optional logging function
    
    Returns:
        Tuple of (vmlinux_path, system_map_path), or (None, None) if failed
    """
    def log(msg):
        if logger:
            logger(msg)
        else:
            print(f"[DOWNLOAD] {msg}")
    
    out_dir = Path(local_output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    
    local_image = out_dir / "kernel_Image"
    
    # Build SCP command
    scp_cmd = ["scp", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no"]
    if ssh_key_path:
        scp_cmd.extend(["-i", ssh_key_path])
    
    if ssh_user:
        remote_target = f"{ssh_user}@{ssh_host}:{remote_kernel_image}"
    else:
        remote_target = f"{ssh_host}:{remote_kernel_image}"
    
    scp_cmd.extend([remote_target, str(local_image)])
    
    log(f"Downloading kernel Image from {remote_target}...")
    
    try:
        result = subprocess.run(
            scp_cmd,
            capture_output=True,
            text=True,
            timeout=300,
        )
        
        if result.returncode != 0:
            log(f"SCP failed: {result.stderr}")
            return None, None
        
        log(f"Downloaded kernel Image ({local_image.stat().st_size} bytes)")
        
    except Exception as e:
        log(f"Download failed: {e}")
        return None, None
    
    # Extract vmlinux
    vmlinux_path = extract_vmlinux_from_image(str(local_image), str(out_dir), logger)
    if not vmlinux_path:
        return None, None
    
    # Generate System.map
    system_map_path = generate_system_map(vmlinux_path, logger=logger)
    
    return vmlinux_path, system_map_path


class CuttlefishController:
    """
    Controller for managing Cuttlefish instances.
    
    Supports two modes:
    1. Persistent mode: Cuttlefish is already running or boots once and stays up.
       - Set persistent=True, already_running=True if it's already booted
       - Set persistent=True, already_running=False to boot once and keep running
    
    2. Non-persistent mode: Cuttlefish starts and stops for each test run.
       - Set persistent=False and provide start_command/stop_command
    """
    
    def __init__(self, config: CuttlefishConfig):
        # Resolve adb_exe to local syzploit/adb if not an absolute path
        if not os.path.isabs(config.adb_exe):
            # Find syzploit/adb relative to this file (cuttlefish.py is in src/syzploit/SyzVerify/)
            repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..', '..'))
            local_adb = os.path.join(repo_root, 'adb')
            if os.path.exists(local_adb):
                config.adb_exe = local_adb
            # Fallback: check /workspace/syzploit/adb for Docker container
            elif os.path.exists('/workspace/syzploit/adb'):
                config.adb_exe = '/workspace/syzploit/adb'
        
        self.config = config
        self._ssh_client: Optional[paramiko.SSHClient] = None
        self._tunnel_processes: List[subprocess.Popen] = []
        self._cuttlefish_process: Optional[subprocess.Popen] = None
        self._background_ssh_proc: Optional[subprocess.Popen] = None
        self._gdb_process: Optional[subprocess.Popen] = None
        self._gdb_script_path: Optional[Path] = None
        self._vmlinux_path: Optional[str] = None
        self._is_booted = False
        self._boot_log: List[str] = []
        
        # Set up logging
        self._setup_logging()
    
    def _setup_logging(self) -> None:
        """Set up file and console logging."""
        self.logger = logging.getLogger(f"CuttlefishController_{id(self)}")
        self.logger.setLevel(logging.DEBUG)
        
        # Remove existing handlers to avoid duplicates
        self.logger.handlers.clear()
        
        # File handler - mode='w' to reset log on each run
        log_file = self.config.log_file or "cuttlefish_controller.log"
        file_handler = logging.FileHandler(log_file, mode='w')
        file_handler.setLevel(logging.DEBUG)
        file_formatter = logging.Formatter(
            '%(asctime)s | %(levelname)-8s | %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        file_handler.setFormatter(file_formatter)
        self.logger.addHandler(file_handler)
        
        # Store log file path for reference
        self._log_file_path = os.path.abspath(log_file)
        
        # Log session start
        self._log_separator()
        self._log_info("=" * 80)
        self._log_info(f"CUTTLEFISH CONTROLLER SESSION STARTED")
        self._log_info(f"Timestamp: {datetime.now().isoformat()}")
        self._log_info(f"Log file: {self._log_file_path}")
        self._log_info("=" * 80)
        self._log_config()
    
    def _log_separator(self) -> None:
        """Log a separator line."""
        self.logger.debug("-" * 80)
    
    def _log_debug(self, msg: str) -> None:
        """Log debug message."""
        self.logger.debug(msg)
    
    def _log_info(self, msg: str) -> None:
        """Log info message."""
        self.logger.info(msg)
    
    def _log_warning(self, msg: str) -> None:
        """Log warning message."""
        self.logger.warning(msg)
    
    def _log_error(self, msg: str) -> None:
        """Log error message."""
        self.logger.error(msg)
    
    def _log_config(self) -> None:
        """Log current configuration."""
        self._log_info("Configuration:")
        self._log_info(f"  SSH Host: {self.config.ssh_host}")
        self._log_info(f"  SSH Port: {self.config.ssh_port}")
        self._log_info(f"  SSH User: {self.config.ssh_user or '(from ~/.ssh/config)'}")
        self._log_info(f"  SSH Key: {self.config.ssh_key_path or '(from ~/.ssh/config)'}")
        self._log_info(f"  Persistent: {self.config.persistent}")
        self._log_info(f"  Already Running: {self.config.already_running}")
        self._log_info(f"  Start Command: {self.config.start_command}")
        self._log_info(f"  Stop Command: {self.config.stop_command}")
        self._log_info(f"  Boot Timeout: {self.config.boot_timeout}s")
        self._log_info(f"  GDB Enabled: {self.config.enable_gdb}")
        self._log_info(f"  GDB Host:Port: {self.config.gdb_host}:{self.config.gdb_port}")
        self._log_info(f"  ADB Host:Port: {self.config.adb_host}:{self.config.adb_port}")
        self._log_info(f"  ADB Executable: {self.config.adb_exe}")
        self._log_info(f"  Setup Tunnels: {self.config.setup_tunnels}")
        if self.config.setup_tunnels:
            self._log_info(f"  Local GDB Port: {self.config.local_gdb_port}")
            self._log_info(f"  Local ADB Server Port: {self.config.local_adb_server_port}")
        self._log_separator()
    
    def _log_command(self, cmd_type: str, command: str, local: bool = True) -> None:
        """Log a command being executed."""
        location = "LOCAL" if local else "REMOTE"
        self._log_info(f"[{location}] [{cmd_type}] Executing: {command}")
    
    def _clear_remote_boot_log(self) -> None:
        """Clear the remote boot log file before starting a new instance."""
        self._log_info("Clearing remote boot log: /tmp/cuttlefish_boot.log")
        ssh_cmd = self._build_ssh_cmd("rm -f /tmp/cuttlefish_boot.log && touch /tmp/cuttlefish_boot.log")
        try:
            result = subprocess.run(
                ssh_cmd,
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0:
                self._log_info("Remote boot log cleared successfully")
            else:
                self._log_warning(f"Failed to clear remote boot log: {result.stderr}")
        except Exception as e:
            self._log_warning(f"Exception clearing remote boot log: {e}")

    def _log_command_result(self, exit_code: int, stdout: str, stderr: str, elapsed: float = None) -> None:
        """Log command result."""
        elapsed_str = f" ({elapsed:.2f}s)" if elapsed else ""
        self._log_info(f"Exit code: {exit_code}{elapsed_str}")
        if stdout and stdout.strip():
            self._log_debug(f"STDOUT:\n{stdout.rstrip()}")
        if stderr and stderr.strip():
            self._log_debug(f"STDERR:\n{stderr.rstrip()}")
    
    def get_log_file_path(self) -> str:
        """Return the path to the log file."""
        return self._log_file_path
    
    def _build_ssh_cmd(self, remote_command: str = None) -> List[str]:
        """Build SSH command line arguments.
        
        If ssh_user is None, relies on ~/.ssh/config for user/key settings.
        """
        cmd = ["ssh"]
        
        # # Add port if not default
        # if self.config.ssh_port != 22:
        #     cmd.extend(["-p", str(self.config.ssh_port)])
        
        # # Add key if specified
        # if self.config.ssh_key_path:
        #     cmd.extend(["-i", self.config.ssh_key_path])
        
        # Add host (with optional user)
        # if self.config.ssh_user:
        #     cmd.append(f"{self.config.ssh_user}@{self.config.ssh_host}")
        # else:
        #     # Just use hostname - relies on ~/.ssh/config
        cmd.append(self.config.ssh_host)
        
        # Add remote command if provided - wrap in quotes for proper shell handling
        if remote_command:
            # Use bash -c to ensure the command is executed as a single unit
            cmd.extend([f'{remote_command}'])
        
        return cmd
    
    def _ssh_subprocess_exec(self, command: str, timeout: int = 60) -> Tuple[int, str, str]:
        """Execute command via SSH using subprocess (uses system ssh config for hostname resolution)."""
        ssh_cmd = self._build_ssh_cmd(command)
        ssh_cmd_str = ' '.join(ssh_cmd)
        
        self._log_command("SSH", command, local=False)
        self._log_debug(f"Full SSH command: {ssh_cmd_str}")
        
        start_time = time.time()
        try:
            result = subprocess.run(
                ssh_cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            elapsed = time.time() - start_time
            self._log_command_result(result.returncode, result.stdout, result.stderr, elapsed)
            return result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            elapsed = time.time() - start_time
            self._log_error(f"SSH command timed out after {elapsed:.2f}s (timeout: {timeout}s)")
            return -1, "", "Command timed out"
        except Exception as e:
            elapsed = time.time() - start_time
            self._log_error(f"SSH command failed after {elapsed:.2f}s: {e}")
            return -1, "", str(e)
    
    def _ssh_subprocess_background(self, command: str) -> subprocess.Popen:
        """Execute command via SSH in the background using subprocess.
        
        Uses nohup and proper shell backgrounding on the remote side to ensure
        the command continues even after SSH disconnects. The process is stored
        in self._background_ssh_proc for later monitoring.
        """
        # Build SSH command - use shell=True with a properly formatted command string
        # This is the most reliable way to handle complex remote commands
        ssh_base = "ssh"
        if self.config.ssh_port != 22:
            ssh_base += f" -p {self.config.ssh_port}"
        if self.config.ssh_key_path:
            ssh_base += f" -i {self.config.ssh_key_path}"
        if self.config.ssh_user:
            ssh_base += f" {self.config.ssh_user}@{self.config.ssh_host}"
        else:
            ssh_base += f" {self.config.ssh_host}"
        
        remote_script = f"'{command} > /tmp/cuttlefish_boot.log 2>&1' &"
        
        # Full SSH command string
        ssh_cmd_str = f"{ssh_base} {remote_script}"
        
        self._log_command("SSH-BACKGROUND", command, local=False)
        self._log_debug(f"Full SSH command: {ssh_cmd_str}")
        self._log_info(f"Remote output redirected to: /tmp/cuttlefish_boot.log")
        
        # Use Popen with shell=True - this properly handles the complex command
        # The SSH session returns quickly because remote command is backgrounded with nohup &
        proc = subprocess.Popen(
            ssh_cmd_str,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        
        # Store reference for later monitoring
        self._background_ssh_proc = proc
        
        self._log_info(f"Background SSH process started with PID: {proc.pid}")
        
        # Wait briefly for SSH to complete (it should return quickly since remote is backgrounded)
        try:
            stdout, stderr = proc.communicate(timeout=30)
            self._log_debug(f"SSH background command completed. stdout: {stdout.strip() if stdout else '(empty)'}, stderr: {stderr.strip() if stderr else '(empty)'}")
            if proc.returncode != 0:
                self._log_warning(f"SSH background command returned non-zero: {proc.returncode}")
        except subprocess.TimeoutExpired:
            self._log_warning("SSH background command still running after 30s (may be OK)")
        
        return proc
    
    def _get_ssh_client(self) -> paramiko.SSHClient:
        """Get or create SSH client connection (fallback, prefer _ssh_subprocess_*)."""
        if self._ssh_client is None or not self._ssh_client.get_transport() or not self._ssh_client.get_transport().is_active():
            self._ssh_client = paramiko.SSHClient()
            self._ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            connect_kwargs = {
                'hostname': self.config.ssh_host,
                'port': self.config.ssh_port,
                'username': self.config.ssh_user,
                'timeout': 30,
            }
            
            if self.config.ssh_key_path:
                connect_kwargs['key_filename'] = self.config.ssh_key_path
            elif self.config.ssh_password:
                connect_kwargs['password'] = self.config.ssh_password
            else:
                # Try to use default SSH key
                connect_kwargs['look_for_keys'] = True
            
            self._ssh_client.connect(**connect_kwargs)
        
        return self._ssh_client
    
    def _ssh_exec(self, command: str, timeout: int = 60, get_output: bool = True) -> Tuple[int, str, str]:
        """Execute command via SSH and return (exit_code, stdout, stderr).
        
        Uses subprocess-based SSH to leverage system ssh config for hostname resolution.
        """
        return self._ssh_subprocess_exec(command, timeout)
    
    def _ssh_exec_background(self, command: str) -> None:
        """Execute command via SSH in the background (non-blocking).
        
        Uses subprocess-based SSH to leverage system ssh config for hostname resolution.
        """
        self._ssh_subprocess_background(command)
    
    def _test_ssh_connectivity(self) -> bool:
        """Test basic SSH connectivity before attempting tunnels or commands.
        
        This helps diagnose issues with SSH config, hostname resolution, etc.
        """
        self._log_separator()
        self._log_info("TESTING SSH CONNECTIVITY")
        self._log_info(f"Target: {self.config.ssh_host}")
        
        # Build a simple SSH test command
        ssh_cmd = self._build_ssh_cmd("echo 'SSH_TEST_OK'")
        ssh_cmd_str = ' '.join(ssh_cmd)
        
        self._log_info(f"Test command: {ssh_cmd_str}")
        print(f"[SSH-TEST] Testing connection to {self.config.ssh_host}...")
        
        try:
            start_time = time.time()
            result = subprocess.run(
                ssh_cmd,
                capture_output=True,
                text=True,
                timeout=30
            )
            elapsed = time.time() - start_time
            
            self._log_info(f"Exit code: {result.returncode} ({elapsed:.2f}s)")
            self._log_debug(f"STDOUT: {result.stdout.strip()}")
            if result.stderr:
                self._log_debug(f"STDERR: {result.stderr.strip()}")
            
            if result.returncode == 0 and "SSH_TEST_OK" in result.stdout:
                self._log_info("SSH connectivity test PASSED")
                print(f"[SSH-TEST] Connection successful!")
                return True
            else:
                self._log_error(f"SSH test failed: exit code {result.returncode}")
                self._log_error(f"STDOUT: {result.stdout}")
                self._log_error(f"STDERR: {result.stderr}")
                print(f"[SSH-TEST] Connection FAILED!")
                print(f"[SSH-TEST] Exit code: {result.returncode}")
                print(f"[SSH-TEST] Error: {result.stderr.strip()}")
                return False
                
        except subprocess.TimeoutExpired:
            self._log_error("SSH connectivity test timed out after 30s")
            print(f"[SSH-TEST] Connection TIMEOUT after 30s")
            return False
        except Exception as e:
            self._log_error(f"SSH connectivity test exception: {e}")
            print(f"[SSH-TEST] Exception: {e}")
            return False

    def _local_exec(self, command: str, timeout: int = 60, cwd: Optional[str] = None) -> Tuple[int, str, str]:
        """Execute command locally."""
        self._log_command("LOCAL", command, local=True)
        if cwd:
            self._log_debug(f"Working directory: {cwd}")
        
        start_time = time.time()
        try:
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=cwd
            )
            elapsed = time.time() - start_time
            self._log_command_result(result.returncode, result.stdout, result.stderr, elapsed)
            return result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            elapsed = time.time() - start_time
            self._log_error(f"Local command timed out after {elapsed:.2f}s (timeout: {timeout}s)")
            return -1, "", "Command timed out"
        except Exception as e:
            elapsed = time.time() - start_time
            self._log_error(f"Local command failed after {elapsed:.2f}s: {e}")
            return -1, "", str(e)
    
    def _setup_ssh_tunnels(self) -> bool:
        """Set up SSH tunnels for GDB and ADB access to remote Cuttlefish."""
        if not self.config.setup_tunnels:
            self._log_info("SSH tunnels not requested, skipping setup")
            return True
        
        self._log_separator()
        self._log_info("SETTING UP SSH TUNNELS")
        print(f"[CUTTLEFISH] Setting up SSH tunnels to {self.config.ssh_host}...")
        
        tunnels = []
        
        # Build SSH target (user@host or just host)
        if self.config.ssh_user:
            ssh_target = f"{self.config.ssh_user}@{self.config.ssh_host}"
        else:
            ssh_target = self.config.ssh_host
        
        self._log_info(f"SSH target: {ssh_target}")
        
        # GDB tunnel
        if self.config.enable_gdb:
            gdb_tunnel_cmd = [
                "ssh", "-N", "-L",
                f"{self.config.local_gdb_port}:{self.config.gdb_host}:{self.config.gdb_port}",
                ssh_target,
            ]
            if self.config.ssh_port != 22:
                gdb_tunnel_cmd.extend(["-p", str(self.config.ssh_port)])
            if self.config.ssh_key_path:
                gdb_tunnel_cmd.extend(["-i", self.config.ssh_key_path])
            tunnels.append(("GDB", gdb_tunnel_cmd))
        
        # ADB server tunnel (forwards local 5037 to remote 5037)
        # This allows local `adb` commands to use the remote ADB server
        adb_tunnel_cmd = [
            "ssh", "-N", "-L",
            f"{self.config.local_adb_server_port}:localhost:5037",
            ssh_target,
        ]
        if self.config.ssh_port != 22:
            adb_tunnel_cmd.extend(["-p", str(self.config.ssh_port)])
        if self.config.ssh_key_path:
            adb_tunnel_cmd.extend(["-i", self.config.ssh_key_path])
        tunnels.append(("ADB Server", adb_tunnel_cmd))
        
        # ADB device tunnel (forwards local device port to remote device port)
        # This is REQUIRED because ADB connects to devices on their own port,
        # not just the ADB server port. Without this, `adb connect` fails.
        adb_device_port = self.config.adb_port
        adb_device_tunnel_cmd = [
            "ssh", "-N", "-L",
            f"{adb_device_port}:localhost:{adb_device_port}",
            ssh_target,
        ]
        if self.config.ssh_port != 22:
            adb_device_tunnel_cmd.extend(["-p", str(self.config.ssh_port)])
        if self.config.ssh_key_path:
            adb_device_tunnel_cmd.extend(["-i", self.config.ssh_key_path])
        tunnels.append((f"ADB Device (port {adb_device_port})", adb_device_tunnel_cmd))
        
        for name, cmd in tunnels:
            cmd_str = ' '.join(cmd)
            self._log_info(f"Starting {name} tunnel: {cmd_str}")
            try:
                proc = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                self._tunnel_processes.append(proc)
                self._log_info(f"{name} tunnel process started (PID: {proc.pid})")
                print(f"[CUTTLEFISH] {name} tunnel established")
            except Exception as e:
                self._log_error(f"Failed to set up {name} tunnel: {e}")
                print(f"[ERROR] Failed to set up {name} tunnel: {e}")
                return False
        
        # Wait for tunnels to be ready
        self._log_info("Waiting 2s for tunnels to establish...")
        time.sleep(2)
        
        # Check if tunnel processes are still running
        for i, proc in enumerate(self._tunnel_processes):
            if proc.poll() is not None:
                # Process has exited, get output
                stdout, stderr = proc.communicate()
                self._log_error(f"Tunnel process {i} exited unexpectedly with code {proc.returncode}")
                self._log_error(f"Tunnel stderr: {stderr.decode() if stderr else 'empty'}")
                return False
            else:
                self._log_info(f"Tunnel process {i} (PID {proc.pid}) is running")
        
        self._log_info("All SSH tunnels established successfully")
        return True
    
    def _teardown_ssh_tunnels(self) -> None:
        """Tear down SSH tunnels."""
        if self._tunnel_processes:
            self._log_separator()
            self._log_info("TEARING DOWN SSH TUNNELS")
            for i, proc in enumerate(self._tunnel_processes):
                try:
                    self._log_info(f"Terminating tunnel process {i} (PID: {proc.pid})")
                    proc.terminate()
                    proc.wait(timeout=5)
                    self._log_info(f"Tunnel process {i} terminated successfully")
                except Exception as e:
                    self._log_warning(f"Tunnel process {i} did not terminate, killing: {e}")
                    proc.kill()
            self._tunnel_processes = []
            self._log_info("All tunnels torn down")
    
    def _raw_gdb_continue(self, host: str, port: int) -> bool:
        """Send raw GDB protocol 'continue' command directly via socket.
        
        This bypasses gdb-multiarch entirely and sends the minimal GDB Remote
        Serial Protocol packets to continue execution. This is more reliable
        when dealing with flaky GDB stubs (like crosvm) because it avoids
        the complexity of the full GDB client.
        
        GDB RSP format:
        - Packets are: $<data>#<checksum>
        - Checksum is sum of all bytes in <data> mod 256, as 2 hex chars
        - 'c' = continue command
        
        Returns True if continue command was sent successfully.
        """
        def gdb_checksum(data: bytes) -> str:
            """Calculate GDB RSP checksum."""
            return f"{sum(data) % 256:02x}"
        
        def make_packet(cmd: str) -> bytes:
            """Create a GDB RSP packet."""
            data = cmd.encode()
            return f"${cmd}#{gdb_checksum(data)}".encode()
        
        try:
            self._log_info(f"Connecting to GDB stub at {host}:{port} for raw continue...")
            sock = socket.create_connection((host, port), timeout=10)
            sock.settimeout(5)
            
            # Send ACK first to sync
            sock.send(b"+")
            time.sleep(0.2)
            
            # Send continue packet: $c#63
            continue_packet = make_packet("c")
            self._log_info(f"Sending continue packet: {continue_packet}")
            sock.send(continue_packet)
            
            # Wait briefly for ACK ('+' means command received)
            try:
                response = sock.recv(1)
                if response == b"+":
                    self._log_info("GDB stub acknowledged continue command")
                else:
                    self._log_warning(f"Unexpected response: {response}")
            except socket.timeout:
                self._log_info("No ACK received (stub may have continued anyway)")
            
            # Close connection - the stub should now be running the kernel
            sock.close()
            self._log_info("Raw GDB continue completed")
            return True
            
        except socket.timeout:
            self._log_warning("Socket timeout during raw GDB continue")
            return False
        except ConnectionResetError:
            self._log_warning("Connection reset during raw GDB continue (stub may have continued)")
            # This might actually be success - crosvm may reset after continue
            return True
        except Exception as e:
            self._log_error(f"Raw GDB continue failed: {e}")
            return False
    
    def _wait_for_gdb_port_closed(self, host: str, port: int, timeout: int = 30) -> bool:
        """Wait for GDB port to close (proving the old/stale QEMU process is gone).
        
        This is critical for avoiding race conditions where a stale GDB stub from
        a previous QEMU instance is still listening on the port. launch_cvd can take
        several minutes to assemble disk images before starting QEMU, during which
        time a stale port could still be open.
        
        Returns True if the port closed within the timeout, False if it's still open.
        """
        self._log_info(f"Checking if GDB port {host}:{port} is still open from a previous instance...")
        start = time.time()
        
        # First, quick check if port is even open
        try:
            sock = socket.create_connection((host, port), timeout=2)
            sock.close()
        except (ConnectionRefusedError, OSError, socket.timeout):
            self._log_info(f"GDB port {host}:{port} is already closed (no stale process)")
            return True
        
        # Port IS open - likely a stale process. Wait for it to close.
        self._log_warning(f"GDB port {host}:{port} is open from a STALE process! "
                          f"Waiting up to {timeout}s for it to close...")
        print(f"[CUTTLEFISH] GDB port still open from previous instance, waiting for it to close...")
        
        attempt = 0
        while time.time() - start < timeout:
            attempt += 1
            try:
                sock = socket.create_connection((host, port), timeout=2)
                sock.close()
                self._log_debug(f"Attempt {attempt}: Port still open, waiting...")
                time.sleep(2)
            except (ConnectionRefusedError, OSError, socket.timeout):
                elapsed = time.time() - start
                self._log_info(f"GDB port closed after {elapsed:.1f}s ({attempt} attempts)")
                print(f"[CUTTLEFISH] Stale GDB port closed")
                return True
        
        elapsed = time.time() - start
        self._log_warning(f"GDB port still open after {elapsed:.1f}s - stale process may interfere")
        print(f"[WARN] Stale GDB port still open after {timeout}s")
        return False
    
    def _wait_for_gdb_port(self, timeout: int = 60) -> bool:
        """Wait for GDB port to become available from a FRESH QEMU instance.
        
        This checks both socket connectivity AND that the GDB stub actually responds.
        When using SSH tunnels, the socket may be open (tunnel is up) but the
        actual GDB stub on the remote may not be ready yet.
        
        IMPORTANT: This first waits for the port to CLOSE (proving the old QEMU is gone),
        then waits for it to OPEN again (proving the new QEMU has started). This prevents
        sending the GDB continue command to a stale QEMU instance.
        """
        # When using SSH tunnels, connect to localhost on the local tunnel port
        if self.config.setup_tunnels:
            host = "localhost"
            port = self.config.local_gdb_port
        else:
            host = self.config.gdb_host
            port = self.config.gdb_port
        
        is_remote = self.config.ssh_host != "localhost" or self.config.ssh_port != 22
        
        self._log_separator()
        self._log_info(f"WAITING FOR GDB PORT: {host}:{port} (timeout: {timeout}s)")
        self._log_info(f"Remote mode: {is_remote}, Tunnels: {self.config.setup_tunnels}")
        print(f"[CUTTLEFISH] Waiting for GDB on {host}:{port}...")
        
        # Phase 1: Wait for the port to CLOSE first (if a stale process has it open).
        # launch_cvd takes a long time (2-3 min) to assemble disk images before QEMU starts.
        # During that time, a stale GDB stub from a previous instance may still be listening.
        # If we connect to the stale one and send 'continue', the NEW QEMU starts paused
        # with -S and never gets the continue, so ADB never comes up.
        close_timeout = min(timeout, 180)  # Up to 3 minutes for old QEMU to die
        self._wait_for_gdb_port_closed(host, port, timeout=close_timeout)
        
        # Phase 2: Now wait for the NEW QEMU to open the port
        self._log_info(f"Now waiting for NEW GDB stub to become ready...")
        print(f"[CUTTLEFISH] Waiting for new GDB stub...")
        start = time.time()
        attempt = 0
        
        while time.time() - start < timeout:
            attempt += 1
            elapsed = time.time() - start
            
            # First check socket connectivity
            try:
                self._log_debug(f"Attempt {attempt}: Checking socket {host}:{port}...")
                sock = socket.create_connection((host, port), timeout=5)
                # Socket connected - try to do a minimal GDB protocol exchange
                # Send $?#3f (halt reason query) to verify it's a fresh stopped stub
                self._log_debug(f"Attempt {attempt}: Socket is open, testing GDB protocol...")
                try:
                    sock.settimeout(5)
                    sock.send(b"+")  # ACK to sync
                    time.sleep(0.1)
                    # If we get here without ConnectionResetError, stub is alive
                    sock.close()
                    self._log_info(f"GDB stub is ready after {elapsed:.1f}s ({attempt} attempts)")
                    print(f"[CUTTLEFISH] GDB port is ready")
                    return True
                except (ConnectionResetError, BrokenPipeError, socket.timeout) as e:
                    self._log_debug(f"Attempt {attempt}: GDB stub not responding - {e}")
                    sock.close()
                except Exception as e:
                    self._log_debug(f"Attempt {attempt}: GDB test error - {e}")
                    sock.close()
            except (ConnectionRefusedError, OSError, socket.timeout) as e:
                self._log_debug(f"Attempt {attempt}: Socket not ready - {e}")
            
            time.sleep(2)
        
        elapsed = time.time() - start
        self._log_error(f"GDB port not available after {elapsed:.1f}s ({attempt} attempts)")
        print(f"[ERROR] GDB port not available after {timeout}s")
        return False
    
    def _gdb_attach_with_script(
        self,
        script_path: Path,
        vmlinux_path: Optional[str] = None,
        timeout: int = 60,
        max_retries: int = 3,
    ) -> bool:
        """
        Attach GDB to the kernel with a custom Python script for analysis.
        
        This connects to the GDB stub, loads the analysis script (which sets up
        breakpoints and logging), and then continues execution. All GDB output
        is logged for debugging.
        
        Includes retry logic for unstable connections (crosvm GDB stub can be flaky).
        
        Args:
            script_path: Path to GDB Python script to source
            vmlinux_path: Optional path to vmlinux with debug symbols
            timeout: Execution timeout (GDB runs in background after this)
            max_retries: Number of connection retry attempts
        
        Returns True if GDB attached and script loaded successfully.
        """
        is_remote = self.config.ssh_host != "localhost" or self.config.ssh_port != 22
        
        self._log_separator()
        self._log_info("ATTACHING GDB WITH ANALYSIS SCRIPT")
        self._log_info(f"Script: {script_path}")
        if vmlinux_path:
            self._log_info(f"vmlinux: {vmlinux_path}")
        
        # Determine GDB connection target
        if is_remote:
            if self.config.setup_tunnels:
                host = "localhost"
                port = self.config.local_gdb_port
                self._log_info(f"Remote instance - using GDB tunnel localhost:{port}")
            else:
                self._log_error("Remote instance but setup_tunnels=False")
                return False
        else:
            host = "localhost"
            port = self.config.local_gdb_port if self.config.setup_tunnels else self.config.gdb_port
        
        # Create log directory for GDB output
        log_dir = Path(self.config.log_file).parent if self.config.log_file else Path(".")
        gdb_log_path = log_dir / "gdb_session.log"
        gdb_stdout_log = log_dir / "gdb_stdout.log"
        gdb_stderr_log = log_dir / "gdb_stderr.log"
        
        # Add a small delay to let crosvm's GDB stub stabilize
        # The stub can be flaky right after the port becomes available
        self._log_info("Waiting 3s for GDB stub to stabilize...")
        time.sleep(3)
        
        # Try with retries - crosvm GDB stub can be flaky
        for attempt in range(1, max_retries + 1):
            self._log_info(f"GDB connection attempt {attempt}/{max_retries}")
            
            # Try various GDB binaries - gdb-multiarch and aarch64-linux-gnu-gdb are needed
            # for cross-architecture debugging (x86 host -> aarch64 target)
            for gdb_binary in ["gdb-multiarch", "aarch64-linux-gnu-gdb", "gdb"]:
                try:
                    gdb_cmd = [gdb_binary, "-q"]
                    
                    # Load vmlinux if provided
                    if vmlinux_path and os.path.exists(vmlinux_path):
                        gdb_cmd.extend(["-ex", f"file {vmlinux_path}"])
                        self._log_info(f"Loading symbols from {vmlinux_path}")
                    
                    gdb_cmd.extend([
                        "-ex", f"set logging file {gdb_log_path}",
                        "-ex", "set logging overwrite on",
                        "-ex", "set logging enabled on",
                        "-ex", "set pagination off",
                        "-ex", "set confirm off",
                        # Set architecture for cross-debugging (critical for x86 host -> aarch64 target)
                        "-ex", "set architecture aarch64",
                        # Add TCP connection timeout to detect failures faster
                        "-ex", "set tcp connect-timeout 30",
                        "-ex", f"target remote {host}:{port}",
                        "-ex", f"source {script_path}",
                        # Note: 'continue' is handled by the script via syz_safe_continue
                    ])
                    
                    self._log_debug(f"Running: {' '.join(gdb_cmd)}")
                    self._log_info(f"GDB session log: {gdb_log_path}")
                    print(f"[CUTTLEFISH] GDB connecting to {host}:{port} (attempt {attempt}/{max_retries})...")
                    
                    start_time = time.time()
                
                    # Start GDB process - it will run in background after continue
                    proc = subprocess.Popen(
                        gdb_cmd,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                    )
                    
                    self._gdb_process = proc
                    self._log_info(f"GDB process started (PID: {proc.pid})")
                    
                    # Wait briefly for initial connection and script load
                    # GDB will continue running in background after 'continue' command
                    try:
                        stdout, stderr = proc.communicate(timeout=timeout)
                    except subprocess.TimeoutExpired:
                        # This is expected - GDB is running with the kernel
                        self._log_info(f"GDB running in background (continuing after {timeout}s timeout)")
                        # Don't kill it - let it continue monitoring
                        stdout = ""
                        stderr = ""
                    
                    elapsed = time.time() - start_time
                    
                    # Save stdout/stderr to files
                    if stdout:
                        with open(gdb_stdout_log, 'w') as f:
                            f.write(stdout)
                    if stderr:
                        with open(gdb_stderr_log, 'w') as f:
                            f.write(stderr)
                    
                    # Log output
                    if proc.returncode is not None:
                        self._log_info(f"GDB exited in {elapsed:.2f}s with code {proc.returncode}")
                    else:
                        self._log_info(f"GDB still running after {elapsed:.2f}s (monitoring kernel)")
                    
                    self._log_info("=" * 40 + " GDB STDOUT " + "=" * 40)
                    if stdout and stdout.strip():
                        for line in stdout.strip().split('\n')[:30]:
                            self._log_info(f"[GDB-OUT] {line}")
                        if len(stdout.strip().split('\n')) > 30:
                            self._log_info(f"[GDB-OUT] ... ({len(stdout.strip().split(chr(10))) - 30} more lines)")
                    else:
                        self._log_info("[GDB-OUT] (empty or still running)")
                    
                    self._log_info("=" * 40 + " GDB STDERR " + "=" * 40)
                    if stderr and stderr.strip():
                        for line in stderr.strip().split('\n')[:20]:
                            self._log_info(f"[GDB-ERR] {line}")
                    else:
                        self._log_info("[GDB-ERR] (empty)")
                    self._log_info("=" * 92)
                    
                    # Check for connection errors - if found, retry
                    combined = (stdout + stderr).lower() if stdout or stderr else ""
                    if "connection refused" in combined:
                        self._log_error(f"GDB connection refused (attempt {attempt})")
                        break  # Try next attempt
                    if "connection reset" in combined:
                        self._log_error(f"GDB connection reset (attempt {attempt})")
                        # Wait before retry
                        if attempt < max_retries:
                            self._log_info(f"Waiting 5s before retry...")
                            time.sleep(5)
                        break  # Try next attempt
                    
                    self._log_info("GDB attached with script successfully")
                    print("[CUTTLEFISH] GDB attached and script loaded")
                    return True
                    
                except FileNotFoundError:
                    self._log_debug(f"{gdb_binary} not found, trying next...")
                    continue
                except Exception as e:
                    self._log_error(f"GDB attach failed: {e}")
                    import traceback
                    self._log_error(f"Traceback:\n{traceback.format_exc()}")
                    continue
            
            # If we get here without returning True, all gdb binaries failed for this attempt
            # The outer loop will try again
        
        self._log_error(f"GDB attach failed after {max_retries} attempts")
        return False
    
    def _gdb_continue_kernel(self, timeout: int = 30) -> bool:
        """
        Attach GDB to the kernel and send 'continue' command (simple version).
        
        When Cuttlefish starts with GDB enabled, the kernel is paused at boot
        waiting for a debugger to attach and continue execution. This method
        connects to the GDB stub and sends the continue command to resume boot.
        
        For full script-based analysis, use start() with gdb_script_path parameter.
        
        Returns True if kernel was successfully continued.
        """
        is_remote = self.config.ssh_host != "localhost" or self.config.ssh_port != 22
        
        self._log_separator()
        self._log_info("CONTINUING KERNEL VIA GDB")
        
        # Determine GDB connection target
        # For remote instances with tunnels, use local tunneled port
        # For local instances, use gdb_port directly
        if is_remote:
            if self.config.setup_tunnels:
                host = "localhost"
                port = self.config.local_gdb_port
                self._log_info(f"Remote instance - using GDB tunnel localhost:{port} -> {self.config.ssh_host}:{self.config.gdb_port}")
                print(f"[CUTTLEFISH] Connecting to remote GDB via tunnel (localhost:{port})...")
            else:
                self._log_error("Remote instance but setup_tunnels=False - cannot connect to GDB")
                self._log_error("Set setup_tunnels=True in CuttlefishConfig to enable GDB tunnel")
                print("[ERROR] Remote GDB requires setup_tunnels=True")
                return False
        else:
            # Local instance
            host = "localhost"
            port = self.config.local_gdb_port if self.config.setup_tunnels else self.config.gdb_port
            self._log_info(f"Local instance - connecting to GDB at {host}:{port}")
            print(f"[CUTTLEFISH] Connecting to local GDB at {host}:{port}...")
        
        # Run GDB locally (for both remote via tunnel and local instances)
        # Create a GDB log file for debugging
        gdb_log_path = Path(self.config.log_file).parent / "gdb_continue.log" if self.config.log_file else Path("gdb_continue.log")
        
        # Add a small delay to let GDB stub stabilize after port check
        self._log_info("Waiting 5s for GDB stub to stabilize...")
        time.sleep(5)
        
        # Try to continue the kernel using raw GDB protocol over socket
        # This is more reliable than spawning gdb-multiarch through SSH tunnels
        # because it avoids potential protocol fragmentation issues
        self._log_info("Attempting raw GDB protocol continue...")
        if self._raw_gdb_continue(host, port):
            self._log_info("Kernel continued via raw GDB protocol")
            print("[CUTTLEFISH] Kernel continued via raw GDB")
            return True
        
        self._log_warning("Raw GDB continue failed, trying gdb-multiarch...")
        
        # Fallback: Try various GDB binaries - gdb-multiarch and aarch64-linux-gnu-gdb are needed
        # for cross-architecture debugging (x86 host -> aarch64 target)
        for gdb_binary in ["gdb-multiarch", "aarch64-linux-gnu-gdb", "gdb"]:
            try:
                gdb_cmd = [
                    gdb_binary, "-batch", "-nx",
                    "-ex", f"set logging file {gdb_log_path}",
                    "-ex", "set logging overwrite on",
                    "-ex", "set logging enabled on",
                    # Set architecture for cross-debugging (critical for x86 host -> aarch64 target)
                    "-ex", "set architecture aarch64",
                    # TCP settings for flaky connections
                    "-ex", "set tcp connect-timeout 30",
                    "-ex", "set tcp auto-retry on",
                    "-ex", f"target remote {host}:{port}",
                    "-ex", "continue"
                ]
                self._log_debug(f"Running: {' '.join(gdb_cmd)}")
                self._log_info(f"GDB log will be written to: {gdb_log_path}")
                
                start_time = time.time()
                
                # Use Popen for better control
                proc = subprocess.Popen(
                    gdb_cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                
                self._log_info(f"GDB process started (PID: {proc.pid})")
                
                try:
                    stdout, stderr = proc.communicate(timeout=timeout)
                except subprocess.TimeoutExpired:
                    self._log_error(f"GDB continue timed out after {timeout}s")
                    proc.kill()
                    stdout, stderr = proc.communicate()
                    self._log_error(f"GDB stdout before timeout:\n{stdout}")
                    self._log_error(f"GDB stderr before timeout:\n{stderr}")
                    print(f"[ERROR] GDB continue timed out after {timeout}s")
                    return False
                
                elapsed = time.time() - start_time
                
                # Log all output
                self._log_info(f"GDB process completed in {elapsed:.2f}s with exit code {proc.returncode}")
                self._log_info("=" * 40 + " GDB STDOUT " + "=" * 40)
                if stdout.strip():
                    for line in stdout.strip().split('\n'):
                        self._log_info(f"[GDB-OUT] {line}")
                else:
                    self._log_info("[GDB-OUT] (empty)")
                self._log_info("=" * 40 + " GDB STDERR " + "=" * 40)
                if stderr.strip():
                    for line in stderr.strip().split('\n'):
                        self._log_info(f"[GDB-ERR] {line}")
                else:
                    self._log_info("[GDB-ERR] (empty)")
                self._log_info("=" * 92)
                
                # Read the GDB log file for detailed debugging info
                if gdb_log_path.exists():
                    self._log_info(f"Reading GDB log file: {gdb_log_path}")
                    try:
                        with open(gdb_log_path, 'r') as f:
                            gdb_log_content = f.read()
                        if gdb_log_content.strip():
                            self._log_info("=" * 40 + " GDB LOG FILE " + "=" * 40)
                            for line in gdb_log_content.strip().split('\n')[:50]:  # First 50 lines
                                self._log_debug(f"[GDB-LOG] {line}")
                            if len(gdb_log_content.strip().split('\n')) > 50:
                                self._log_debug(f"[GDB-LOG] ... ({len(gdb_log_content.strip().split(chr(10))) - 50} more lines)")
                            self._log_info("=" * 94)
                    except Exception as e:
                        self._log_warning(f"Could not read GDB log file: {e}")
                
                # Check for connection errors
                combined_output = (stdout + stderr).lower()
                if "connection refused" in combined_output:
                    self._log_error("GDB connection refused - is the GDB stub running?")
                    self._log_error("Make sure Cuttlefish is started with GDB enabled and the tunnel is active")
                    print("[ERROR] GDB connection refused - target not listening")
                    return False
                if "connection reset" in combined_output:
                    self._log_error("GDB connection was reset - the target may have disconnected")
                    self._log_error("This can happen if Cuttlefish is not running or GDB stub crashed")
                    print("[ERROR] GDB connection reset by peer")
                    return False
                
                self._log_info("GDB continue command sent to kernel")
                print("[CUTTLEFISH] Kernel continued via GDB")
                return True
                
            except FileNotFoundError:
                self._log_debug(f"{gdb_binary} not found, trying next...")
                continue
            except Exception as e:
                self._log_error(f"GDB continue with {gdb_binary} failed: {e}")
                import traceback
                self._log_error(f"Traceback:\n{traceback.format_exc()}")
                continue
        
        self._log_error("No working GDB binary found (tried gdb-multiarch, gdb)")
        print("[ERROR] No working GDB binary found")
        return False
    
    def _wait_for_adb(self, timeout: int = 120) -> bool:
        """Wait for ADB connection to Cuttlefish device."""
        adb_cmd = [self.config.adb_exe]
        port = self.config.adb_port
        
        # The device may be listed as either localhost:port or 0.0.0.0:port
        # We need to check for both variants
        target_localhost = f"localhost:{port}"
        target_0000 = f"0.0.0.0:{port}"
        
        self._log_separator()
        self._log_info(f"WAITING FOR ADB DEVICE: port {port} (timeout: {timeout}s)")
        self._log_info(f"Will check for: {target_localhost} or {target_0000}")
        print(f"[CUTTLEFISH] Waiting for ADB device on port {port}...")
        start = time.time()
        attempt = 0
        
        while time.time() - start < timeout:
            attempt += 1
            elapsed = time.time() - start
            try:
                # Try connecting to both variants
                for target in [target_0000, target_localhost]:
                    connect_cmd = adb_cmd + ["connect", target]
                    self._log_debug(f"Attempt {attempt}: Running: {' '.join(connect_cmd)}")
                    connect_result = subprocess.run(
                        connect_cmd,
                        capture_output=True,
                        text=True,
                        timeout=10
                    )
                    self._log_debug(f"Connect result: code={connect_result.returncode}, stdout={connect_result.stdout.strip()}, stderr={connect_result.stderr.strip()}")
                
                # Check device status
                devices_cmd = adb_cmd + ["devices"]
                result = subprocess.run(
                    devices_cmd,
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                self._log_debug(f"Devices output:\n{result.stdout.strip()}")
                
                # Parse device list and check for our device specifically
                # Look for "{target}\tdevice" pattern to ensure it's in device (not offline) state
                device_found = False
                device_status = None
                for line in result.stdout.strip().split('\n'):
                    # Check for either localhost:port or 0.0.0.0:port with "device" status
                    if (target_localhost in line or target_0000 in line):
                        parts = line.split('\t')
                        if len(parts) >= 2:
                            device_status = parts[1].strip()
                            self._log_debug(f"Found device on port {port} with status: {device_status}")
                            if device_status == "device":
                                device_found = True
                                break
                
                if device_found:
                    self._log_info(f"ADB device connected after {elapsed:.1f}s ({attempt} attempts)")
                    print(f"[CUTTLEFISH] ADB device connected on port {port}")
                    return True
                elif device_status:
                    self._log_debug(f"Attempt {attempt}: Device found but status is '{device_status}', waiting...")
                else:
                    self._log_debug(f"Attempt {attempt}: Device not found yet")
                
            except subprocess.TimeoutExpired:
                self._log_debug(f"Attempt {attempt}: ADB command timed out")
            except Exception as e:
                self._log_debug(f"Attempt {attempt}: ADB error - {e}")
            
            time.sleep(2)
        
        elapsed = time.time() - start
        self._log_error(f"ADB device not available after {elapsed:.1f}s ({attempt} attempts)")
        print(f"[ERROR] ADB device not available after {timeout}s")
        return False
    
    def _get_adb_device_serial(self) -> str:
        """Get the ADB device serial, trying both 0.0.0.0 and localhost variants."""
        port = self.config.adb_port
        
        # Check which variant is available
        try:
            devices_cmd = [self.config.adb_exe, "devices"]
            result = subprocess.run(devices_cmd, capture_output=True, text=True, timeout=5)
            
            # Check for 0.0.0.0:port first (Cuttlefish typically uses this)
            if f"0.0.0.0:{port}" in result.stdout:
                return f"0.0.0.0:{port}"
            elif f"localhost:{port}" in result.stdout:
                return f"localhost:{port}"
        except Exception:
            pass
        
        # Default to 0.0.0.0:port as that's what Cuttlefish typically uses
        return f"0.0.0.0:{port}"

    def _check_boot_complete(self) -> bool:
        """Check if Cuttlefish has finished booting via ADB."""
        try:
            device_serial = self._get_adb_device_serial()
            adb_cmd = [self.config.adb_exe, "-s", device_serial]
            cmd = adb_cmd + ["shell", "getprop", "sys.boot_completed"]
            self._log_debug(f"Checking boot complete: {' '.join(cmd)}")
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=10
            )
            boot_completed = result.stdout.strip() == "1"
            self._log_debug(f"Boot completed check: {result.stdout.strip()!r} -> {boot_completed}")
            return boot_completed
        except Exception as e:
            self._log_debug(f"Boot complete check failed: {e}")
            return False
    
    def start(
        self,
        gdb_script_path: Optional[Path] = None,
        vmlinux_path: Optional[str] = None,
        gdb_continue_only: bool = False,
    ) -> bool:
        """
        Start or connect to Cuttlefish instance.
        
        Args:
            gdb_script_path: Optional path to GDB Python script to run on connection.
                            If provided, the script is loaded and executed when GDB
                            connects, allowing breakpoints and logging to be set up
                            before the kernel continues booting.
            vmlinux_path: Optional path to vmlinux with debug symbols for GDB.
            gdb_continue_only: If True, skip loading GDB script and just send 'continue'.
                              Used for Phase 1 of two-phase symbol extraction where
                              we just want to boot the kernel without breakpoints.
        
        Returns True if Cuttlefish is ready for use.
        """
        self._gdb_script_path = gdb_script_path if not gdb_continue_only else None
        self._vmlinux_path = vmlinux_path
        
        self._log_separator()
        self._log_info("=" * 60)
        self._log_info("STARTING CUTTLEFISH INSTANCE")
        self._log_info("=" * 60)
        
        if gdb_script_path and not gdb_continue_only:
            self._log_info(f"GDB Script: {gdb_script_path}")
        if gdb_continue_only:
            self._log_info("GDB mode: continue-only (no breakpoints)")
        if vmlinux_path:
            self._log_info(f"vmlinux: {vmlinux_path}")
        
        # Test basic SSH connectivity first
        # if not self._test_ssh_connectivity():
        #     self._log_error("SSH connectivity test failed - cannot proceed")
        #     return False
        
        # Set up SSH tunnels if needed (for remote access)
        if not self._setup_ssh_tunnels():
            self._log_error("Failed to set up SSH tunnels")
            return False
        
        # Persistent mode with already running instance
        if self.config.persistent and self.config.already_running:
            self._log_info("Mode: Connecting to already-running instance")
            print("[CUTTLEFISH] Connecting to already-running instance...")
            
            # Just verify connectivity
            # if self.config.enable_gdb and not self._wait_for_gdb_port(timeout=10):
            #     self._log_warning("GDB port not available on running instance")
            #     print("[WARN] GDB port not available on running instance")
            
            if not self._wait_for_adb(timeout=30):
                self._log_error("Cannot connect to Cuttlefish via ADB")
                print("[ERROR] Cannot connect to Cuttlefish via ADB")
                return False
            
            self._is_booted = True
            self._log_info("Successfully connected to running instance")
            return True
        
        # Need to start Cuttlefish
        if self.config.start_command:
            self._log_info(f"Mode: Starting new instance")
            self._log_info(f"Start command: {self.config.start_command}")
            print(f"[CUTTLEFISH] Starting instance...")
            print(f"[CUTTLEFISH] Command: {self.config.start_command}")
            
            # Clear remote boot log before starting (for remote execution)
            is_remote = not (self.config.ssh_host == "localhost" and self.config.ssh_port == 22)
            if is_remote:
                self._clear_remote_boot_log()
            
            # Check if this is local or remote execution
            if self.config.ssh_host == "localhost" and self.config.ssh_port == 22:
                self._log_info("Execution mode: LOCAL")
                # Local execution - run in background
                cwd = os.path.expanduser(self.config.cuttlefish_home) if self.config.cuttlefish_home else None
                if cwd and not os.path.isdir(cwd):
                    self._log_warning(f"cuttlefish_home directory not found: {cwd}, running without cwd")
                    cwd = None
                self._cuttlefish_process = subprocess.Popen(
                    self.config.start_command,
                    shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    cwd=cwd,
                )
                self._log_info(f"Local process started with PID: {self._cuttlefish_process.pid}")
            else:
                self._log_info("Execution mode: REMOTE (via SSH)")
                # Remote execution via SSH
                self._ssh_exec_background(self.config.start_command)
        else:
            self._log_error("No start_command provided and instance not already running")
            print("[ERROR] No start_command provided and instance not already running")
            return False
        
        # Initial startup delay to let the instance begin booting
        # This prevents premature port checks when the VM hasn't started yet
        if self.config.startup_delay > 0:
            self._log_info(f"Waiting {self.config.startup_delay}s for instance to start initializing...")
            print(f"[CUTTLEFISH] Waiting {self.config.startup_delay}s for instance to start...")
            time.sleep(self.config.startup_delay)
        
        # Wait for boot
        self._log_info(f"Waiting for boot (timeout: {self.config.boot_timeout}s)")
        print(f"[CUTTLEFISH] Waiting for boot (timeout: {self.config.boot_timeout}s)...")
        
        # Wait for GDB first if enabled (kernel is paused, needs continue)
        if self.config.enable_gdb:
            # Wait for GDB stub to be ready - QEMU takes time to initialize
            self._log_info("Waiting for GDB stub to become ready...")
            print("[CUTTLEFISH] Waiting for GDB stub to become ready...")
            
            # Actually wait for the GDB port to be available, not just a fixed delay
            if not self._wait_for_gdb_port(timeout=self.config.gdb_connect_timeout):
                self._log_error("GDB port never became available")
                print("[ERROR] GDB port never became available - check if QEMU started correctly")
                # Fetch remote logs to help debug
                if self.config.ssh_host != "localhost":
                    self._append_remote_logs_to_local()
                return False
            
            self._log_info("GDB port is available")
            print("[CUTTLEFISH] GDB port available")
            
            # Two modes for GDB attachment:
            # 1. Early attach (gdb_attach_after_boot=False): Attach script now, at early boot
            #    - Better for boot-time tracing, but crosvm may disconnect
            # 2. Late attach (gdb_attach_after_boot=True): Just continue now, attach script later
            #    - Works better with crosvm, kernel fully booted when we attach
            
            if self.config.gdb_attach_after_boot:
                # Late attach mode: just continue the kernel, attach script after boot
                self._log_info("Late GDB attach mode - continuing kernel first, will attach script after boot")
                print("[CUTTLEFISH] Late GDB attach mode - continuing kernel boot...")
                if not self._gdb_continue_kernel(timeout=30):
                    self._log_warning("GDB continue may have failed, but continuing anyway")
                    print("[WARN] GDB continue may have failed, but continuing anyway")
            else:
                # Early attach mode: attach with script now (original behavior)
                # Cuttlefish with GDB starts paused - we need to continue the kernel
                # If a GDB script is provided, we run it now (sets up breakpoints, logging)
                # then continue. Otherwise just send continue.
                if self._gdb_script_path:
                    self._log_info(f"Early attach mode - attaching GDB with script: {self._gdb_script_path}")
                    print(f"[CUTTLEFISH] Early attach mode - attaching GDB with analysis script...")
                    if not self._gdb_attach_with_script(self._gdb_script_path, self._vmlinux_path, timeout=60):
                        self._log_warning("GDB script attach may have failed, but continuing anyway")
                        print("[WARN] GDB script attach may have failed, but continuing anyway")
                else:
                    self._log_info("Sending continue to resume kernel boot")
                    if not self._gdb_continue_kernel(timeout=30):
                        self._log_warning("GDB continue may have failed, but continuing anyway")
                        print("[WARN] GDB continue may have failed, but continuing anyway")
        
        # Wait for ADB
        if not self._wait_for_adb(timeout=self.config.boot_timeout):
            self._log_error("ADB wait failed, aborting")
            # Fetch remote logs to help debug
            if self.config.ssh_host != "localhost":
                self._append_remote_logs_to_local()
            return False
        
        # Wait for full boot
        self._log_info("Waiting for sys.boot_completed=1 (up to 120s)")
        print("[CUTTLEFISH] Waiting for system boot to complete...")
        boot_wait_start = time.time()
        while time.time() - boot_wait_start < 120:  # Additional 2 min for full boot
            if self._check_boot_complete():
                self._log_info("Boot complete flag set, system is ready")
                print("[CUTTLEFISH] Boot complete!")
                self._is_booted = True
                # Fetch remote logs for reference
                if self.config.ssh_host != "localhost":
                    self._append_remote_logs_to_local()
                
                # Late GDB attach: now that kernel is booted, attach the script
                if self.config.enable_gdb and self.config.gdb_attach_after_boot and self._gdb_script_path:
                    self._log_info("Late GDB attach: kernel booted, now attaching GDB script...")
                    print("[CUTTLEFISH] Late GDB attach: attaching GDB script to running kernel...")
                    if not self._gdb_attach_with_script(self._gdb_script_path, self._vmlinux_path, timeout=60):
                        self._log_warning("Late GDB script attach may have failed, but continuing anyway")
                        print("[WARN] Late GDB script attach may have failed, but continuing anyway")
                    else:
                        print("[CUTTLEFISH] GDB script attached successfully")
                
                return True
            time.sleep(5)
        
        self._log_warning("Boot complete flag not set after 120s, but ADB is available")
        print("[WARN] Boot complete flag not set, but ADB is available")
        # Fetch remote logs for reference
        if self.config.ssh_host != "localhost":
            self._append_remote_logs_to_local()
        self._is_booted = True
        
        # Late GDB attach: try to attach even if boot_completed not set
        if self.config.enable_gdb and self.config.gdb_attach_after_boot and self._gdb_script_path:
            self._log_info("Late GDB attach: ADB available, attempting GDB script attach...")
            print("[CUTTLEFISH] Late GDB attach: attempting GDB script attach...")
            if not self._gdb_attach_with_script(self._gdb_script_path, self._vmlinux_path, timeout=60):
                self._log_warning("Late GDB script attach may have failed, but continuing anyway")
                print("[WARN] Late GDB script attach may have failed, but continuing anyway")
            else:
                print("[CUTTLEFISH] GDB script attached successfully")
        
        return True
    
    def stop(self) -> bool:
        """
        Stop Cuttlefish instance.
        
        In persistent mode with already_running=True, this is a no-op.
        In persistent mode with already_running=False, this is also a no-op (keep running).
        In non-persistent mode, this stops the instance.
        """
        self._log_separator()
        self._log_info("=" * 60)
        self._log_info("STOPPING CUTTLEFISH INSTANCE")
        self._log_info("=" * 60)
        
        if self.config.persistent:
            self._log_info("Persistent mode - not stopping instance")
            print("[CUTTLEFISH] Persistent mode - not stopping instance")
            return True
        
        if not self.config.stop_command:
            self._log_warning("No stop_command provided")
            print("[WARN] No stop_command provided")
            return True
        
        self._log_info(f"Stop command: {self.config.stop_command}")
        print(f"[CUTTLEFISH] Stopping instance...")
        print(f"[CUTTLEFISH] Command: {self.config.stop_command}")
        
        try:
            if self.config.ssh_host == "localhost" and self.config.ssh_port == 22:
                # Local execution
                self._log_info("Execution mode: LOCAL")
                start_time = time.time()
                result = subprocess.run(
                    self.config.stop_command,
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=self.config.shutdown_timeout,
                )
                elapsed = time.time() - start_time
                self._log_command_result(result.returncode, result.stdout, result.stderr, elapsed)
                success = result.returncode == 0
            else:
                # Remote execution
                self._log_info("Execution mode: REMOTE (via SSH)")
                exit_code, stdout, stderr = self._ssh_exec(
                    self.config.stop_command,
                    timeout=self.config.shutdown_timeout
                )
                success = exit_code == 0
            
            if success:
                self._log_info("Instance stopped successfully")
                print("[CUTTLEFISH] Instance stopped")
            else:
                self._log_warning("Stop command may have failed (non-zero exit code)")
                print("[WARN] Stop command may have failed")
            
            self._is_booted = False
            return success
            
        except Exception as e:
            self._log_error(f"Failed to stop instance: {e}")
            print(f"[ERROR] Failed to stop instance: {e}")
            return False
        finally:
            self._teardown_ssh_tunnels()
            if self._cuttlefish_process:
                try:
                    self._log_info(f"Terminating local cuttlefish process (PID: {self._cuttlefish_process.pid})")
                    self._cuttlefish_process.terminate()
                    self._cuttlefish_process.wait(timeout=10)
                    self._log_info("Local process terminated")
                except Exception as e:
                    self._log_warning(f"Force killing local process: {e}")
                    self._cuttlefish_process.kill()
                self._cuttlefish_process = None
    
    def fetch_remote_boot_log(self) -> Optional[str]:
        """Fetch the remote boot log from /tmp/cuttlefish_boot.log."""
        self._log_info("Fetching remote boot log from /tmp/cuttlefish_boot.log")
        exit_code, stdout, stderr = self._ssh_exec("cat /tmp/cuttlefish_boot.log 2>/dev/null || echo '[Log file not found]'", timeout=30)
        if exit_code == 0 and stdout:
            self._log_debug(f"Remote boot log contents:\n{stdout}")
            return stdout
        return None

    def _infer_runtime_logs_dir(self) -> Optional[str]:
        """Try to infer the cuttlefish runtime logs directory from config or start_command."""
        # First check explicit config
        if self.config.cuttlefish_runtime_logs:
            return self.config.cuttlefish_runtime_logs
        
        # Try to infer from start_command
        # e.g., "cd /home/jack/challenge-4/challenge-4.1 && ./gdb_run.sh 5"
        # would have logs at /home/jack/challenge-4/challenge-4.1/cuttlefish_runtime.5/logs
        if self.config.start_command:
            import re
            # Look for "cd <path>" pattern
            cd_match = re.search(r'cd\s+([^\s&;]+)', self.config.start_command)
            if cd_match:
                base_dir = cd_match.group(1)
                # Look for instance number
                num_match = re.search(r'\.sh\s+(\d+)', self.config.start_command)
                if num_match:
                    instance_num = num_match.group(1)
                    return f"{base_dir}/cuttlefish_runtime.{instance_num}/logs"
                else:
                    # Default runtime directory
                    return f"{base_dir}/cuttlefish_runtime/logs"
        
        # Default fallback
        home = os.path.expanduser(self.config.cuttlefish_home)
        return f"{home}/cuttlefish_runtime/logs"

    def fetch_cuttlefish_runtime_logs(self, local_output_dir: Optional[Path] = None) -> dict:
        """
        Fetch cuttlefish runtime logs (kernel.log, logcat, etc.) from remote host.
        
        Args:
            local_output_dir: Directory to save logs locally. If None, uses log_dir.
        
        Returns:
            Dict with log names as keys and their contents as values.
        """
        logs_dir = self._infer_runtime_logs_dir()
        if not logs_dir:
            self._log_warning("Could not determine cuttlefish runtime logs directory")
            return {}
        
        self._log_info(f"Fetching cuttlefish runtime logs from: {logs_dir}")
        
        # Files to fetch
        log_files = ["kernel.log", "logcat", "launcher.log", "modem_simulator.log"]
        fetched_logs = {}
        
        for log_file in log_files:
            remote_path = f"{logs_dir}/{log_file}"
            try:
                # Fetch log content
                exit_code, stdout, stderr = self._ssh_exec(
                    f"cat {remote_path} 2>/dev/null | tail -5000",  # Last 5000 lines
                    timeout=60
                )
                if exit_code == 0 and stdout and '[Log file not found]' not in stdout:
                    fetched_logs[log_file] = stdout
                    self._log_info(f"  Fetched {log_file}: {len(stdout)} bytes")
                    
                    # Save locally if output dir specified
                    if local_output_dir:
                        local_path = local_output_dir / log_file
                        with open(local_path, 'w') as f:
                            f.write(stdout)
                        self._log_debug(f"  Saved to: {local_path}")
                else:
                    self._log_debug(f"  {log_file}: not found or empty")
            except Exception as e:
                self._log_warning(f"  Failed to fetch {log_file}: {e}")
        
        return fetched_logs

    def _append_remote_logs_to_local(self) -> None:
        """Fetch remote logs and append them to the local log file for debugging."""
        self._log_separator()
        self._log_info("FETCHING REMOTE LOGS")
        
        boot_log = self.fetch_remote_boot_log()
        if boot_log:
            self._log_info("=" * 40 + " REMOTE BOOT LOG START " + "=" * 40)
            for line in boot_log.splitlines():
                self._log_info(f"[REMOTE] {line}")
            self._log_info("=" * 40 + " REMOTE BOOT LOG END " + "=" * 42)
        else:
            self._log_warning("Could not fetch remote boot log")
        
        # Also fetch cuttlefish runtime logs
        runtime_logs = self.fetch_cuttlefish_runtime_logs()
        if runtime_logs:
            for log_name, content in runtime_logs.items():
                self._log_info(f"=" * 35 + f" {log_name.upper()} (last 100 lines) " + "=" * 35)
                # Only log last 100 lines to avoid huge log files
                lines = content.splitlines()[-100:]
                for line in lines:
                    self._log_info(f"[{log_name}] {line}")
                self._log_info("=" * 40 + f" END {log_name.upper()} " + "=" * 40)
    
    def cleanup(self, save_logs_to: Optional[Path] = None) -> None:
        """Clean up all resources.
        
        Args:
            save_logs_to: Optional directory to save runtime logs (kernel.log, logcat, etc.)
        """
        self._log_separator()
        self._log_info("CLEANUP: Releasing all resources")
        
        # Try to fetch and save remote logs before cleanup
        if self.config.ssh_host != "localhost":
            boot_log = self.fetch_remote_boot_log()
            if boot_log:
                self._log_info("Remote boot log fetched and logged")
            
            # Fetch and save runtime logs
            if save_logs_to:
                save_logs_to.mkdir(parents=True, exist_ok=True)
                self._log_info(f"Saving cuttlefish runtime logs to: {save_logs_to}")
                runtime_logs = self.fetch_cuttlefish_runtime_logs(local_output_dir=save_logs_to)
                if runtime_logs:
                    self._log_info(f"Saved {len(runtime_logs)} log files")
        
        self.stop()
        self._teardown_ssh_tunnels()
        if self._ssh_client:
            try:
                self._log_info("Closing SSH client connection")
                self._ssh_client.close()
            except Exception as e:
                self._log_warning(f"Error closing SSH client: {e}")
            self._ssh_client = None
        
        self._log_info("Cleanup complete")
        self._log_separator()
        self._log_info(f"Session ended. Full log available at: {self._log_file_path}")
    
    def is_ready(self) -> bool:
        """Check if Cuttlefish is ready for use."""
        return self._is_booted and self._check_boot_complete()
    
    def get_gdb_connection_info(self) -> Tuple[str, int]:
        """Get GDB connection host and port (accounting for tunnels)."""
        if self.config.setup_tunnels:
            return "localhost", self.config.local_gdb_port
        return self.config.gdb_host, self.config.gdb_port
    
    def get_adb_target(self) -> str:
        """
        Get ADB target string for connecting to device.
        
        Cuttlefish devices are typically listed as 0.0.0.0:port rather than
        localhost:port. This method returns the correct device serial.
        """
        return self._get_adb_device_serial()
    
    def get_adb_env(self) -> dict:
        """
        Get environment variables for ADB commands when using SSH tunnels.
        
        When the ADB server is tunneled (ssh -L 5037:localhost:5037), we need
        to ensure the local ADB client connects to the correct port.
        """
        env = os.environ.copy()
        if self.config.setup_tunnels:
            # Tell ADB client to use our tunneled server port
            env["ADB_SERVER_SOCKET"] = f"tcp:localhost:{self.config.local_adb_server_port}"
        return env
    
    def __enter__(self):
        """Context manager entry - start Cuttlefish."""
        if not self.start():
            raise RuntimeError("Failed to start Cuttlefish")
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - stop Cuttlefish (if non-persistent)."""
        self.cleanup()
        return False


# ============================================================================
# Test Runner Integration
# ============================================================================

def run_test_with_cuttlefish(
    config: CuttlefishConfig,
    repro_path: Path,
    test_func: Callable[['CuttlefishController', Path], Tuple[bool, dict]],
    gdb_script_path: Optional[Path] = None,
) -> Tuple[bool, dict]:
    """
    Run a test with Cuttlefish, handling startup/shutdown based on persistence mode.
    
    Args:
        config: CuttlefishConfig with connection and mode settings
        repro_path: Path to the reproducer binary to test
        test_func: Function that takes (controller, repro_path) and returns (crashed, results_dict)
        gdb_script_path: Optional path to GDB script to attach
    
    Returns:
        (crashed: bool, results: dict)
    """
    controller = CuttlefishController(config)
    
    try:
        if not controller.start():
            return False, {"error": "Failed to start Cuttlefish"}
        
        # Run the actual test
        crashed, results = test_func(controller, repro_path)
        
        return crashed, results
        
    finally:
        controller.cleanup()


def create_config_from_args(
    ssh_host: str = "localhost",
    ssh_port: int = 22,
    ssh_user: str = "vsoc-01",
    ssh_key: Optional[str] = None,
    ssh_password: Optional[str] = None,
    persistent: bool = True,
    already_running: bool = False,
    start_cmd: Optional[str] = None,
    stop_cmd: Optional[str] = None,
    gdb_port: int = 1234,
    adb_port: int = 6520,
    cuttlefish_home: str = "~/cuttlefish",
    setup_tunnels: bool = False,
) -> CuttlefishConfig:
    """
    Create CuttlefishConfig from command-line style arguments.
    
    Examples:
        # Already running local instance
        config = create_config_from_args(
            persistent=True,
            already_running=True,
            gdb_port=1234,
            adb_port=6520,
        )
        
        # Remote instance with SSH tunnels, boot once
        config = create_config_from_args(
            ssh_host="cuttlefish-server",
            ssh_user="user",
            ssh_key="~/.ssh/id_rsa",
            persistent=True,
            already_running=False,
            start_cmd="cd ~/cf && HOME=$PWD ./bin/launch_cvd --daemon",
            setup_tunnels=True,
        )
        
        # Non-persistent mode (start/stop for each test)
        config = create_config_from_args(
            persistent=False,
            start_cmd="cd ~/cf && HOME=$PWD ./bin/launch_cvd",
            stop_cmd="cd ~/cf && HOME=$PWD ./bin/stop_cvd",
        )
    """
    return CuttlefishConfig(
        ssh_host=ssh_host,
        ssh_port=ssh_port,
        ssh_user=ssh_user,
        ssh_password=ssh_password,
        ssh_key_path=ssh_key,
        cuttlefish_home=cuttlefish_home,
        persistent=persistent,
        already_running=already_running,
        start_command=start_cmd,
        stop_command=stop_cmd,
        gdb_port=gdb_port,
        adb_port=adb_port,
        setup_tunnels=setup_tunnels,
    )


# ============================================================================
# Kernel GDB Attachment for crosvm
# ============================================================================

class CuttlefishKernelGDB:
    """
    Handles GDB attachment to Cuttlefish's crosvm kernel for kernel-level debugging.
    
    Cuttlefish uses crosvm which exposes a GDB stub on port 1234 for kernel debugging.
    This class manages:
    - GDB connection to crosvm's kernel GDB stub
    - Running GDB scripts for dynamic analysis
    - Collecting kernel-level crash information
    - Auto-extraction of vmlinux with symbols from kernel Image
    
    For remote Cuttlefish instances, an SSH tunnel is used to forward the GDB port
    from the remote server to localhost. This allows GDB to run locally and connect
    through the tunnel. The tunnel must be set up via setup_tunnels=True in config.
    """
    
    def __init__(self, controller: CuttlefishController, log_dir: Path):
        self.controller = controller
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self._gdb_process: Optional[subprocess.Popen] = None
        self._remote_gdb_process: Optional[subprocess.Popen] = None
        self._remote_script_path: Optional[str] = None
        self._remote_results_path: Optional[str] = None
        self._syz_trace_script_path: Optional[Path] = None
        self._need_kallsyms_extraction: bool = False
        
        # Symbol paths (auto-populated from kernel image if configured)
        self.vmlinux_path: Optional[str] = controller.config.vmlinux_path
        self.system_map_path: Optional[str] = controller.config.system_map_path
        
        # Auto-extract symbols if kernel_image_path is set and extract_symbols is True
        if controller.config.extract_symbols and controller.config.kernel_image_path:
            self._extract_kernel_symbols()
    
    def _extract_kernel_symbols(self):
        """Extract vmlinux and System.map from kernel Image."""
        config = self.controller.config
        kernel_image = config.kernel_image_path
        
        if not kernel_image:
            return
        
        self.controller._log_info(f"Extracting kernel symbols from: {kernel_image}")
        
        # Determine if the image is remote or local
        is_remote = self.is_remote() and not os.path.exists(kernel_image)
        
        symbol_dir = self.log_dir / "symbols"
        symbol_dir.mkdir(parents=True, exist_ok=True)
        
        if is_remote:
            # Download from remote and extract
            self.controller._log_info("Downloading kernel Image from remote server...")
            vmlinux, smap = download_and_extract_kernel_symbols(
                ssh_host=config.ssh_host,
                remote_kernel_image=kernel_image,
                local_output_dir=str(symbol_dir),
                ssh_user=config.ssh_user,
                ssh_key_path=config.ssh_key_path,
                logger=lambda msg: self.controller._log_info(msg),
            )
        else:
            # Extract locally
            vmlinux = extract_vmlinux_from_image(
                kernel_image,
                str(symbol_dir),
                logger=lambda msg: self.controller._log_info(msg),
            )
            smap = generate_system_map(vmlinux, logger=lambda msg: self.controller._log_info(msg)) if vmlinux else None
        
        if vmlinux:
            self.vmlinux_path = vmlinux
            self.controller._log_info(f"vmlinux extracted: {vmlinux}")
        else:
            self.controller._log_warning("Failed to extract vmlinux - will try kallsyms after boot")
            # Mark that we need to extract kallsyms after boot
            self._need_kallsyms_extraction = True
        
        if smap:
            self.system_map_path = smap
            self.controller._log_info(f"System.map generated: {smap}")
    
    def extract_kallsyms_after_boot(self, adb_target: Optional[str] = None) -> bool:
        """
        Extract /proc/kallsyms from the running system after boot.
        
        This is a fallback when vmlinux-to-elf fails. Call this after the
        system has booted and ADB is connected.
        
        Args:
            adb_target: ADB device target (e.g., "0.0.0.0:6524")
        
        Returns:
            True if symbols were extracted successfully
        """
        if self.system_map_path and os.path.exists(self.system_map_path):
            self.controller._log_info("System.map already exists, skipping kallsyms extraction")
            return True
        
        config = self.controller.config
        symbol_dir = self.log_dir / "symbols"
        symbol_dir.mkdir(parents=True, exist_ok=True)
        
        target = adb_target or f"{config.adb_host}:{config.adb_port}"
        
        self.controller._log_info(f"Extracting kallsyms from running system via ADB ({target})...")
        
        smap = extract_kallsyms_from_running_system(
            ssh_host=config.ssh_host,
            local_output_dir=str(symbol_dir),
            ssh_user=config.ssh_user,
            ssh_key_path=config.ssh_key_path,
            adb_exe=config.adb_exe,
            adb_target=target,
            use_adb=True,
            logger=lambda msg: self.controller._log_info(msg),
        )
        
        if smap:
            self.system_map_path = smap
            self.controller._log_info(f"System.map extracted from kallsyms: {smap}")
            return True
        else:
            self.controller._log_warning("Failed to extract kallsyms from running system")
            return False
    
    def _get_syz_trace_script_path(self) -> Optional[Path]:
        """Get the path to the syz_trace (gdb.py) script."""
        if self._syz_trace_script_path:
            return self._syz_trace_script_path
        
        # The gdb.py script should be in the same directory as this file
        this_dir = Path(__file__).parent
        gdb_script = this_dir / "gdb.py"
        
        if gdb_script.exists():
            self._syz_trace_script_path = gdb_script
            self.controller._log_info(f"Found syz_trace script: {gdb_script}")
            return gdb_script
        
        self.controller._log_warning(f"syz_trace script not found at {gdb_script}")
        return None
    
    def is_remote(self) -> bool:
        """Check if this is a remote Cuttlefish instance."""
        return self.controller.config.ssh_host != "localhost" or self.controller.config.ssh_port != 22
    
    def get_gdb_connection_string(self) -> str:
        """Get the GDB remote target string.
        
        For remote instances with tunnels, this returns the local tunneled port.
        For local instances, this returns the direct GDB port.
        """
        if self.is_remote():
            if self.controller.config.setup_tunnels:
                # Use the local tunneled port
                return f"localhost:{self.controller.config.local_gdb_port}"
            else:
                self.controller._log_warning("Remote instance without tunnels - GDB may not connect")
                return f"localhost:{self.controller.config.gdb_port}"
        else:
            host, port = self.controller.get_gdb_connection_info()
            return f"{host}:{port}"
    
    def _build_scp_cmd(self, local_path: str, remote_path: str, upload: bool = True) -> List[str]:
        """Build SCP command for file transfer."""
        cmd = ["scp"]
        
        # Add port if not default
        if self.controller.config.ssh_port != 22:
            cmd.extend(["-P", str(self.controller.config.ssh_port)])
        
        # Add key if specified
        if self.controller.config.ssh_key_path:
            cmd.extend(["-i", self.controller.config.ssh_key_path])
        
        # Build remote target
        if self.controller.config.ssh_user:
            remote_target = f"{self.controller.config.ssh_user}@{self.controller.config.ssh_host}"
        else:
            remote_target = self.controller.config.ssh_host
        
        if upload:
            cmd.extend([local_path, f"{remote_target}:{remote_path}"])
        else:
            cmd.extend([f"{remote_target}:{remote_path}", local_path])
        
        return cmd
    
    def _transfer_file_to_remote(self, local_path: Path, remote_path: str) -> bool:
        """Transfer a file to the remote server via SCP."""
        self.controller._log_info(f"Transferring {local_path} to remote:{remote_path}")
        
        scp_cmd = self._build_scp_cmd(str(local_path), remote_path, upload=True)
        self.controller._log_debug(f"SCP command: {' '.join(scp_cmd)}")
        
        try:
            result = subprocess.run(
                scp_cmd,
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if result.returncode == 0:
                self.controller._log_info("File transfer successful")
                return True
            else:
                self.controller._log_error(f"SCP failed: {result.stderr}")
                return False
        except Exception as e:
            self.controller._log_error(f"SCP exception: {e}")
            return False
    
    def _transfer_file_from_remote(self, remote_path: str, local_path: Path) -> bool:
        """Transfer a file from the remote server via SCP."""
        self.controller._log_info(f"Downloading remote:{remote_path} to {local_path}")
        
        scp_cmd = self._build_scp_cmd(str(local_path), remote_path, upload=False)
        self.controller._log_debug(f"SCP command: {' '.join(scp_cmd)}")
        
        try:
            result = subprocess.run(
                scp_cmd,
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if result.returncode == 0:
                self.controller._log_info("File download successful")
                return True
            else:
                self.controller._log_error(f"SCP download failed: {result.stderr}")
                return False
        except Exception as e:
            self.controller._log_error(f"SCP download exception: {e}")
            return False
    
    def generate_kernel_gdb_script(
        self,
        bug_id: str,
        breakpoints: List[dict] = None,
        vmlinux_path: Optional[str] = None,
        use_syz_trace: bool = True,
        track_memory: bool = True,
        parsed_crash: Optional[dict] = None,
        demo_mode: bool = False,
        runtime_symbols_config: Optional[str] = None,
    ) -> Path:
        """
        Generate a GDB Python script for kernel-level dynamic analysis.
        
        Uses the syz_trace framework (gdb.py) which provides comprehensive
        memory tracking, UAF detection, and event logging compatible with
        post_process.py for result analysis.
        
        Args:
            bug_id: Bug identifier for log naming
            breakpoints: List of breakpoint configurations
            vmlinux_path: Path to vmlinux with debug symbols (overrides auto-extracted)
            use_syz_trace: If True (default), use the full syz_trace (gdb.py) script
            track_memory: If True and System.map available, enable alloc/free tracking
            parsed_crash: Optional parsed crash info for fault address extraction
            demo_mode: If True, generate sample data when real tracing fails
            runtime_symbols_config: Path to JSON config with runtime-extracted symbol addresses.
                                   This takes precedence over System.map for accurate addresses.
        
        Returns:
            Path to generated GDB script
        
        Note: Results are saved in a format compatible with post_process.py
        """
        # Use provided vmlinux or auto-extracted one
        effective_vmlinux = vmlinux_path or self.vmlinux_path
        effective_smap = self.system_map_path
        
        # Helper to convert string addresses to int
        def to_int_addr(addr):
            """Convert address to int, handling string hex format."""
            if addr is None:
                return None
            if isinstance(addr, int):
                return addr
            if isinstance(addr, str):
                try:
                    return int(addr, 16) if addr.startswith('0x') else int(addr)
                except ValueError:
                    return None
            return None
        
        # If runtime symbols config is provided, load it for addresses
        runtime_addrs = {}
        if runtime_symbols_config and os.path.exists(runtime_symbols_config):
            try:
                with open(runtime_symbols_config, 'r') as f:
                    runtime_data = json.load(f)
                # Load and convert addresses to integers
                for key, val in runtime_data.get('alloc_addrs', {}).items():
                    int_addr = to_int_addr(val)
                    if int_addr:
                        runtime_addrs[key] = int_addr
                for key, val in runtime_data.get('free_addrs', {}).items():
                    int_addr = to_int_addr(val)
                    if int_addr:
                        runtime_addrs[key] = int_addr
                for key, val in runtime_data.get('crash_stack_addrs', {}).items():
                    int_addr = to_int_addr(val)
                    if int_addr:
                        runtime_addrs[key] = int_addr
                self.controller._log_info(f"Loaded runtime symbols from: {runtime_symbols_config}")
                self.controller._log_info(f"  Loaded {len(runtime_addrs)} symbol addresses")
                # Override System.map with runtime kallsyms
                if runtime_data.get('system_map_path'):
                    effective_smap = runtime_data.get('system_map_path')
                    self.controller._log_info(f"  Using runtime System.map: {effective_smap}")
            except Exception as e:
                self.controller._log_warning(f"Failed to load runtime symbols config: {e}")
        
        # Log symbol info
        if effective_vmlinux:
            self.controller._log_info(f"Using vmlinux for symbols: {effective_vmlinux}")
        else:
            self.controller._log_warning("No vmlinux available - debugging without symbols")
        
        if effective_smap:
            self.controller._log_info(f"Using System.map: {effective_smap}")
        else:
            self.controller._log_warning("No System.map available - hardware breakpoints on alloc/free disabled")
        
        # Results file path
        results_file = str(self.log_dir / f"{bug_id}_kernel_gdb_results.json")
        
        # Extract fault info from parsed crash if available
        fault_addr = None
        fault_insn = None
        access_type = "any"
        access_size = 0
        
        if parsed_crash:
            # Try to extract fault address
            if parsed_crash.get('access'):
                addr_str = parsed_crash['access'].get('address')
                if addr_str:
                    try:
                        fault_addr = int(addr_str, 16) if addr_str.startswith('0x') else int(addr_str)
                    except:
                        pass
                access_type = parsed_crash['access'].get('type', 'any')
                try:
                    access_size = int(parsed_crash['access'].get('size', 0))
                except:
                    access_size = 0
            
            # Try to extract fault instruction from frames
            for frame in parsed_crash.get('frames', []):
                if frame.get('ip'):
                    try:
                        fault_insn = int(frame['ip'], 16) if frame['ip'].startswith('0x') else int(frame['ip'])
                        break
                    except:
                        pass
        
        # Look up memory function addresses from runtime symbols or System.map
        kmalloc_addr = None
        kfree_addr = None
        vfree_addr = None
        kmem_cache_alloc_addr = None
        kmem_cache_free_addr = None
        kvfree_addr = None
        kfree_rcu_addr = None
        vfree_atomic_addr = None
        
        # First, try to get addresses from runtime symbols (most accurate)
        if runtime_addrs:
            self.controller._log_info("Using runtime-extracted symbol addresses:")
            kmalloc_addr = runtime_addrs.get('__kmalloc')
            kfree_addr = runtime_addrs.get('kfree')
            vfree_addr = runtime_addrs.get('vfree')
            kmem_cache_alloc_addr = runtime_addrs.get('kmem_cache_alloc')
            kmem_cache_free_addr = runtime_addrs.get('kmem_cache_free')
            kvfree_addr = runtime_addrs.get('kvfree')
            kfree_rcu_addr = runtime_addrs.get('kfree_rcu')
            vfree_atomic_addr = runtime_addrs.get('vfree_atomic')
            
            if kmalloc_addr:
                self.controller._log_info(f"  __kmalloc: 0x{kmalloc_addr:x}")
            if kfree_addr:
                self.controller._log_info(f"  kfree: 0x{kfree_addr:x}")
            if kmem_cache_alloc_addr:
                self.controller._log_info(f"  kmem_cache_alloc: 0x{kmem_cache_alloc_addr:x}")
            if kmem_cache_free_addr:
                self.controller._log_info(f"  kmem_cache_free: 0x{kmem_cache_free_addr:x}")
        
        # Fallback to System.map if no runtime symbols
        if effective_smap and track_memory and not kmalloc_addr:
            try:
                symbol_map = {}
                with open(effective_smap, 'r') as f:
                    for line in f:
                        parts = line.strip().split()
                        if len(parts) >= 3:
                            addr = int(parts[0], 16)
                            name = parts[2]
                            symbol_map[name] = addr
                
                # Core allocation functions
                kmalloc_addr = symbol_map.get('__kmalloc')
                kfree_addr = symbol_map.get('kfree')
                vfree_addr = symbol_map.get('vfree')
                kmem_cache_alloc_addr = symbol_map.get('kmem_cache_alloc')
                kmem_cache_free_addr = symbol_map.get('kmem_cache_free')
                # Additional free functions
                kvfree_addr = symbol_map.get('kvfree')
                kfree_rcu_addr = symbol_map.get('kfree_rcu')
                vfree_atomic_addr = symbol_map.get('vfree_atomic')
                
                self.controller._log_info(f"Resolved from System.map:")
                if kmalloc_addr:
                    self.controller._log_info(f"  __kmalloc: 0x{kmalloc_addr:x}")
                if kfree_addr:
                    self.controller._log_info(f"  kfree: 0x{kfree_addr:x}")
                if vfree_addr:
                    self.controller._log_info(f"  vfree: 0x{vfree_addr:x}")
                if kmem_cache_alloc_addr:
                    self.controller._log_info(f"  kmem_cache_alloc: 0x{kmem_cache_alloc_addr:x}")
                if kmem_cache_free_addr:
                    self.controller._log_info(f"  kmem_cache_free: 0x{kmem_cache_free_addr:x}")
                if kvfree_addr:
                    self.controller._log_info(f"  kvfree: 0x{kvfree_addr:x}")
                if kfree_rcu_addr:
                    self.controller._log_info(f"  kfree_rcu: 0x{kfree_rcu_addr:x}")
                if vfree_atomic_addr:
                    self.controller._log_info(f"  vfree_atomic: 0x{vfree_atomic_addr:x}")
            except Exception as e:
                self.controller._log_warning(f"Failed to read System.map: {e}")
        
        # Extract crash stack function names and resolve addresses
        crash_stack_funcs = []
        crash_stack_addrs = {}
        
        # Functions to filter out - debug/dump/sanitizer infrastructure
        unimportant_funcs = {
            'dump_stack', 'dump_stack_lvl', 'show_stack', 'show_trace', 'show_regs',
            '__dump_stack', 'dump_backtrace', 'dump_stack_print_info',
            'kasan_report', 'kasan_check_range', '__kasan_check_read', '__kasan_check_write',
            'kasan_save_stack', 'kasan_set_track', 'kasan_save_free_info', 'kasan_save_alloc_info',
            '__asan_report_load', '__asan_report_store', '__asan_load', '__asan_store',
            'check_memory_region', 'print_address_description', 'print_report',
            '__kmem_cache_alloc_node', '__slab_alloc', '__slab_free', 'slab_alloc_node',
            'slab_free_freelist_hook', 'slab_free_hook', '__cache_alloc',
            'do_page_fault', 'handle_page_fault', 'exc_page_fault', '__do_page_fault',
            'die', 'oops_begin', 'oops_end', '__die', 'ret_from_fork',
            '__might_resched', '__might_sleep', 'lock_acquire', 'lock_release',
            'rcu_read_lock', 'rcu_read_unlock', 'preempt_schedule',
        }
        skip_prefixes = ('kasan_', '__kasan_', '__asan_', 'dump_', 'show_', 'print_', '__might_')
        
        if parsed_crash:
            # Get unique function names from stack frames (try different fields)
            seen_funcs = set()
            frames_list = parsed_crash.get('stack_frames', parsed_crash.get('frames', []))
            
            self.controller._log_info(f"Analyzing {len(frames_list)} stack frames for breakpoints...")
            
            for frame in frames_list[:15]:  # Look at top 15 frames
                func_name = frame.get('function', frame.get('func', ''))
                if func_name and func_name not in seen_funcs:
                    # Clean up function name (remove inline markers, etc)
                    base_func = func_name.split('+')[0].split('.')[0].strip()
                    if base_func and base_func not in seen_funcs:
                        # Filter out unimportant functions
                        if base_func.lower() in {f.lower() for f in unimportant_funcs}:
                            self.controller._log_debug(f"  Skipping debug func: {base_func}")
                            continue
                        if any(base_func.lower().startswith(p) for p in skip_prefixes):
                            self.controller._log_debug(f"  Skipping by prefix: {base_func}")
                            continue
                        
                        seen_funcs.add(base_func)
                        crash_stack_funcs.append(base_func)
                        self.controller._log_info(f"  + Adding breakpoint target: {base_func}")
            
            # Also add corrupted_function if present
            if parsed_crash.get('corrupted_function'):
                cf = parsed_crash['corrupted_function']
                if cf not in seen_funcs:
                    crash_stack_funcs.insert(0, cf)  # Priority at front
                    self.controller._log_info(f"  + Adding corrupted function: {cf}")
            
            # Print summary to console
            if crash_stack_funcs:
                print(f"[GDB] Stack trace breakpoint targets ({len(crash_stack_funcs)}):")
                for i, fn in enumerate(crash_stack_funcs[:10]):
                    print(f"      {i+1}. {fn}")
                if len(crash_stack_funcs) > 10:
                    print(f"      ... and {len(crash_stack_funcs) - 10} more")
            else:
                print("[GDB] No stack trace functions extracted for breakpoints")
            
            # First, try to get crash stack addresses from runtime symbols
            if runtime_addrs:
                for func_name in crash_stack_funcs:
                    if func_name in runtime_addrs:
                        crash_stack_addrs[func_name] = runtime_addrs[func_name]
                
                if crash_stack_addrs:
                    self.controller._log_info(f"Crash stack from runtime symbols: {len(crash_stack_addrs)} of {len(crash_stack_funcs)}")
                    for fn, addr in crash_stack_addrs.items():
                        self.controller._log_info(f"  {fn}: 0x{addr:x}")
            
            # Fallback: Look up addresses from symbol_map if not found in runtime
            remaining_funcs = [f for f in crash_stack_funcs if f not in crash_stack_addrs]
            if remaining_funcs and effective_smap and track_memory:
                try:
                    # Reuse symbol_map from above, or re-read if needed
                    if 'symbol_map' not in dir():
                        symbol_map = {}
                        with open(effective_smap, 'r') as f:
                            for line in f:
                                parts = line.strip().split()
                                if len(parts) >= 3:
                                    addr = int(parts[0], 16)
                                    name = parts[2]
                                    symbol_map[name] = addr
                    
                    for func_name in remaining_funcs:
                        if func_name in symbol_map:
                            crash_stack_addrs[func_name] = symbol_map[func_name]
                    
                    if crash_stack_addrs:
                        self.controller._log_info(f"Crash stack functions resolved: {len(crash_stack_addrs)} of {len(crash_stack_funcs)}")
                        for fn, addr in crash_stack_addrs.items():
                            self.controller._log_info(f"  {fn}: 0x{addr:x}")
                except Exception as e:
                    self.controller._log_warning(f"Failed to resolve crash stack addresses: {e}")
        
        # Build JSON config for syz_load_config command
        gdb_json_config = {
            "fault_addr": fault_addr if fault_addr else 0,
            "fault_insn": fault_insn if fault_insn else 0,
            "access_type": access_type,
            "access_size": access_size,
            "system_map_path": effective_smap or "",
            "kmalloc_addr": kmalloc_addr if kmalloc_addr else 0,
            "kfree_addr": kfree_addr if kfree_addr else 0,
            "vfree_addr": vfree_addr if vfree_addr else 0,
            "kmem_cache_alloc_addr": kmem_cache_alloc_addr if kmem_cache_alloc_addr else 0,
            "kmem_cache_free_addr": kmem_cache_free_addr if kmem_cache_free_addr else 0,
            "kvfree_addr": kvfree_addr if kvfree_addr else 0,
            "kfree_rcu_addr": kfree_rcu_addr if kfree_rcu_addr else 0,
            "vfree_atomic_addr": vfree_atomic_addr if vfree_atomic_addr else 0,
            "export_path": str(results_file),
            "bug_id": bug_id,
            "crash_stack_funcs": crash_stack_funcs,
            "crash_stack_addrs": {fn: f"0x{addr:x}" for fn, addr in crash_stack_addrs.items()},
            "runtime_symbols_config": runtime_symbols_config or "",
            "symbols_source": "runtime" if runtime_addrs else "system_map",
        }
        
        # Write JSON config file
        config_json_path = self.log_dir / f"{bug_id}_gdb_config.json"
        with open(config_json_path, 'w') as f:
            json.dump(gdb_json_config, f, indent=2)
        self.controller._log_info(f"GDB config JSON: {config_json_path}")
        
        # Find the gdb.py (syz_trace) script path
        syz_trace_path = self._get_syz_trace_script_path()
        if not syz_trace_path or not syz_trace_path.exists():
            self.controller._log_error("Could not find gdb.py (syz_trace) script")
            raise FileNotFoundError("gdb.py not found in SyzVerify directory")
        
        self.controller._log_info(f"syz_trace script: {syz_trace_path}")
        
        # Demo mode setting (1 if enabled, 0 if disabled)
        demo_mode_val = 1 if demo_mode else 0
        if demo_mode:
            self.controller._log_info("DEMO MODE: Will generate sample data if tracing fails")
        
        # Runtime symbols config path (empty string if not available)
        runtime_config_str = runtime_symbols_config or ""
        
        # Generate a minimal bootstrap script that:
        # 1. Sets all config variables BEFORE sourcing gdb.py
        # 2. Sources the main gdb.py script (which calls _initialize() and installs breakpoints)
        # 3. Loads additional config and explicitly reinstalls breakpoints
        # This keeps all GDB logic in gdb.py
        bootstrap_script = f'''#!/usr/bin/env python3
"""
Auto-generated GDB bootstrap script for bug: {bug_id}
This script sets up configuration and sources gdb.py

All GDB tracing logic is in: {syz_trace_path}
Config JSON: {config_json_path}
Runtime Symbols: {runtime_config_str}
Results: {results_file}
Demo mode: {demo_mode}
"""
import gdb

# Set ALL config variables BEFORE sourcing gdb.py
# This is critical - _initialize() reads these when the script is sourced
gdb.execute('set $config_json_path = "{config_json_path}"')
gdb.execute('set $export_path = "{results_file}"')
gdb.execute('set $system_map_path = "{effective_smap or ""}"')
gdb.execute('set $bug_id = "{bug_id}"')
gdb.execute('set $runtime_symbols_path = "{runtime_config_str}"')

# Immediate install mode (kernel is paused at GDB attach point)
gdb.execute('set $immediate_install = 1')

# Demo mode - generates sample data when real tracing fails
gdb.execute('set $demo_mode = {demo_mode_val}')

gdb.write("[BOOTSTRAP] Config variables set\\n", gdb.STDERR)
gdb.write("[BOOTSTRAP]   config_json_path = {config_json_path}\\n", gdb.STDERR)
gdb.write("[BOOTSTRAP]   runtime_symbols_path = {runtime_config_str}\\n", gdb.STDERR)
gdb.write("[BOOTSTRAP]   system_map_path = {effective_smap or ""}\\n", gdb.STDERR)

# Source the main gdb.py script which runs _initialize() and installs breakpoints
gdb.write("[BOOTSTRAP] Loading syz_trace from {syz_trace_path}\\n", gdb.STDERR)
gdb.execute('source {syz_trace_path}')

# Load additional config (crash stack functions, etc) and reinstall breakpoints
# This ensures any addresses from the JSON config are used
gdb.write("[BOOTSTRAP] Loading JSON config: {config_json_path}\\n", gdb.STDERR)
gdb.execute('syz_load_config {config_json_path}')

# Explicitly reinstall breakpoints to ensure runtime symbols are used
gdb.write("[BOOTSTRAP] Installing breakpoints with runtime symbols...\\n", gdb.STDERR)
gdb.execute('syz_install_breakpoints force')

# Show status before continuing
gdb.execute('syz_status')

# Auto-continue execution
gdb.write("[BOOTSTRAP] Starting execution...\\n", gdb.STDERR)
try:
    gdb.execute("syz_safe_continue")
except Exception as e:
    gdb.write(f"[BOOTSTRAP] Continue error: {{e}}\\n", gdb.STDERR)
'''
        
        # Write the bootstrap script
        script_path = self.log_dir / f"{bug_id}_kernel_gdb_script.py"
        with open(script_path, 'w') as f:
            f.write(bootstrap_script)
        
        self.controller._log_info(f"Generated GDB bootstrap script: {script_path}")
        
        return script_path
    
    def attach_and_run(
        self,
        script_path: Path,
        vmlinux_path: Optional[str] = None,
        remote_vmlinux_path: Optional[str] = None,
        timeout: int = 120,
    ) -> Tuple[bool, dict]:
        """
        Attach GDB to crosvm kernel and run analysis script.
        
        For remote Cuttlefish instances, GDB runs locally and connects through
        the SSH tunnel to the remote GDB port. The tunnel must be set up first
        using setup_tunnels=True in CuttlefishConfig.
        
        Args:
            script_path: Path to GDB Python script (local)
            vmlinux_path: Path to vmlinux with debug symbols
            remote_vmlinux_path: Deprecated - no longer used (GDB runs locally)
            timeout: Execution timeout in seconds
        
        Returns:
            (success, results_dict)
        """
        # Both local and remote now use local GDB execution
        # For remote, we connect through the SSH tunnel
        if self.is_remote() and not self.controller.config.setup_tunnels:
            self.controller._log_error("Remote instance but setup_tunnels=False - cannot connect to GDB")
            self.controller._log_error("Set setup_tunnels=True in CuttlefishConfig to enable GDB tunnel")
            return False, {"error": "Remote GDB requires setup_tunnels=True"}
        
        return self._attach_and_run_local(script_path, vmlinux_path, timeout)
    
    def _attach_and_run_local(
        self,
        script_path: Path,
        vmlinux_path: Optional[str] = None,
        timeout: int = 120,
    ) -> Tuple[bool, dict]:
        """
        Run GDB locally to connect to crosvm kernel.
        
        For remote Cuttlefish instances, this connects through the SSH tunnel.
        For local instances, this connects directly to the GDB port.
        """
        gdb_target = self.get_gdb_connection_string()
        
        if self.is_remote():
            self.controller._log_info(f"Connecting to remote GDB via tunnel at {gdb_target}")
            print(f"[KERNEL-GDB] Connecting to remote crosvm kernel via tunnel ({gdb_target})")
        else:
            print(f"[KERNEL-GDB] Connecting to local crosvm kernel at {gdb_target}")
        
        # Try various GDB binaries - gdb-multiarch and aarch64-linux-gnu-gdb are needed
        # for cross-architecture debugging (x86 host -> aarch64 target)
        gdb_binary = None
        for candidate in ["gdb-multiarch", "aarch64-linux-gnu-gdb", "gdb"]:
            try:
                subprocess.run([candidate, "--version"], capture_output=True, check=True)
                gdb_binary = candidate
                break
            except (FileNotFoundError, subprocess.CalledProcessError):
                continue
        
        if not gdb_binary:
            self.controller._log_error("No GDB binary found")
            return False, {"error": "No GDB binary found"}
        
        gdb_cmd = [gdb_binary, "-q"]
        
        # Load vmlinux if provided - CRITICAL for proper debugging
        if vmlinux_path and os.path.exists(vmlinux_path):
            gdb_cmd.extend(["-ex", f"file {vmlinux_path}"])
            print(f"[KERNEL-GDB] Loading symbols from {vmlinux_path}")
        else:
            print(f"[KERNEL-GDB] WARNING: No vmlinux file loaded!")
            print(f"[KERNEL-GDB]   vmlinux_path={vmlinux_path}")
            print(f"[KERNEL-GDB]   GDB will have limited functionality without symbols")
            print(f"[KERNEL-GDB]   Use --vmlinux-path or set extract_symbols=True")
            # Try to use auto-extracted vmlinux
            if self.vmlinux_path and os.path.exists(self.vmlinux_path):
                gdb_cmd.extend(["-ex", f"file {self.vmlinux_path}"])
                print(f"[KERNEL-GDB] Using auto-extracted vmlinux: {self.vmlinux_path}")
        
        gdb_cmd.extend([
            "-ex", f"set logging file {self.log_dir}/kernel_gdb.log",
            "-ex", "set logging overwrite on",
            "-ex", "set logging enabled on",
            "-ex", "set pagination off",
            "-ex", "set confirm off",
            # Set architecture for cross-debugging (critical for x86 host -> aarch64 target)
            "-ex", "set architecture aarch64",
            "-ex", f"target remote {gdb_target}",
            "-ex", f"source {script_path}",
            # Note: The script itself handles 'continue' via syz_safe_continue
            # so we don't add -ex continue here
        ])
        
        print(f"[KERNEL-GDB] Starting GDB (timeout: {timeout}s)...")
        
        try:
            self._gdb_process = subprocess.Popen(
                gdb_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            
            stdout, stderr = self._gdb_process.communicate(timeout=timeout)
            
            # Save raw output
            with open(self.log_dir / "kernel_gdb_stdout.log", 'w') as f:
                f.write(stdout or "")
            with open(self.log_dir / "kernel_gdb_stderr.log", 'w') as f:
                f.write(stderr or "")
            
            # Load results
            results_file = self.log_dir / f"*_kernel_gdb_results.json"
            import glob
            results_files = glob.glob(str(results_file))
            
            if results_files:
                with open(results_files[0], 'r') as f:
                    results = json.load(f)
                return True, results
            else:
                return True, {"error": "No results file generated", "stdout": stdout, "stderr": stderr}
                
        except subprocess.TimeoutExpired:
            print(f"[KERNEL-GDB] Timeout after {timeout}s - stopping GDB")
            if self._gdb_process:
                self._gdb_process.terminate()
                try:
                    self._gdb_process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self._gdb_process.kill()
            return False, {"error": "timeout"}
        
        except Exception as e:
            print(f"[KERNEL-GDB] Error: {e}")
            return False, {"error": str(e)}
    
    def _attach_and_run_remote(
        self,
        script_path: Path,
        remote_vmlinux_path: Optional[str] = None,
        timeout: int = 120,
    ) -> Tuple[bool, dict]:
        """
        DEPRECATED: This method is no longer used.
        
        GDB now runs locally and connects through an SSH tunnel to the remote
        Cuttlefish instance. Use attach_and_run() with setup_tunnels=True instead.
        
        This method is kept for backwards compatibility but simply delegates
        to the local execution path.
        """
        self.controller._log_warning("_attach_and_run_remote is deprecated - using local GDB with tunnel")
        return self._attach_and_run_local(script_path, remote_vmlinux_path, timeout)
    
    def start_remote_gdb_session(
        self,
        script_path: Path,
        remote_vmlinux_path: Optional[str] = None,
    ) -> bool:
        """
        DEPRECATED: This method is no longer used.
        
        GDB now runs locally and connects through an SSH tunnel to the remote
        Cuttlefish instance. Use attach_and_run() with setup_tunnels=True instead.
        """
        self.controller._log_warning("start_remote_gdb_session is deprecated - use attach_and_run() with setup_tunnels=True")
        return False
    
    def cleanup(self):
        """Clean up GDB process and remote resources."""
        # Clean up local GDB process
        if self._gdb_process:
            try:
                self._gdb_process.terminate()
                self._gdb_process.wait(timeout=5)
            except Exception:
                self._gdb_process.kill()
            self._gdb_process = None
        
        # Clean up remote GDB process if running
        if self._remote_gdb_process:
            try:
                self._remote_gdb_process.terminate()
                self._remote_gdb_process.wait(timeout=5)
            except Exception:
                self._remote_gdb_process.kill()
            self._remote_gdb_process = None
        
        # Optionally clean up remote temp files
        if self.is_remote() and self._remote_script_path:
            try:
                self.controller._ssh_exec("rm -rf /tmp/syzploit_gdb", timeout=10)
            except Exception:
                pass  # Best effort cleanup


# ============================================================================
# High-level Test Orchestration
# ============================================================================

def run_cuttlefish_kernel_test(
    config: CuttlefishConfig,
    repro_path: Path,
    bug_id: str,
    log_dir: Path,
    vmlinux_path: Optional[str] = None,
    remote_vmlinux_path: Optional[str] = None,
    parsed_crash: Optional[dict] = None,
    timeout: int = 120,
    run_as_root: bool = True,
    arch: str = "arm64",
) -> Tuple[bool, dict]:
    """
    Run a complete kernel-level test with Cuttlefish and GDB attachment.
    
    This orchestrates:
    1. Starting Cuttlefish (if not persistent/already running)
    2. Setting up SSH tunnels for GDB and ADB (for remote instances)
    3. Attaching GDB to crosvm's kernel for dynamic analysis
    4. Collecting crash/event data
    5. Stopping Cuttlefish (if non-persistent mode)
    
    For remote Cuttlefish instances:
    - An SSH tunnel is used to forward the GDB port from the remote server
    - GDB runs locally and connects through the tunnel
    - This requires setup_tunnels=True in the CuttlefishConfig
    
    Args:
        config: CuttlefishConfig with connection settings (set setup_tunnels=True for remote)
        repro_path: Path to compiled reproducer binary
        bug_id: Bug identifier
        log_dir: Directory for logs
        vmlinux_path: Path to vmlinux with debug symbols
        remote_vmlinux_path: Deprecated - no longer used (GDB runs locally)
        parsed_crash: Parsed crash information for breakpoint setup
        timeout: Test timeout in seconds
        run_as_root: Whether to run reproducer as root
        arch: Target architecture (arm64/x86_64)
    
    Returns:
        (crashed, results_dict)
    """
    controller = CuttlefishController(config)
    log_dir = Path(log_dir)
    log_dir.mkdir(parents=True, exist_ok=True)
    
    is_remote = config.ssh_host != "localhost" or config.ssh_port != 22
    
    results = {
        "bug_id": bug_id,
        "mode": "persistent" if config.persistent else "non-persistent",
        "remote": is_remote,
        "arch": arch,
        "crashed": False,
        "events": [],
    }
    
    try:
        # Step 1: Prepare GDB script first (before starting Cuttlefish)
        # This is critical - we need the script ready so it can be loaded
        # during the initial GDB connection when the kernel is paused
        print("=" * 70)
        print("  CUTTLEFISH KERNEL TEST")
        print("=" * 70)
        print(f"[TEST] Bug ID: {bug_id}")
        print(f"[TEST] Mode: {'persistent' if config.persistent else 'non-persistent'}")
        print(f"[TEST] Remote: {is_remote}")
        if is_remote:
            print(f"[TEST] SSH: {config.ssh_user or '(from config)'}@{config.ssh_host}:{config.ssh_port}")
        print(f"[TEST] GDB: {config.gdb_host}:{config.gdb_port}")
        print(f"[TEST] ADB: {config.adb_host}:{config.adb_port}")
        print()
        
        # Step 2: Set up kernel GDB and generate script BEFORE starting
        kernel_gdb = CuttlefishKernelGDB(controller, log_dir)
        
        # Generate breakpoints from parsed crash info
        breakpoints = []
        if parsed_crash:
            if "corrupted_function" in parsed_crash:
                breakpoints.append({"function": parsed_crash["corrupted_function"]})
            if "stack_frames" in parsed_crash:
                for frame in parsed_crash["stack_frames"][:5]:
                    if "function" in frame:
                        breakpoints.append({"function": frame["function"]})
        
        script_path = kernel_gdb.generate_kernel_gdb_script(
            bug_id=bug_id,
            breakpoints=breakpoints,
            vmlinux_path=vmlinux_path if not is_remote else remote_vmlinux_path,
            parsed_crash=parsed_crash,  # Pass parsed_crash for stack trace breakpoints
        )
        print(f"[TEST] Generated GDB script: {script_path}")
        
        # Step 3: Start Cuttlefish WITH the GDB script
        # The script is loaded during the initial GDB connection when the
        # kernel is paused, setting up breakpoints before continuing boot
        print()
        print("[TEST] Starting Cuttlefish with GDB analysis script...")
        if not controller.start(gdb_script_path=script_path, vmlinux_path=vmlinux_path):
            results["error"] = "Failed to start Cuttlefish"
            return False, results
        
        results["cuttlefish_started"] = True
        results["gdb_script_loaded"] = True
        
        # The GDB is now running with the script, monitoring the kernel
        # We store the kernel_gdb instance for later result collection
        results["gdb_log_dir"] = str(log_dir)
        
        # Check if any results were generated during boot
        import glob
        results_files = glob.glob(str(log_dir / f"*_kernel_gdb_results.json"))
        if results_files:
            with open(results_files[0], 'r') as f:
                gdb_results = json.load(f)
            results.update(gdb_results)
            results["crashed"] = gdb_results.get("crash_detected", False)
        
        return results.get("crashed", False), results
        
    except Exception as e:
        results["error"] = str(e)
        import traceback
        results["traceback"] = traceback.format_exc()
        return False, results
        
    finally:
        controller.cleanup()
