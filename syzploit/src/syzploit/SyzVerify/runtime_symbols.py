"""
Runtime Symbol Extraction Module

Extracts /proc/kallsyms from a running VM (Cuttlefish or QEMU) with kptr_restrict disabled.
This provides accurate symbol addresses for GDB breakpoints.

Key Features:
1. Disable kptr_restrict via root access (echo 0 > /proc/sys/kernel/kptr_restrict)
2. Dump /proc/kallsyms to get current symbol addresses
3. Parse kallsyms into a System.map-compatible format
4. Feed symbols to GDB for accurate hardware breakpoints
"""

import os
import subprocess
import tempfile
import time
from pathlib import Path
from dataclasses import dataclass
from typing import Optional, Dict, List, Tuple, Callable


@dataclass
class SymbolInfo:
    """Information about a kernel symbol."""
    address: int
    symbol_type: str
    name: str
    module: Optional[str] = None


@dataclass 
class RuntimeSymbols:
    """Container for runtime-extracted kernel symbols."""
    symbols: Dict[str, SymbolInfo]  # name -> SymbolInfo
    symbol_list: List[SymbolInfo]   # ordered by address
    system_map_path: Optional[str]  # path to generated System.map file
    kallsyms_path: Optional[str]    # path to raw kallsyms dump
    extraction_method: str          # 'adb' or 'ssh'
    kptr_restrict_disabled: bool    # whether we successfully disabled kptr_restrict
    
    def get_address(self, name: str) -> Optional[int]:
        """Get address for a symbol name."""
        if name in self.symbols:
            return self.symbols[name].address
        return None
    
    def get_alloc_free_addresses(self) -> Dict[str, int]:
        """Get addresses for common alloc/free functions."""
        result = {}
        alloc_free_funcs = [
            "__kmalloc", "kmalloc", "kfree",
            "kmem_cache_alloc", "kmem_cache_free",
            "kmem_cache_alloc_trace",
            "__kmem_cache_alloc_node",
            "kmalloc_trace",
            "krealloc", "__krealloc",
            "vmalloc", "vfree",
            "kzalloc", "__kzalloc",
        ]
        for func in alloc_free_funcs:
            addr = self.get_address(func)
            if addr:
                result[func] = addr
        return result
    
    def get_crash_stack_addresses(self, func_names: List[str]) -> Dict[str, int]:
        """Get addresses for crash stack functions."""
        result = {}
        for func in func_names:
            addr = self.get_address(func)
            if addr:
                result[func] = addr
        return result


def disable_kptr_restrict_adb(adb_exe: str = "adb", adb_target: Optional[str] = None, 
                               logger: Optional[Callable] = None) -> bool:
    """
    Disable kptr_restrict on a running Android device via ADB.
    
    Requires root/su access on the device.
    
    Args:
        adb_exe: Path to adb executable
        adb_target: Optional device target (e.g., "0.0.0.0:6524")
        logger: Optional logging function
    
    Returns:
        True if kptr_restrict was successfully disabled
    """
    def log(msg):
        if logger:
            logger(msg)
        else:
            print(f"[KPTR] {msg}")
    
    def adb_cmd(*args) -> List[str]:
        cmd = [adb_exe]
        if adb_target:
            cmd.extend(["-s", adb_target])
        cmd.extend(args)
        return cmd
    
    log("Disabling kptr_restrict on device...")
    
    # First, try adb root (works on userdebug/eng builds)
    try:
        root_cmd = adb_cmd("root")
        result = subprocess.run(root_cmd, capture_output=True, text=True, timeout=10)
        if "restarting adbd as root" in result.stdout or "already running as root" in result.stdout:
            log("ADB restarted as root")
            time.sleep(2)  # Wait for adb to restart
            
            # Now try direct write
            direct_cmd = adb_cmd("shell", "echo 0 > /proc/sys/kernel/kptr_restrict")
            result = subprocess.run(direct_cmd, capture_output=True, text=True, timeout=10)
            if result.returncode == 0 and "Permission denied" not in result.stderr:
                log("kptr_restrict disabled via adb root")
                return True
    except Exception as e:
        log(f"adb root failed: {e}")
    
    # Method: Pipe command into su (works when su doesn't support -c flag)
    # This is the key fix - pipe the command to su's stdin
    pipe_methods = [
        # Pipe echo command into su stdin
        'echo "echo 0 > /proc/sys/kernel/kptr_restrict" | su',
        # Alternative: use sh -c inside su
        'echo "sh -c \'echo 0 > /proc/sys/kernel/kptr_restrict\'" | su',
        # Using su 0 (run as uid 0)
        'su 0 sh -c "echo 0 > /proc/sys/kernel/kptr_restrict"',
        # Using toybox/busybox style
        'su root sh -c "echo 0 > /proc/sys/kernel/kptr_restrict"',
        # su -c format (for devices that support it)
        'su -c "echo 0 > /proc/sys/kernel/kptr_restrict"',
        # Using tee with pipe into su
        'echo "echo 0 | tee /proc/sys/kernel/kptr_restrict" | su',
    ]
    
    for shell_cmd in pipe_methods:
        try:
            cmd = adb_cmd("shell", shell_cmd)
            log(f"Trying: {shell_cmd[:60]}...")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            
            # Check if it worked (no permission denied, no invalid uid/gid)
            combined_output = result.stdout + result.stderr
            if "Permission denied" not in combined_output and "invalid uid/gid" not in combined_output:
                # Verify the change took effect
                if _verify_kptr_restrict_adb(adb_exe, adb_target, log):
                    log(f"kptr_restrict disabled via: {shell_cmd[:40]}...")
                    return True
        except Exception as e:
            log(f"Method failed: {e}")
            continue
    
    log("WARNING: Could not disable kptr_restrict via any method")
    log("TIP: Try manually: adb shell -> su -> echo 0 > /proc/sys/kernel/kptr_restrict")
    return False


def _verify_kptr_restrict_adb(adb_exe: str, adb_target: Optional[str], log: Callable) -> bool:
    """Verify kptr_restrict is disabled by checking kallsyms addresses."""
    def adb_cmd(*args) -> List[str]:
        cmd = [adb_exe]
        if adb_target:
            cmd.extend(["-s", adb_target])
        cmd.extend(args)
        return cmd
    
    # Try to read kptr_restrict value
    verify_methods = [
        'echo "cat /proc/sys/kernel/kptr_restrict" | su',
        'su 0 cat /proc/sys/kernel/kptr_restrict',
        'cat /proc/sys/kernel/kptr_restrict',
    ]
    
    for method in verify_methods:
        try:
            cmd = adb_cmd("shell", method)
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            value = result.stdout.strip()
            if value == "0":
                log("Verified: kptr_restrict = 0")
                return True
        except:
            continue
    
    # Alternative: check if kallsyms shows real addresses
    try:
        cmd = adb_cmd("shell", 'echo "head -5 /proc/kallsyms" | su')
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        lines = result.stdout.strip().split('\n')
        for line in lines:
            if line.strip() and not line.startswith('0000000000000000'):
                log("Verified: kallsyms shows real addresses")
                return True
    except:
        pass
    
    return False


def disable_kptr_restrict_ssh(ssh_host: str, ssh_user: Optional[str] = None,
                               ssh_key_path: Optional[str] = None, ssh_port: int = 22,
                               logger: Optional[Callable] = None) -> bool:
    """
    Disable kptr_restrict on a running QEMU VM via SSH.
    
    Args:
        ssh_host: SSH host or hostname from ~/.ssh/config
        ssh_user: Optional SSH username
        ssh_key_path: Optional path to SSH private key
        ssh_port: SSH port (default: 22)
        logger: Optional logging function
    
    Returns:
        True if kptr_restrict was successfully disabled
    """
    def log(msg):
        if logger:
            logger(msg)
        else:
            print(f"[KPTR] {msg}")
    
    def build_ssh_cmd(remote_cmd: str) -> List[str]:
        cmd = ["ssh"]
        if ssh_port != 22:
            cmd.extend(["-p", str(ssh_port)])
        if ssh_key_path:
            cmd.extend(["-i", ssh_key_path])
        if ssh_user:
            cmd.append(f"{ssh_user}@{ssh_host}")
        else:
            cmd.append(ssh_host)
        cmd.append(remote_cmd)
        return cmd
    
    log(f"Disabling kptr_restrict on {ssh_host}...")
    
    # Try various methods
    disable_methods = [
        "echo 0 > /proc/sys/kernel/kptr_restrict",
        "sudo sh -c 'echo 0 > /proc/sys/kernel/kptr_restrict'",
        "echo 0 | sudo tee /proc/sys/kernel/kptr_restrict",
    ]
    
    for remote_cmd in disable_methods:
        try:
            cmd = build_ssh_cmd(remote_cmd)
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                log(f"kptr_restrict disabled via: {remote_cmd[:40]}...")
                
                # Verify
                verify_cmd = build_ssh_cmd("cat /proc/sys/kernel/kptr_restrict")
                verify_result = subprocess.run(verify_cmd, capture_output=True, text=True, timeout=5)
                if verify_result.returncode == 0 and verify_result.stdout.strip() == "0":
                    log("Verified: kptr_restrict = 0")
                    return True
        except Exception:
            continue
    
    log("WARNING: Could not disable kptr_restrict via SSH")
    return False


def extract_kallsyms_adb(
    output_dir: str,
    adb_exe: str = "adb",
    adb_target: Optional[str] = None,
    logger: Optional[Callable] = None,
) -> Optional[RuntimeSymbols]:
    """
    Extract /proc/kallsyms from a running Android device via ADB.
    
    Steps:
    1. Disable kptr_restrict with root access
    2. Dump /proc/kallsyms
    3. Parse into RuntimeSymbols
    
    Args:
        output_dir: Directory to save kallsyms and System.map
        adb_exe: Path to adb executable
        adb_target: Optional device target
        logger: Optional logging function
    
    Returns:
        RuntimeSymbols object, or None if extraction failed
    """
    def log(msg):
        if logger:
            logger(msg)
        else:
            print(f"[KALLSYMS] {msg}")
    
    def adb_cmd(*args) -> List[str]:
        cmd = [adb_exe]
        if adb_target:
            cmd.extend(["-s", adb_target])
        cmd.extend(args)
        return cmd
    
    os.makedirs(output_dir, exist_ok=True)
    
    # Step 1: Disable kptr_restrict
    kptr_disabled = disable_kptr_restrict_adb(adb_exe, adb_target, logger)
    
    # Step 2: Extract kallsyms
    log("Extracting /proc/kallsyms...")
    
    # Try multiple methods to read kallsyms - use piping for su without -c support
    kallsyms_content = None
    extraction_cmds = [
        # Pipe command into su stdin (works on devices where su doesn't support -c)
        'echo "cat /proc/kallsyms" | su',
        # su 0 variant
        'su 0 cat /proc/kallsyms',
        # su root variant  
        'su root cat /proc/kallsyms',
        # su -c variant (for devices that support it)
        'su -c "cat /proc/kallsyms"',
        # Direct (if already root or adb root worked)
        'cat /proc/kallsyms',
    ]
    
    for shell_cmd in extraction_cmds:
        try:
            cmd = adb_cmd("shell", shell_cmd)
            log(f"Trying extraction via: {shell_cmd[:40]}...")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            if result.returncode == 0 and len(result.stdout) > 1000:
                # Check if we got real addresses (not all zeros)
                first_lines = result.stdout.strip().split('\n')[:10]
                has_real_addr = any(not line.startswith('0000000000000000') for line in first_lines if line.strip())
                if has_real_addr:
                    kallsyms_content = result.stdout
                    log(f"Extracted kallsyms ({len(kallsyms_content)} bytes) with real addresses")
                    break
                else:
                    log(f"Got kallsyms but addresses are zeroed, trying next method...")
        except Exception as e:
            log(f"Extraction method failed: {e}")
            continue
    
    if not kallsyms_content:
        log("ERROR: Failed to extract kallsyms")
        return None
    
    # Check if addresses are zeroed (kptr_restrict still active)
    lines = kallsyms_content.strip().split('\n')[:20]
    all_zeroed = all(line.startswith('0000000000000000') for line in lines if line.strip())
    
    if all_zeroed:
        log("WARNING: All addresses are zeroed - kptr_restrict may still be enabled")
        log("The device may need to be rebooted with userdebug build or manual root access")
        return None
    
    return _parse_kallsyms(kallsyms_content, output_dir, "adb", kptr_disabled, logger)


def extract_kallsyms_ssh(
    output_dir: str,
    ssh_host: str,
    ssh_user: Optional[str] = None,
    ssh_key_path: Optional[str] = None,
    ssh_port: int = 22,
    logger: Optional[Callable] = None,
) -> Optional[RuntimeSymbols]:
    """
    Extract /proc/kallsyms from a running QEMU VM via SSH.
    
    Steps:
    1. Disable kptr_restrict with root access
    2. Dump /proc/kallsyms
    3. Parse into RuntimeSymbols
    
    Args:
        output_dir: Directory to save kallsyms and System.map
        ssh_host: SSH host
        ssh_user: Optional SSH username
        ssh_key_path: Optional path to SSH private key
        ssh_port: SSH port
        logger: Optional logging function
    
    Returns:
        RuntimeSymbols object, or None if extraction failed
    """
    def log(msg):
        if logger:
            logger(msg)
        else:
            print(f"[KALLSYMS] {msg}")
    
    def build_ssh_cmd(remote_cmd: str) -> List[str]:
        cmd = ["ssh"]
        if ssh_port != 22:
            cmd.extend(["-p", str(ssh_port)])
        if ssh_key_path:
            cmd.extend(["-i", ssh_key_path])
        if ssh_user:
            cmd.append(f"{ssh_user}@{ssh_host}")
        else:
            cmd.append(ssh_host)
        cmd.append(remote_cmd)
        return cmd
    
    os.makedirs(output_dir, exist_ok=True)
    
    # Step 1: Disable kptr_restrict
    kptr_disabled = disable_kptr_restrict_ssh(ssh_host, ssh_user, ssh_key_path, ssh_port, logger)
    
    # Step 2: Extract kallsyms
    log("Extracting /proc/kallsyms...")
    
    kallsyms_content = None
    extraction_cmds = [
        "cat /proc/kallsyms",
        "sudo cat /proc/kallsyms",
    ]
    
    for remote_cmd in extraction_cmds:
        try:
            cmd = build_ssh_cmd(remote_cmd)
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            if result.returncode == 0 and len(result.stdout) > 1000:
                kallsyms_content = result.stdout
                log(f"Extracted kallsyms ({len(kallsyms_content)} bytes)")
                break
        except Exception as e:
            log(f"Extraction method failed: {e}")
            continue
    
    if not kallsyms_content:
        log("ERROR: Failed to extract kallsyms")
        return None
    
    # Check if addresses are zeroed
    lines = kallsyms_content.strip().split('\n')[:20]
    all_zeroed = all(line.startswith('0000000000000000') for line in lines if line.strip())
    
    if all_zeroed:
        log("WARNING: All addresses are zeroed - kptr_restrict may still be enabled")
        return None
    
    return _parse_kallsyms(kallsyms_content, output_dir, "ssh", kptr_disabled, logger)


def _parse_kallsyms(
    kallsyms_content: str,
    output_dir: str,
    extraction_method: str,
    kptr_disabled: bool,
    logger: Optional[Callable] = None,
) -> RuntimeSymbols:
    """
    Parse kallsyms content into RuntimeSymbols.
    
    kallsyms format: <address> <type> <name> [<module>]
    Example: ffffxxxxxxxxxxxx T __kmalloc
    """
    def log(msg):
        if logger:
            logger(msg)
        else:
            print(f"[KALLSYMS] {msg}")
    
    out_dir = Path(output_dir)
    kallsyms_path = out_dir / "kallsyms.txt"
    system_map_path = out_dir / "System.map"
    
    # Save raw kallsyms
    with open(kallsyms_path, 'w') as f:
        f.write(kallsyms_content)
    log(f"Saved raw kallsyms to {kallsyms_path}")
    
    # Parse symbols
    symbols = {}
    symbol_list = []
    
    for line in kallsyms_content.strip().split('\n'):
        parts = line.strip().split()
        if len(parts) < 3:
            continue
        
        try:
            addr = int(parts[0], 16)
        except ValueError:
            continue
        
        sym_type = parts[1]
        name = parts[2]
        module = parts[3] if len(parts) > 3 else None
        
        # Skip zero addresses
        if addr == 0:
            continue
        
        sym_info = SymbolInfo(
            address=addr,
            symbol_type=sym_type,
            name=name,
            module=module
        )
        
        # Use first occurrence (kallsyms can have duplicates)
        if name not in symbols:
            symbols[name] = sym_info
        symbol_list.append(sym_info)
    
    # Sort by address
    symbol_list.sort(key=lambda s: s.address)
    
    # Generate System.map
    with open(system_map_path, 'w') as f:
        for sym in symbol_list:
            f.write(f"{sym.address:016x} {sym.symbol_type} {sym.name}\n")
    
    log(f"Generated System.map with {len(symbols)} unique symbols")
    log(f"System.map saved to {system_map_path}")
    
    # Log some important symbols
    important = ["__kmalloc", "kfree", "kmem_cache_alloc", "kmem_cache_free", "schedule"]
    for name in important:
        if name in symbols:
            log(f"  {name}: 0x{symbols[name].address:x}")
    
    return RuntimeSymbols(
        symbols=symbols,
        symbol_list=symbol_list,
        system_map_path=str(system_map_path),
        kallsyms_path=str(kallsyms_path),
        extraction_method=extraction_method,
        kptr_restrict_disabled=kptr_disabled,
    )


def extract_runtime_symbols(
    output_dir: str,
    vm_type: str = "cuttlefish",
    # ADB options (Cuttlefish)
    adb_exe: str = "adb",
    adb_target: Optional[str] = None,
    # SSH options (QEMU)
    ssh_host: Optional[str] = None,
    ssh_user: Optional[str] = None,
    ssh_key_path: Optional[str] = None,
    ssh_port: int = 22,
    logger: Optional[Callable] = None,
) -> Optional[RuntimeSymbols]:
    """
    Extract runtime kernel symbols from a running VM.
    
    This is the main entry point that automatically selects the appropriate
    extraction method based on vm_type.
    
    Args:
        output_dir: Directory to save symbol files
        vm_type: "cuttlefish" or "qemu"
        adb_exe: Path to adb executable (for Cuttlefish)
        adb_target: ADB device target (for Cuttlefish)
        ssh_host: SSH host (for QEMU)
        ssh_user: SSH username (for QEMU)
        ssh_key_path: SSH key path (for QEMU)
        ssh_port: SSH port (for QEMU)
        logger: Optional logging function
    
    Returns:
        RuntimeSymbols object, or None if extraction failed
    """
    def log(msg):
        if logger:
            logger(msg)
        else:
            print(f"[SYMBOLS] {msg}")
    
    log(f"Extracting runtime symbols (vm_type={vm_type})...")
    
    if vm_type.lower() in ("cuttlefish", "android", "adb"):
        return extract_kallsyms_adb(
            output_dir=output_dir,
            adb_exe=adb_exe,
            adb_target=adb_target,
            logger=logger,
        )
    elif vm_type.lower() in ("qemu", "ssh", "linux"):
        if not ssh_host:
            log("ERROR: ssh_host is required for QEMU extraction")
            return None
        return extract_kallsyms_ssh(
            output_dir=output_dir,
            ssh_host=ssh_host,
            ssh_user=ssh_user,
            ssh_key_path=ssh_key_path,
            ssh_port=ssh_port,
            logger=logger,
        )
    else:
        log(f"ERROR: Unknown vm_type: {vm_type}")
        return None


def generate_gdb_symbol_commands(
    runtime_symbols: RuntimeSymbols,
    crash_stack_funcs: Optional[List[str]] = None,
    output_file: Optional[str] = None,
    logger: Optional[Callable] = None,
) -> str:
    """
    Generate GDB commands to set up symbols and breakpoints.
    
    Creates a GDB command script that:
    1. Sets convenience variables for symbol addresses
    2. Defines hbreak commands for crash stack functions
    3. Defines hbreak commands for alloc/free functions
    
    Args:
        runtime_symbols: RuntimeSymbols object with parsed symbols
        crash_stack_funcs: List of crash stack function names
        output_file: Optional path to save commands
        logger: Optional logging function
    
    Returns:
        GDB command script as string
    """
    def log(msg):
        if logger:
            logger(msg)
        else:
            print(f"[GDB-CMD] {msg}")
    
    lines = [
        "# Auto-generated GDB commands from runtime kallsyms",
        f"# System.map: {runtime_symbols.system_map_path}",
        "",
        "# === Alloc/Free Function Addresses ===",
    ]
    
    # Set alloc/free addresses
    alloc_free = runtime_symbols.get_alloc_free_addresses()
    for name, addr in alloc_free.items():
        var_name = name.replace("__", "").replace("-", "_")
        lines.append(f"set ${var_name}_addr = 0x{addr:x}")
    
    lines.append("")
    lines.append("# === Crash Stack Function Addresses ===")
    
    # Set crash stack addresses
    if crash_stack_funcs:
        crash_addrs = runtime_symbols.get_crash_stack_addresses(crash_stack_funcs)
        for name, addr in crash_addrs.items():
            var_name = name.replace("__", "").replace("-", "_").replace(".", "_")
            lines.append(f"set ${var_name}_addr = 0x{addr:x}")
    
    lines.append("")
    lines.append("# === Hardware Breakpoints (max 4) ===")
    lines.append("# Prioritize crash stack functions")
    
    # Generate hbreak commands for crash stack (up to 4)
    hbreak_count = 0
    max_hbreaks = 4
    
    if crash_stack_funcs:
        crash_addrs = runtime_symbols.get_crash_stack_addresses(crash_stack_funcs)
        for name, addr in list(crash_addrs.items())[:max_hbreaks]:
            lines.append(f"# hbreak *0x{addr:x}  # {name}")
            hbreak_count += 1
    
    # Add alloc/free if we have room
    remaining = max_hbreaks - hbreak_count
    if remaining > 0:
        priority_funcs = ["__kmalloc", "kfree"]
        for name in priority_funcs[:remaining]:
            if name in alloc_free:
                lines.append(f"# hbreak *0x{alloc_free[name]:x}  # {name}")
    
    lines.append("")
    lines.append("# === System.map for symbol resolution ===")
    lines.append(f"# Load with: set $system_map = \"{runtime_symbols.system_map_path}\"")
    
    script = "\n".join(lines)
    
    if output_file:
        with open(output_file, 'w') as f:
            f.write(script)
        log(f"Saved GDB commands to {output_file}")
    
    return script
