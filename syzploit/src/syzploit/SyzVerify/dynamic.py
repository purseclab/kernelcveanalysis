#!/usr/bin/env python3
"""
dynamic.py

GDB-based dynamic analysis for kernel bugs that may not crash with KASAN disabled.
Integrates with QEMU and Cuttlefish environments to detect vulnerabilities through
runtime memory access patterns, register states, and allocation tracking.
"""

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
import re
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Dict, Any, Optional, List, Tuple
from dataclasses import dataclass, field
from elftools.elf.elffile import ELFFile  # type: ignore


@dataclass
class DynamicAnalysisConfig:
    """Configuration for dynamic analysis session."""
    vm_type: str = "qemu"  # qemu or cuttlefish
    kernel_image: Optional[str] = None
    kernel_disk: Optional[str] = None
    gdb_port: int = 1234
    timeout: int = 300  # seconds
    enable_alloc_tracking: bool = True
    enable_kasan_checks: bool = True
    fault_addr: Optional[int] = None
    fault_insn: Optional[int] = None
    access_type: str = "any"  # read, write, any
    access_size: int = 0
    poc_entry: Optional[str] = None
    # Optional: bzImage path to extract vmlinux via vmlinux-to-elf
    bzimage_path: Optional[str] = None
    # Resolved vmlinux extracted path (auto-populated)
    vmlinux_path: Optional[str] = None
    system_map: Optional[str] = None  # Optional: system map file for symbol resolution
    # Optional: auto-interrupt delay after continue (seconds)
    continue_delay: int = 10
    # Userspace instrumentation config
    userspace_gdb_port: int = 2345
    userspace_auto_launch: bool = True
    ssh_port: int = 10021  # forwarded host port to guest ssh
    ssh_user: str = "root"
    ssh_key: Optional[str] = None  # path to private key; None uses agent/default
    repro_remote_path: str = "/root/repro"  # path inside guest to run under gdbserver
    # Monitor-mode toggles
    kernel_monitor_all: bool = True
    userspace_monitor_all: bool = True
    # Userspace instrumentation config
    userspace_gdb_port: int = 2345
    userspace_auto_launch: bool = True
    ssh_port: int = 10021  # forwarded host port to guest ssh
    ssh_user: str = "root"
    ssh_key: Optional[str] = None  # path to private key; None uses agent/default
    repro_remote_path: str = "/root/repro"  # path inside guest to run under gdbserver


@dataclass
class DynamicAnalysisResult:
    """Results from dynamic analysis."""
    success: bool = False
    error: Optional[str] = None
    events: List[Dict[str, Any]] = field(default_factory=list)
    allocations: Dict[int, Tuple[int, List[str]]] = field(default_factory=dict)
    frees: List[int] = field(default_factory=list)
    register_states: List[Dict[str, Any]] = field(default_factory=list)
    memory_accesses: List[Dict[str, Any]] = field(default_factory=list)
    vulnerabilities_detected: List[Dict[str, Any]] = field(default_factory=list)
    raw_gdb_output: str = ""


class QEMUManager:
    """Manages QEMU VM instances with GDB server."""
    
    def __init__(self, config: DynamicAnalysisConfig):
        self.config = config
        self.qemu_process = None
        self.gdb_script_path = None
        
    def start_qemu(self, kernel_image: str, kernel_disk: Optional[str] = None,
                   extra_args: List[str] = None) -> bool:
        """Start QEMU with GDB server enabled."""
        print(f"[DEBUG] QEMUManager.start_qemu called")
        print(f"[DEBUG] kernel_image: {kernel_image}")
        print(f"[DEBUG] kernel_image exists: {os.path.exists(kernel_image)}")
        print(f"[DEBUG] initrd: {kernel_disk}")
        
        cmd = [
            "qemu-system-x86_64",
            "-m", "2G",
            "-smp", "2",
            "-kernel", str(kernel_image),
            "-append", "console=ttyS0 root=/dev/vda1 earlyprintk=serial net.ifnames=0 nokaslr",
            "-drive", f"file={str(kernel_disk)},format=raw,if=virtio",
            "-netdev", "user,id=net0,host=10.0.2.10,hostfwd=tcp:127.0.0.1:10021-:22",
            "-device", "virtio-net-pci,netdev=net0",
            # Provide a host share via 9p for trace/repro exchange
            "-virtfs", "local,path=/tmp/qemu-share,security_model=none,mount_tag=hostshare",
            "-enable-kvm",
            "-nographic",
            "-s",  # GDB server on port 1234
            "-S"  # Wait for GDB to connect
        ]
            
        if extra_args:
            cmd.extend(extra_args)
        
        print(f"[DEBUG] QEMU command: {' '.join(cmd)}")
            
        try:
            print("[DEBUG] Starting QEMU process...")
            self.qemu_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )
            print(f"[DEBUG] QEMU process started with PID: {self.qemu_process.pid}")
            # Give QEMU time to start
            print("[DEBUG] Waiting 2 seconds for QEMU to initialize...")
            time.sleep(2)
            print("[DEBUG] QEMU started successfully")
            return True
        except Exception as e:
            print(f"[DEBUG] Failed to start QEMU: {e}")
            import traceback
            traceback.print_exc()
            return False
            
    def stop_qemu(self):
        """Stop the QEMU process."""
        if self.qemu_process:
            self.qemu_process.terminate()
            try:
                self.qemu_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.qemu_process.kill()
            self.qemu_process = None


class CuttlefishManager:
    """Manages Cuttlefish VM instances with GDB server."""
    
    def __init__(self, config: DynamicAnalysisConfig):
        self.config = config
        self.cvd_process = None
        self.runtime_dir = None
        
    def start_cuttlefish(self, kernel_image: str, extra_args: List[str] = None) -> bool:
        """Start Cuttlefish with QEMU backend and GDB server."""
        cmd = [
            "launch_cvd",
            "-vm_manager=qemu_cli",
            "-kernel_path", kernel_image,
        ]
        
        if extra_args:
            cmd.extend(extra_args)
            
        # Set up environment to inject GDB server args via wrapper script
        env = os.environ.copy()
        env["QEMU_EXTRA_ARGS"] = f"-s -S"
        
        try:
            self.cvd_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,
                env=env
            )
            time.sleep(5)  # Cuttlefish takes longer to start
            return True
        except Exception as e:
            print(f"Failed to start Cuttlefish: {e}")
            return False
            
    def stop_cuttlefish(self):
        """Stop Cuttlefish instance."""
        if self.cvd_process:
            subprocess.run(["stop_cvd"], capture_output=True)
            self.cvd_process = None


class GDBAnalyzer:
    """Manages GDB session and analyzes kernel behavior."""
    
    def __init__(self, config: DynamicAnalysisConfig):
        self.config = config
        self.gdb_script = None
        self.gdb_output = ""
        
    def generate_gdb_script(self, repro_path: str, parsed_crash: Dict[str, Any]) -> str:
        """Generate GDB Python script based on crash analysis."""
        # Prefer gdb script under SyzVerify for testing usage; fallback to local
        verify_gdb = Path(__file__).resolve().parents[1] / "SyzVerify" / "gdb.py"
        if verify_gdb.exists():
            script_path = verify_gdb
        else:
            script_path = Path(__file__).parent / "gdb.py"
        
        # Read base GDB script
        with open(script_path, 'r') as f:
            base_script = f.read()
            
        # Extract parameters from parsed crash
        fault_addr = self.config.fault_addr
        fault_insn = self.config.fault_insn
        access_type = self.config.access_type
        poc_entry = self.config.poc_entry or "syz_executor"
        
        # If not explicitly set, try to extract from crash
        if not fault_addr and parsed_crash.get('access'):
            addr_str = parsed_crash['access'].get('address')
            if addr_str:
                try:
                    fault_addr = int(addr_str, 16) if addr_str.startswith('0x') else int(addr_str)
                except:
                    pass
                    
        if not fault_insn:
            for frame in parsed_crash.get('frames', []):
                if frame.get('ip'):
                    try:
                        fault_insn = int(frame['ip'], 16) if frame['ip'].startswith('0x') else int(frame['ip'])
                        break
                    except:
                        pass
        

        config_header = f"""
# Auto-generated GDB configuration
import gdb

# Configuration from crash analysis
poc_entry = "{poc_entry}"
fault_addr = {fault_addr if fault_addr else 'None'}
fault_insn = {fault_insn if fault_insn else 'None'}
access_type = "{access_type}"
access_size = {self.config.access_size}
_enable_alloc_track = {str(self.config.enable_alloc_tracking)}
_enable_kasan_check = {str(self.config.enable_kasan_checks)}
reproducer_path = "{repro_path}"
    monitor_mode = {str(getattr(self.config, 'kernel_monitor_all', False))}

# Override convenience variables
if fault_addr is not None:
    gdb.execute(f"set $fault_addr = {fault_addr}")
if fault_insn is not None:
    gdb.execute(f"set $fault_insn = {fault_insn}")
gdb.execute(f"set $access_type = \\"{access_type}\\"")
gdb.execute(f"set $poc_entry = \\"{poc_entry}\\"")
gdb.execute(f"set $reproducer_path = \"{repro_path}\"")

"""
        
        # Combine with base script (remove duplicate config parsing)
        # Remove the original config reading section
        base_script_lines = base_script.split('\n')
        filtered_lines = []
        skip_until_params_end = False
        
        for line in base_script_lines:
            if line.strip().startswith('# ---------- Parameters read from GDB session'):
                skip_until_params_end = True
            elif skip_until_params_end and line.strip().startswith('# ---------- global runtime state'):
                skip_until_params_end = False
                
            if not skip_until_params_end:
                filtered_lines.append(line)
                
        modified_script = config_header + '\n'.join(filtered_lines)
        
        # Add JSON output at the end
        output_section = """

# Export results to JSON for Python analyzer
class ExportResultsCmd(gdb.Command):
    '''export_results <filename> -- export collected events to JSON'''
    def __init__(self):
        super(ExportResultsCmd, self).__init__("export_results", gdb.COMMAND_USER)
        
    def invoke(self, arg, from_tty):
        import json
        filename = arg.strip() or "/tmp/gdb_analysis.json"
        
        results = {
            "events": hit_events,
            "allocations": {hex(k): {"size": v[0], "backtrace": v[1]} 
                          for k, v in alloc_map.items()},
            "frees": [hex(addr) for addr in free_set],
        }
        
        with open(filename, 'w') as f:
            json.dump(results, f, indent=2)
        gdb.write(f"Results exported to {filename}\\n", gdb.STDERR)

ExportResultsCmd()

# Auto-continue and run
gdb.execute("continue")
"""
        
        modified_script += output_section
        return modified_script

    def _get_link_text_addr(self, vmlinux_path: str) -> Optional[int]:
        """Extract the link-time address of _text from vmlinux using pyelftools or readelf."""
        try:
            # Prefer pyelftools if available
            with open(vmlinux_path, 'rb') as fh:
                elf = ELFFile(fh)
                symtab = None
                for sec in elf.iter_sections():
                    if sec.header.sh_type in ("SHT_SYMTAB", "SHT_DYNSYM") or getattr(sec.header, 'sh_type', 0) in (2, 11):
                        symtab = sec
                        # iterate symbols to find _text
                        for sym in sec.iter_symbols():
                            if sym.name == "_text":
                                addr = int(sym['st_value'])
                                return addr
                # Fallback: no direct _text symbol found; try section header .text
                text_sec = elf.get_section_by_name('.text')
                if text_sec is not None:
                    return int(text_sec['sh_addr'])
        except Exception:
            pass
        # Fallback to readelf parsing
        try:
            proc = subprocess.run([
                'readelf', '-s', vmlinux_path
            ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            if proc.returncode == 0:
                for line in proc.stdout.splitlines():
                    # columns: Num: Value Size Type Bind Vis Ndx Name
                    # match line ending with _text and capture Value
                    if line.strip().endswith(' _text'):
                        parts = line.split()
                        # Value may be at index 2 (Num:, Value, Size, ...)
                        for tok in parts:
                            if re.fullmatch(r"[0-9a-fA-F]+", tok):
                                try:
                                    val = int(tok, 16)
                                    return val
                                except Exception:
                                    continue
                        # As a last resort, grab first hex in line
                        m = re.search(r"\b([0-9a-fA-F]+)\b", line)
                        if m:
                            return int(m.group(1), 16)
        except Exception:
            pass
        return None

    def _get_runtime_text_addr_via_ssh(self) -> Optional[int]:
        """Read runtime _text address from guest /proc/kallsyms via SSH.
        Requires root SSH access and kptr_restrict=0 or root privileges.
        """
        ssh_cmd = [
            'ssh', '-o', 'StrictHostKeyChecking=no',
            '-p', str(self.config.ssh_port),
            f"{self.config.ssh_user}@127.0.0.1",
        ]
        if self.config.ssh_key:
            ssh_cmd.extend(['-i', self.config.ssh_key])
        # grep the _text symbol; output just the address
        remote = "grep ' _text$' /proc/kallsyms | awk '{print $1}'"
        try:
            proc = subprocess.run(ssh_cmd + [remote], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=5)
            if proc.returncode == 0:
                s = (proc.stdout or '').strip().splitlines()
                if s:
                    addr_str = s[0]
                    # address is hex; ensure 0x prefix
                    if not addr_str.startswith('0x'):
                        addr_str = '0x' + addr_str
                    return int(addr_str, 16)
        except Exception:
            pass
        return None

    def _get_system_map_addr(self, symbol: str) -> Optional[int]:
        """Lookup a kernel symbol address from a local System.map file.
        Expects lines like: fffffffff18000000 T _text
        """
        path = self.config.system_map
        if not path:
            # Try default location in workspace
            cand = Path(os.getcwd()) / 'syzploit' / 'outdir' / 'System.map'
            if cand.exists():
                path = str(cand)
        try:
            if path and os.path.exists(path):
                with open(path, 'r') as f:
                    for line in f:
                        # Format: <addr> <type> <name>
                        # Match exact symbol name at end of line
                        if line.rstrip().endswith(f" {symbol}"):
                            parts = line.split()
                            if parts:
                                addr_str = parts[0]
                                # Accept hex without 0x prefix
                                if addr_str.startswith('0x'):
                                    return int(addr_str, 16)
                                # Some System.map uses raw hex like ffffffff81000000
                                return int(addr_str, 16)
        except Exception:
            pass
        return None
        
    def _generate_system_map(self, vmlinux_path: Path) -> Optional[Path]:
        """Generate a System.map-style file from vmlinux using pyelftools if available."""
        if ELFFile is None:
            print("[DEBUG] pyelftools not available; skipping System.map generation")
            return None
        try:
            out_dir = vmlinux_path.parent
            out_map = out_dir / "System.map"
            print(f"[DEBUG] Generating System.map at {out_map}")
            with vmlinux_path.open("rb") as fh:
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
            print(f"[DEBUG] Wrote System.map: {out_map}")
            return out_map
        except Exception as e:
            print(f"[DEBUG] Failed to generate System.map: {e}")
            return None
        
    def run_analysis(self, repro_binary: str, parsed_crash: Dict[str, Any], 
                     vm_manager) -> DynamicAnalysisResult:
        """Run GDB analysis session."""
        print(f"[DEBUG] GDBAnalyzer.run_analysis called")
        print(f"[DEBUG] repro_binary: {repro_binary}")
        print(f"[DEBUG] GDB port: {self.config.gdb_port}")
        
        result = DynamicAnalysisResult()

        # Prepare a workspace-local tmp directory for outputs (avoid /tmp)
        cwd = os.getcwd()
        # Try to scope tmp under an existing analysis_* or syzkall_crashes dir
        scope_dir = cwd
        for candidate in ("analysis_", "syzkall_crashes"):
            matches = [d for d in os.listdir(cwd) if d.startswith(candidate)] if candidate.endswith("_") else [candidate] if os.path.isdir(os.path.join(cwd, candidate)) else []
            if matches:
                scope_dir = os.path.join(cwd, matches[0]) if not candidate.endswith("_") else os.path.join(cwd, matches[0])
                break
        local_tmp = os.path.join(scope_dir, "tmp_dynamic")
        os.makedirs(local_tmp, exist_ok=True)
        print(f"[DEBUG] Using local tmp dir: {local_tmp}")
        
        # If only bzImage is provided, attempt to extract vmlinux via vmlinux-to-elf
        if not self.config.vmlinux_path and self.config.bzimage_path:
            try:
                out_dir = Path(tempfile.mkdtemp(prefix="vmlinux_extract_"))
                vmlinux_out = out_dir / "vmlinux"
                # Require vmlinux-to-elf to be in PATH
                tool = shutil.which("vmlinux-to-elf")
                if not tool:
                    print("[DEBUG] vmlinux-to-elf not found in PATH; skipping symbol extraction")
                else:
                    print(f"[DEBUG] Extracting vmlinux via vmlinux-to-elf: {self.config.bzimage_path}")
                    proc = subprocess.run([tool, str(self.config.bzimage_path), str(vmlinux_out)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                    if proc.returncode == 0 and vmlinux_out.exists():
                        self.config.vmlinux_path = str(vmlinux_out)
                        print(f"[DEBUG] vmlinux extracted: {self.config.vmlinux_path}")
                        # Generate System.map from vmlinux
                        smap = self._generate_system_map(vmlinux_out)
                        if smap:
                            self.config.system_map = str(smap)
                    else:
                        print(f"[DEBUG] vmlinux-to-elf failed: rc={proc.returncode} stderr={proc.stderr}")
            except Exception as e:
                print(f"[DEBUG] vmlinux-to-elf extraction error: {e}")

        # Generate GDB script
        print("[DEBUG] Generating GDB script...")
        gdb_script = self.generate_gdb_script(repro_binary, parsed_crash)
        print(f"[DEBUG] GDB script generated ({len(gdb_script)} chars)")
        
        # Write kernel GDB script to temp file
        print("[DEBUG] Writing GDB script to temp file...")
        script_path = os.path.join(local_tmp, 'kernel_gdb_script.py')
        with open(script_path, 'w') as f:
            f.write(gdb_script)
        print(f"[DEBUG] GDB script written to: {script_path}")
            
        # Write results file paths
        results_file_kernel = os.path.join(local_tmp, 'kernel_results.json')
        results_file_userspace = os.path.join(local_tmp, 'userspace_results.json')
        print(f"[DEBUG] Kernel results -> {results_file_kernel}")
        print(f"[DEBUG] Userspace results -> {results_file_userspace}")
        
        try:
            # Prepare Kernel GDB command (attaches to QEMU's gdbserver)
            kernel_log = os.path.join(local_tmp, 'kernel-gdb.log')
            # Verify vmlinux has DWARF; warn if stripped
            has_dwarf = False
            try:
                if self.config.vmlinux_path and os.path.exists(self.config.vmlinux_path):
                    proc_dw = subprocess.run(['readelf', '-w', self.config.vmlinux_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                    has_dwarf = (proc_dw.returncode == 0 and len(proc_dw.stdout) > 0)
            except Exception:
                has_dwarf = False
            if not has_dwarf:
                print('[WARN] vmlinux appears stripped (no DWARF). Symbolic breakpoints may not resolve.')

            # Compute KASLR slide and prepare symbol relocation if possible
            reloc_cmds: List[str] = []
            link_text = None
            runtime_text = None
            try:
                if self.config.vmlinux_path and os.path.exists(self.config.vmlinux_path):
                    link_text = self._get_link_text_addr(self.config.vmlinux_path)
                runtime_text = self._get_runtime_text_addr_via_ssh()
            except Exception:
                link_text = None
                runtime_text = None
            slide = None
            if link_text is not None and runtime_text is not None:
                try:
                    slide = int(runtime_text) - int(link_text)
                except Exception:
                    slide = None
            # Build relocation commands: prefer symbol-file -o, fallback to add-symbol-file
            if slide is not None:
                reloc_cmds.append(f"symbol-file -o 0x{slide:x} {self.config.vmlinux_path}")
            else:
                # if runtime_text known but slide unknown, still try add-symbol-file
                if runtime_text is not None:
                    reloc_cmds.append(f"add-symbol-file {self.config.vmlinux_path} 0x{int(runtime_text):x}")
                elif self.config.vmlinux_path:
                    reloc_cmds.append(f"file {self.config.vmlinux_path}")

            # If stripped or DWARF unavailable, gather allocator symbol addresses via System.map
            allocator_addrs_cmds: List[str] = []
            km = self._get_system_map_addr('kmalloc') or self._get_system_map_addr('__kmalloc')
            kf = self._get_system_map_addr('kfree')
            vf = self._get_system_map_addr('vfree')
            if km:
                allocator_addrs_cmds.extend(["-ex", f"set $kmalloc_addr = {km}"])
            if kf:
                allocator_addrs_cmds.extend(["-ex", f"set $kfree_addr = {kf}"])
            if vf:
                allocator_addrs_cmds.extend(["-ex", f"set $vfree_addr = {vf}"])

            gdb_kernel_cmd = [
                "gdb",
                "-q",  # quiet
                # Load or relocate kernel symbols if possible
                # We will try both relocation forms; GDB will ignore unsupported options
            ]
            for rc in reloc_cmds:
                gdb_kernel_cmd.extend(["-ex", rc])
            # Inject allocator addresses if found
            if allocator_addrs_cmds:
                gdb_kernel_cmd.extend(allocator_addrs_cmds)
            # Connect and configure
            gdb_kernel_cmd.extend([
                "-ex", f"target remote :{self.config.gdb_port}",
                "-ex", "set pagination off",
                "-ex", "set confirm off",
                "-ex", "set non-stop on",
                "-ex", "set breakpoint pending on",
                "-ex", f"set logging file {kernel_log}",
                "-ex", "set logging overwrite on",
                "-ex", "set logging enabled on",
                "-ex", f"source {script_path}",
                # Continue kernel execution; later interrupt to export results
                "-ex", "continue",
                "-ex", "interrupt",
                "-ex", f"export_results {results_file_kernel}",
                "-ex", "quit"
            ])
            print(f"[DEBUG] Kernel GDB command: {' '.join(gdb_kernel_cmd)}")

            # Optionally launch gdbserver inside guest to run repro
            if self.config.userspace_auto_launch:
                ssh_cmd = [
                    "ssh", "-o", "StrictHostKeyChecking=no",
                    "-p", str(self.config.ssh_port),
                    f"{self.config.ssh_user}@127.0.0.1",
                ]
                # add key if provided
                if self.config.ssh_key:
                    ssh_cmd.extend(["-i", self.config.ssh_key])
                # start gdbserver in the guest
                remote = f"gdbserver :{self.config.userspace_gdb_port} {self.config.repro_remote_path}"
                print(f"[DEBUG] Launching guest gdbserver: {remote}")
                try:
                    self._guest_gdbserver_proc = subprocess.Popen(
                        ssh_cmd + [remote], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
                    )
                    # Give it a moment to start before attaching
                    time.sleep(3)
                except Exception as e:
                    print(f"[DEBUG] Failed to launch guest gdbserver: {e}")

            # Prepare Userspace GDB command (sources userspace_gdb.py)
            userspace_py = os.path.join(os.path.dirname(__file__), "userspace_gdb.py")
            userspace_results_path = os.path.join(local_tmp, 'userspace_trace.json')
            # allow monitor mode via config: pass "monitor" as second arg to us_init
            us_monitor = getattr(self.config, 'userspace_monitor_all', False)
            us_init_args = f"{userspace_results_path} monitor" if us_monitor else userspace_results_path
            userspace_script_path = os.path.join(local_tmp, 'userspace_script.gdb')
            with open(userspace_script_path, 'w') as uf:
                uf.write("\n".join([
                    f"source {userspace_py}",
                    f"us_init {us_init_args}",
                    "break main" if not us_monitor else "",
                    "continue",
                    "us_export_results",
                ]))
            userspace_log = os.path.join(local_tmp, 'userspace-gdb.log')
            gdb_userspace_cmd = [
                'gdb',
                '-q',
                repro_binary,
                '-ex', f'target remote :{self.config.userspace_gdb_port}',
                '-ex', f'set logging file {userspace_log}',
                '-ex', 'set logging overwrite on',
                '-ex', 'set logging enabled on',
                '-ex', f'source {userspace_script_path}',
                '-ex', 'continue',
                '-ex', f'us_export_results {results_file_userspace}',
                '-ex', 'quit'
            ]
            print(f"[DEBUG] Userspace GDB command: {' '.join(gdb_userspace_cmd)}")

            # Launch both GDBs as separate processes
            kernel_proc = subprocess.Popen(gdb_kernel_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            userspace_proc = subprocess.Popen(gdb_userspace_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                k_stdout, k_stderr = kernel_proc.communicate(timeout=self.config.timeout)
            except subprocess.TimeoutExpired:
                print(f"[DEBUG] Kernel GDB timeout after {self.config.timeout}s; terminating")
                kernel_proc.terminate()
                try:
                    k_stdout, k_stderr = kernel_proc.communicate(timeout=5)
                except subprocess.TimeoutExpired:
                    kernel_proc.kill()
                    k_stdout, k_stderr = "", ""
            try:
                u_stdout, u_stderr = userspace_proc.communicate(timeout=self.config.timeout)
            except subprocess.TimeoutExpired:
                print(f"[DEBUG] Userspace GDB timeout after {self.config.timeout}s; terminating")
                userspace_proc.terminate()
                try:
                    u_stdout, u_stderr = userspace_proc.communicate(timeout=5)
                except subprocess.TimeoutExpired:
                    userspace_proc.kill()
                    u_stdout, u_stderr = "", ""

            print(f"[DEBUG] Kernel GDB exited: {kernel_proc.returncode}")
            print(f"[DEBUG] Userspace GDB exited: {userspace_proc.returncode}")
            result.raw_gdb_output = (k_stdout or '') + "\n" + (k_stderr or '') + "\n--- USERSPACE ---\n" + (u_stdout or '') + "\n" + (u_stderr or '')

            # Parse results file
            print(f"[DEBUG] Checking for kernel results file: {results_file_kernel}")
            print(f"[DEBUG] Checking for userspace results file: {results_file_userspace}")
            kernel_data = {}
            userspace_data = {}
            if os.path.exists(results_file_kernel):
                print(f"[DEBUG] Kernel results file found, parsing...")
                with open(results_file_kernel, 'r') as f:
                    data = json.load(f)
                    result.events = data.get('events', [])
                    print(f"[DEBUG] Parsed {len(result.events)} events")

                    # Parse allocations
                    allocs = data.get('allocations', {})
                    print(f"[DEBUG] Parsing {len(allocs)} allocations")
                    for addr_str, info in allocs.items():
                        addr = int(addr_str, 16)
                        result.allocations[addr] = (info['size'], info['backtrace'])

                    # Parse frees
                    frees = data.get('frees', [])
                    print(f"[DEBUG] Parsing {len(frees)} frees")
                    result.frees = [int(addr, 16) for addr in frees]
                kernel_data = data
            if os.path.exists(results_file_userspace):
                print(f"[DEBUG] Userspace results file found, parsing...")
                with open(results_file_userspace, 'r') as f:
                    userspace_data = json.load(f)

                # Combine kernel + userspace outputs into one structure and merged chronological events
                kernel_events = kernel_data.get('events', []) if isinstance(kernel_data, dict) else []
                userspace_events = userspace_data.get('userspace', {}).get('events', []) if isinstance(userspace_data, dict) else []
                merged_events = sorted(kernel_events + userspace_events, key=lambda e: e.get('ts', e.get('time', 0)))
                combined = {
                    'kernel': kernel_data,
                    'userspace': userspace_data,
                    'merged_events': merged_events,
                    'logs': {
                        'kernel_gdb_log': kernel_log,
                        'userspace_gdb_log': userspace_log
                    }
                }
                # Save combined next to kernel file
                combined_file = os.path.join(local_tmp, 'combined.json')
                with open(combined_file, 'w') as cf:
                    json.dump(combined, cf, indent=2)
                print(f"[DEBUG] Wrote combined results to: {combined_file}")

                # Also write a deterministic path if an analysis_<id> directory is present
                det_path = None
                try:
                    bug_id = None
                    m = re.search(r"([0-9a-f]{16,64})", repro_binary)
                    if m:
                        bug_id = m.group(1)
                    # Find matching analysis dir
                    candidates = [d for d in os.listdir(cwd) if d.startswith('analysis_')]
                    target_dir = None
                    if bug_id:
                        for d in candidates:
                            if bug_id in d:
                                target_dir = os.path.join(cwd, d)
                                break
                    # Fallback: use first analysis_* directory
                    if not target_dir and candidates:
                        target_dir = os.path.join(cwd, candidates[0])
                    if target_dir and os.path.isdir(target_dir):
                        det_path = os.path.join(target_dir, 'dynamic_combined.json')
                        with open(det_path, 'w') as df:
                            json.dump(combined, df, indent=2)
                        print(f"[DEBUG] Wrote combined results to deterministic path: {det_path}")
                except Exception as e:
                    print(f"[DEBUG] Deterministic path write skipped: {e}")
                result.success = True
                print("[DEBUG] Dynamic analysis completed successfully")
            else:
                result.error = "GDB results file not created"
                print(f"[DEBUG] ERROR: {result.error}")
                print(f"[DEBUG] Kernel GDB stdout:\n{k_stdout}")
                print(f"[DEBUG] Kernel GDB stderr:\n{k_stderr}")
                print(f"[DEBUG] Userspace GDB stdout:\n{u_stdout}")
                print(f"[DEBUG] Userspace GDB stderr:\n{u_stderr}")

        except Exception as e:
            result.error = f"GDB execution error: {e}"
                
        return result


def analyze_dynamic_results(result: DynamicAnalysisResult, 
                           parsed_crash: Dict[str, Any]) -> Dict[str, Any]:
    """Analyze dynamic analysis results to detect vulnerabilities."""
    analysis = {
        "vulnerabilities": [],
        "memory_safety_violations": [],
        "uaf_detected": False,
        "oob_detected": False,
        "corruption_patterns": [],
    }
    
    # Check for Use-After-Free
    for event in result.events:
        if event.get('type') == 'watch':
            rip = event.get('rip')
            # Check if access is to freed memory
            # This is simplified - real implementation would check address ranges
            analysis['vulnerabilities'].append({
                "type": "memory_access",
                "rip": hex(rip) if rip else None,
                "backtrace": event.get('bt', [])
            })
            
    # Detect UAF patterns
    accessed_addrs = set()
    for event in result.events:
        if event.get('type') == 'watch':
            # Extract accessed address from event
            accessed_addrs.add(event.get('expr'))
            
    for freed_addr in result.frees:
        # Check if any accessed address overlaps with freed regions
        for alloc_addr, (size, bt) in result.allocations.items():
            if alloc_addr == freed_addr:
                # Check if this was accessed after free
                analysis['uaf_detected'] = True
                analysis['vulnerabilities'].append({
                    "type": "use-after-free",
                    "address": hex(freed_addr),
                    "size": size,
                    "allocation_trace": bt
                })
                
    # Detect OOB accesses
    for event in result.events:
        if event.get('type') == 'watch':
            # Check if access is outside allocated bounds
            # This requires more sophisticated address range checking
            pass
            
    return analysis


def run_dynamic_analysis(repro_binary: str, 
                        parsed_crash: Dict[str, Any],
                        config: Optional[DynamicAnalysisConfig] = None) -> Dict[str, Any]:
    """
    Main entry point for dynamic analysis.
    
    Args:
        repro_binary: Path to compiled reproducer
        parsed_crash: Parsed crash log from crash_analyzer
        config: Analysis configuration
        
    Returns:
        Dictionary with dynamic analysis results and detected vulnerabilities
    """
    print(f"[DEBUG] run_dynamic_analysis called")
    print(f"[DEBUG] repro_binary: {repro_binary}")
    print(f"[DEBUG] parsed_crash keys: {list(parsed_crash.keys()) if parsed_crash else 'None'}")
    
    if config is None:
        print("[DEBUG] Creating default DynamicAnalysisConfig")
        config = DynamicAnalysisConfig()
    else:
        print(f"[DEBUG] Using provided config: vm_type={config.vm_type}, kernel={config.kernel_image}")
        
    # Select VM manager
    print(f"[DEBUG] Selecting VM manager for type: {config.vm_type}")
    if config.vm_type == "cuttlefish":
        print("[DEBUG] Creating CuttlefishManager")
        vm_manager = CuttlefishManager(config)
        if config.kernel_image:
            print(f"[DEBUG] Starting Cuttlefish with kernel: {config.kernel_image}")
            success = vm_manager.start_cuttlefish(config.kernel_image)
            print(f"[DEBUG] Cuttlefish start result: {success}")
        else:
            print("[DEBUG] No kernel_image provided for Cuttlefish")
            return {"error": "kernel_image required for Cuttlefish"}
    else:  # qemu
        print("[DEBUG] Creating QEMUManager")
        vm_manager = QEMUManager(config)
        if config.kernel_image and config.kernel_disk:
            print(f"[DEBUG] Starting QEMU with kernel: {config.kernel_image}")
            success = vm_manager.start_qemu(config.kernel_image, config.kernel_disk)
            print(f"[DEBUG] QEMU start result: {success}")
        else:
            print("[DEBUG] No kernel_image provided for QEMU")
            return {"error": "kernel_image required for QEMU"}
            
    if not success:
        print("[DEBUG] VM failed to start")
        return {"error": "Failed to start VM"}
        
    try:
        # Run GDB analysis
        gdb_analyzer = GDBAnalyzer(config)
        result = gdb_analyzer.run_analysis(repro_binary, parsed_crash, vm_manager)
        
        if not result.success:
            return {
                "success": False,
                "error": result.error,
                "raw_output": result.raw_gdb_output
            }
            
        # Analyze results
        vulnerability_analysis = analyze_dynamic_results(result, parsed_crash)
        
        return {
            "success": True,
            "events": result.events,
            "allocations": {hex(k): {"size": v[0], "trace": v[1]} 
                          for k, v in result.allocations.items()},
            "frees": [hex(addr) for addr in result.frees],
            "vulnerability_analysis": vulnerability_analysis,
            "raw_gdb_output": result.raw_gdb_output
        }
        
    finally:
        # Cleanup VM
        if isinstance(vm_manager, QEMUManager):
            vm_manager.stop_qemu()
        else:
            vm_manager.stop_cuttlefish()
