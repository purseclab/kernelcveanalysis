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
import socket
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
    gdbserver_path: str = "/workspace/syzploit/gdbserver_x86_64"  # path to gdbserver in guest
    access_type: str = "any"  # read, write, any
    access_size: int = 0
    poc_entry: Optional[str] = None
    # Optional: bzImage path to extract vmlinux via vmlinux-to-elf
    bzimage_path: Optional[str] = None
    # Resolved vmlinux extracted path (auto-populated)
    vmlinux_path: Optional[str] = None
    system_map: Optional[str] = None  # Optional: system map file for symbol resolution
    # Optional: auto-interrupt delay after continue (seconds)
    continue_delay: int = 60
    # Userspace instrumentation config
    userspace_gdb_port: int = 2345
    userspace_auto_launch: bool = True
    ssh_port: int = 10021  # forwarded host port to guest ssh
    ssh_user: str = "root"
    ssh_key: Optional[str] = None  # path to private key; None uses agent/default
    repro_remote_path: str = "/root/repro"  # path inside guest to run under gdbserver
    # Host-side path to a gdbserver binary to upload if missing in guest
    host_gdbserver_path: Optional[str] = "/workspace/syzploit/gdbserver_x86_64"
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
    # Preferred local scope directory for tmp outputs (e.g., analysis_<bug_id>)
    tmp_scope_dir: Optional[str] = None


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

    def _wait_for_port(self, host: str, port: int, timeout: int = 30) -> bool:
        """Wait until a TCP port is accepting connections."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                with socket.create_connection((host, port), timeout=1):
                    return True
            except Exception:
                time.sleep(0.5)
        return False
        
    def start_qemu(self, kernel_image: str, kernel_disk: Optional[str] = None,
                   extra_args: List[str] = None) -> bool:
        """Start QEMU with GDB server enabled."""
        print(f"[DEBUG] QEMUManager.start_qemu called")
        print(f"[DEBUG] kernel_image: {kernel_image}")
        print(f"[DEBUG] kernel_image exists: {os.path.exists(kernel_image)}")
        print(f"[DEBUG] initrd: {kernel_disk}")

        # Ensure 9p share path exists to avoid QEMU errors
        try:
            os.makedirs('/tmp/qemu-share', exist_ok=True)
        except Exception:
            pass

        cmd = [
            "qemu-system-x86_64",
            "-m", "2G",
            "-smp", "2",
            "-kernel", str(kernel_image),
            "-append", "console=ttyS0 root=/dev/vda1 earlyprintk=serial net.ifnames=0 nokaslr",
            "-drive", f"file={str(kernel_disk)},format=raw,if=virtio",
            "-netdev", f"user,id=net0,host=10.0.2.10,hostfwd=tcp:127.0.0.1:{self.config.ssh_port}-:22,hostfwd=tcp:127.0.0.1:{self.config.userspace_gdb_port}-:{self.config.userspace_gdb_port}",
            "-device", "virtio-net-pci,netdev=net0",
            "-virtfs", "local,path=/tmp/qemu-share,security_model=none,mount_tag=hostshare",
            "-enable-kvm",
            "-nographic",
            "-s",
            "-S"
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
            print("[DEBUG] Waiting for QEMU gdb stub on 127.0.0.1:{}...".format(self.config.gdb_port))
            if not self._wait_for_port('127.0.0.1', self.config.gdb_port, timeout=30):
                print("[DEBUG] QEMU gdb stub not ready within timeout")
                return False
            print("[DEBUG] QEMU gdb stub is ready")
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
            
        env = os.environ.copy()
        env["QEMU_EXTRA_ARGS"] = "-s -S"
        
        try:
            self.cvd_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,
                env=env
            )
            time.sleep(5)
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
        # Preferred gdbserver path in guest (set by _ensure_guest_gdbserver)
        self._guest_gdbserver_path = "gdbserver"

    def _get_guest_time(self, attempts: int = 240, delay: float = 0.5, cmd_timeout: int = 5) -> Optional[float]:
        """Return guest wall-clock time via SSH `date +%s.%N` with retries.
        Attempts up to `attempts` times, waiting `delay` seconds between tries.
        """
        ssh_cmd = [
            "ssh",
            "-o", "StrictHostKeyChecking=no",
            "-o", "BatchMode=yes",
            "-o", "ConnectTimeout=2",
            "-p", str(self.config.ssh_port),
            f"{self.config.ssh_user}@127.0.0.1",
        ]
        if self.config.ssh_key:
            ssh_cmd.extend(["-i", self.config.ssh_key])
        for _ in range(max(1, attempts)):
            try:
                # Quick port readiness check to avoid long SSH delays
                try:
                    with socket.create_connection(("127.0.0.1", self.config.ssh_port), timeout=1):
                        pass
                except Exception:
                    time.sleep(delay)
                    continue
                proc = subprocess.run(ssh_cmd + ["date +%s.%N"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=cmd_timeout)
                if proc.returncode == 0:
                    out = (proc.stdout or "").strip()
                    try:
                        return float(out)
                    except Exception:
                        # Some shells may not support %N; fall back to seconds only
                        try:
                            sec_only = subprocess.run(ssh_cmd + ["date +%s"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=cmd_timeout)
                            if sec_only.returncode == 0:
                                return float((sec_only.stdout or "").strip())
                        except Exception:
                            pass
                # Retry on failure
            except Exception:
                pass
            time.sleep(delay)
        return None

    def _repo_root(self) -> Path:
        """Best-effort to locate the workspace root (repo root)."""
        # dynamic.py -> .../src/syzploit/SyzVerify/dynamic.py
        # Repo root is parents[3] of this file path
        p = Path(__file__).resolve()
        # Guard against shallow paths
        return p.parents[3] if len(p.parents) >= 4 else p.parents[-1]

    def _detect_guest_arch(self, ssh_base: List[str]) -> Optional[str]:
        """Return guest architecture via `uname -m` (e.g., x86_64, aarch64)."""
        try:
            proc = subprocess.run(ssh_base + ["uname -m"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=10)
            if proc.returncode == 0:
                arch = (proc.stdout or "").strip()
                return arch if arch else None
        except Exception:
            pass
        return None

    def _find_bundled_gdbserver(self, guest_arch: str) -> Optional[str]:
        """Find a bundled gdbserver binary in the repo for the given arch.
        Returns an absolute path or None if not found.
        """
        root = self._repo_root()
        candidates: List[Path] = []
        # Common naming patterns in repo root
        if guest_arch in ("x86_64", "amd64"):
            candidates += [
                root / "gdbserver_x86_64",
                root / "gdbserver-amd64",
                root / "gdbserver_amd64",
            ]
        if guest_arch in ("aarch64", "arm64"):
            candidates += [
                root / "gdbserver_arm64",
                root / "gdbserver-aarch64",
                root / "gdbserver_aarch64",
            ]
        # Also check a common folder if present
        extra_dir = root / "gdb-static"
        if extra_dir.exists():
            if guest_arch in ("x86_64", "amd64"):
                candidates += list(extra_dir.glob("*x86_64*"))
            if guest_arch in ("aarch64", "arm64"):
                candidates += list(extra_dir.glob("*aarch64*")) + list(extra_dir.glob("*arm64*"))

        for c in candidates:
            try:
                if c.exists() and c.is_file():
                    return str(c)
            except Exception:
                continue
        return None

    def _ensure_guest_gdbserver(self) -> bool:
        """Ensure gdbserver exists in the guest; upload via scp if missing.
        Returns True if available after the operation, False otherwise.
        """
        ssh_base = [
            "ssh", "-o", "StrictHostKeyChecking=no",
            "-p", str(self.config.ssh_port),
            f"{self.config.ssh_user}@127.0.0.1",
        ]
        if self.config.ssh_key:
            ssh_base.extend(["-i", self.config.ssh_key])
        try:
            # Wait up to 120s for SSH service to become available in guest
            try:
                deadline = time.time() + 120
                while time.time() < deadline:
                    try:
                        with socket.create_connection(("127.0.0.1", self.config.ssh_port), timeout=2):
                            break
                    except Exception:
                        time.sleep(1)
            except Exception:
                pass
            # Check presence: either in PATH or at /root/gdbserver
            chk = subprocess.run(ssh_base + ["command -v gdbserver || true"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=30)
            in_path = (chk.returncode == 0 and "gdbserver" in (chk.stdout or ""))
            if in_path:
                self._guest_gdbserver_path = "gdbserver"
                print("[DEBUG] gdbserver already present in guest PATH")
                return True
            # Alternatively check uploaded location
            chk_alt = subprocess.run(ssh_base + ["test -x /root/gdbserver && echo OK || true"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=30)
            if "OK" in (chk_alt.stdout or ""):
                self._guest_gdbserver_path = "/root/gdbserver"
                print("[DEBUG] Found existing /root/gdbserver in guest")
                return True
            print("[DEBUG] gdbserver not found in guest; attempting upload via scp")
            # Detect guest arch to select the appropriate bundled gdbserver
            guest_arch = self._detect_guest_arch(ssh_base) or "x86_64"
            print(f"[DEBUG] Detected guest arch: {guest_arch}")
            # Determine host gdbserver path (priority: explicit -> bundled -> system which)
            host_path: Optional[str] = self.config.host_gdbserver_path
            if not host_path:
                host_path = self._find_bundled_gdbserver(guest_arch)
            if not host_path:
                host_path = shutil.which("gdbserver")
            if not host_path or not os.path.exists(host_path):
                print("[DEBUG] Host gdbserver not found; install gdbserver on host or provide host_gdbserver_path")
                return False
            # Prefer statically linked and matching arch; warn if not static but still proceed
            try:
                fi = subprocess.run(["file", host_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                finfo = fi.stdout.lower() if fi.returncode == 0 else ""
                is_static = ("statically linked" in finfo)
                arch_ok = False
                if guest_arch in ("x86_64", "amd64"):
                    arch_ok = ("x86-64" in finfo or "x86_64" in finfo)
                elif guest_arch in ("aarch64", "arm64"):
                    arch_ok = ("aarch64" in finfo or "arm aarch64" in finfo or "arm64" in finfo)
                if not arch_ok:
                    print(f"[DEBUG] Host gdbserver architecture mismatch for guest={guest_arch}; skipping userspace attach")
                    return False
                if not is_static:
                    print("[WARN] Host gdbserver is dynamically linked; proceeding but may fail if libs missing in guest")
            except Exception:
                pass
            # Upload to /root/gdbserver
            scp_cmd = [
                "scp", "-o", "StrictHostKeyChecking=no",
                "-o", "PasswordAuthentication=no",
                "-o", "PreferredAuthentications=publickey",
                "-P", str(self.config.ssh_port),
            ]
            if self.config.ssh_key:
                scp_cmd.extend(["-i", self.config.ssh_key])
            scp_cmd.extend([host_path, f"{self.config.ssh_user}@127.0.0.1:/root/gdbserver"])
            # Ensure destination directory exists
            # subprocess.run(ssh_base, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            up = subprocess.run(scp_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=60)
            if up.returncode != 0:
                print(f"[DEBUG] scp upload failed: rc={up.returncode} stderr={up.stderr}")
                return False
            # chmod +x
            subprocess.run(ssh_base + ["chmod +x /root/gdbserver"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            # Verify uploaded binary exists and is executable
            chk2 = subprocess.run(ssh_base + ["test -x /root/gdbserver && echo OK || true"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=30)
            ok = ("OK" in (chk2.stdout or ""))
            if ok:
                self._guest_gdbserver_path = "/root/gdbserver"
            print(f"[DEBUG] gdbserver upload verification (/root/gdbserver): {ok}")
            return ok
        except Exception as e:
            print(f"[DEBUG] _ensure_guest_gdbserver error: {e}")
            return False
        
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

# Guest SSH config for guest-clock timestamping from GDB side
guest_ssh_port = {int(self.config.ssh_port)}
guest_ssh_user = "{self.config.ssh_user}"
guest_ssh_key = {f'"{self.config.ssh_key}"' if self.config.ssh_key else 'None'}

# Override convenience variables
if fault_addr is not None:
    gdb.execute(f"set $fault_addr = {{fault_addr}}")
if fault_insn is not None:
    gdb.execute(f"set $fault_insn = {{fault_insn}}")
gdb.execute(f'set $access_type = "{{access_type}}"')
gdb.execute(f'set $poc_entry = "{{poc_entry}}"')
gdb.execute(f'set $reproducer_path = "{{reproducer_path}}"')
gdb.execute(f'set $guest_ssh_port = {{guest_ssh_port}}')
gdb.execute(f'set $guest_ssh_user = "{{guest_ssh_user}}"')

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
        
        # Do not inject a duplicate ExportResultsCmd; gdb.py already defines it with detailed fields.
        # Auto-continue and run using safe continue to handle breakpoint insertion errors
        output_section = """
# Use syz_safe_continue command if available, otherwise fallback to regular continue with error handling
try:
    gdb.execute("syz_safe_continue")
except gdb.error as e:
    # Fallback: syz_safe_continue might not exist yet on first source
    try:
        gdb.execute("continue")
    except gdb.error as e2:
        gdb.write("[WARN] continue failed: %s\\n" % e2, gdb.STDERR)
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
        # Prefer a caller-provided scope directory (analysis_<bug_id>)
        scope_dir = self.config.tmp_scope_dir or os.getcwd()
        # If not provided, try to scope under an existing analysis_* or syzkall_crashes dir
        if not self.config.tmp_scope_dir:
            cwd = os.getcwd()
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

        # Prepare kernel GDB config JSON for late variable setting
        kernel_conf_path = os.path.join(local_tmp, 'kernel_gdb_config.json')
        try:
            # Resolve fault_addr/fault_insn/access_type similarly to generate_gdb_script
            fault_addr_val = self.config.fault_addr
            fault_insn_val = self.config.fault_insn
            access_type_val = self.config.access_type
            # If not explicitly set, try to extract from crash
            if not fault_addr_val and parsed_crash.get('access'):
                addr_str = parsed_crash['access'].get('address')
                if addr_str:
                    try:
                        fault_addr_val = int(addr_str, 16) if addr_str.startswith('0x') else int(addr_str)
                    except Exception:
                        pass
            if not fault_insn_val:
                for frame in parsed_crash.get('frames', []):
                    if frame.get('ip'):
                        try:
                            ip = frame['ip']
                            fault_insn_val = int(ip, 16) if isinstance(ip, str) and ip.startswith('0x') else int(ip)
                            break
                        except Exception:
                            continue
            cfg = {
                "poc_entry": self.config.poc_entry or "syz_executor",
                "fault_addr": fault_addr_val if fault_addr_val is not None else None,
                "fault_insn": fault_insn_val if fault_insn_val is not None else None,
                "access_type": access_type_val,
                "access_size": int(self.config.access_size or 0),
                "monitor_mode": bool(getattr(self.config, 'kernel_monitor_all', False)),
                "reproducer_path": str(repro_binary),
                "guest_ssh_port": int(self.config.ssh_port),
                "guest_ssh_user": str(self.config.ssh_user),
                "guest_ssh_key": str(self.config.ssh_key) if self.config.ssh_key else None,
            }
            with open(kernel_conf_path, 'w') as cf:
                json.dump(cfg, cf, indent=2)
            print(f"[DEBUG] Wrote kernel GDB config JSON: {kernel_conf_path}")
        except Exception as e:
            print(f"[DEBUG] Failed to write kernel GDB config JSON: {e}")
        
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
                # Configure logging and behavior first
                "-ex", f"set logging file {kernel_log}",
                "-ex", "set logging overwrite on",
                "-ex", "set logging enabled on",
                "-ex", "set pagination off",
                "-ex", "set confirm off",
                # Ensure non-stop is off (QEMU stub often lacks support)
                "-ex", "set non-stop off",
                "-ex", "set breakpoint pending on",
                # Pre-bind convenience variables (doesn't require target to be stopped)
                "-ex", f"set $poc_entry = \"{self.config.poc_entry or 'syz_executor'}\"",
                "-ex", f"set $access_type = \"{access_type_val}\"",
                "-ex", f"set $access_size = {int(self.config.access_size or 0)}",
                "-ex", f"set $reproducer_path = \"{repro_binary}\"",
                "-ex", f"set $export_path = \"{results_file_kernel}\"",
                # Attach to QEMU gdbstub
                "-ex", "set tcp connect-timeout 30",
                "-ex", f"target remote :{self.config.gdb_port}",
                # Ensure a clean stop before sourcing
                "-ex", "interrupt",
                "-ex", "python import time; time.sleep(1)",
                # Source instrumentation script before letting kernel run, so commands available
                "-ex", f"source {script_path}",
                # Late variable binding from JSON after script is sourced (skips if file doesn't exist)
                "-ex", f"syz_load_config {kernel_conf_path}",
                # Also directly set numeric convenience vars in case JSON failed
                "-ex", (f"set $fault_addr = {fault_addr_val}" if fault_addr_val is not None else "python pass"),
                "-ex", (f"set $fault_insn = {fault_insn_val}" if fault_insn_val is not None else "python pass"),
                # Let the kernel boot so virtual memory is set up with instrumentation active
                # Use syz_safe_continue to handle breakpoint insertion errors gracefully
                "-ex", "syz_safe_continue"
            ])
            print(f"[DEBUG] Kernel GDB command: {' '.join(gdb_kernel_cmd)}")

            # Removed ad-hoc scp copy; rely on _ensure_guest_gdbserver() for provisioning


            # Prepare guest userspace gdbserver launch, but start it AFTER kernel instrumentation begins
            ssh_cmd = [
                "ssh", "-o", "StrictHostKeyChecking=no",
                "-p", str(self.config.ssh_port),
                f"{self.config.ssh_user}@127.0.0.1",
            ]
            if self.config.ssh_key:
                ssh_cmd.extend(["-i", self.config.ssh_key])
            remote_cmd = f"{self._guest_gdbserver_path} :{self.config.userspace_gdb_port} {self.config.repro_remote_path}"
            userspace_ready = False
            primitive_ran = False
            primitive_stdout, primitive_stderr = "", ""

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
                    "us_try_break main" if not us_monitor else "",
                    "python import time; time.sleep(1)",
                    "us_maybe_continue",
                    "us_export_results",
                ]))
            userspace_log = os.path.join(local_tmp, 'userspace-gdb.log')
            gdb_userspace_cmd = [
                'gdb',
                '-q',
                repro_binary,
                '-ex', f'set logging file {userspace_log}',
                '-ex', 'set logging overwrite on',
                '-ex', 'set logging enabled on',
                '-ex', 'set pagination off',
                '-ex', 'set confirm off',
                '-ex', 'set non-stop off',
                '-ex', f'target remote :{self.config.userspace_gdb_port}',
                '-ex', f'source {userspace_script_path}',
                '-ex', f'us_export_results {results_file_userspace}',
                '-ex', 'quit'
            ]
            print(f"[DEBUG] Userspace GDB command: {' '.join(gdb_userspace_cmd)}")

            # Launch kernel GDB first to install instrumentation (async)
            kernel_proc = subprocess.Popen(
                gdb_kernel_cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                text=True
            )
            # Wait a short period to allow kernel GDB to execute initial commands (source script)
            time.sleep(3)
            # Optionally launch gdbserver inside guest to run repro
            primitive_start_ts = None
            if self.config.userspace_auto_launch:
                if not self._ensure_guest_gdbserver():
                    print("[DEBUG] Userspace gdbserver unavailable; executing primitive directly")
                    try:
                        # Capture start just before launching primitive directly
                        primitive_start_ts = self._get_guest_time()
                        prim = subprocess.Popen(
                            ssh_cmd + [self.config.repro_remote_path],
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            text=True
                        )
                        primitive_stdout, primitive_stderr = prim.communicate(timeout=self.config.timeout)
                        primitive_ran = True
                    except subprocess.TimeoutExpired:
                        print(f"[DEBUG] Primitive execution timeout after {self.config.timeout}s; terminating")
                        try:
                            prim.terminate()
                            primitive_stdout, primitive_stderr = prim.communicate(timeout=5)
                        except Exception:
                            try:
                                prim.kill()
                            except Exception:
                                pass
                            primitive_stdout, primitive_stderr = "", ""
                    except Exception as e:
                        print(f"[DEBUG] Failed to execute primitive directly: {e}")
                else:
                    print(f"[DEBUG] Launching guest gdbserver: {remote_cmd}")
                    try:
                        # Capture start just before launching gdbserver
                        primitive_start_ts = self._get_guest_time()
                        self._guest_gdbserver_proc = subprocess.Popen(
                            ssh_cmd + [remote_cmd], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
                        )
                        print(f"[DEBUG] Waiting for userspace gdbserver on 127.0.0.1:{self.config.userspace_gdb_port}...")
                        deadline = time.time() + 60
                        while time.time() < deadline:
                            try:
                                with socket.create_connection(("127.0.0.1", self.config.userspace_gdb_port), timeout=1):
                                    userspace_ready = True
                                    break
                            except Exception:
                                time.sleep(0.5)
                        # Fallback: run primitive if gdbserver port didn't open
                        if not userspace_ready:
                            print("[DEBUG] gdbserver port not ready; executing primitive directly")
                            try:
                                # Re-capture start for direct exec to tighten window
                                primitive_start_ts = self._get_guest_time()
                                prim = subprocess.Popen(
                                    ssh_cmd + [self.config.repro_remote_path],
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE,
                                    text=True
                                )
                                primitive_stdout, primitive_stderr = prim.communicate(timeout=self.config.timeout)
                                primitive_ran = True
                            except subprocess.TimeoutExpired:
                                print(f"[DEBUG] Primitive execution timeout after {self.config.timeout}s; terminating")
                                try:
                                    prim.terminate()
                                    primitive_stdout, primitive_stderr = prim.communicate(timeout=5)
                                except Exception:
                                    try:
                                        prim.kill()
                                    except Exception:
                                        pass
                                    primitive_stdout, primitive_stderr = "", ""
                    except Exception as e:
                        print(f"[DEBUG] Failed to execute primitive directly: {e}")

            # Only run userspace GDB if gdbserver became ready
            userspace_proc = None
            if self.config.userspace_auto_launch and userspace_ready:
                userspace_proc = subprocess.Popen(gdb_userspace_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            # Run userspace synchronously; finalize kernel afterwards
            u_stdout, u_stderr = "", ""
            if userspace_proc:
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

            # Capture primitive end time from guest clock using robust retrieval
            primitive_end_ts = self._get_guest_time()
            if primitive_start_ts is None:
                print("[DEBUG] primitive_start_ts is None (failed to retrieve guest time)")
            if primitive_end_ts is None:
                print("[DEBUG] primitive_end_ts is None (failed to retrieve guest time)")
            if primitive_start_ts is not None and primitive_end_ts is not None:
                print(f"[DEBUG] primitive window: start={primitive_start_ts:.9f}, end={primitive_end_ts:.9f}")

            # Finalize kernel: interrupt, ensure stopped, export results, quit
            if kernel_proc and kernel_proc.poll() is None:
                try:
                    finalize = (
                        "interrupt\n"
                        "python exec(\"import gdb, time\\n"
                        "def _is_running():\\n"
                        "    try:\\n"
                        "        out = gdb.execute('info program', to_string=True)\\n"
                        "        return 'It stopped' not in out\\n"
                        "    except Exception:\\n"
                        "        return True\\n"
                        "for _ in range(20):\\n"
                        "    if not _is_running():\\n"
                        "        break\\n"
                        "    try:\\n"
                        "        gdb.execute('interrupt', to_string=True)\\n"
                        "    except Exception:\\n"
                        "        pass\\n"
                        "    time.sleep(0.5)\\n\")\n"
                        f"export_results {results_file_kernel}\n"
                        "quit\n"
                    )
                    if kernel_proc.stdin:
                        kernel_proc.stdin.write(finalize)
                        kernel_proc.stdin.flush()
                    # Wait for kernel GDB to exit
                    kernel_proc.wait(timeout=self.config.timeout)
                except subprocess.TimeoutExpired:
                    print(f"[DEBUG] Kernel GDB finalize timeout after {self.config.timeout}s; terminating")
                    kernel_proc.terminate()
                    try:
                        kernel_proc.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        kernel_proc.kill()

            print(f"[DEBUG] Kernel GDB exited: {kernel_proc.returncode}")
            print(f"[DEBUG] Userspace GDB exited: {userspace_proc.returncode if userspace_proc else 'skipped'}")
            # Read logs instead of stdout/stderr (since kernel runs async)
            k_log_text = ""
            try:
                if os.path.exists(kernel_log):
                    with open(kernel_log, 'r', encoding='utf-8', errors='ignore') as lf:
                        k_log_text = lf.read()
            except Exception:
                k_log_text = ""
            u_log_text = ""
            try:
                if os.path.exists(userspace_log):
                    with open(userspace_log, 'r', encoding='utf-8', errors='ignore') as uf:
                        u_log_text = uf.read()
            except Exception:
                u_log_text = ""
            # Compose raw output including primitive fallback if used
            user_out = (u_stdout or '')
            user_err = (u_stderr or '')
            if primitive_ran:
                user_out = (primitive_stdout or '')
                user_err = (primitive_stderr or '')
            result.raw_gdb_output = (k_log_text or '') + "\n--- USERSPACE ---\n" + user_out + "\n" + user_err + "\n" + (u_log_text or '')

            # Parse results file
            print(f"[DEBUG] Checking for kernel results file: {results_file_kernel}")
            print(f"[DEBUG] Checking for userspace results file: {results_file_userspace}")
            kernel_data = {}
            userspace_data = {}
            if os.path.exists(results_file_kernel):
                print(f"[DEBUG] Kernel results file found, parsing...")
                with open(results_file_kernel, 'r') as f:
                    data = json.load(f)
                    # Sort events by time for readability
                    ev = data.get('events', [])
                    if isinstance(ev, list):
                        ev.sort(key=lambda e: e.get('time', 0))
                    result.events = ev
                    print(f"[DEBUG] Parsed {len(result.events)} events")

                    # Merge UAF watch hits into events for downstream analysis
                    uaf_hits = data.get('uaf_watch_hits', [])
                    if isinstance(uaf_hits, list) and uaf_hits:
                        result.events.extend(uaf_hits)
                        print(f"[DEBUG] Merged {len(uaf_hits)} UAF watch hits into events")

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
            if userspace_proc is not None and os.path.exists(results_file_userspace):
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
            # else:
            #     result.error = "GDB results file not created"
            #     print(f"[DEBUG] ERROR: {result.error}")
            #     print(f"[DEBUG] Kernel GDB stdout:\n{k_stdout}")
            #     print(f"[DEBUG] Kernel GDB stderr:\n{k_stderr}")
            #     print(f"[DEBUG] Userspace GDB stdout:\n{u_stdout}")
            #     print(f"[DEBUG] Userspace GDB stderr:\n{u_stderr}")
            if primitive_start_ts is not None and primitive_end_ts is not None and isinstance(kernel_data, dict):
                window_events = [e for e in kernel_data.get('events', []) if isinstance(e, dict) and isinstance(e.get('time'), (int, float)) and primitive_start_ts <= e.get('time') <= primitive_end_ts]
                # allocations_detailed may contain timestamps
                allocs_det = kernel_data.get('allocations_detailed', {}) or {}
                window_allocs = {}
                for k, v in allocs_det.items():
                    try:
                        ts = v.get('time')
                        if ts is not None and primitive_start_ts <= ts <= primitive_end_ts:
                            window_allocs[k] = v
                    except Exception:
                        pass
                frees_det = kernel_data.get('frees_detailed', []) or []
                window_frees = [ev for ev in frees_det if isinstance(ev.get('time'), (int, float)) and primitive_start_ts <= ev.get('time') <= primitive_end_ts]
                windowed = {
                    'primitive_start': primitive_start_ts,
                    'primitive_end': primitive_end_ts,
                    'events': window_events,
                    'allocations_detailed': window_allocs,
                    'frees_detailed': window_frees,
                }
                base_dir = os.path.dirname(results_file_kernel)
                window_file = os.path.join(local_tmp, 'kernel_results_windowed.json')
                with open(window_file, 'w') as wf:
                    json.dump(windowed, wf, indent=2)
                print(f"[DEBUG] Wrote windowed kernel results to: {window_file}")
            else:
                # print what is missing
                if primitive_start_ts is None:
                    print("[DEBUG] primitive_start_ts is None")
                if primitive_end_ts is None:
                    print("[DEBUG] primitive_end_ts is None")
                
            
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
        t = event.get('type')
        if t == 'uaf_watch':
            analysis['uaf_detected'] = True
            analysis['vulnerabilities'].append({
                "type": "use-after-free",
                "address": hex(event.get('ptr')) if isinstance(event.get('ptr'), int) else event.get('ptr'),
                "rip": hex(event.get('rip')) if event.get('rip') else None,
                "backtrace": event.get('bt', [])
            })
        elif t == 'watch':
            rip = event.get('rip')
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

    # Double-free detection
    try:
        seen = {}
        for ptr in result.frees:
            seen[ptr] = seen.get(ptr, 0) + 1
        for ptr, count in seen.items():
            if count > 1:
                analysis['vulnerabilities'].append({
                    "type": "double-free",
                    "address": hex(ptr),
                    "count": count
                })
    except Exception:
        pass

    # Invalid-free detection (free of unallocated pointer)
    try:
        alloc_ptrs = set(result.allocations.keys())
        for ptr in result.frees:
            if ptr not in alloc_ptrs:
                analysis['vulnerabilities'].append({
                    "type": "invalid-free",
                    "address": hex(ptr)
                })
    except Exception:
        pass
                
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
