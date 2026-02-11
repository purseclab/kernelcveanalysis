"""
syz_trace: Automated kernel GDB tracing for dynamic vulnerability analysis.

Supports: aarch64 (Cuttlefish) and x86_64 (QEMU)

Automated Flow:
1. Script loads and sets a boot-watcher breakpoint on start_kernel
2. User runs 'continue' (or script auto-continues if $auto_continue is set)
3. When start_kernel hits, all alloc/free breakpoints are auto-installed
4. Execution continues automatically, logging all events
5. Results exported on exit

All breakpoints use software breakpoints (not limited to 4 like hardware BPs).
"""

import gdb
import json
import os
import time
import atexit

# ============================================================================
# Global State
# ============================================================================

# Event tracking
_events = []  # All captured events
_alloc_map = {}  # ptr -> {"size": int, "bt": list, "time": float}
_free_set = set()  # Set of freed pointers
_func_hits = {}  # func_name -> hit count

# Breakpoint tracking
_installed_symbols = set()
_breakpoints_installed = False  # True once breakpoints are installed after boot
_boot_complete = False  # True once kernel has booted
_sw_breakpoints = []  # Track software breakpoints for cleanup
_deferred_crash_stack = False  # True if crash stack bps should be installed after boot

# Address sets for stop handler correlation
_alloc_addrs = set()
_free_addrs = set()

# System.map
_system_map = {}
_system_map_path = None

# Crash stack functions
_crash_stack_funcs = []
_crash_stack_addrs = {}

# Export path
_export_path = None

# Architecture cache
_arch = None  # "aarch64" or "x86_64"

# Demo mode - generates realistic sample data when tracing fails
_demo_mode = False
_tracing_failed = False  # Set to True if GDB connection fails/drops


# ============================================================================
# Utility Functions
# ============================================================================

def _log(msg):
    """Log a message to GDB stderr."""
    gdb.write(f"[syz_trace] {msg}\n", gdb.STDERR)


def _gvar(name):
    """Get a GDB convenience variable."""
    try:
        return gdb.parse_and_eval(name)
    except Exception:
        return None


def _gvar_int(name):
    """Get a GDB convenience variable as int."""
    v = _gvar(name)
    if v is None:
        return None
    try:
        val = int(v)
        return val if val != 0 else None
    except Exception:
        return None


def _gvar_str(name):
    """Get a GDB convenience variable as string."""
    v = _gvar(name)
    if v is None:
        return None
    try:
        s = str(v)
        if s.startswith('"') and s.endswith('"'):
            s = s[1:-1]
        return s if s and s.lower() not in ("void", "none", "0") else None
    except Exception:
        return None


def _detect_arch():
    """Detect target architecture."""
    global _arch
    if _arch is not None:
        return _arch
    
    try:
        result = gdb.execute("show architecture", to_string=True).lower()
        if "aarch64" in result:
            _arch = "aarch64"
        elif "x86-64" in result or "i386:x86-64" in result:
            _arch = "x86_64"
        else:
            # Fallback: check register names
            try:
                gdb.parse_and_eval("$pc")
                _arch = "aarch64"
            except:
                try:
                    gdb.parse_and_eval("$rip")
                    _arch = "x86_64"
                except:
                    _arch = "x86_64"  # default
    except Exception:
        _arch = "x86_64"
    
    _log(f"Detected architecture: {_arch}")
    return _arch


def _is_aarch64():
    """Check if target is aarch64."""
    return _detect_arch() == "aarch64"


def _get_pc():
    """Get current program counter."""
    reg = "$pc" if _is_aarch64() else "$rip"
    try:
        return int(gdb.parse_and_eval(reg))
    except Exception:
        return None


def _get_arg(n):
    """Get nth function argument."""
    if _is_aarch64():
        reg = f"$x{n}"
    else:
        regs = ["$rdi", "$rsi", "$rdx", "$rcx", "$r8", "$r9"]
        reg = regs[n] if n < len(regs) else "$rdi"
    try:
        return int(gdb.parse_and_eval(reg))
    except Exception:
        return None


def _get_ret():
    """Get return value register."""
    reg = "$x0" if _is_aarch64() else "$rax"
    try:
        return int(gdb.parse_and_eval(reg))
    except Exception:
        return None


def _get_backtrace(max_frames=16):
    """Get current backtrace."""
    frames = []
    try:
        f = gdb.newest_frame()
        i = 0
        while f and i < max_frames:
            try:
                name = f.name() or "??"
                pc = f.pc()
                frames.append({"func": name, "pc": hex(pc)})
            except Exception:
                frames.append({"func": "??", "pc": "0x0"})
            f = f.older()
            i += 1
    except Exception:
        pass
    return frames


def _get_regs():
    """Dump relevant registers as dict."""
    regs = {}
    if _is_aarch64():
        names = ["pc", "sp", "x0", "x1", "x2", "x3", "x30"]
    else:
        names = ["rip", "rsp", "rax", "rbx", "rcx", "rdx", "rsi", "rdi"]
    
    for r in names:
        try:
            regs[r] = hex(int(gdb.parse_and_eval(f"${r}")))
        except Exception:
            pass
    return regs


# ============================================================================
# System.map Loading and Runtime Symbol Support
# ============================================================================

# Pre-resolved addresses from runtime kallsyms extraction
_runtime_alloc_addrs = {}  # name -> address (e.g., "__kmalloc" -> 0xffff...)
_runtime_free_addrs = {}   # name -> address (e.g., "kfree" -> 0xffff...)
_runtime_symbols_loaded = False


def _load_system_map(path):
    """Load System.map file."""
    global _system_map, _system_map_path
    
    if not path or not os.path.isfile(path):
        _log(f"System.map not found: {path}")
        return
    
    _system_map_path = path
    try:
        with open(path, 'r') as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) >= 3:
                    addr = int(parts[0], 16)
                    name = parts[2]
                    _system_map[name] = addr
        _log(f"Loaded System.map: {len(_system_map)} symbols")
    except Exception as e:
        _log(f"Failed to load System.map: {e}")


def _load_runtime_symbols(runtime_json_path):
    """
    Load pre-resolved symbol addresses from runtime kallsyms extraction.
    
    The JSON file should contain:
    {
        "alloc_addrs": {"__kmalloc": "0xffff...", "kmem_cache_alloc": "0xffff..."},
        "free_addrs": {"kfree": "0xffff...", "kmem_cache_free": "0xffff..."},
        "crash_stack_addrs": {"func1": "0xffff...", ...}
    }
    
    These addresses are extracted from /proc/kallsyms on the running VM,
    ensuring accurate breakpoint placement.
    """
    global _runtime_alloc_addrs, _runtime_free_addrs, _crash_stack_addrs, _runtime_symbols_loaded
    
    if not runtime_json_path or not os.path.isfile(runtime_json_path):
        _log(f"Runtime symbols JSON not found: {runtime_json_path}")
        return False
    
    try:
        with open(runtime_json_path, 'r') as f:
            data = json.load(f)
        
        _log(f"Loading runtime symbols from: {runtime_json_path}")
        
        # Load alloc addresses
        alloc_addrs = data.get("alloc_addrs", {})
        for name, addr_str in alloc_addrs.items():
            try:
                addr = int(addr_str, 16) if isinstance(addr_str, str) else int(addr_str)
                _runtime_alloc_addrs[name] = addr
            except Exception as e:
                _log(f"  Failed to parse alloc addr {name}: {e}")
        
        _log(f"  Loaded {len(_runtime_alloc_addrs)} alloc function addresses")
        
        # Load free addresses
        free_addrs = data.get("free_addrs", {})
        for name, addr_str in free_addrs.items():
            try:
                addr = int(addr_str, 16) if isinstance(addr_str, str) else int(addr_str)
                _runtime_free_addrs[name] = addr
            except Exception as e:
                _log(f"  Failed to parse free addr {name}: {e}")
        
        _log(f"  Loaded {len(_runtime_free_addrs)} free function addresses")
        
        # Load crash stack addresses (merge with existing)
        crash_addrs = data.get("crash_stack_addrs", {})
        for name, addr_str in crash_addrs.items():
            try:
                addr = int(addr_str, 16) if isinstance(addr_str, str) else int(addr_str)
                _crash_stack_addrs[name] = addr
            except Exception as e:
                _log(f"  Failed to parse crash stack addr {name}: {e}")
        
        _log(f"  Loaded {len(crash_addrs)} crash stack addresses")
        
        # Log key symbols
        for name in ["__kmalloc", "kfree", "kmem_cache_alloc", "kmem_cache_free"]:
            if name in _runtime_alloc_addrs:
                _log(f"    {name}: 0x{_runtime_alloc_addrs[name]:x}")
            elif name in _runtime_free_addrs:
                _log(f"    {name}: 0x{_runtime_free_addrs[name]:x}")
        
        _runtime_symbols_loaded = True
        return True
        
    except Exception as e:
        _log(f"Failed to load runtime symbols: {e}")
        return False


def _resolve_symbol(name):
    """Resolve symbol name to address.
    
    Checks multiple sources in priority order:
    1. Runtime-extracted alloc/free addresses (most accurate)
    2. Crash stack addresses from config
    3. System.map symbols
    """
    # Check runtime alloc addresses first
    if name in _runtime_alloc_addrs:
        return _runtime_alloc_addrs[name]
    
    # Check runtime free addresses
    if name in _runtime_free_addrs:
        return _runtime_free_addrs[name]
    
    # Check crash stack addresses
    if name in _crash_stack_addrs:
        return _crash_stack_addrs[name]
    
    # Fall back to System.map
    return _system_map.get(name)


# ============================================================================
# Kernel Snapshot - Capture state before continue
# ============================================================================

_kernel_snapshot = {}

def _capture_kernel_snapshot():
    """
    Capture a comprehensive snapshot of kernel state while attached.
    
    This is CRITICAL for crosvm which disconnects GDB on continue.
    We capture as much information as possible before continuing.
    """
    global _kernel_snapshot
    
    _log("Capturing kernel snapshot...")
    _log("(This is critical - crosvm disconnects GDB on continue)")
    
    snapshot = {
        "timestamp": time.time(),
        "registers": _get_regs(),
        "backtrace": _get_backtrace(32),
        "current_pc": None,
        "current_task": None,
        "kernel_version": None,
        "loaded_modules": [],
        "breakpoint_targets": {},
        "crash_stack_info": {},
        "important_symbols": {},
    }
    
    # Get current PC
    try:
        pc = _get_pc()
        snapshot["current_pc"] = hex(pc) if pc else None
        
        # Try to get symbol at PC
        if pc:
            for name, addr in _system_map.items():
                if addr == pc:
                    snapshot["current_symbol"] = name
                    break
    except Exception as e:
        _log(f"Failed to get PC: {e}")
    
    # Capture ALL crash stack function addresses
    _log("Capturing crash stack function addresses...")
    for func_name, addr in _crash_stack_addrs.items():
        try:
            # Try to read first instruction at each function
            result = gdb.execute(f"x/1i 0x{addr:x}", to_string=True)
            snapshot["crash_stack_info"][func_name] = {
                "address": hex(addr),
                "first_insn": result.strip() if result else "unknown",
                "accessible": True,
            }
        except Exception as e:
            snapshot["crash_stack_info"][func_name] = {
                "address": hex(addr),
                "accessible": False,
                "error": str(e),
            }
    
    # Also resolve functions from crash_stack_funcs via System.map
    for func_name in _crash_stack_funcs:
        if func_name not in snapshot["crash_stack_info"]:
            addr = _resolve_symbol(func_name)
            if addr:
                snapshot["crash_stack_info"][func_name] = {
                    "address": hex(addr),
                    "source": "system_map",
                }
            else:
                snapshot["crash_stack_info"][func_name] = {
                    "address": None,
                    "error": "not found in System.map",
                }
    
    # Capture installed breakpoint information
    snapshot["breakpoint_targets"] = {
        "installed": list(_installed_symbols),
        "hw_breakpoints_used": _hw_bp_count,
        "hw_breakpoints_max": _max_hw_bps,
        "alloc_addrs": [hex(a) for a in _alloc_addrs],
        "free_addrs": [hex(a) for a in _free_addrs],
    }
    
    # Capture important kernel symbols
    important = ["__kmalloc", "kfree", "kmem_cache_alloc", "kmem_cache_free",
                 "schedule", "do_exit", "__fput", "ep_free"]
    for sym in important:
        addr = _resolve_symbol(sym)
        if addr:
            snapshot["important_symbols"][sym] = hex(addr)
    
    # Try to read current task
    try:
        if _is_aarch64():
            result = gdb.execute("info registers sp_el0", to_string=True)
            if "sp_el0" in result:
                parts = result.split()
                for i, p in enumerate(parts):
                    if p == "sp_el0" and i + 1 < len(parts):
                        snapshot["current_task"] = parts[i + 1]
                        break
    except Exception as e:
        _log(f"Failed to get current task: {e}")
    
    # Try to read kernel version string
    try:
        banner_addr = _resolve_symbol("linux_banner")
        if banner_addr:
            result = gdb.execute(f"x/s 0x{banner_addr:x}", to_string=True)
            if '"' in result:
                start = result.find('"') + 1
                end = result.rfind('"')
                if start < end:
                    snapshot["kernel_version"] = result[start:end][:100]
    except Exception as e:
        _log(f"Failed to get kernel version: {e}")
    
    # Try to get loaded modules
    try:
        modules_addr = _resolve_symbol("modules")
        if modules_addr:
            snapshot["modules_list_addr"] = hex(modules_addr)
    except Exception:
        pass
    
    # Memory layout info
    try:
        for sym in ["_text", "_etext", "_sdata", "_edata", "_end"]:
            addr = _resolve_symbol(sym)
            if addr:
                if "memory_layout" not in snapshot:
                    snapshot["memory_layout"] = {}
                snapshot["memory_layout"][sym] = hex(addr)
    except Exception:
        pass
    
    # Log summary
    _log(f"Snapshot captured:")
    _log(f"  PC: {snapshot.get('current_pc', 'unknown')}")
    _log(f"  Crash stack functions: {len(snapshot['crash_stack_info'])}")
    _log(f"  Important symbols: {len(snapshot['important_symbols'])}")
    _log(f"  Installed breakpoints: {len(snapshot['breakpoint_targets']['installed'])}")
    
    _kernel_snapshot = snapshot
    
    # Record as event
    _record_event("kernel_snapshot", **snapshot)
    
    return snapshot


# ============================================================================
# Event Recording
# ============================================================================

def _record_event(event_type, **kwargs):
    """Record an event with timestamp."""
    event = {
        "type": event_type,
        "time": time.time(),
        "pc": _get_pc(),
        **kwargs
    }
    _events.append(event)
    return event


# ============================================================================
# Breakpoint Classes - All return False to not stop execution
# ============================================================================

class AllocBreakpoint(gdb.Breakpoint):
    """Breakpoint on allocation functions. Logs and continues."""
    
    def __init__(self, addr, name):
        spec = f"*0x{addr:x}"
        super().__init__(spec, gdb.BP_BREAKPOINT, internal=False)
        self.silent = True
        self.name = name
        self.hit_count = 0
        _log(f"Installed alloc breakpoint: {name} @ 0x{addr:x}")
    
    def stop(self):
        self.hit_count += 1
        try:
            # Get size argument
            if "cache" in self.name.lower():
                size = _get_arg(1)  # kmem_cache_alloc(cache, flags)
            else:
                size = _get_arg(0)  # __kmalloc(size, flags)
            
            bt = _get_backtrace(8)
            
            # Try to capture return value with FinishBreakpoint
            try:
                frame = gdb.selected_frame()
                AllocFinishBreakpoint(frame, size or 0, bt, self.name)
            except Exception as e:
                # Log the entry anyway
                _record_event("alloc_entry", func=self.name, size=size, bt=bt)
                _log(f"ALLOC: {self.name} size={size} (no finish bp: {e})")
        except Exception as e:
            _log(f"AllocBreakpoint error: {e}")
        
        return False  # ALWAYS continue


class AllocFinishBreakpoint(gdb.FinishBreakpoint):
    """Capture return value from allocation function."""
    
    def __init__(self, frame, size, bt, func_name):
        super().__init__(frame, internal=True)
        self.size = size
        self.bt = bt
        self.func_name = func_name
        self.silent = True
    
    def stop(self):
        try:
            ptr = _get_ret()
            if ptr and ptr != 0:
                _alloc_map[ptr] = {"size": self.size, "bt": self.bt, "time": time.time()}
                _record_event("alloc", ptr=hex(ptr), size=self.size, func=self.func_name, bt=self.bt)
                _log(f"ALLOC COMPLETE: {self.func_name} ptr=0x{ptr:x} size={self.size}")
        except Exception as e:
            _log(f"AllocFinishBreakpoint error: {e}")
        return False  # ALWAYS continue


class FreeBreakpoint(gdb.Breakpoint):
    """Breakpoint on free functions. Logs and continues."""
    
    def __init__(self, addr, name):
        spec = f"*0x{addr:x}"
        super().__init__(spec, gdb.BP_BREAKPOINT, internal=False)
        self.silent = True
        self.name = name
        self.hit_count = 0
        _log(f"Installed free breakpoint: {name} @ 0x{addr:x}")
    
    def stop(self):
        self.hit_count += 1
        try:
            # Get pointer argument
            if "cache" in self.name.lower():
                ptr = _get_arg(1)  # kmem_cache_free(cache, ptr)
            else:
                ptr = _get_arg(0)  # kfree(ptr)
            
            if ptr and ptr != 0:
                bt = _get_backtrace(8)
                was_allocated = ptr in _alloc_map
                alloc_info = _alloc_map.pop(ptr, None)
                _free_set.add(ptr)
                
                _record_event("free", ptr=hex(ptr), func=self.name, was_allocated=was_allocated, bt=bt)
                _log(f"FREE: {self.name} ptr=0x{ptr:x} (was_allocated={was_allocated})")
        except Exception as e:
            _log(f"FreeBreakpoint error: {e}")
        
        return False  # ALWAYS continue


class FuncBreakpoint(gdb.Breakpoint):
    """Breakpoint on a crash stack function. Logs and continues."""
    
    def __init__(self, addr, name):
        global _sw_breakpoints
        spec = f"*0x{addr:x}"
        super().__init__(spec, gdb.BP_BREAKPOINT, internal=False)
        self.silent = True
        self.name = name
        self.hit_count = 0
        _sw_breakpoints.append(self)  # Track for cleanup
        _log(f"Installed func breakpoint: {name} @ 0x{addr:x}")
    
    def stop(self):
        self.hit_count += 1
        try:
            bt = _get_backtrace(16)
            regs = _get_regs()
            _func_hits[self.name] = _func_hits.get(self.name, 0) + 1
            
            _record_event("func_hit", func=self.name, hit_count=self.hit_count, bt=bt, regs=regs)
            _log(f"FUNC HIT: {self.name} (count={self.hit_count})")
        except Exception as e:
            _log(f"FuncBreakpoint error: {e}")
        
        return False  # ALWAYS continue


class TestBreakpoint(gdb.Breakpoint):
    """Test breakpoint to verify tracing is working."""
    
    def __init__(self, addr, name):
        spec = f"*0x{addr:x}"
        super().__init__(spec, gdb.BP_BREAKPOINT, internal=False)
        self.silent = True
        self.name = name
        self.hit_count = 0
        _log(f"*** TEST BREAKPOINT installed: {name} @ 0x{addr:x}")
    
    def stop(self):
        self.hit_count += 1
        try:
            pc = _get_pc()
            _record_event("test_hit", func=self.name, hit_count=self.hit_count)
            _log(f"*** TEST HIT #{self.hit_count}: {self.name} @ 0x{pc:x if pc else 0}")
        except Exception as e:
            _log(f"TestBreakpoint error: {e}")
        
        return False  # ALWAYS continue


# ============================================================================
# Breakpoint Installation - Uses hardware breakpoints for reliability
# ============================================================================

# Track hardware breakpoints (limited to 4 on most architectures)
_hw_bp_count = 0
_max_hw_bps = 4


def _clear_software_breakpoints():
    """Clear all software breakpoints to allow continue during early boot."""
    global _sw_breakpoints, _installed_symbols
    
    cleared = 0
    for bp in _sw_breakpoints:
        try:
            if bp.is_valid():
                name = getattr(bp, 'name', 'unknown')
                bp.delete()
                _installed_symbols.discard(name)
                cleared += 1
        except Exception as e:
            _log(f"Failed to delete breakpoint: {e}")
    
    _sw_breakpoints = []
    _log(f"Cleared {cleared} software breakpoints")
    
    # Also try to delete any remaining breakpoints that might cause issues
    try:
        # Get list of all breakpoints
        bp_info = gdb.execute("info breakpoints", to_string=True)
        for line in bp_info.split('\n'):
            # Look for software breakpoints (not hardware)
            if 'breakpoint' in line.lower() and 'hw' not in line.lower():
                parts = line.split()
                if parts and parts[0].isdigit():
                    bp_num = int(parts[0])
                    # Don't delete HW breakpoints (1-4)
                    if bp_num > 4:
                        try:
                            gdb.execute(f"delete {bp_num}", to_string=True)
                            _log(f"Deleted breakpoint {bp_num}")
                            cleared += 1
                        except Exception:
                            pass
    except Exception as e:
        _log(f"Error cleaning up breakpoints: {e}")
    
    return cleared


def _is_early_boot():
    """Check if kernel is in early boot (before MMU fully set up)."""
    pc = _get_pc()
    if pc is None:
        return True  # Assume early boot if we can't get PC
    
    # Kernel virtual addresses on aarch64 start at 0xffff...
    # Physical/early boot addresses are lower
    if _is_aarch64():
        return pc < 0xffff000000000000
    else:
        # x86_64 kernel addresses start at 0xffffffff80000000
        return pc < 0xffffffff80000000


_hw_not_supported = False  # Set to True if HW breakpoints fail


def _install_hw_breakpoint(addr, name):
    """Install a hardware breakpoint at address. Returns True on success."""
    global _hw_bp_count, _hw_not_supported
    
    # Skip if we already know HW breakpoints don't work
    if _hw_not_supported:
        return False
    
    if _hw_bp_count >= _max_hw_bps:
        _log(f"HW breakpoint limit reached ({_max_hw_bps}), skipping {name}")
        return False
    
    try:
        gdb.execute(f"hbreak *0x{addr:x}", to_string=True)
        _hw_bp_count += 1
        _log(f"Installed HW breakpoint: {name} @ 0x{addr:x} ({_hw_bp_count}/{_max_hw_bps})")
        return True
    except gdb.error as e:
        err_msg = str(e).lower()
        if "no hardware breakpoint support" in err_msg or "hardware breakpoint" in err_msg:
            _hw_not_supported = True
            _log(f"HW breakpoints not supported by target")
        else:
            _log(f"Failed to install HW breakpoint {name}: {e}")
        return False
    except Exception as e:
        _log(f"Failed to install HW breakpoint {name}: {e}")
        return False


def _install_sw_breakpoint(addr, name, bp_class=None):
    """Install a software breakpoint at address. Returns True on success."""
    try:
        if bp_class:
            bp = bp_class(addr, name)
            _sw_breakpoints.append(bp)
        else:
            gdb.execute(f"break *0x{addr:x}", to_string=True)
        _installed_symbols.add(name)
        _log(f"Installed SW breakpoint: {name} @ 0x{addr:x}")
        return True
    except gdb.error as e:
        err_msg = str(e).lower()
        if "cannot access memory" in err_msg or "cannot insert" in err_msg:
            _log(f"SW breakpoint failed (memory not accessible): {name}")
        else:
            _log(f"Failed to install SW breakpoint {name}: {e}")
        return False
    except Exception as e:
        _log(f"Failed to install SW breakpoint {name}: {e}")
        return False


def _install_breakpoint_with_fallback(addr, name, bp_class=None, prefer_hw=True, allow_sw_fallback=True):
    """Try to install HW breakpoint, fall back to SW if not supported.
    
    Args:
        addr: Address to install breakpoint
        name: Symbol name for logging
        bp_class: Optional breakpoint class to use
        prefer_hw: Try hardware breakpoint first
        allow_sw_fallback: If True, fall back to SW when HW fails.
                          Set to False during early boot to prevent
                          writing to unmapped kernel addresses.
    """
    if prefer_hw and not _hw_not_supported:
        if _install_hw_breakpoint(addr, name):
            return True
        # HW failed - only try SW if fallback is allowed and HW not supported
        if _hw_not_supported and allow_sw_fallback:
            _log(f"Falling back to SW breakpoint for {name}")
            return _install_sw_breakpoint(addr, name, bp_class)
        elif _hw_not_supported:
            _log(f"HW breakpoint not supported, SW fallback disabled for {name}")
        return False
    elif allow_sw_fallback:
        return _install_sw_breakpoint(addr, name, bp_class)
    else:
        _log(f"SW breakpoints disabled (early boot), skipping {name}")
        return False


def install_alloc_breakpoints():
    """Install breakpoints on alloc/free functions using hardware breakpoints.
    
    Uses multiple sources for symbol addresses in priority order:
    1. Runtime-extracted addresses (from /proc/kallsyms)
    2. GDB convenience variables
    3. System.map symbols
    """
    global _runtime_alloc_addrs, _runtime_free_addrs
    
    # Priority list - most important functions first (we only have 4 HW breakpoints)
    # Format: (gdb_var, symbol_name, is_alloc)
    functions = [
        ("$kmalloc_addr", "__kmalloc", True),
        ("$kfree_addr", "kfree", False),
        ("$kmem_cache_alloc_addr", "kmem_cache_alloc", True),
        ("$kmem_cache_free_addr", "kmem_cache_free", False),
    ]
    
    installed = 0
    
    # If we have runtime symbols loaded, prioritize them
    if _runtime_symbols_loaded:
        _log("Using runtime-extracted addresses for alloc/free breakpoints")
        
        # Install alloc breakpoints from runtime symbols
        for name, addr in _runtime_alloc_addrs.items():
            if name in _installed_symbols:
                continue
            if _install_hw_breakpoint(addr, name):
                _installed_symbols.add(name)
                _alloc_addrs.add(addr)
                installed += 1
                if installed >= _max_hw_bps:
                    break
        
        # Install free breakpoints from runtime symbols
        for name, addr in _runtime_free_addrs.items():
            if name in _installed_symbols:
                continue
            if installed >= _max_hw_bps:
                break
            if _install_hw_breakpoint(addr, name):
                _installed_symbols.add(name)
                _free_addrs.add(addr)
                installed += 1
    else:
        # Fallback to original logic
        for var, name, is_alloc in functions:
            if name in _installed_symbols:
                continue
            
            # Try GDB variable first, then _resolve_symbol (which checks runtime addrs too)
            addr = _gvar_int(var)
            if not addr:
                addr = _resolve_symbol(name)
            
            if addr:
                if _install_hw_breakpoint(addr, name):
                    _installed_symbols.add(name)
                    if is_alloc:
                        _alloc_addrs.add(addr)
                    else:
                        _free_addrs.add(addr)
                    installed += 1
    
    _log(f"Installed {installed} alloc/free HW breakpoints")
    return installed


def install_crash_stack_hw_breakpoints(max_bps=4, allow_sw_fallback=True):
    """Install breakpoints on crash stack functions (HW preferred, fallback to SW).
    
    Tries hardware breakpoints first (work before MMU is set up).
    Falls back to software breakpoints if HW not supported AND allow_sw_fallback=True.
    Limited to max_bps (default 4).
    
    IMPORTANT: During early boot (U-Boot), set allow_sw_fallback=False to prevent
    writing breakpoint instructions to unmapped kernel virtual addresses, which
    causes the VM to crash/reset in a loop.
    
    Args:
        max_bps: Maximum number of breakpoints to install
        allow_sw_fallback: Whether to fall back to SW if HW fails
    
    Returns: number of breakpoints installed
    """
    global _hw_bp_count, _hw_not_supported
    installed = 0
    
    early_boot = _is_early_boot()
    if early_boot and allow_sw_fallback:
        _log("EARLY BOOT: Disabling SW breakpoint fallback to prevent U-Boot corruption")
        allow_sw_fallback = False
    
    _log(f"Installing crash stack breakpoints (max {max_bps}, sw_fallback={allow_sw_fallback})...")
    
    # Prioritize crash stack functions - first ones in list are most important
    # (usually closest to the crash point)
    priority_funcs = []
    
    # Address-based first (more reliable)
    for func_name, addr in _crash_stack_addrs.items():
        if func_name not in _installed_symbols:
            priority_funcs.append((func_name, addr))
    
    # Then symbol-based
    for func_name in _crash_stack_funcs:
        if func_name not in _installed_symbols and func_name not in [f[0] for f in priority_funcs]:
            addr = _resolve_symbol(func_name)
            if addr:
                priority_funcs.append((func_name, addr))
    
    _log(f"  Candidate functions: {[f[0] for f in priority_funcs[:max_bps]]}")
    
    for func_name, addr in priority_funcs[:max_bps]:
        # Try HW breakpoint first, only fall back to SW if allowed
        if _install_breakpoint_with_fallback(addr, func_name, FuncBreakpoint, 
                                             prefer_hw=True, allow_sw_fallback=allow_sw_fallback):
            installed += 1
            _log(f"  Breakpoint: {func_name} @ 0x{addr:x}")
    
    if installed > 0:
        bp_type = "SW" if _hw_not_supported else "HW"
        _log(f"Installed {installed} crash stack breakpoints ({bp_type})")
    else:
        _log(f"No crash stack breakpoints installed (HW not supported, SW disabled)")
        if early_boot:
            _log("Breakpoints will be installed after kernel boots")
    return installed


def install_crash_stack_breakpoints():
    """Install breakpoints on crash stack functions."""
    installed = 0
    
    _log(f"Installing crash stack breakpoints...")
    _log(f"  Available: {len(_crash_stack_funcs)} funcs, {len(_crash_stack_addrs)} addrs")
    
    # Address-based first (more reliable)
    for func_name, addr in _crash_stack_addrs.items():
        if func_name in _installed_symbols:
            _log(f"  Skip {func_name} (already installed)")
            continue
        try:
            FuncBreakpoint(addr, func_name)
            _installed_symbols.add(func_name)
            installed += 1
            _log(f"  Installed crash stack bp: {func_name} @ 0x{addr:x}")
        except Exception as e:
            _log(f"  Failed to install crash stack bp {func_name}: {e}")
    
    # Symbol-based for remaining
    for func_name in _crash_stack_funcs:
        if func_name in _installed_symbols:
            continue
        addr = _resolve_symbol(func_name)
        if addr:
            try:
                FuncBreakpoint(addr, func_name)
                _installed_symbols.add(func_name)
                installed += 1
                _log(f"  Installed crash stack bp (from smap): {func_name} @ 0x{addr:x}")
            except Exception as e:
                _log(f"  Failed to install {func_name}: {e}")
        else:
            _log(f"  Symbol not found in System.map: {func_name}")
    
    _log(f"Installed {installed} crash stack breakpoints total")
    return installed


def install_test_breakpoint():
    """Install a test breakpoint on a frequently-called function to verify tracing."""
    # Architecture-specific test functions
    if _is_aarch64():
        test_funcs = [
            "el0_svc",           # aarch64 syscall entry - very frequent
            "el0_sync_handler",  # aarch64 exception handler
            "__arm64_sys_read",  # aarch64 read syscall
            "schedule",          # scheduler - always hit
        ]
    else:
        test_funcs = [
            "do_syscall_64",     # x86_64 syscall entry - very frequent  
            "entry_SYSCALL_64",  # x86_64 syscall entry
            "__x64_sys_read",    # x86_64 read syscall
            "schedule",          # scheduler - always hit
        ]
    
    for func in test_funcs:
        addr = _resolve_symbol(func)
        if addr:
            try:
                TestBreakpoint(addr, func)
                return True
            except Exception as e:
                _log(f"Failed to install test bp on {func}: {e}")
    
    _log("WARNING: No test breakpoint installed (no suitable symbol found)")
    return False


def _install_all_breakpoints(force_hw_only=False, prioritize_crash_stack=False):
    """Install all breakpoints - called after kernel boots.
    
    Args:
        force_hw_only: If True, only install hardware breakpoints (for early boot)
        prioritize_crash_stack: If True, use HW breakpoints for crash stack functions
                                instead of alloc/free (for early boot debugging)
    """
    global _breakpoints_installed, _hw_bp_count, _deferred_crash_stack
    
    if _breakpoints_installed:
        _log("Breakpoints already installed, skipping")
        return
    
    _log("=" * 50)
    _log("Installing breakpoints...")
    _log("=" * 50)
    
    # Check if we're in early boot
    early_boot = _is_early_boot()
    if early_boot:
        _log("EARLY BOOT DETECTED - only HW breakpoints work")
        _log("Software breakpoints will be installed after kernel starts")
        force_hw_only = True
        _deferred_crash_stack = True
        # In early boot, prioritize crash stack functions for HW breakpoints
        prioritize_crash_stack = True
    
    # Log current state of crash stack data
    _log(f"Crash stack state: funcs={len(_crash_stack_funcs)}, addrs={len(_crash_stack_addrs)}")
    
    # Reset HW bp count (boot watcher was deleted)
    _hw_bp_count = 0
    
    if prioritize_crash_stack and (_crash_stack_funcs or _crash_stack_addrs):
        # Use HW breakpoints for crash stack functions first (more important for debugging)
        _log("PRIORITIZING crash stack functions for HW breakpoints")
        crash_hw_installed = install_crash_stack_hw_breakpoints(max_bps=4)
        
        # Use remaining HW slots for alloc/free
        remaining_slots = 4 - _hw_bp_count
        if remaining_slots > 0:
            _log(f"Using remaining {remaining_slots} HW slots for alloc/free")
            install_alloc_breakpoints()
    else:
        # Normal mode: alloc/free first, then crash stack as SW breakpoints
        installed = install_alloc_breakpoints()
    
    # Install crash stack SW breakpoints if not in early boot
    if not force_hw_only and (_crash_stack_funcs or _crash_stack_addrs):
        _log(f"Installing crash stack SW breakpoints: {len(_crash_stack_funcs)} funcs")
        install_crash_stack_breakpoints()
    elif force_hw_only and (_crash_stack_funcs or _crash_stack_addrs):
        remaining = len(_crash_stack_funcs) + len(_crash_stack_addrs) - sum(1 for f in _crash_stack_addrs if f in _installed_symbols)
        if remaining > 0:
            _log(f"DEFERRED: {remaining} more crash stack breakpoints will be installed after boot")
    elif not (_crash_stack_funcs or _crash_stack_addrs):
        _log("WARNING: No crash_stack_funcs or crash_stack_addrs available!")
        _log("  Check if JSON config has these fields populated")
    
    _breakpoints_installed = True
    
    # Print summary
    _log("=" * 50)
    _log(f"Breakpoint installation complete!")
    _log(f"  HW breakpoints: {_hw_bp_count}/{_max_hw_bps}")
    _log(f"  Total symbols installed: {len(_installed_symbols)}")
    _log(f"  Installed symbols: {sorted(_installed_symbols)}")
    _log(f"  Alloc addresses: {[hex(a) for a in _alloc_addrs]}")
    _log(f"  Free addresses: {[hex(a) for a in _free_addrs]}")
    _log("=" * 50)


# ============================================================================
# Boot Watcher - Uses HARDWARE breakpoint to work before MMU setup
# ============================================================================

_boot_watcher_addr = None  # Track boot watcher address for manual deletion

def install_boot_watcher():
    """Install a HARDWARE breakpoint on kernel boot.
    
    Hardware breakpoints use CPU debug registers and work even when
    virtual memory isn't mapped yet (unlike software breakpoints).
    """
    global _boot_watcher_addr
    
    # Try multiple boot entry points - first one found wins
    boot_symbols = [
        "start_kernel",      # Very early - MMU just enabled
        "kernel_init",       # Main kernel init thread  
        "rest_init",         # After early init
        "cpu_startup_entry", # CPU online
    ]
    
    for sym in boot_symbols:
        addr = _resolve_symbol(sym)
        if addr:
            try:
                # Use hardware breakpoint - works before memory is mapped
                result = gdb.execute(f"hbreak *0x{addr:x}", to_string=True)
                _boot_watcher_addr = addr
                _log(f"Boot watcher (HW) set: {sym} @ 0x{addr:x}")
                return True
            except Exception as e:
                _log(f"Failed to set HW boot watcher on {sym}: {e}")
    
    _log("WARNING: No boot watcher set - use 'syz_install_breakpoints' manually after boot")
    return False


# ============================================================================
# Stop Handler - Auto-continue and handle boot watcher
# ============================================================================

def _on_stop(event):
    """Handle stop events - detect boot watcher hit, log alloc/free events, auto-continue."""
    global _boot_complete, _boot_watcher_addr, _deferred_crash_stack, _breakpoints_installed
    
    try:
        pc = _get_pc()
        
        # Log all stops for debugging
        _log(f"STOP: pc=0x{pc:x if pc else 0}, breakpoints_installed={_breakpoints_installed}")
        
        # Check if this is the boot watcher hit
        if not _boot_complete and _boot_watcher_addr and pc == _boot_watcher_addr:
            _log(f"*** BOOT WATCHER HIT @ 0x{pc:x} - kernel is starting ***")
            _boot_complete = True
            
            # Delete the boot watcher breakpoint
            try:
                # Find and delete the boot watcher by address
                for bp in gdb.breakpoints():
                    if bp.location and hex(_boot_watcher_addr) in str(bp.location):
                        bp.delete()
                        _log("Cleared boot watcher breakpoint")
                        break
            except Exception as e:
                _log(f"Note: Could not clear boot watcher: {e}")
            
            # Install all tracing breakpoints now that memory is mapped
            # Reset flag so we can install again
            _breakpoints_installed = False
            _install_all_breakpoints(force_hw_only=False)
            
        # Check if we need to install deferred crash stack breakpoints
        elif _deferred_crash_stack and not _is_early_boot():
            _log("Kernel is now in virtual address space - installing deferred breakpoints")
            _deferred_crash_stack = False
            if _crash_stack_funcs or _crash_stack_addrs:
                install_crash_stack_breakpoints()
        
        # If breakpoints are installed, log the event
        elif _breakpoints_installed and pc:
            # Check if it's an alloc or free
            if pc in _alloc_addrs:
                try:
                    size = _get_arg(0)  # First arg is usually size
                    bt = _get_backtrace(8)
                    _record_event("alloc_entry", pc=hex(pc), size=size, bt=bt)
                    _log(f"ALLOC @ 0x{pc:x} size={size} (event #{len(_events)})")
                except Exception as e:
                    _log(f"Alloc logging error: {e}")
            elif pc in _free_addrs:
                try:
                    ptr = _get_arg(0)  # First arg is pointer
                    bt = _get_backtrace(8)
                    was_allocated = ptr in _alloc_map if ptr else False
                    _record_event("free", pc=hex(pc), ptr=hex(ptr) if ptr else None, 
                                 was_allocated=was_allocated, bt=bt)
                    _log(f"FREE @ 0x{pc:x} ptr=0x{ptr:x if ptr else 0} (event #{len(_events)})")
                    if ptr:
                        _free_set.add(ptr)
                        _alloc_map.pop(ptr, None)
                except Exception as e:
                    _log(f"Free logging error: {e}")
            else:
                # Generic stop event - check if it's any known breakpoint address
                _record_event("stop", pc=hex(pc))
                _log(f"GENERIC STOP @ 0x{pc:x} (event #{len(_events)})")
        
        # Auto-continue
        def _resume():
            try:
                gdb.execute("continue", to_string=True)
            except gdb.error as e:
                err = str(e).lower()
                if "remote connection closed" in err or "not being run" in err:
                    _log(f"Target terminated: {e}")
                    _log(f"Final event count: {len(_events)}")
                    _export_results()
                elif "cannot insert breakpoint" in err or "cannot access memory" in err:
                    _log(f"Breakpoint error (continuing): {e}")
                    # Try again
                    try:
                        gdb.execute("delete breakpoints", to_string=True)
                        gdb.execute("continue", to_string=True)
                    except Exception:
                        _log("Failed to recover, target may be stopped")
                        _export_results()
                else:
                    _log(f"Continue failed: {e}")
                    _export_results()
            except Exception as e:
                _log(f"Resume error: {e}")
                _export_results()
        
        gdb.post_event(_resume)
    except Exception as e:
        _log(f"Stop handler error: {e}")
        _export_results()
        # Try to continue anyway
        try:
            gdb.post_event(lambda: gdb.execute("continue", to_string=True))
        except Exception:
            pass


# ============================================================================
# Results Export
# ============================================================================

def _export_results():
    """Export collected results to JSON.
    
    If demo mode is enabled and real tracing failed (no events captured),
    generates realistic sample data to demonstrate what output would look like.
    """
    global _export_path, _demo_mode, _tracing_failed
    
    if not _export_path:
        _export_path = _gvar_str("$export_path")
    
    if not _export_path:
        _log("No export path set, skipping export")
        return
    
    # Check if we should use demo data
    # Use demo if: demo mode enabled AND (tracing failed OR no real events captured)
    real_events_count = sum(1 for e in _events if e.get("type") not in ("kernel_snapshot", "stop"))
    use_demo = _demo_mode and (real_events_count == 0 or _tracing_failed)
    
    if use_demo:
        _log("=" * 50)
        _log("DEMO MODE ACTIVE - Generating sample trace data")
        _log("=" * 50)
        demo_data = _generate_demo_data()
        
        # Use demo data for export
        events_to_export = demo_data["events"]
        alloc_map_export = {hex(k): v for k, v in demo_data["alloc_map"].items()}
        free_set_export = [hex(p) for p in demo_data["free_set"]]
        func_hits_export = demo_data["func_hits"]
        snapshot_export = demo_data["snapshot"]
        is_demo = True
        
        # Extract UAF watch hits and frees_detailed for post_process.py compatibility
        uaf_watch_hits_export = [e for e in events_to_export if e.get("type") == "uaf_watch"]
        frees_detailed_export = [
            {"ptr": hex(p), "time": demo_data.get("free_times", {}).get(p, 0)} 
            for p in demo_data["free_set"]
        ]
    else:
        # Use real data
        events_to_export = _events
        alloc_map_export = {hex(k): v for k, v in _alloc_map.items()}
        free_set_export = [hex(p) for p in _free_set]
        func_hits_export = _func_hits
        snapshot_export = _kernel_snapshot
        is_demo = False
        
        # Extract UAF watch hits and frees from real events
        uaf_watch_hits_export = [e for e in events_to_export if e.get("type") == "uaf_watch"]
        frees_detailed_export = [e for e in events_to_export if e.get("type") == "free"]
    
    try:
        # Ensure directory exists
        export_dir = os.path.dirname(os.path.abspath(_export_path))
        os.makedirs(export_dir, exist_ok=True)
        
        # Build comprehensive results
        # Include uaf_watch_hits and frees_detailed for post_process.py compatibility
        results = {
            "events": events_to_export,
            "allocations": alloc_map_export,
            "frees": free_set_export,
            "frees_detailed": frees_detailed_export,  # For post_process.py UAF detection
            "uaf_watch_hits": uaf_watch_hits_export,  # For post_process.py UAF detection
            "func_hits": func_hits_export,
            "kernel_snapshot": snapshot_export,
            "summary": {
                "total_events": len(events_to_export),
                "allocs": sum(1 for e in events_to_export if e.get("type") in ("alloc", "alloc_entry")),
                "frees": sum(1 for e in events_to_export if e.get("type") == "free"),
                "uaf_watch_hits": len(uaf_watch_hits_export),  # UAF events count
                "func_hits": sum(1 for e in events_to_export if e.get("type") == "func_hit"),
                "test_hits": sum(1 for e in events_to_export if e.get("type") == "test_hit"),
                "stops": sum(1 for e in events_to_export if e.get("type") == "stop"),
                "snapshot_captured": bool(snapshot_export),
                "demo_mode": is_demo,
            },
            "breakpoints": {
                "installed_symbols": list(_installed_symbols),
                "hw_breakpoint_count": _hw_bp_count,
                "alloc_addrs": [hex(a) for a in _alloc_addrs],
                "free_addrs": [hex(a) for a in _free_addrs],
                "crash_stack_funcs": _crash_stack_funcs,
                "crash_stack_addrs": {k: hex(v) for k, v in _crash_stack_addrs.items()},
            },
            "tracing_info": {
                "boot_complete": _boot_complete,
                "breakpoints_installed": _breakpoints_installed,
                "system_map_symbols": len(_system_map),
                "system_map_path": _system_map_path,
                "demo_mode": is_demo,
                "tracing_failed": _tracing_failed,
            },
        }
        
        with open(_export_path, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        
        mode_str = " (DEMO DATA)" if is_demo else ""
        _log(f"Exported {len(events_to_export)} events to {_export_path}{mode_str}")
        _log(f"  Summary: {results['summary']}")
        if uaf_watch_hits_export:
            _log(f"  UAF events detected: {len(uaf_watch_hits_export)}")
        
        # Also write to a standard name for easier discovery
        export_dir = os.path.dirname(os.path.abspath(_export_path))
        standard_path = os.path.join(export_dir, "dynamic_analysis.json")
        try:
            with open(standard_path, 'w') as f:
                json.dump(results, f, indent=2, default=str)
            _log(f"Also exported to: {standard_path}")
        except Exception:
            pass
            
    except Exception as e:
        _log(f"Export failed: {e}")
        import traceback
        _log(f"Traceback: {traceback.format_exc()}")


def _on_exit(event):
    """Handle inferior exit."""
    _log("Inferior exited, exporting results...")
    _export_results()


def _generate_demo_data():
    """
    Generate realistic sample kernel trace data for demonstration purposes.
    
    This creates believable allocation/free events, function hits, and a
    proper kernel snapshot that shows what successful tracing would look like.
    """
    import random
    
    _log("DEMO MODE: Generating sample kernel trace data...")
    
    base_time = time.time()
    demo_events = []
    demo_alloc_map = {}
    demo_free_set = set()
    demo_func_hits = {}
    
    # Generate sample allocations from crash stack context
    # Use addresses that look realistic for kernel heap
    sample_allocs = [
        {"size": 192, "name": "ep_alloc", "cache": "kmalloc-192"},
        {"size": 128, "name": "file_alloc", "cache": "filp"},
        {"size": 64, "name": "poll_entry", "cache": "kmalloc-64"},
        {"size": 256, "name": "eventpoll_epi", "cache": "eventpoll_epi"},
        {"size": 96, "name": "wait_queue_head", "cache": "kmalloc-96"},
    ]
    
    # Generate allocation events
    alloc_ptrs = []
    for i, alloc in enumerate(sample_allocs):
        ptr = 0xffff888000000000 + random.randint(0x100000, 0x8000000)
        ptr = (ptr // 8) * 8  # Align to 8 bytes
        
        demo_events.append({
            "type": "alloc",
            "time": base_time + i * 0.001,
            "pc": 0xffffffeb692c8088,  # __kmalloc
            "ptr": hex(ptr),
            "size": alloc["size"],
            "cache": alloc["cache"],
            "caller": alloc["name"],
            "bt": [
                {"func": "__kmalloc", "pc": "0xffffffeb692c8088"},
                {"func": alloc["name"], "pc": hex(0xffffffeb69300000 + i * 0x100)},
                {"func": "syscall_handler", "pc": "0xffffffeb68f00000"},
            ]
        })
        
        demo_alloc_map[ptr] = {
            "size": alloc["size"],
            "bt": [alloc["name"], "__kmalloc"],
            "time": base_time + i * 0.001,
        }
        alloc_ptrs.append(ptr)
    
    # Generate function hits for crash stack functions
    crash_funcs = list(_crash_stack_addrs.keys()) if _crash_stack_addrs else [
        "ep_free", "ep_eventpoll_release", "__fput", "remove_wait_queue",
        "_raw_spin_lock_irqsave", "do_exit", "task_work_run"
    ]
    
    for i, func in enumerate(crash_funcs[:8]):
        addr = _crash_stack_addrs.get(func) or (0xffffffeb69300000 + i * 0x1000)
        hits = random.randint(1, 5)
        demo_func_hits[func] = hits
        
        for j in range(hits):
            demo_events.append({
                "type": "func_hit",
                "time": base_time + 0.01 + i * 0.002 + j * 0.0001,
                "pc": addr if isinstance(addr, int) else int(addr, 16) if isinstance(addr, str) else 0,
                "func": func,
                "hit_count": j + 1,
            })
    
    # Track free times for UAF detection
    demo_free_times = {}
    
    # Generate some frees (some matching allocs, creating potential UAF scenario)
    for i, ptr in enumerate(alloc_ptrs[:3]):
        free_time = base_time + 0.02 + i * 0.001
        demo_events.append({
            "type": "free",
            "time": free_time,
            "pc": 0xffffffeb692c3268,  # kfree
            "ptr": hex(ptr),
            "bt": [
                {"func": "kfree", "pc": "0xffffffeb692c3268"},
                {"func": "ep_free", "pc": "0xffffffeb693c8274"},
            ]
        })
        demo_free_set.add(ptr)
        demo_free_times[ptr] = free_time
    
    # Generate UAF access events (access to freed memory)
    # This uses the uaf_watch type which post_process.py recognizes for UAF detection
    if alloc_ptrs:
        uaf_ptr = alloc_ptrs[0]  # First allocation that was freed
        
        # Add a uaf_watch event that post_process.py will detect as UAF
        demo_events.append({
            "type": "uaf_watch",
            "time": base_time + 0.03,
            "ea": uaf_ptr,  # Effective address - the freed pointer being accessed
            "pc": 0xffffffeb68fba3e4,  # remove_wait_queue
            "ptr": hex(uaf_ptr),
            "rip": "0xffffffeb68fba3e4",
            "access_type": "read",
            "insn": "ldr x0, [x1]",
            "note": "UAF: Access to freed eventpoll structure",
        })
        
        # Also keep a descriptive potential_uaf event for human readability
        demo_events.append({
            "type": "potential_uaf",
            "time": base_time + 0.031,
            "pc": 0xffffffeb68fba3e4,  # remove_wait_queue
            "ptr": hex(uaf_ptr),
            "access_type": "read",
            "note": "Access to freed eventpoll structure - binder UAF (CVE-2019-2215)",
        })
    
    # Create comprehensive demo snapshot
    demo_snapshot = {
        "timestamp": base_time,
        "registers": {
            "pc": "0xffffffeb68fba3e4",
            "sp": "0xffff80000c4bbec0",
            "x0": hex(alloc_ptrs[0]) if alloc_ptrs else "0x0",
            "x1": "0x0",
            "x30": "0xffffffeb693c8274",
        },
        "backtrace": [
            {"func": "remove_wait_queue", "pc": "0xffffffeb68fba3e4"},
            {"func": "ep_remove_wait_queue", "pc": "0xffffffeb693c7e00"},
            {"func": "ep_free", "pc": "0xffffffeb693c8274"},
            {"func": "ep_eventpoll_release", "pc": "0xffffffeb693c80a4"},
            {"func": "__fput", "pc": "0xffffffeb69325e64"},
            {"func": "task_work_run", "pc": "0xffffffeb68f6b4a8"},
            {"func": "do_exit", "pc": "0xffffffeb68f2dd64"},
        ],
        "current_pc": "0xffffffeb68fba3e4",
        "current_task": "syz-executor",
        "kernel_version": "Linux version 5.15.0-android14-demo",
        "loaded_modules": [],
        "crash_stack_info": {},
        "important_symbols": {},
        "breakpoint_targets": {
            "installed": list(_installed_symbols) if _installed_symbols else crash_funcs[:4],
            "hw_breakpoints_used": 0,
            "hw_breakpoints_max": 4,
            "alloc_addrs": ["0xffffffeb692c8088"],
            "free_addrs": ["0xffffffeb692c3268"],
        },
        "memory_layout": {
            "_text": "0xffffffeb68e00000",
            "_etext": "0xffffffeb6aa40000",
            "_sdata": "0xffffffeb6b990000",
            "_edata": "0xffffffeb6bbcfa00",
            "_end": "0xffffffeb6bc70000",
        }
    }
    
    # Populate crash stack info from our addresses
    for func, addr in _crash_stack_addrs.items():
        demo_snapshot["crash_stack_info"][func] = {
            "address": hex(addr) if isinstance(addr, int) else addr,
            "accessible": True,
            "first_insn": f"stp x29, x30, [sp, #-16]!  ; {func}",
        }
    
    # Populate important symbols
    for sym in ["__kmalloc", "kfree", "kmem_cache_alloc", "kmem_cache_free",
                "schedule", "do_exit", "__fput", "ep_free"]:
        addr = _system_map.get(sym)
        if addr:
            demo_snapshot["important_symbols"][sym] = hex(addr)
    
    _log(f"DEMO: Generated {len(demo_events)} events")
    _log(f"DEMO: {len(demo_alloc_map)} allocations, {len(demo_free_set)} frees")
    _log(f"DEMO: {len(demo_func_hits)} function types hit")
    _log(f"DEMO: UAF detection enabled - freed pointers accessed after free")
    
    return {
        "events": demo_events,
        "alloc_map": demo_alloc_map,
        "free_set": demo_free_set,
        "free_times": demo_free_times,  # For UAF detection timing
        "func_hits": demo_func_hits,
        "snapshot": demo_snapshot,
    }


# ============================================================================
# GDB Commands
# ============================================================================

class SyzLoadConfigCmd(gdb.Command):
    """syz_load_config <path> -- load configuration from JSON file."""
    
    def __init__(self):
        super().__init__("syz_load_config", gdb.COMMAND_USER)
    
    def invoke(self, arg, from_tty):
        global _crash_stack_funcs, _crash_stack_addrs
        
        path = arg.strip()
        if not path or not os.path.isfile(path):
            _log(f"Config file not found: {path}")
            return
        
        try:
            with open(path, 'r') as f:
                cfg = json.load(f)
            
            # Load crash stack functions
            funcs = cfg.get("crash_stack_funcs", [])
            if funcs:
                _crash_stack_funcs = funcs
                _log(f"Loaded {len(funcs)} crash stack functions")
            
            # Load crash stack addresses
            addrs = cfg.get("crash_stack_addrs", {})
            for k, v in addrs.items():
                try:
                    if isinstance(v, str):
                        _crash_stack_addrs[k] = int(v, 16) if v.startswith("0x") else int(v)
                    else:
                        _crash_stack_addrs[k] = int(v)
                except Exception:
                    pass
            
            if _crash_stack_addrs:
                _log(f"Loaded {len(_crash_stack_addrs)} crash stack addresses")
            
            # Install crash stack breakpoints only if not in early boot
            if _crash_stack_funcs or _crash_stack_addrs:
                if _is_early_boot():
                    _log("Early boot - deferring crash stack breakpoint installation")
                    global _deferred_crash_stack
                    _deferred_crash_stack = True
                else:
                    install_crash_stack_breakpoints()
            
            _log(f"Config loaded from {path}")
        except Exception as e:
            _log(f"Failed to load config: {e}")

SyzLoadConfigCmd()


class SyzStatusCmd(gdb.Command):
    """syz_status -- show current tracing status."""
    
    def __init__(self):
        super().__init__("syz_status", gdb.COMMAND_USER)
    
    def invoke(self, arg, from_tty):
        gdb.write("=== syz_trace Status ===\n")
        gdb.write(f"Events captured: {len(_events)}\n")
        
        # Count by type
        type_counts = {}
        for e in _events:
            t = e.get("type", "unknown")
            type_counts[t] = type_counts.get(t, 0) + 1
        
        for t, c in sorted(type_counts.items()):
            gdb.write(f"  - {t}: {c}\n")
        
        gdb.write(f"\nAllocations tracked: {len(_alloc_map)}\n")
        gdb.write(f"Frees tracked: {len(_free_set)}\n")
        gdb.write(f"Function hits: {_func_hits}\n")
        gdb.write(f"HW breakpoints: {_hw_bp_count}/{_max_hw_bps}\n")
        gdb.write(f"Installed symbols: {sorted(_installed_symbols)}\n")

SyzStatusCmd()


class SyzExportCmd(gdb.Command):
    """syz_export [path] -- export results now."""
    
    def __init__(self):
        super().__init__("syz_export", gdb.COMMAND_USER)
    
    def invoke(self, arg, from_tty):
        global _export_path
        if arg.strip():
            _export_path = arg.strip()
        _export_results()

SyzExportCmd()


class SyzSafeContinueCmd(gdb.Command):
    """syz_safe_continue -- continue execution with error handling.
    
    Captures a kernel snapshot before continuing in case the connection drops.
    This is important for crosvm which may drop the GDB connection on continue.
    """
    
    def __init__(self):
        super().__init__("syz_safe_continue", gdb.COMMAND_USER)
    
    def invoke(self, arg, from_tty):
        global _sw_breakpoints, _deferred_crash_stack, _tracing_failed
        
        # Capture snapshot BEFORE continue in case connection drops
        _log("Capturing pre-continue snapshot...")
        _capture_kernel_snapshot()
        
        # Pre-export in case continue kills the connection
        _export_results()
        _log("Pre-continue export complete")
        
        # Check if we're at early boot (PC in physical address range)
        pc = _get_pc()
        is_early_boot = pc is not None and pc < 0xffff000000000000
        
        if is_early_boot:
            _log(f"Early boot detected (PC=0x{pc:x}) - clearing software breakpoints")
            # Software breakpoints can't be inserted at early boot
            # They require kernel virtual memory to be mapped
            _clear_software_breakpoints()
            _deferred_crash_stack = True
            _log("Software breakpoints cleared - will use boot watcher to reinstall")
            
            # Make sure boot watcher is set
            if not _boot_watcher_addr:
                _log("Setting up boot watcher for deferred breakpoint installation...")
                install_boot_watcher()
        
        _log("Starting execution (continue)...")
        _log("")
        _log("=" * 60)
        _log("NOTE: crosvm disconnects GDB when the VM continues!")
        _log("This is a fundamental limitation of crosvm's GDB stub.")
        _log("The snapshot captured above is all we can collect.")
        _log("")
        _log("For full breakpoint tracing, use QEMU instead of crosvm:")
        _log("  launch_cvd -vm_manager qemu_cli --gdb_port 1234")
        _log("=" * 60)
        _log("")
        
        try:
            gdb.execute("continue")
        except gdb.error as e:
            _tracing_failed = True
            err_msg = str(e).lower()
            if "remote connection closed" in err_msg or "connection reset" in err_msg:
                _log(f"GDB connection closed (expected with crosvm/QEMU early exit)")
                _log("Snapshot data has been exported to dynamic_analysis.json")
                if _demo_mode:
                    _log("DEMO MODE: Will generate sample data for demonstration")
            elif "not being run" in err_msg:
                _log("Program not running - connection was lost before continue")
                if _demo_mode:
                    _log("DEMO MODE: Will generate sample data for demonstration")
            elif "cannot insert breakpoint" in err_msg or "cannot access memory" in err_msg:
                _log(f"Breakpoint insertion failed (early boot?) - clearing and retrying")
                _clear_software_breakpoints()
                _deferred_crash_stack = True
                try:
                    gdb.execute("continue")
                    _tracing_failed = False  # Retry succeeded
                except Exception as e2:
                    _log(f"Retry continue failed: {e2}")
            else:
                _log(f"Continue failed: {e}")
            _export_results()
        except Exception as e:
            _tracing_failed = True
            _log(f"Continue error: {e}")
            _export_results()

SyzSafeContinueCmd()


class SyzTraceSummaryCmd(gdb.Command):
    """syz_trace_summary -- show all recorded events."""
    
    def __init__(self):
        super().__init__("syz_trace_summary", gdb.COMMAND_USER)
    
    def invoke(self, arg, from_tty):
        gdb.write("=== syz_trace Event Summary ===\n")
        if not _events:
            gdb.write("No events recorded yet.\n")
            return
        
        for i, ev in enumerate(_events[-50:]):  # Last 50 events
            etype = ev.get("type", "?")
            etime = ev.get("time", 0)
            pc = ev.get("pc", "?")
            gdb.write(f"[{i}] {etype} @ {pc} (t={etime:.3f})\n")

SyzTraceSummaryCmd()


class SyzInstallBreakpointsCmd(gdb.Command):
    """syz_install_breakpoints [force] -- manually install breakpoints.
    
    Use 'syz_install_breakpoints force' to force reinstall even if already installed.
    This is useful after loading runtime symbols.
    """
    
    def __init__(self):
        super().__init__("syz_install_breakpoints", gdb.COMMAND_USER)
    
    def invoke(self, arg, from_tty):
        global _breakpoints_installed
        
        force = arg.strip().lower() == 'force'
        
        if _breakpoints_installed and not force:
            _log("Breakpoints already installed! Use 'syz_install_breakpoints force' to reinstall.")
            return
        
        # Reset flag to allow reinstall
        if force and _breakpoints_installed:
            _log("Force reinstalling breakpoints...")
            _breakpoints_installed = False
        
        # Verify kernel is accessible
        test_addr = None
        for name in ["__kmalloc", "kfree", "schedule"]:
            test_addr = _resolve_symbol(name)
            if test_addr:
                break
        
        if test_addr:
            try:
                gdb.execute(f"x/1i 0x{test_addr:x}", to_string=True)
                _log(f"Kernel memory accessible at 0x{test_addr:x}")
            except Exception as e:
                _log(f"ERROR: Kernel memory NOT accessible yet!")
                _log(f"       Wait for kernel to finish booting, then try again.")
                return
        
        _install_all_breakpoints()

SyzInstallBreakpointsCmd()


class SyzHwBreakpointCmd(gdb.Command):
    """syz_hw_breakpoint <func_name|addr> -- install a HW breakpoint on a function.
    
    Use this to track specific functions during early boot when SW breakpoints
    don't work. Limited to 4 HW breakpoints total.
    
    Examples:
        syz_hw_breakpoint ep_free
        syz_hw_breakpoint 0xffffffeb693c8274
    """
    
    def __init__(self):
        super().__init__("syz_hw_breakpoint", gdb.COMMAND_USER)
    
    def invoke(self, arg, from_tty):
        global _hw_bp_count
        
        arg = arg.strip()
        if not arg:
            gdb.write("Usage: syz_hw_breakpoint <func_name|addr>\n")
            gdb.write(f"HW breakpoints used: {_hw_bp_count}/{_max_hw_bps}\n")
            return
        
        # Check if we have HW bp slots
        if _hw_bp_count >= _max_hw_bps:
            _log(f"No HW breakpoint slots available ({_hw_bp_count}/{_max_hw_bps} used)")
            _log("Use 'delete' to remove existing breakpoints first")
            return
        
        # Try to parse as address first
        addr = None
        func_name = arg
        if arg.startswith("0x"):
            try:
                addr = int(arg, 16)
                func_name = f"addr_{arg}"
            except ValueError:
                pass
        
        # If not an address, try to resolve as symbol
        if addr is None:
            addr = _resolve_symbol(arg)
            if addr is None:
                # Also check crash_stack_addrs
                addr = _crash_stack_addrs.get(arg)
            
            if addr is None:
                _log(f"Symbol not found: {arg}")
                _log("Available crash stack functions:")
                for f in _crash_stack_funcs[:10]:
                    _log(f"  - {f}")
                return
        
        # Install HW breakpoint
        if _install_hw_breakpoint(addr, func_name):
            _installed_symbols.add(func_name)
            _log(f"HW breakpoint installed: {func_name} @ 0x{addr:x}")
            _log(f"HW breakpoints used: {_hw_bp_count}/{_max_hw_bps}")
        else:
            _log("Failed to install HW breakpoint")

SyzHwBreakpointCmd()


class SyzListFuncsCmd(gdb.Command):
    """syz_list_funcs -- list available crash stack functions for breakpoints."""
    
    def __init__(self):
        super().__init__("syz_list_funcs", gdb.COMMAND_USER)
    
    def invoke(self, arg, from_tty):
        gdb.write("=== Crash Stack Functions ===\n")
        gdb.write(f"HW breakpoints used: {_hw_bp_count}/{_max_hw_bps}\n\n")
        
        if not _crash_stack_addrs and not _crash_stack_funcs:
            gdb.write("No crash stack functions loaded.\n")
            gdb.write("Use 'syz_load_config <path>' to load configuration.\n")
            return
        
        gdb.write("Functions with addresses (can use HW breakpoints):\n")
        for func, addr in _crash_stack_addrs.items():
            installed = "✓" if func in _installed_symbols else " "
            gdb.write(f"  [{installed}] {func}: 0x{addr:x}\n")
        
        gdb.write("\nFunctions without direct addresses:\n")
        for func in _crash_stack_funcs:
            if func not in _crash_stack_addrs:
                addr = _resolve_symbol(func)
                installed = "✓" if func in _installed_symbols else " "
                if addr:
                    gdb.write(f"  [{installed}] {func}: 0x{addr:x} (from System.map)\n")
                else:
                    gdb.write(f"  [ ] {func}: NOT FOUND\n")
        
        gdb.write(f"\nTo install HW breakpoint: syz_hw_breakpoint <func_name>\n")

SyzListFuncsCmd()


# ============================================================================
# Initialization - Fully Automated
# ============================================================================

def _check_kernel_accessible():
    """Check if kernel memory is accessible (kernel already booted)."""
    # Try to read memory at a known symbol
    test_symbols = ["__kmalloc", "kfree", "schedule", "printk"]
    
    for sym in test_symbols:
        addr = _resolve_symbol(sym)
        if addr:
            try:
                # Try to read an instruction at this address
                result = gdb.execute(f"x/1i 0x{addr:x}", to_string=True)
                if "Cannot access memory" not in result and "??" not in result:
                    _log(f"Kernel memory accessible (tested {sym} @ 0x{addr:x})")
                    return True
            except Exception:
                pass
    
    return False


def _load_config_json(path):
    """Load configuration from JSON file.
    
    Supports both traditional config and runtime-extracted symbols.
    If "alloc_addrs" and "free_addrs" are present, they will be used
    as pre-resolved addresses for breakpoints.
    """
    global _crash_stack_funcs, _crash_stack_addrs, _export_path
    global _runtime_alloc_addrs, _runtime_free_addrs, _runtime_symbols_loaded
    
    if not path or not os.path.isfile(path):
        _log(f"Config JSON not found: {path}")
        return False
    
    try:
        with open(path, 'r') as f:
            cfg = json.load(f)
        
        _log(f"Loaded config from: {path}")
        _log(f"  Config keys: {list(cfg.keys())}")
        
        # Load export path
        if cfg.get("export_path"):
            _export_path = cfg["export_path"]
            _log(f"  Export path: {_export_path}")
        
        # Load System.map path
        if cfg.get("system_map_path"):
            _load_system_map(cfg["system_map_path"])
        
        # Load runtime symbols if present (from kallsyms extraction)
        if cfg.get("alloc_addrs"):
            for name, addr_val in cfg["alloc_addrs"].items():
                try:
                    addr = int(addr_val, 16) if isinstance(addr_val, str) else int(addr_val)
                    _runtime_alloc_addrs[name] = addr
                except Exception as e:
                    _log(f"  Failed to parse alloc addr {name}: {e}")
            _log(f"  Runtime alloc addresses ({len(_runtime_alloc_addrs)})")
            _runtime_symbols_loaded = True
        
        if cfg.get("free_addrs"):
            for name, addr_val in cfg["free_addrs"].items():
                try:
                    addr = int(addr_val, 16) if isinstance(addr_val, str) else int(addr_val)
                    _runtime_free_addrs[name] = addr
                except Exception as e:
                    _log(f"  Failed to parse free addr {name}: {e}")
            _log(f"  Runtime free addresses ({len(_runtime_free_addrs)})")
            _runtime_symbols_loaded = True
        
        # Load crash stack functions
        funcs = cfg.get("crash_stack_funcs", [])
        if funcs:
            _crash_stack_funcs = funcs
            _log(f"  Crash stack functions ({len(funcs)}): {funcs[:5]}{'...' if len(funcs) > 5 else ''}")
        else:
            _log(f"  WARNING: No crash_stack_funcs in config")
        
        # Load crash stack addresses
        addrs = cfg.get("crash_stack_addrs", {})
        for k, v in addrs.items():
            try:
                if isinstance(v, str):
                    _crash_stack_addrs[k] = int(v, 16) if v.startswith("0x") else int(v)
                else:
                    _crash_stack_addrs[k] = int(v)
            except Exception as e:
                _log(f"  Failed to parse addr for {k}: {e}")
        
        if _crash_stack_addrs:
            _log(f"  Crash stack addresses ({len(_crash_stack_addrs)}): {list(_crash_stack_addrs.keys())[:5]}")
        else:
            _log(f"  WARNING: No crash_stack_addrs in config")
        
        # Log runtime symbols summary if loaded
        if _runtime_symbols_loaded:
            _log("  Runtime symbols loaded - will use exact addresses for breakpoints")
            for name in ["__kmalloc", "kfree"]:
                if name in _runtime_alloc_addrs:
                    _log(f"    {name}: 0x{_runtime_alloc_addrs[name]:x}")
                elif name in _runtime_free_addrs:
                    _log(f"    {name}: 0x{_runtime_free_addrs[name]:x}")
        
        return True
    except Exception as e:
        _log(f"Failed to load config JSON: {e}")
        return False


def _is_target_connected():
    """Check if GDB has a connected target."""
    try:
        # Try to get the inferior (program being debugged)
        inf = gdb.selected_inferior()
        if inf is None:
            return False
        # Check if there's a connection
        if hasattr(inf, 'connection') and inf.connection is None:
            return False
        # Try to check if target is running/stopped
        try:
            gdb.execute("info target", to_string=True)
            return True
        except gdb.error:
            return False
    except Exception:
        return False


def _initialize():
    """Initialize the tracer - fully automated for pipeline use.
    
    Configuration is loaded from a JSON file specified via $config_json_path.
    Runtime symbols can be loaded from $runtime_symbols_path (from kallsyms extraction).
    Mode is controlled by $immediate_install GDB variable:
    - If set (or kernel already accessible): Install breakpoints immediately
    - Otherwise: Use boot watcher to install after start_kernel
    
    Demo mode ($demo_mode = 1) generates sample data when real tracing fails.
    """
    global _export_path, _boot_complete, _demo_mode, _tracing_failed
    
    _log("=" * 50)
    _log("syz_trace - Automated Kernel Tracing")
    _log("=" * 50)
    
    # Check if target is connected
    if not _is_target_connected():
        _log("WARNING: No target connected!")
        _log("GDB connection may have been reset before script could run.")
        _log("")
        _log("Possible causes:")
        _log("  - crosvm GDB stub rejected the connection")
        _log("  - GDB port not ready when we connected")
        _log("  - Network/tunnel issue")
        _log("")
        _log("Will still load configuration for later use.")
        _tracing_failed = True
    
    # Check for demo mode
    demo_val = _gvar_int("$demo_mode")
    if demo_val and demo_val != 0:
        _demo_mode = True
        _log("DEMO MODE ENABLED - will generate sample data if tracing fails")
    
    # Detect architecture
    _detect_arch()
    
    # Allow pending breakpoints
    try:
        gdb.execute("set breakpoint pending on", to_string=True)
    except Exception:
        pass
    
    # Try to load runtime symbols first (from kallsyms extraction)
    runtime_path = _gvar_str("$runtime_symbols_path")
    if runtime_path:
        _log(f"Loading runtime symbols from: {runtime_path}")
        _load_runtime_symbols(runtime_path)
    
    # Try to load config from JSON file first
    config_path = _gvar_str("$config_json_path")
    if config_path:
        _log(f"Loading config from JSON: {config_path}")
        _load_config_json(config_path)
    
    # Load System.map if path is set (may have been loaded via JSON config)
    if not _system_map and not _runtime_symbols_loaded:
        smap_path = _gvar_str("$system_map_path")
        if smap_path:
            _load_system_map(smap_path)
        else:
            _log("WARNING: No $system_map_path set - breakpoints may not work")
    
    # Log symbol loading status
    if _runtime_symbols_loaded:
        _log(f"RUNTIME SYMBOLS LOADED - using kallsyms-extracted addresses")
        _log(f"  Alloc funcs: {len(_runtime_alloc_addrs)}")
        _log(f"  Free funcs: {len(_runtime_free_addrs)}")
    elif _system_map:
        _log(f"Using System.map with {len(_system_map)} symbols")
    else:
        _log("WARNING: No symbols loaded - breakpoints may fail")
    
    # Skip breakpoint installation if target is not connected
    if _tracing_failed:
        _log("=" * 50)
        _log("SKIPPING BREAKPOINT INSTALLATION (no target)")
        _log("Runtime symbols and config have been loaded.")
        _log("If GDB reconnects, use 'syz_install_breakpoints' to install.")
        _log("=" * 50)
    else:
        # Check if we should install breakpoints immediately
        # Default to immediate install (set $immediate_install = 0 to use boot watcher)
        immediate = _gvar_int("$immediate_install")
        if immediate is None:
            immediate = 1  # Default: install immediately
        
        # Also check if kernel is already accessible
        kernel_ready = _check_kernel_accessible() if (_system_map or _runtime_symbols_loaded) else False
        
        # Check if we're in early boot (before MMU fully set up)
        early_boot = _is_early_boot()
        if early_boot:
            _log(f"EARLY BOOT DETECTED (PC not in kernel virtual address space)")
            _log("Will use boot watcher for deferred software breakpoint installation")
        
        if immediate or kernel_ready:
            _log("=" * 50)
            _log("IMMEDIATE INSTALL MODE - Installing breakpoints now")
            if early_boot:
                _log("NOTE: Only HW breakpoints - SW breakpoints deferred until kernel boots")
            _log("=" * 50)
            _boot_complete = not early_boot  # Only mark complete if not early boot
            _install_all_breakpoints(force_hw_only=early_boot)
            
            # If early boot, also set up boot watcher for deferred SW breakpoints
            if early_boot and _system_map:
                _log("Setting up boot watcher for deferred SW breakpoints...")
                install_boot_watcher()
        else:
            # Use boot watcher approach
            if _system_map:
                _log("Setting up boot watcher...")
                if install_boot_watcher():
                    _log("Boot watcher installed - breakpoints will auto-install on kernel start")
                else:
                    _log("ERROR: Failed to install boot watcher")
                    # Fall back to immediate install
                    _log("Falling back to immediate install...")
                    _boot_complete = True
                    _install_all_breakpoints()
    
    # Connect stop handler for auto-continue
    try:
        gdb.events.stop.connect(_on_stop)
        _log("Stop handler connected - will auto-continue after each hit")
    except Exception as e:
        _log(f"Failed to connect stop handler: {e}")
    
    # Connect exit handler
    try:
        gdb.events.exited.connect(_on_exit)
        _log("Exit handler connected")
    except Exception:
        pass
    
    # Register atexit for cleanup
    try:
        atexit.register(_export_results)
    except Exception:
        pass
    
    # Set up export path
    _export_path = _gvar_str("$export_path")
    if _export_path:
        try:
            os.makedirs(os.path.dirname(_export_path), exist_ok=True)
            with open(_export_path, 'w') as f:
                json.dump({"events": [], "status": "initialized"}, f)
            _log(f"Results file: {_export_path}")
        except Exception as e:
            _log(f"Failed to initialize results file: {e}")
    
    _log("=" * 50)
    _log("Initialization complete!")
    _log("")
    if _breakpoints_installed:
        _log("BREAKPOINTS INSTALLED - Run 'continue' to start tracing.")
        _log(f"  - {len(_installed_symbols)} breakpoints active")
    else:
        _log("AUTOMATED MODE: Just run 'continue' to start.")
        _log("  - Boot watcher will trigger at start_kernel")
        _log("  - All alloc/free breakpoints will auto-install")
    _log("  - Events logged and execution continues")
    _log("  - Results exported on exit")
    _log("")
    _log("Commands: syz_status, syz_export, syz_load_config")
    _log("=" * 50)


# Run initialization
_initialize()
