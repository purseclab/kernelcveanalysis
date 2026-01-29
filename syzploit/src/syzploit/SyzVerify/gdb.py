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
# System.map Loading
# ============================================================================

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


def _resolve_symbol(name):
    """Resolve symbol name to address."""
    return _system_map.get(name)


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
        spec = f"*0x{addr:x}"
        super().__init__(spec, gdb.BP_BREAKPOINT, internal=False)
        self.silent = True
        self.name = name
        self.hit_count = 0
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

def _install_hw_breakpoint(addr, name):
    """Install a hardware breakpoint at address. Returns True on success."""
    global _hw_bp_count
    
    if _hw_bp_count >= _max_hw_bps:
        _log(f"HW breakpoint limit reached ({_max_hw_bps}), skipping {name}")
        return False
    
    try:
        gdb.execute(f"hbreak *0x{addr:x}", to_string=True)
        _hw_bp_count += 1
        _log(f"Installed HW breakpoint: {name} @ 0x{addr:x} ({_hw_bp_count}/{_max_hw_bps})")
        return True
    except Exception as e:
        _log(f"Failed to install HW breakpoint {name}: {e}")
        return False


def install_alloc_breakpoints():
    """Install breakpoints on alloc/free functions using hardware breakpoints."""
    
    # Priority list - most important functions first (we only have 4 HW breakpoints)
    # Format: (gdb_var, symbol_name, is_alloc)
    functions = [
        ("$kmalloc_addr", "__kmalloc", True),
        ("$kfree_addr", "kfree", False),
        ("$kmem_cache_alloc_addr", "kmem_cache_alloc", True),
        ("$kmem_cache_free_addr", "kmem_cache_free", False),
    ]
    
    installed = 0
    
    for var, name, is_alloc in functions:
        if name in _installed_symbols:
            continue
        
        # Try GDB variable first, then System.map
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


def install_crash_stack_breakpoints():
    """Install breakpoints on crash stack functions."""
    installed = 0
    
    # Address-based first (more reliable)
    for func_name, addr in _crash_stack_addrs.items():
        if func_name in _installed_symbols:
            continue
        try:
            FuncBreakpoint(addr, func_name)
            _installed_symbols.add(func_name)
            installed += 1
        except Exception as e:
            _log(f"Failed to install crash stack bp {func_name}: {e}")
    
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
            except Exception as e:
                _log(f"Failed to install {func_name}: {e}")
    
    if installed:
        _log(f"Installed {installed} crash stack breakpoints")
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


def _install_all_breakpoints():
    """Install all breakpoints - called after kernel boots."""
    global _breakpoints_installed, _hw_bp_count
    
    if _breakpoints_installed:
        return
    
    _log("=" * 50)
    _log("KERNEL BOOTED - Installing HW breakpoints...")
    _log("=" * 50)
    
    # Reset HW bp count (boot watcher was deleted)
    _hw_bp_count = 0
    
    # Install alloc/free breakpoints (uses HW breakpoints)
    install_alloc_breakpoints()
    
    # Note: We skip test breakpoint to save HW breakpoint slots
    # install_test_breakpoint()
    
    # Skip crash stack breakpoints for now (would exceed HW limit)
    # if _crash_stack_funcs or _crash_stack_addrs:
    #     install_crash_stack_breakpoints()
    
    _breakpoints_installed = True
    _log(f"Tracing active! Using {_hw_bp_count} HW breakpoints.")


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
    global _boot_complete, _boot_watcher_addr
    
    try:
        pc = _get_pc()
        
        # Check if this is the boot watcher hit
        if not _boot_complete and _boot_watcher_addr and pc == _boot_watcher_addr:
            _log(f"*** BOOT WATCHER HIT @ 0x{pc:x} - kernel is starting ***")
            _boot_complete = True
            
            # Delete the boot watcher breakpoint (it's breakpoint 1)
            try:
                gdb.execute("delete 1", to_string=True)
                _log("Cleared boot watcher breakpoint")
            except Exception:
                pass
            
            # Install all tracing breakpoints now that memory is mapped
            _install_all_breakpoints()
        
        # If breakpoints are installed, log the event
        elif _breakpoints_installed and pc:
            # Check if it's an alloc or free
            if pc in _alloc_addrs:
                try:
                    size = _get_arg(0)  # First arg is usually size
                    bt = _get_backtrace(8)
                    _record_event("alloc_entry", pc=hex(pc), size=size, bt=bt)
                    _log(f"ALLOC @ 0x{pc:x} size={size}")
                except Exception as e:
                    _log(f"Alloc logging error: {e}")
            elif pc in _free_addrs:
                try:
                    ptr = _get_arg(0)  # First arg is pointer
                    bt = _get_backtrace(8)
                    was_allocated = ptr in _alloc_map if ptr else False
                    _record_event("free", pc=hex(pc), ptr=hex(ptr) if ptr else None, 
                                 was_allocated=was_allocated, bt=bt)
                    _log(f"FREE @ 0x{pc:x} ptr=0x{ptr:x if ptr else 0}")
                    if ptr:
                        _free_set.add(ptr)
                        _alloc_map.pop(ptr, None)
                except Exception as e:
                    _log(f"Free logging error: {e}")
            else:
                # Generic stop event
                _record_event("stop", pc=hex(pc))
        
        # Auto-continue
        def _resume():
            try:
                gdb.execute("continue", to_string=True)
            except gdb.error as e:
                err = str(e).lower()
                if "remote connection closed" in err or "not being run" in err:
                    _log(f"Target terminated: {e}")
                    _export_results()
                elif "cannot insert breakpoint" in err or "cannot access memory" in err:
                    _log(f"Breakpoint error (continuing): {e}")
                    # Try again
                    try:
                        gdb.execute("delete breakpoints", to_string=True)
                        gdb.execute("continue", to_string=True)
                    except Exception:
                        _log("Failed to recover, target may be stopped")
                else:
                    _log(f"Continue failed: {e}")
            except Exception as e:
                _log(f"Resume error: {e}")
        
        gdb.post_event(_resume)
    except Exception as e:
        _log(f"Stop handler error: {e}")
        # Try to continue anyway
        try:
            gdb.post_event(lambda: gdb.execute("continue", to_string=True))
        except Exception:
            pass


# ============================================================================
# Results Export
# ============================================================================

def _export_results():
    """Export collected results to JSON."""
    global _export_path
    
    if not _export_path:
        _export_path = _gvar_str("$export_path")
    
    if not _export_path:
        _log("No export path set, skipping export")
        return
    
    try:
        os.makedirs(os.path.dirname(_export_path), exist_ok=True)
        
        results = {
            "events": _events,
            "allocations": {hex(k): v for k, v in _alloc_map.items()},
            "frees": [hex(p) for p in _free_set],
            "func_hits": _func_hits,
            "summary": {
                "total_events": len(_events),
                "allocs": sum(1 for e in _events if e.get("type") == "alloc"),
                "frees": sum(1 for e in _events if e.get("type") == "free"),
                "func_hits": sum(1 for e in _events if e.get("type") == "func_hit"),
                "test_hits": sum(1 for e in _events if e.get("type") == "test_hit"),
            }
        }
        
        with open(_export_path, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        
        _log(f"Exported {len(_events)} events to {_export_path}")
    except Exception as e:
        _log(f"Export failed: {e}")


def _on_exit(event):
    """Handle inferior exit."""
    _log("Inferior exited, exporting results...")
    _export_results()


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
            
            # Install crash stack breakpoints now
            if _crash_stack_funcs or _crash_stack_addrs:
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
    """syz_safe_continue -- continue execution with error handling."""
    
    def __init__(self):
        super().__init__("syz_safe_continue", gdb.COMMAND_USER)
    
    def invoke(self, arg, from_tty):
        try:
            gdb.execute("continue")
        except gdb.error as e:
            _log(f"Continue failed: {e}")
            _export_results()
        except Exception as e:
            _log(f"Continue error: {e}")

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
    """syz_install_breakpoints -- manually install breakpoints (if boot watcher didn't trigger)."""
    
    def __init__(self):
        super().__init__("syz_install_breakpoints", gdb.COMMAND_USER)
    
    def invoke(self, arg, from_tty):
        if _breakpoints_installed:
            _log("Breakpoints already installed!")
            return
        
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


def _initialize():
    """Initialize the tracer - fully automated for pipeline use.
    
    Mode is controlled by $immediate_install GDB variable:
    - If set (or kernel already accessible): Install breakpoints immediately
    - Otherwise: Use boot watcher to install after start_kernel
    """
    global _export_path, _boot_complete
    
    _log("=" * 50)
    _log("syz_trace - Automated Kernel Tracing")
    _log("=" * 50)
    
    # Detect architecture
    _detect_arch()
    
    # Allow pending breakpoints
    try:
        gdb.execute("set breakpoint pending on", to_string=True)
    except Exception:
        pass
    
    # Load System.map if path is set
    smap_path = _gvar_str("$system_map_path")
    if smap_path:
        _load_system_map(smap_path)
    else:
        _log("WARNING: No $system_map_path set - breakpoints may not work")
    
    # Check if we should install breakpoints immediately
    # Default to immediate install (set $immediate_install = 0 to use boot watcher)
    immediate = _gvar_int("$immediate_install")
    if immediate is None:
        immediate = 1  # Default: install immediately
    
    # Also check if kernel is already accessible
    kernel_ready = _check_kernel_accessible() if _system_map else False
    
    if immediate or kernel_ready:
        _log("=" * 50)
        _log("IMMEDIATE INSTALL MODE - Installing breakpoints now")
        _log("=" * 50)
        _boot_complete = True
        _install_all_breakpoints()
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
