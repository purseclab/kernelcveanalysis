# syz_trace.py (patched to only monitor after poc_entry)

import gdb
import re
import time

# Monitor mode toggle injected by dynamic.py as `monitor_mode` in config header
try:
    from typing import Any
except Exception:
    pass
try:
    monitor_mode = bool(int(gdb.parse_and_eval('$monitor_mode')))
except Exception:
    monitor_mode = False
try:
    monitor_always = bool(int(gdb.parse_and_eval('$monitor_always')))
except Exception:
    # Default to always monitor to handle cases without userspace gating
    monitor_always = True

# ---------- configuration helpers ----------
def conv_u64(v):
    try:
        return int(v)
    except Exception:
        s = str(v)
        if s.startswith("0x"):
            return int(s, 16)
        return int(s)

def gvar(name):
    try:
        return gdb.parse_and_eval(name)
    except Exception:
        return None

_poc_entry_v = gvar("$poc_entry")
_fault_addr_v = gvar("$fault_addr")
_access_type_v = gvar("$access_type")
_access_size_v = gvar("$access_size")
_fault_insn_v = gvar("$fault_insn")
_enable_alloc_track = True
_enable_kasan_check = True

poc_entry = str(_poc_entry_v) if _poc_entry_v is not None else None
fault_addr = None
if _fault_addr_v is not None:
    try:
        fault_addr = conv_u64(_fault_addr_v)
    except Exception:
        fault_addr = None
access_type = str(_access_type_v) if _access_type_v is not None else "any"
try:
    access_size = int(_access_size_v) if _access_size_v is not None else 0
except Exception:
    access_size = 0
fault_insn = None
if _fault_insn_v is not None:
    try:
        fault_insn = conv_u64(_fault_insn_v)
    except Exception:
        fault_insn = None

# Guest SSH config for guest-clock timestamping
_guest_ssh_port_v = gvar('$guest_ssh_port')
_guest_ssh_user_v = gvar('$guest_ssh_user')
try:
    guest_ssh_port = int(_guest_ssh_port_v) if _guest_ssh_port_v is not None else 10021
except Exception:
    guest_ssh_port = 10021
guest_ssh_user = str(_guest_ssh_user_v) if _guest_ssh_user_v is not None else 'root'
guest_ssh_key = None

# Compute guest time offset once, then reuse to avoid SSH roundtrips
_guest_time_offset = None
def _compute_guest_time_offset():
    global _guest_time_offset
    try:
        import subprocess
        cmd = ['ssh', '-o', 'StrictHostKeyChecking=no', '-p', str(guest_ssh_port)]
        if guest_ssh_key:
            cmd += ['-i', guest_ssh_key]
        cmd += [f'{guest_ssh_user}@127.0.0.1', 'date +%s.%N']
        start = time.time()
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=5)
        if proc.returncode == 0:
            out = (proc.stdout or '').strip()
            try:
                guest_now = float(out)
                host_now = start
                _guest_time_offset = guest_now - host_now
            except Exception:
                _guest_time_offset = 0.0
        else:
            _guest_time_offset = 0.0
    except Exception:
        _guest_time_offset = 0.0

def _guest_time():
    try:
        if _guest_time_offset is None:
            _compute_guest_time_offset()
        return time.time() + (_guest_time_offset or 0.0)
    except Exception:
        return time.time()

# Resolve optional alloc/free addresses for hardware breakpoints (no symbols loaded)
_kmalloc_addr_v = gvar("$kmalloc_addr")
_kfree_addr_v = gvar("$kfree_addr")
_vfree_addr_v = gvar("$vfree_addr")
kmalloc_addr = None
kfree_addr = None
vfree_addr = None
try:
    if _kmalloc_addr_v is not None:
        kmalloc_addr = conv_u64(_kmalloc_addr_v)
except Exception:
    kmalloc_addr = None
try:
    if _kfree_addr_v is not None:
        kfree_addr = conv_u64(_kfree_addr_v)
except Exception:
    kfree_addr = None
try:
    if _vfree_addr_v is not None:
        vfree_addr = conv_u64(_vfree_addr_v)
except Exception:
    vfree_addr = None

alloc_addrs = set([a for a in (kmalloc_addr,) if a])
free_addrs = set([a for a in (kfree_addr, vfree_addr) if a])

gdb.write("syz_trace: configuration\n", gdb.STDERR)
gdb.write("  poc_entry = %s\n" % (poc_entry,), gdb.STDERR)
gdb.write("  fault_addr = %s\n" % (hex(fault_addr) if fault_addr else "None"), gdb.STDERR)
gdb.write("  access_type = %s\n" % (access_type,), gdb.STDERR)
gdb.write("  access_size = %s\n" % (access_size if access_size else "any"), gdb.STDERR)
gdb.write("  fault_insn = %s\n" % (hex(fault_insn) if fault_insn else "None"), gdb.STDERR)
gdb.write("\n", gdb.STDERR)

alloc_map = {}
free_set = set()
hit_events = []
free_events = []
alloc_ts_map = {}
uaf_watch_hits = []
_installed_free_watches = set()
_max_free_watchpoints = 4

# Optional verifier: monitor specific functions/fields from crash log
_path_verify_enabled_v = gvar('$path_verify')
try:
    path_verify_enabled = bool(int(_path_verify_enabled_v)) if _path_verify_enabled_v is not None else True
except Exception:
    path_verify_enabled = True

def _struct_field_offset(typename, fieldname):
    try:
        t = gdb.lookup_type(typename)
        if not t:
            return None
        for f in t.fields():
            try:
                if f.name == fieldname:
                    # bitpos is in bits; convert to bytes
                    return int(getattr(f, 'bitpos', 0)) // 8
            except Exception:
                continue
        return None
    except Exception:
        return None

# Compute offset for struct file->f_count via DWARF; fallback to convenience var or None
_file_f_count_offset_v = gvar('$file_f_count_offset')
file_f_count_offset = _struct_field_offset('struct file', 'f_count')
try:
    if file_f_count_offset is None and _file_f_count_offset_v is not None:
        file_f_count_offset = int(_file_f_count_offset_v)
except Exception:
    pass

# Generic bug offset from analysis (bytes inside object)
_bug_offset_v = gvar('$bug_offset')
bug_offset = None
try:
    if _bug_offset_v is not None:
        bug_offset = int(_bug_offset_v)
except Exception:
    bug_offset = None

# Object cache metadata (optional)
_object_cache_size_v = gvar('$object_cache_size')
object_cache_size = None
try:
    if _object_cache_size_v is not None:
        object_cache_size = int(_object_cache_size_v)
except Exception:
    object_cache_size = None

# Track installed path symbols to avoid duplicates
_installed_path_syms = set()

# ---------------- System.map support ----------------
_system_map_path_v = gvar('$system_map_path')
_system_map_path = str(_system_map_path_v) if _system_map_path_v is not None else None
_system_map = None

def _load_system_map(path):
    global _system_map
    try:
        m = {}
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                try:
                    parts = line.strip().split()
                    if len(parts) >= 3:
                        addr_s, sym_type, name = parts[0], parts[1], parts[2]
                        # address is hex string
                        a = int(addr_s, 16)
                        m[name] = a
                except Exception:
                    continue
        _system_map = m
        gdb.write(f"[syz_trace] loaded System.map entries: {len(m)}\n", gdb.STDERR)
    except Exception as e:
        gdb.write(f"[syz_trace] failed to load System.map: {e}\n", gdb.STDERR)
        _system_map = {}

def _resolve_addr(sym):
    try:
        if _system_map is None and _system_map_path:
            _load_system_map(_system_map_path)
        if _system_map and sym in _system_map:
            return int(_system_map[sym])
    except Exception:
        pass
    return None

def _set_hw_bp_addr(addr, label=None):
    try:
        gdb.execute("hbreak *0x%x" % int(addr), to_string=True)
        if label:
            gdb.write("[syz_trace] installed HARDWARE bp at %s 0x%x\n" % (label, int(addr)), gdb.STDERR)
        else:
            gdb.write("[syz_trace] installed HARDWARE bp at 0x%x\n" % int(addr), gdb.STDERR)
        return True
    except Exception:
        return False

def _set_hw_bp_for_symbol(sym):
    try:
        addr = _resolve_addr(sym)
        if addr is not None:
            return _set_hw_bp_addr(addr, sym)
    except Exception:
        pass
    return False

# New global toggle: monitor immediately if monitor_always, monitor_mode, or no poc_entry provided
poc_reached = bool(monitor_always or monitor_mode or (poc_entry is None))

def _bt(max_frames=10):
    frames = []
    i = 0
    f = gdb.newest_frame()
    while f and i < max_frames:
        try:
            sym = f.name() or "<unknown>"
        except Exception:
            sym = "<unknown>"
        sal = f.find_sal()
        fileline = "%s:%s" % (sal.symtab.filename, sal.line) if sal and sal.symtab else ""
        frames.append("%s %s" % (sym, fileline))
        i += 1
        f = f.older()
    return frames

def dump_regs():
    regs = {}
    for r in ["rip","rsp","rbp","rax","rbx","rcx","rdx","rsi","rdi","r8","r9","r10","r11","r12","r13","r14","r15"]:
        try:
            regs[r] = gdb.parse_and_eval("$" + r)
        except Exception:
            regs[r] = "<na>"
    return regs

def mem_read(addr, size):
    try:
        inferior = gdb.selected_inferior()
        data = inferior.read_memory(addr, size)
        return bytes(data)
    except Exception:
        return None

def _thread_ptid():
    try:
        t = gdb.selected_thread()
        if not t:
            return None
        ptid = t.ptid
        if isinstance(ptid, tuple) and len(ptid) >= 2:
            return f"{ptid[0]}.{ptid[1]}"
        return str(ptid)
    except Exception:
        return None

def _insn_str():
    try:
        s = gdb.execute('x/i $rip', to_string=True)
        return s.strip()
    except Exception:
        return ""

def _parse_expr_addr(expr):
    try:
        import re as _re
        m = _re.search(r"0x[0-9a-fA-F]+", expr)
        if m:
            return int(m.group(0), 16)
        m2 = _re.search(r"\b\d+\b", expr)
        if m2:
            return int(m2.group(0))
    except Exception:
        pass
    return None

# ---------------- NEW: poc_entry gating breakpoint ----------------
class PocEntryBreakpoint(gdb.Breakpoint):
    def __init__(self, spec):
        super().__init__(spec, gdb.BP_BREAKPOINT, internal=False)
        self.silent = True

    def stop(self):
        global poc_reached
        poc_reached = True
        gdb.write("[syz_trace] poc_entry reached, enabling instrumentation\n", gdb.STDERR)
        return False


# ---------------- Breakpoints patched with gating ----------------
class AllocBp(gdb.Breakpoint):
    def __init__(self, spec, is_alloc=True):
        super().__init__(spec, gdb.BP_BREAKPOINT, internal=False)
        self.is_alloc = is_alloc
        self.silent = True
    def stop(self):
        if not poc_reached:
            return False
        try:
            if self.is_alloc:
                size = None
                try:
                    size = int(gdb.parse_and_eval("((unsigned long)$rdi)"))
                except Exception:
                    try:
                        size = int(gdb.parse_and_eval("((unsigned long)$rsi)"))
                    except Exception:
                        size = None
                regs = dump_regs()
                frames = _bt(8)
                gdb.write("[syz_trace] alloc detected size=%s\n" % (size,), gdb.STDERR)
                try:
                    AllocRetBp(gdb.newest_frame(), size, frames)
                except Exception:
                    pass
                return False
            else:
                try:
                    p = int(gdb.parse_and_eval("((unsigned long)$rdi)"))
                except Exception:
                    p = None
                if p:
                    free_set.add(p)
                    gdb.write("[syz_trace] free detected %s\n" % (hex(p),), gdb.STDERR)
                    try:
                        if len(_installed_free_watches) < _max_free_watchpoints and p not in _installed_free_watches:
                            _installed_free_watches.add(p)
                            FreePtrWatchpoint(p)
                    except Exception:
                        pass
                return False
        except Exception as e:
            gdb.write("[syz_trace] allocbp error: %s\n" % e, gdb.STDERR)
        return False

class AllocRetBp(gdb.FinishBreakpoint):
    def __init__(self, frame, size, frames):
        super().__init__(frame, internal=True)
        self.size = size
        self.frames = frames
    def stop(self):
        if not poc_reached:
            return False
        try:
            p = int(gdb.parse_and_eval("((unsigned long)$rax)"))
            alloc_map[p] = (self.size, self.frames)
            alloc_ts_map[p] = _guest_time()
            gdb.write("[syz_trace] recorded alloc %s size=%s\n" % (hex(p), self.size), gdb.STDERR)
        except Exception as e:
            gdb.write("[syz_trace] allocretbp error: %s\n" % e, gdb.STDERR)
        return False

class AccessWatchpoint(gdb.Breakpoint):
    def __init__(self, expr, expected_type="any", expected_size=0):
        super().__init__(spec=None, type=gdb.BP_BREAKPOINT, internal=True)
        self.expr = expr
        self.expected_type = expected_type.lower()
        self.expected_size = expected_size
        self.silent = True
        try:
            gdb.execute("awatch %s" % expr, to_string=True)
            gdb.write("[syz_trace] installed awatch %s\n" % expr, gdb.STDERR)
        except Exception as e:
            gdb.write("[syz_trace] awatch failed for %s: %s\n" % (expr, e), gdb.STDERR)
    def stop(self):
        if not poc_reached:
            return False
        try:
            rip = int(gdb.parse_and_eval("$rip"))
        except Exception:
            rip = None
        regs = dump_regs()
        frames = _bt(16)
        insn = _insn_str()
        ea = _parse_expr_addr(self.expr)
        ev = {"type": "watch", "expr": self.expr, "rip": rip, "regs": regs, "bt": frames, "time": _guest_time(), "ptid": _thread_ptid(), "insn": insn, "ea": ea}
        hit_events.append(ev)
        gdb.write("[syz_trace] watchpoint hit at RIP=%s expr=%s\n" % (hex(rip) if rip else "?", self.expr), gdb.STDERR)
        if fault_insn and rip == fault_insn:
            gdb.write("[syz_trace] RIP matches crash RIP; probable match\n", gdb.STDERR)
        return False

class RipBreakpoint(gdb.Breakpoint):
    def __init__(self, addr):
        super().__init__(str(addr), gdb.BP_BREAKPOINT, internal=False)
        self.silent = True
    def stop(self):
        if not poc_reached:
            return False
        rip = int(gdb.parse_and_eval("$rip"))
        gdb.write("[syz_trace] breakpoint at fault RIP %s reached\n" % hex(rip), gdb.STDERR)
        regs = dump_regs()
        frames = _bt(24)
        ev = {"type": "rip", "rip": rip, "regs": regs, "bt": frames, "time": _guest_time(), "ptid": _thread_ptid(), "insn": _insn_str()}
        hit_events.append(ev)
        return False


class FreePtrWatchpoint(gdb.Breakpoint):
    def __init__(self, ptr):
        super().__init__(spec=None, type=gdb.BP_BREAKPOINT, internal=True)
        self.ptr = ptr
        self.silent = True
        try:
            gdb.execute("awatch *(char*)0x%x" % ptr, to_string=True)
            gdb.write("[syz_trace] installed UAF awatch on freed ptr %s\n" % hex(ptr), gdb.STDERR)
        except Exception as e:
            gdb.write("[syz_trace] failed to install UAF awatch on %s: %s\n" % (hex(ptr), e), gdb.STDERR)
        # Also watch file->f_count if offset is known and size suggests filp cache
        try:
            if file_f_count_offset is not None:
                # If we recorded alloc size for this ptr and it looks like filp (~464), add precise field watch
                sz = None
                try:
                    rec = alloc_map.get(ptr)
                    if rec:
                        sz = rec[0]
                except Exception:
                    sz = None
                if sz is None or (400 <= int(sz) <= 600):
                    addr = int(ptr) + int(file_f_count_offset)
                    try:
                        gdb.execute("awatch *(long*)0x%x" % addr, to_string=True)
                        gdb.write("[syz_trace] installed awatch on file->f_count at 0x%x\n" % addr, gdb.STDERR)
                    except Exception:
                        pass
        except Exception:
            pass
        # Generic bug offset watch if provided
        try:
            if bug_offset is not None:
                addr2 = int(ptr) + int(bug_offset)
                try:
                    gdb.execute("awatch *(char*)0x%x" % addr2, to_string=True)
                    gdb.write("[syz_trace] installed awatch at freed_ptr+bug_offset 0x%x\n" % addr2, gdb.STDERR)
                except Exception:
                    pass
        except Exception:
            pass
    def stop(self):
        if not poc_reached:
            return False
        try:
            rip = int(gdb.parse_and_eval("$rip"))
        except Exception:
            rip = None
        regs = dump_regs()
        frames = _bt(16)
        ev = {"type": "uaf_watch", "ptr": self.ptr, "rip": rip, "regs": regs, "bt": frames, "time": _guest_time(), "ptid": _thread_ptid(), "insn": _insn_str(), "ea": int(self.ptr)}
        uaf_watch_hits.append(ev)
        gdb.write("[syz_trace] UAF watchpoint hit at RIP=%s ptr=%s\n" % (hex(rip) if rip else "?", hex(self.ptr)), gdb.STDERR)
        return False


# ---------------- Path verifier breakpoints ----------------
class FuncBreakpoint(gdb.Breakpoint):
    def __init__(self, sym, arg_names=None):
        super().__init__(sym, gdb.BP_BREAKPOINT, internal=False)
        self.silent = True
        self.sym = sym
        self.arg_names = arg_names or []
    def stop(self):
        if not poc_reached:
            return False
        rip = None
        try:
            rip = int(gdb.parse_and_eval('$rip'))
        except Exception:
            pass
        regs = dump_regs()
        frames = _bt(16)
        info = {"type": "path", "func": self.sym, "rip": rip, "regs": regs, "bt": frames, "time": _guest_time(), "ptid": _thread_ptid(), "insn": _insn_str()}
        # Capture first argument (RDI) for functions like filp_close and atomic_long_read
        try:
            rdi = int(gdb.parse_and_eval('((unsigned long)$rdi)'))
        except Exception:
            rdi = None
        if rdi is not None:
            info["rdi"] = rdi
            # If monitoring atomic reads, attempt to relate to freed struct file->f_count
            try:
                if file_f_count_offset is not None:
                    # If rdi points to atomic_long_t*, compute parent file base
                    # Parent candidate = rdi - offset
                    parent = int(rdi) - int(file_f_count_offset)
                    info["parent_candidate"] = parent
                    info["matches_freed"] = bool(parent in free_set)
            except Exception:
                pass
        hit_events.append(info)
        return False

def install_path_verifier():
    if not path_verify_enabled:
        return
    for sym in [
        'filp_close',
        'instrument_atomic_read',
        'atomic64_read',
        'atomic_long_read',
        '__fput',
        'put_fs_context',
        'fscontext_release',
    ]:
        try:
            if sym not in _installed_path_syms:
                # Prefer hardware bp by address via System.map
                if not _set_hw_bp_for_symbol(sym):
                    FuncBreakpoint(sym)
                _installed_path_syms.add(sym)
                gdb.write("[syz_trace] installed path verifier bp on %s\n" % sym, gdb.STDERR)
        except Exception:
            pass

def _parse_functions_from_text(txt):
    try:
        import re
        funs = set()
        # Capture function names of the form: name+0x... or name (...)
        for m in re.finditer(r"\n\s*([A-Za-z0-9_]+)\+0x[0-9a-f]+/[0-9a-f]+", txt):
            funs.add(m.group(1))
        # Also capture lines like 'BUG: KASAN: ... in function'
        for m in re.finditer(r"BUG: [^\n]* in ([A-Za-z0-9_]+)", txt):
            funs.add(m.group(1))
        return list(funs)
    except Exception:
        return []

def _install_funcs(funcs):
    for sym in funcs:
        try:
            if sym not in _installed_path_syms:
                if not _set_hw_bp_for_symbol(sym):
                    FuncBreakpoint(sym)
                _installed_path_syms.add(sym)
                gdb.write("[syz_trace] installed bp on %s (analysis)\n" % sym, gdb.STDERR)
        except Exception:
            pass

def _set_convenience_var(name, val):
    try:
        if isinstance(val, str):
            gdb.execute(f"set ${name} = \"{val}\"", to_string=True)
        elif isinstance(val, bool):
            gdb.execute(f"set ${name} = {int(val)}", to_string=True)
        elif isinstance(val, (int,)):
            gdb.execute(f"set ${name} = {val}", to_string=True)
    except Exception:
        pass

class SyzImportAnalysisCmd(gdb.Command):
    """syz_import_analysis <path> -- read static/crash analysis JSON or text.

    Extracts:
      - target functions from crash stacks
      - access address and size
      - object cache size and bug offset inside object
    Then installs breakpoints/watchpoints accordingly.
    """
    def __init__(self):
        super(SyzImportAnalysisCmd, self).__init__("syz_import_analysis", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        path = arg.strip()
        if not path:
            gdb.write("[syz_import_analysis] usage: syz_import_analysis <path>\n", gdb.STDERR)
            return
        try:
            import json
            txt = None
            data = None
            try:
                with open(path, 'r', encoding='utf-8') as f:
                    raw = f.read()
                txt = raw
            except Exception as e:
                gdb.write(f"[syz_import_analysis] failed to read file: {e}\n", gdb.STDERR)
                return

            # Try JSON first
            try:
                data = json.loads(txt)
            except Exception:
                data = None

            # Extract functions
            funcs = []
            if data and isinstance(data, dict):
                # parsed.raw may contain the crash text
                try:
                    crash_txt = data.get('parsed', {}).get('raw', '')
                    funcs = _parse_functions_from_text(crash_txt)
                except Exception:
                    funcs = []
                # access addr/size
                try:
                    acc = data.get('parsed', {}).get('access', {})
                    addr = acc.get('addr')
                    if addr:
                        try:
                            a = int(str(addr), 16) if isinstance(addr, str) and addr.startswith('ffff') else int(addr)
                            AccessWatchpoint("*((char *)%d)" % a, expected_type='any', expected_size=0)
                            gdb.write(f"[syz_trace] awatch installed on crash addr {hex(a)}\n", gdb.STDERR)
                        except Exception:
                            pass
                except Exception:
                    pass
                # bug offset and cache size
                try:
                    obj = data.get('exploitability', {}).get('object', {})
                    off = obj.get('offset')
                    if off is not None:
                        _set_convenience_var('bug_offset', int(off))
                        gdb.write(f"[syz_trace] bug_offset set to {int(off)}\n", gdb.STDERR)
                except Exception:
                    pass
                try:
                    # cache size may be under parsed.raw or classification; attempt regex from raw
                    crash_txt = data.get('parsed', {}).get('raw', '')
                    import re
                    m = re.search(r"cache\s+([A-Za-z0-9_\-]+)\s+of\s+size\s+(\d+)", crash_txt)
                    if m:
                        sz = int(m.group(2))
                        _set_convenience_var('object_cache_size', sz)
                        gdb.write(f"[syz_trace] object_cache_size set to {sz}\n", gdb.STDERR)
                except Exception:
                    pass
            else:
                # Treat as plain crash text
                funcs = _parse_functions_from_text(txt)
                # attempt to install awatch on 'Read of size N at addr ...'
                try:
                    import re
                    m2 = re.search(r"Read of size\s+(\d+)\s+at addr\s+(0x[0-9a-fA-F]+|ffff[0-9a-fA-F]+)", txt)
                    if m2:
                        addr_s = m2.group(2)
                        a = int(addr_s, 16)
                        AccessWatchpoint("*((char *)%d)" % a, expected_type='any', expected_size=0)
                        gdb.write(f"[syz_trace] awatch installed on crash addr {hex(a)}\n", gdb.STDERR)
                except Exception:
                    pass
                # bug offset
                try:
                    import re
                    m3 = re.search(r"located\s+(\d+)\s+bytes\s+inside\s+of", txt)
                    if m3:
                        off = int(m3.group(1))
                        _set_convenience_var('bug_offset', off)
                        gdb.write(f"[syz_trace] bug_offset set to {off}\n", gdb.STDERR)
                except Exception:
                    pass

            # Install breakpoints for extracted functions
            _install_funcs(funcs)
            gdb.write(f"[syz_import_analysis] installed {len(funcs)} function breakpoints from analysis\n", gdb.STDERR)
        except Exception as e:
            gdb.write(f"[syz_import_analysis] failed: {e}\n", gdb.STDERR)

SyzImportAnalysisCmd()


# ---------------- Install all checks ----------------
def install_kasan_watch():
    try:
        # Prefer hardware breakpoint if available
        try:
            gdb.execute("hbreak kasan_report", to_string=True)
            gdb.write("[syz_trace] set HARDWARE breakpoint on kasan_report\n", gdb.STDERR)
            return
        except Exception:
            pass
        bp = gdb.Breakpoint("kasan_report", gdb.BP_BREAKPOINT)
        bp.silent = True
        gdb.write("[syz_trace] set breakpoint on kasan_report\n", gdb.STDERR)
    except Exception:
        gdb.write("[syz_trace] kasan_report symbol not found\n", gdb.STDERR)

def install_checks():
    if fault_addr:
        expr = "*((char *)%d)" % fault_addr
        try:
            AccessWatchpoint(expr, expected_type=access_type, expected_size=access_size)
        except Exception as e:
            gdb.write("[syz_trace] failed to install access watch: %s\n" % e, gdb.STDERR)

    if fault_insn and not monitor_mode:
        try:
            RipBreakpoint(" *0x%x " % fault_insn)
            gdb.write("[syz_trace] breakpoint placed at fault_insn %s\n" % hex(fault_insn), gdb.STDERR)
        except Exception as e:
            gdb.write("[syz_trace] could not place breakpoint at fault_insn: %s\n" % e, gdb.STDERR)

    if poc_entry and not monitor_mode:
        try:
            PocEntryBreakpoint(poc_entry)
            gdb.write("[syz_trace] breakpoint placed at poc_entry %s\n" % poc_entry, gdb.STDERR)
        except Exception:
            try:
                PocEntryBreakpoint("*%s" % poc_entry)
                gdb.write("[syz_trace] breakpoint placed at poc_entry %s (addr)\n" % poc_entry, gdb.STDERR)
            except Exception as e:
                gdb.write("[syz_trace] could not place poc_entry BP: %s\n" % e, gdb.STDERR)

    if _enable_alloc_track:
        # Try symbols first; if unavailable, hardware breakpoints on provided addresses still work.
        for sym in ("__kmalloc", "kmalloc", "kfree", "vfree"):
            try:
                # Prefer address from System.map
                if not _set_hw_bp_for_symbol(sym):
                    try:
                        gdb.execute("hbreak %s" % sym, to_string=True)
                        gdb.write("[syz_trace] installed HARDWARE bp on %s\n" % sym, gdb.STDERR)
                    except Exception:
                        AllocBp(sym, is_alloc=(sym not in ("kfree", "vfree")))
                        gdb.write("[syz_trace] installed alloc/free bp on %s\n" % sym, gdb.STDERR)
            except Exception as e:
                gdb.write("[syz_trace] failed to set bp on %s: %s\n" % (sym, e), gdb.STDERR)

        # Populate alloc/free address sets from System.map for stop handler correlation
        try:
            km_addr = _resolve_addr('__kmalloc') or _resolve_addr('kmalloc')
            kf_addr = _resolve_addr('kfree')
            vf_addr = _resolve_addr('vfree')
            for a in [km_addr]:
                if a:
                    alloc_addrs.add(int(a))
            for a in [kf_addr, vf_addr]:
                if a:
                    free_addrs.add(int(a))
        except Exception:
            pass
        try:
            if not monitor_mode:
                km = gvar("$kmalloc_addr")
                kf = gvar("$kfree_addr")
                vf = gvar("$vfree_addr")
                if km is not None:
                    try:
                        addr = conv_u64(km)
                        gdb.execute("hbreak *0x%x" % addr, to_string=True)
                        gdb.write("[syz_trace] installed HARDWARE bp at kmalloc addr 0x%x\n" % addr, gdb.STDERR)
                    except Exception:
                        AllocBp("*0x%x" % conv_u64(km), is_alloc=True)
                        gdb.write("[syz_trace] installed alloc bp at kmalloc addr\n", gdb.STDERR)
                if kf is not None:
                    try:
                        addr = conv_u64(kf)
                        gdb.execute("hbreak *0x%x" % addr, to_string=True)
                        gdb.write("[syz_trace] installed HARDWARE bp at kfree addr 0x%x\n" % addr, gdb.STDERR)
                    except Exception:
                        AllocBp("*0x%x" % conv_u64(kf), is_alloc=False)
                        gdb.write("[syz_trace] installed free bp at kfree addr\n", gdb.STDERR)
                if vf is not None:
                    try:
                        addr = conv_u64(vf)
                        gdb.execute("hbreak *0x%x" % addr, to_string=True)
                        gdb.write("[syz_trace] installed HARDWARE bp at vfree addr 0x%x\n" % addr, gdb.STDERR)
                    except Exception:
                        AllocBp("*0x%x" % conv_u64(vf), is_alloc=False)
                        gdb.write("[syz_trace] installed free bp at vfree addr\n", gdb.STDERR)
        except Exception:
            pass

    # if _enable_kasan_check:
    #     if not monitor_mode:
    #         install_kasan_watch()
    #     else:
    #         # In monitor mode, still attempt an awatch on fault_addr if known
    #         if fault_addr:
    #             try:
    #                 AccessWatchpoint("*((char *)%d)" % fault_addr, expected_type=access_type, expected_size=access_size)
    #             except Exception:
    #                 pass

install_checks()

gdb.write("[syz_trace] instrumentation installed. Run/continue the inferior to begin tracing.\n", gdb.STDERR)

# Ensure the results file exists early to avoid orchestrator errors
def _touch_export():
    try:
        p = gdb.parse_and_eval('$export_path')
        s = str(p)
        if s.startswith('"') and s.endswith('"'):
            s = s[1:-1]
        path = s if s else None
    except Exception:
        path = None
    if not path:
        return
    try:
        import json
        with open(path, 'w', encoding='utf-8') as f:
            json.dump({
                'events': [],
                'allocations': {},
                'frees': []
            }, f, indent=2)
        gdb.write(f"[syz_trace] initialized results file at {path}\n", gdb.STDERR)
    except Exception:
        pass

_touch_export()

# Monitor mode: hook stop events to log and auto-continue
def _on_stop(event):
    try:
        rip = int(gdb.parse_and_eval('$rip'))
    except Exception:
        rip = None
    frames = _bt(16)
    ts = _guest_time()
    # Record generic stop
    hit_events.append({"type": "stop", "rip": rip, "bt": frames, "time": ts})

    # Hardware breakpoint tracking when symbols are not loaded
    try:
        if poc_reached or monitor_mode:
            if rip and rip in alloc_addrs:
                # allocation: capture size from rdi/rsi and install finish bp to get return ptr
                size = None
                try:
                    size = int(gdb.parse_and_eval('((unsigned long)$rdi)'))
                except Exception:
                    try:
                        size = int(gdb.parse_and_eval('((unsigned long)$rsi)'))
                    except Exception:
                        size = None
                try:
                    AllocRetBp(gdb.newest_frame(), size, frames)
                except Exception:
                    pass
            elif rip and rip in free_addrs:
                # free: capture pointer from rdi
                try:
                    p = int(gdb.parse_and_eval('((unsigned long)$rdi)'))
                except Exception:
                    p = None
                if p:
                    free_set.add(p)
                    free_events.append({"ptr": p, "time": ts})
                    try:
                        if len(_installed_free_watches) < _max_free_watchpoints and p not in _installed_free_watches:
                            _installed_free_watches.add(p)
                            FreePtrWatchpoint(p)
                    except Exception:
                        pass
    except Exception:
        pass

    if monitor_mode:
        # Defer continue to avoid recursive re-entry and RecursionError
        def _resume():
            try:
                gdb.execute('continue')
            except Exception:
                pass
        try:
            gdb.post_event(_resume)
        except Exception:
            pass

    # Path verifier monitors from crash log/static analysis
    try:
        install_path_verifier()
    except Exception:
        pass

try:
    gdb.events.stop.connect(_on_stop)
    gdb.write("[syz_trace] stop handler installed (monitor=%s)\n" % ("on" if monitor_mode else "off"), gdb.STDERR)
except Exception:
    pass

# Auto-export results when the inferior exits (e.g., crash or normal exit)
def _on_exit(event):
    try:
        path = None
        try:
            p = gdb.parse_and_eval('$export_path')
            s = str(p)
            if s.startswith('"') and s.endswith('"'):
                s = s[1:-1]
            path = s if s else None
        except Exception:
            path = None
        if not path:
            path = "/tmp/gdb_analysis.json"
        # Use the command to serialize current in-memory results
        gdb.execute(f"export_results {path}", to_string=True)
        gdb.write("[syz_trace] auto-export on inferior exit\n", gdb.STDERR)
    except Exception:
        pass

try:
    gdb.events.exited.connect(_on_exit)
except Exception:
    pass


# ---------------- Commands ----------------
class SyzTraceSummaryCmd(gdb.Command):
    def __init__(self):
        super(SyzTraceSummaryCmd, self).__init__("syz_trace_summary", gdb.COMMAND_USER)
    def invoke(self, arg, from_tty):
        gdb.write("=== syz_trace summary ===\n", gdb.STDERR)
        if not hit_events:
            gdb.write("  No watchpoint or RIP events seen yet.\n", gdb.STDERR)
            return
        for i, ev in enumerate(hit_events):
            gdb.write("Event %d type=%s time=%s\n" %
                      (i, ev.get("type"), time.ctime(ev.get("time"))), gdb.STDERR)
            gdb.write(" RIP: %s\n" %
                      (hex(ev.get("rip")) if ev.get("rip") else "unknown"), gdb.STDERR)
            gdb.write(" Backtrace:\n", gdb.STDERR)
            for f in ev.get("bt", []):
                gdb.write("   %s\n" % f, gdb.STDERR)
            gdb.write("\n", gdb.STDERR)

SyzTraceSummaryCmd()


class ExportResultsCmd(gdb.Command):
    def __init__(self):
        super(ExportResultsCmd, self).__init__("export_results", gdb.COMMAND_USER)
    def invoke(self, arg, from_tty):
        path = arg.strip()
        if not path:
            gdb.write("[export_results] usage: export_results <output_path>\n", gdb.STDERR)
            return
        try:
            import json
            # Detailed allocations with timestamps
            allocations_detailed = {}
            try:
                for k, v in alloc_map.items():
                    hexk = hex(k)
                    size, frames = v
                    allocations_detailed[hexk] = {
                        "size": size,
                        "bt": frames,
                        "time": alloc_ts_map.get(k)
                    }
            except Exception:
                allocations_detailed = {}

            with open(path, "w", encoding="utf-8") as f:
                json.dump({
                    "events": hit_events,
                    "allocations": {hex(k): {"size": v[0], "backtrace": v[1]} for k, v in alloc_map.items()},
                    "frees": [hex(x) for x in list(free_set)],
                    "allocations_detailed": allocations_detailed,
                    "frees_detailed": [{"ptr": hex(ev.get("ptr")), "time": ev.get("time")} for ev in free_events],
                    "uaf_watch_hits": [{"ptr": hex(ev.get("ptr")), "rip": ev.get("rip"), "time": ev.get("time"), "bt": ev.get("bt"), "regs": ev.get("regs")} for ev in uaf_watch_hits],
                }, f, indent=2)
            gdb.write(f"[export_results] wrote results to {path}\n", gdb.STDERR)
        except Exception as e:
            gdb.write(f"[export_results] failed: {e}\n", gdb.STDERR)

ExportResultsCmd()

# ---------------- Config loader ----------------
class SyzLoadConfigCmd(gdb.Command):
    """syz_load_config <json_path> -- set convenience variables from JSON.

    JSON keys supported:
      poc_entry (str), fault_addr (int), fault_insn (int),
      access_type (str), access_size (int),
      kmalloc_addr (int), kfree_addr (int), vfree_addr (int),
      monitor_mode (bool), reproducer_path (str)
    """
    def __init__(self):
        super(SyzLoadConfigCmd, self).__init__("syz_load_config", gdb.COMMAND_USER)

    def _set_var(self, name, val):
        try:
            if isinstance(val, str):
                gdb.execute(f"set ${name} = \"{val}\"", to_string=True)
            elif isinstance(val, bool):
                gdb.execute(f"set ${name} = {int(val)}", to_string=True)
            elif isinstance(val, (int,)):
                gdb.execute(f"set ${name} = {val}", to_string=True)
        except Exception:
            pass

    def invoke(self, arg, from_tty):
        path = arg.strip()
        if not path:
            gdb.write("[syz_load_config] usage: syz_load_config <json_path>\n", gdb.STDERR)
            return
        try:
            import json
            with open(path, "r", encoding="utf-8") as f:
                cfg = json.load(f)
            # Map known keys to convenience vars
            mapping = {
                "poc_entry": "poc_entry",
                "fault_addr": "fault_addr",
                "fault_insn": "fault_insn",
                "access_type": "access_type",
                "access_size": "access_size",
                "kmalloc_addr": "kmalloc_addr",
                "kfree_addr": "kfree_addr",
                "vfree_addr": "vfree_addr",
                "monitor_mode": "monitor_mode",
                "monitor_always": "monitor_always",
                "reproducer_path": "reproducer_path",
                "guest_ssh_port": "guest_ssh_port",
                "guest_ssh_user": "guest_ssh_user",
                "guest_ssh_key": "guest_ssh_key",
                "file_f_count_offset": "file_f_count_offset",
                "path_verify": "path_verify",
                "system_map_path": "system_map_path",
            }
            for k, v in cfg.items():
                name = mapping.get(k)
                if name:
                    self._set_var(name, v)
            gdb.write(f"[syz_load_config] applied config from {path}\n", gdb.STDERR)
        except Exception as e:
            gdb.write(f"[syz_load_config] failed: {e}\n", gdb.STDERR)

SyzLoadConfigCmd()

class SyzLoadSystemMapCmd(gdb.Command):
    """syz_load_system_map <path> -- load System.map and enable hardware bp resolution."""
    def __init__(self):
        super(SyzLoadSystemMapCmd, self).__init__("syz_load_system_map", gdb.COMMAND_USER)
    def invoke(self, arg, from_tty):
        path = arg.strip()
        if not path:
            gdb.write("[syz_load_system_map] usage: syz_load_system_map <path>\n", gdb.STDERR)
            return
        try:
            _load_system_map(path)
            gdb.execute(f"set $system_map_path = \"{path}\"", to_string=True)
            gdb.write("[syz_load_system_map] System.map loaded\n", gdb.STDERR)
        except Exception as e:
            gdb.write(f"[syz_load_system_map] failed: {e}\n", gdb.STDERR)

SyzLoadSystemMapCmd()
# syz_trace.py (patched for logging + poc_entry=main + thread IDs)

# import gdb
# import time
# import traceback

# # -------------------------------------------------------------------
# # Logging subsystem
# # -------------------------------------------------------------------

# def _get_log_path():
#     """Returns path to the log output file."""
#     try:
#         v = gdb.parse_and_eval("$syz_trace_log")
#         s = str(v)
#         if s.startswith('"') and s.endswith('"'):
#             s = s[1:-1]
#         if len(s) > 0:
#             return s
#     except Exception:
#         pass
#     return "/tmp/syz_trace.log"

# LOG_PATH = "/tmp/syz_trace.log"

# def _thread_id():
#     """Returns a string describing the current thread, ex: (1234.5678)."""
#     try:
#         t = gdb.selected_thread()
#         if not t:
#             return "(tid=unknown)"
#         ptid = t.ptid
#         if isinstance(ptid, tuple) and len(ptid) >= 2:
#             return "(%s.%s)" % (ptid[0], ptid[1])
#         return "(tid=%s)" % str(ptid)
#     except Exception:
#         return "(tid=unknown)"

# def log(msg):
#     """Append log message to external trace log with timestamp + thread ID."""
#     try:
#         ts = time.strftime("%Y-%m-%d %H:%M:%S")
#         tid = _thread_id()
#         with open(LOG_PATH, "a", encoding="utf-8") as f:
#             f.write("[%s] %s %s\n" % (ts, tid, msg))
#     except Exception as e:
#         gdb.write("[syz_trace logging error] %s\n" % e, gdb.STDERR)

# log("=== syz_trace started ===")
# log("Log file: %s" % LOG_PATH)


# # -------------------------------------------------------------------
# # poc_entry hardcoded to main
# # -------------------------------------------------------------------

# POC_ENTRY = "main"      # Always start tracing AFTER main() in repro.c
# log("poc_entry forced to: main")

# poc_reached = False


# # -------------------------------------------------------------------
# # Helpers
# # -------------------------------------------------------------------

# def dump_regs():
#     regs = {}
#     for r in ["rip","rsp","rbp","rax","rbx","rcx","rdx","rsi","rdi",
#               "r8","r9","r10","r11","r12","r13","r14","r15"]:
#         try:
#             regs[r] = gdb.parse_and_eval("$" + r)
#         except Exception:
#             regs[r] = "<na>"
#     return regs

# def bt(max_frames=12):
#     out = []
#     f = gdb.newest_frame()
#     i = 0
#     while f and i < max_frames:
#         try:
#             name = f.name() or "<unknown>"
#         except Exception:
#             name = "<unknown>"

#         sal = f.find_sal()
#         if sal and sal.symtab:
#             loc = "%s:%d" % (sal.symtab.filename, sal.line)
#         else:
#             loc = ""

#         out.append("%s %s" % (name, loc))
#         f = f.older()
#         i += 1
#     return out


# # -------------------------------------------------------------------
# # Breakpoint: poc_entry (main)
# # -------------------------------------------------------------------

# class PocEntryBP(gdb.Breakpoint):
#     def __init__(self):
#         super().__init__(POC_ENTRY, gdb.BP_BREAKPOINT, internal=False)
#         self.silent = True

#     def stop(self):
#         global poc_reached
#         poc_reached = True
#         msg = "poc_entry reached (main). instrumentation enabled"
#         log(msg)
#         gdb.write("[syz_trace] %s\n" % msg, gdb.STDERR)
#         return False


# # -------------------------------------------------------------------
# # Allocation / free breakpoints
# # -------------------------------------------------------------------

# class AllocBP(gdb.Breakpoint):
#     def __init__(self, sym, is_alloc):
#         super().__init__(sym, gdb.BP_BREAKPOINT, internal=False)
#         self.silent = True
#         self.sym = sym
#         self.is_alloc = is_alloc

#     def stop(self):
#         if not poc_reached:
#             return False

#         try:
#             if self.is_alloc:
#                 try:
#                     size = int(gdb.parse_and_eval("$rdi"))
#                 except Exception:
#                     size = None
#                 log("alloc: %s size=%s" % (self.sym, size))
#                 return False
#             else:
#                 try:
#                     p = int(gdb.parse_and_eval("$rdi"))
#                 except Exception:
#                     p = None
#                 log("free: %s ptr=%s" % (self.sym, hex(p) if p else "??"))
#                 return False

#         except Exception as e:
#             log("AllocBP error: %s" % e)
#             return False


# # -------------------------------------------------------------------
# # Fault instruction BP
# # -------------------------------------------------------------------

# class RipBP(gdb.Breakpoint):
#     def __init__(self, addr):
#         super().__init__(addr, gdb.BP_BREAKPOINT, internal=False)
#         self.silent = True

#     def stop(self):
#         if not poc_reached:
#             return False

#         rip = int(gdb.parse_and_eval("$rip"))
#         log("fault_rip hit at %x" % rip)
#         for line in bt():
#             log("  bt: %s" % line)
#         return False


# # -------------------------------------------------------------------
# # Watchpoint wrapper
# # -------------------------------------------------------------------

# class AccessWatchBP(gdb.Breakpoint):
#     def __init__(self, expr):
#         super().__init__(spec=None, type=gdb.BP_BREAKPOINT, internal=True)
#         self.expr = expr
#         self.silent = True
#         try:
#             gdb.execute("awatch %s" % expr, to_string=True)
#             log("installed awatch %s" % expr)
#         except Exception as e:
#             log("awatch failed for %s: %s" % (expr, e))

#     def stop(self):
#         if not poc_reached:
#             return False

#         try:
#             rip = int(gdb.parse_and_eval("$rip"))
#         except Exception:
#             rip = None

#         log("watchpoint hit RIP=%s expr=%s" %
#             (hex(rip) if rip else "?", self.expr))

#         for frame in bt():
#             log("  bt: %s" % frame)

#         return False


# class ExportResultsCmd(gdb.Command):
#     def __init__(self):
#         super(ExportResultsCmd, self).__init__("export_results", gdb.COMMAND_USER)
#     def invoke(self, arg, from_tty):
#         path = arg.strip()
#         if not path:
#             gdb.write("[export_results] usage: export_results <output_path>\n", gdb.STDERR)
#             return
#         try:
#             import json
#             with open(path, "w", encoding="utf-8") as f:
#                 json.dump({
#                     "events": hit_events,
#                     "allocations": {hex(k): v for k, v in alloc_map.items()},
#                     "frees": [hex(x) for x in list(free_set)],
#                 }, f, indent=2)
#             gdb.write(f"[export_results] wrote results to {path}\n", gdb.STDERR)
#         except Exception as e:
#             gdb.write(f"[export_results] failed: {e}\n", gdb.STDERR)

# ExportResultsCmd()

# # -------------------------------------------------------------------
# # Instrumentation installation
# # -------------------------------------------------------------------

# def install():
#     PocEntryBP()

#     # Alloc/free instrumentation
#     for sym, is_alloc in [
#         ("__kmalloc", True),
#         ("kmalloc", True),
#         ("kfree", False),
#         ("vfree", False)
#     ]:
#         try:
#             AllocBP(sym, is_alloc)
#             log("installed alloc/free bp: %s" % sym)
#         except Exception:
#             pass

#     # kasan_report if present
#     try:
#         bp = gdb.Breakpoint("kasan_report", gdb.BP_BREAKPOINT)
#         bp.silent = True
#         log("installed kasan_report bp")
#     except Exception:
#         log("kasan_report symbol unavailable")


# install()

# gdb.write("[syz_trace] instrumentation installed. log: %s\n" % LOG_PATH, gdb.STDERR)
# log("instrumentation installed; waiting for main()")
