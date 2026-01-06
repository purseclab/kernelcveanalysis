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
    monitor_mode = bool(gdb.parse_and_eval('monitor_mode'))
except Exception:
    try:
        # Fallback: set to False if not provided
        monitor_mode = False
    except Exception:
        monitor_mode = False

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

# New global toggle
poc_reached = False

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
                return False
            else:
                try:
                    p = int(gdb.parse_and_eval("((unsigned long)$rdi)"))
                except Exception:
                    p = None
                if p:
                    free_set.add(p)
                    gdb.write("[syz_trace] free detected %s\n" % (hex(p),), gdb.STDERR)
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
        ev = {"type": "watch", "expr": self.expr, "rip": rip, "regs": regs, "bt": frames, "time": time.time()}
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
        ev = {"type": "rip", "rip": rip, "regs": regs, "bt": frames, "time": time.time()}
        hit_events.append(ev)
        return False


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
        for sym in ("__kmalloc", "kmalloc", "kfree", "vfree"):
            try:
                if monitor_mode:
                    # In monitor mode, avoid placing breakpoints; rely on awatch/stop hooks
                    continue
                # Try hardware breakpoint first to avoid memory writes when pages unmapped
                try:
                    gdb.execute("hbreak %s" % sym, to_string=True)
                    gdb.write("[syz_trace] installed HARDWARE bp on %s\n" % sym, gdb.STDERR)
                except Exception:
                    AllocBp(sym, is_alloc=(sym not in ("kfree", "vfree")))
                    gdb.write("[syz_trace] installed alloc/free bp on %s\n" % sym, gdb.STDERR)
            except Exception as e:
                gdb.write("[syz_trace] failed to set bp on %s: %s\n" % (sym, e), gdb.STDERR)

    if _enable_kasan_check:
        if not monitor_mode:
            install_kasan_watch()
        else:
            # In monitor mode, still attempt an awatch on fault_addr if known
            if fault_addr:
                try:
                    AccessWatchpoint("*((char *)%d)" % fault_addr, expected_type=access_type, expected_size=access_size)
                except Exception:
                    pass

install_checks()

gdb.write("[syz_trace] instrumentation installed. Run/continue the inferior to begin tracing.\n", gdb.STDERR)

# Monitor mode: hook stop events to log and auto-continue
def _on_stop(event):
    try:
        rip = int(gdb.parse_and_eval('$rip'))
    except Exception:
        rip = None
    frames = _bt(16)
    hit_events.append({"type": "stop", "rip": rip, "bt": frames, "time": time.time()})
    if monitor_mode:
        try:
            gdb.execute('continue')
        except Exception:
            pass

try:
    gdb.events.stop.connect(_on_stop)
    gdb.write("[syz_trace] stop handler installed (monitor=%s)\n" % ("on" if monitor_mode else "off"), gdb.STDERR)
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
            with open(path, "w", encoding="utf-8") as f:
                json.dump({
                    "events": hit_events,
                    "allocations": {hex(k): v for k, v in alloc_map.items()},
                    "frees": [hex(x) for x in list(free_set)],
                }, f, indent=2)
            gdb.write(f"[export_results] wrote results to {path}\n", gdb.STDERR)
        except Exception as e:
            gdb.write(f"[export_results] failed: {e}\n", gdb.STDERR)

ExportResultsCmd()
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
