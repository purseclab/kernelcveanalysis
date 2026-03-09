"""
feasibility.py

Cross-version vulnerability feasibility analysis.

Given a bug originally discovered on kernel version X (from syzbot), this module
determines whether that bug is still present/exploitable on a *different* target
kernel version Y by:

  1. **Symbol / code-path analysis** — check if the vulnerable functions still
     exist in the target kernel (via /proc/kallsyms, System.map, or vmlinux).
  2. **Fix-commit backport detection** — check if the known fix commit has been
     cherry-picked or backported into the target kernel's git tree.
  3. **Live reproducer test** — compile and run the syzbot C reproducer against
     the target kernel in a QEMU/Cuttlefish VM, checking for the expected crash
     signature.  4. **GDB path verification** — attach GDB to a running target kernel with
     breakpoints on the crash-stack functions, run the reproducer, and verify
     that the *same* code path (function sequence) is executed.
The module returns a structured ``FeasibilityReport`` with a per-check verdict
and an overall assessment (LIKELY_FEASIBLE, LIKELY_PATCHED, INCONCLUSIVE).
"""

import json
import os
import re
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class SymbolCheckResult:
    """Result of checking whether vulnerable symbols exist in the target kernel."""
    functions_checked: List[str] = field(default_factory=list)
    functions_found: List[str] = field(default_factory=list)
    functions_missing: List[str] = field(default_factory=list)
    source: str = ""  # "kallsyms", "system_map", "vmlinux", "none"
    verdict: str = "unknown"  # "present", "absent", "partial", "unknown"


@dataclass
class FixBackportResult:
    """Result of checking whether the known fix has been backported."""
    fix_commits: List[str] = field(default_factory=list)  # known fix commit hashes
    backported: bool = False
    evidence: str = ""  # git log excerpt, changelog match, etc.
    verdict: str = "unknown"  # "patched", "unpatched", "unknown"


@dataclass
class LiveTestResult:
    """Result of running the reproducer against the target kernel."""
    repro_compiled: bool = False
    repro_ran: bool = False
    crash_triggered: bool = False
    crash_signature_match: bool = False
    crash_log_excerpt: str = ""
    expected_functions: List[str] = field(default_factory=list)
    matched_functions: List[str] = field(default_factory=list)
    verdict: str = "unknown"  # "triggered", "no_crash", "different_crash", "compile_fail", "unknown"


@dataclass
class GdbPathCheckResult:
    """Result of GDB-based crash-path verification.

    Attaches GDB to a running kernel with breakpoints on the expected crash
    stack functions, runs the reproducer, and checks which breakpoints fire.
    A high hit-ratio means the same code path is still reachable.
    """
    expected_functions: List[str] = field(default_factory=list)
    hit_functions: List[str] = field(default_factory=list)
    missed_functions: List[str] = field(default_factory=list)
    func_hit_counts: Dict[str, int] = field(default_factory=dict)
    events_captured: int = 0
    crash_detected: bool = False
    crash_backtrace: List[str] = field(default_factory=list)
    hit_ratio: float = 0.0  # len(hit) / len(expected)
    verdict: str = "unknown"  # "path_confirmed", "partial_path", "path_diverged", "no_hits", "error", "unknown"


@dataclass
class FeasibilityReport:
    """Overall cross-version feasibility report."""
    bug_id: str = ""
    original_kernel: str = ""
    target_kernel: str = ""
    symbol_check: Optional[SymbolCheckResult] = None
    fix_check: Optional[FixBackportResult] = None
    live_test: Optional[LiveTestResult] = None
    gdb_path_check: Optional[GdbPathCheckResult] = None
    overall_verdict: str = "inconclusive"  # "likely_feasible", "likely_patched", "inconclusive"
    confidence: float = 0.0  # 0.0 to 1.0
    notes: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        from dataclasses import asdict
        return asdict(self)

    def summary(self) -> str:
        lines = [
            f"=== Feasibility Report: {self.bug_id} ===",
            f"  Original kernel : {self.original_kernel}",
            f"  Target kernel   : {self.target_kernel}",
            f"  Overall verdict : {self.overall_verdict}",
            f"  Confidence      : {self.confidence:.0%}",
        ]
        if self.symbol_check:
            lines.append(f"  Symbol check    : {self.symbol_check.verdict} "
                         f"({len(self.symbol_check.functions_found)}/"
                         f"{len(self.symbol_check.functions_checked)} found)")
        if self.fix_check:
            lines.append(f"  Fix backport    : {self.fix_check.verdict}")
        if self.live_test:
            lines.append(f"  Live test       : {self.live_test.verdict}")
        if self.gdb_path_check:
            gpc = self.gdb_path_check
            lines.append(f"  GDB path check  : {gpc.verdict} "
                         f"({len(gpc.hit_functions)}/{len(gpc.expected_functions)} hit, "
                         f"ratio={gpc.hit_ratio:.0%})")
        for n in self.notes:
            lines.append(f"  Note: {n}")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Symbol / code-path analysis
# ---------------------------------------------------------------------------

def check_symbols(
    vulnerable_functions: List[str],
    *,
    kallsyms_path: Optional[str] = None,
    system_map_path: Optional[str] = None,
    vmlinux_path: Optional[str] = None,
    ssh_host: Optional[str] = None,
    ssh_port: int = 22,
    ssh_user: str = "root",
    ssh_key: Optional[str] = None,
) -> SymbolCheckResult:
    """Check if the vulnerable functions exist in the target kernel.

    Tries sources in order: remote /proc/kallsyms (via SSH), local
    kallsyms file, System.map, vmlinux (via ``nm``).
    """
    result = SymbolCheckResult(functions_checked=list(vulnerable_functions))

    # Try SSH-based /proc/kallsyms on a running target
    if ssh_host:
        symbols_text = _read_remote_kallsyms(ssh_host, ssh_port, ssh_user, ssh_key)
        if symbols_text:
            result.source = "remote_kallsyms"
            _match_functions(result, symbols_text)
            return result

    # Try local kallsyms file
    if kallsyms_path and os.path.isfile(kallsyms_path):
        with open(kallsyms_path, "r") as f:
            symbols_text = f.read()
        result.source = "kallsyms"
        _match_functions(result, symbols_text)
        return result

    # Try System.map
    if system_map_path and os.path.isfile(system_map_path):
        with open(system_map_path, "r") as f:
            symbols_text = f.read()
        result.source = "system_map"
        _match_functions(result, symbols_text)
        return result

    # Try vmlinux via nm
    if vmlinux_path and os.path.isfile(vmlinux_path):
        try:
            cp = subprocess.run(
                ["nm", vmlinux_path],
                capture_output=True, text=True, timeout=60,
            )
            if cp.returncode == 0:
                result.source = "vmlinux"
                _match_functions(result, cp.stdout)
                return result
        except Exception:
            pass

    result.source = "none"
    result.verdict = "unknown"
    return result


def _read_remote_kallsyms(
    host: str, port: int, user: str, key: Optional[str]
) -> Optional[str]:
    """Read /proc/kallsyms from a remote device via SSH."""
    cmd = ["ssh", "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=10"]
    if key:
        cmd += ["-i", key]
    cmd += ["-p", str(port), f"{user}@{host}", "cat /proc/kallsyms"]
    try:
        cp = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if cp.returncode == 0 and len(cp.stdout) > 100:
            return cp.stdout
    except Exception:
        pass
    return None


def _match_functions(result: SymbolCheckResult, symbols_text: str) -> None:
    """Match functions against a symbols dump (kallsyms, System.map, nm output)."""
    # Build a set of known symbols for fast lookup
    known_syms: set = set()
    for line in symbols_text.splitlines():
        parts = line.split()
        if len(parts) >= 3:
            known_syms.add(parts[2].split("\t")[0])  # name, strip module tag
        elif len(parts) == 2:
            known_syms.add(parts[1])

    for func in result.functions_checked:
        # Strip trailing +offset and .isra/.constprop suffixes for comparison
        base = func.split("+")[0].split(".")[0].strip()
        if base in known_syms:
            result.functions_found.append(func)
        else:
            result.functions_missing.append(func)

    total = len(result.functions_checked)
    found = len(result.functions_found)
    if found == total:
        result.verdict = "present"
    elif found == 0:
        result.verdict = "absent"
    else:
        result.verdict = "partial"


# ---------------------------------------------------------------------------
# Fix-commit backport detection
# ---------------------------------------------------------------------------

def check_fix_backported(
    fix_commits: List[str],
    *,
    kernel_tree_path: Optional[str] = None,
    changelog_path: Optional[str] = None,
    target_branch: str = "HEAD",
) -> FixBackportResult:
    """Check if known fix commits have been cherry-picked / backported into the
    target kernel tree.

    Strategies:
    1. ``git log --oneline`` in the target tree, searching for the fix subject.
    2. ``git log --grep`` for the upstream commit hash (cherry-pick tags).
    3. Scan a changelog/CHANGES file for the fix commit.
    """
    result = FixBackportResult(fix_commits=list(fix_commits))

    if not fix_commits:
        result.verdict = "unknown"
        return result

    # Strategy 1+2: git-based detection
    if kernel_tree_path and os.path.isdir(os.path.join(kernel_tree_path, ".git")):
        for commit_hash in fix_commits:
            # Check if the commit itself exists in the tree
            found, evidence = _git_has_commit(kernel_tree_path, commit_hash, target_branch)
            if found:
                result.backported = True
                result.evidence = evidence
                result.verdict = "patched"
                return result

            # Check for cherry-pick reference
            found, evidence = _git_cherry_pick_search(kernel_tree_path, commit_hash, target_branch)
            if found:
                result.backported = True
                result.evidence = evidence
                result.verdict = "patched"
                return result

    # Strategy 3: changelog scanning
    if changelog_path and os.path.isfile(changelog_path):
        with open(changelog_path, "r") as f:
            changelog = f.read()
        for commit_hash in fix_commits:
            short = commit_hash[:12]
            if short in changelog:
                result.backported = True
                result.evidence = f"Fix {short} found in changelog"
                result.verdict = "patched"
                return result

    result.verdict = "unknown"
    return result


def _git_has_commit(tree: str, commit_hash: str, branch: str) -> Tuple[bool, str]:
    """Check if a commit hash is an ancestor of the target branch."""
    try:
        cp = subprocess.run(
            ["git", "merge-base", "--is-ancestor", commit_hash, branch],
            cwd=tree, capture_output=True, timeout=30,
        )
        if cp.returncode == 0:
            return True, f"Commit {commit_hash[:12]} is an ancestor of {branch}"
    except Exception:
        pass
    return False, ""


def _git_cherry_pick_search(tree: str, commit_hash: str, branch: str) -> Tuple[bool, str]:
    """Search git log for cherry-pick tags referencing the upstream fix."""
    try:
        short = commit_hash[:12]
        cp = subprocess.run(
            ["git", "log", "--oneline", "--grep", short, branch, "--", "."],
            cwd=tree, capture_output=True, text=True, timeout=30,
        )
        if cp.returncode == 0 and cp.stdout.strip():
            return True, f"Cherry-pick reference found: {cp.stdout.strip()[:200]}"
    except Exception:
        pass

    # Also search for "(cherry picked from commit <hash>)" pattern
    try:
        cp = subprocess.run(
            ["git", "log", "--all", "--grep", f"cherry picked from commit {commit_hash[:12]}",
             "--oneline", branch],
            cwd=tree, capture_output=True, text=True, timeout=30,
        )
        if cp.returncode == 0 and cp.stdout.strip():
            return True, f"Cherry-pick tag found: {cp.stdout.strip()[:200]}"
    except Exception:
        pass

    return False, ""


# ---------------------------------------------------------------------------
# Live reproducer test
# ---------------------------------------------------------------------------

def run_live_test(
    repro_source: str,
    expected_crash_functions: List[str],
    *,
    arch: str = "arm64",
    ssh_host: Optional[str] = None,
    ssh_port: int = 22,
    ssh_user: str = "root",
    ssh_key: Optional[str] = None,
    adb_port: int = 6520,
    compile_script: Optional[str] = None,
    timeout: int = 120,
    use_adb: bool = True,
) -> LiveTestResult:
    """Compile and run the reproducer on the target device, check for crash.

    This sends the reproducer to a running QEMU/Cuttlefish VM and checks
    if the expected kernel crash occurs by monitoring dmesg.
    """
    result = LiveTestResult(expected_functions=list(expected_crash_functions))

    # Step 1: Compile the reproducer
    repro_binary = _compile_repro(repro_source, arch, compile_script)
    if not repro_binary:
        result.verdict = "compile_fail"
        return result
    result.repro_compiled = True

    # Step 2: Push to device
    if use_adb:
        if not _adb_push(repro_binary, "/data/local/tmp/repro_test", adb_port):
            result.verdict = "unknown"
            return result
    elif ssh_host:
        if not _ssh_push(repro_binary, "/tmp/repro_test", ssh_host, ssh_port, ssh_user, ssh_key):
            result.verdict = "unknown"
            return result
    else:
        result.verdict = "unknown"
        return result

    # Step 3: Clear dmesg, run the reproducer, read dmesg
    dmesg_before = _get_dmesg(ssh_host, ssh_port, ssh_user, ssh_key, adb_port, use_adb) or ""

    _run_repro_remote(ssh_host, ssh_port, ssh_user, ssh_key, adb_port, use_adb, timeout)
    result.repro_ran = True

    # Wait briefly for crash to propagate to dmesg
    time.sleep(3)
    dmesg_after = _get_dmesg(ssh_host, ssh_port, ssh_user, ssh_key, adb_port, use_adb) or ""

    # Step 4: Analyze dmesg diff for crash
    new_dmesg = _dmesg_diff(dmesg_before, dmesg_after)
    result.crash_log_excerpt = new_dmesg[:4000]

    crash_indicators = [
        "BUG:", "KASAN:", "WARNING:", "general protection fault",
        "unable to handle kernel", "kernel panic", "Oops:",
        "Call Trace:", "RIP:", "PC is at",
    ]

    for indicator in crash_indicators:
        if indicator.lower() in new_dmesg.lower():
            result.crash_triggered = True
            break

    if result.crash_triggered:
        # Check if the crash matches the expected signature
        for func in expected_crash_functions:
            base = func.split("+")[0].split(".")[0].strip()
            if base and base in new_dmesg:
                result.matched_functions.append(func)

        if result.matched_functions:
            result.crash_signature_match = True
            result.verdict = "triggered"
        else:
            result.verdict = "different_crash"
    else:
        result.verdict = "no_crash"

    return result


# ---------------------------------------------------------------------------
# GDB path verification
# ---------------------------------------------------------------------------

def run_gdb_path_check(
    crash_stack_functions: List[str],
    *,
    repro_source: Optional[str] = None,
    arch: str = "arm64",
    gdb_port: int = 1234,
    ssh_host: Optional[str] = None,
    ssh_port: int = 22,
    ssh_user: str = "root",
    ssh_key: Optional[str] = None,
    adb_port: int = 6520,
    use_adb: bool = True,
    vmlinux_path: Optional[str] = None,
    system_map_path: Optional[str] = None,
    timeout: int = 180,
    compile_script: Optional[str] = None,
) -> GdbPathCheckResult:
    """Attach GDB to a running kernel, set breakpoints on the crash-stack
    functions, run the reproducer, and check which breakpoints fire.

    This reuses the GDB tracing script from SyzVerify/gdb.py.  The workflow:

    1. Compile the reproducer (if source provided).
    2. Push it to the target device.
    3. Generate a lightweight GDB config that installs crash-stack BPs.
    4. Launch ``gdb`` in batch mode against the target's gdbstub.
    5. Run the reproducer (via SSH/ADB) while GDB is tracing.
    6. Parse the JSON results to see which crash-stack functions were hit.

    Returns:
        GdbPathCheckResult with hit/miss details and verdict.
    """
    result = GdbPathCheckResult(expected_functions=list(crash_stack_functions))

    if not crash_stack_functions:
        result.verdict = "unknown"
        return result

    # ── Step 1: Compile reproducer ───────────────────────────────────
    repro_binary: Optional[str] = None
    if repro_source and os.path.isfile(repro_source):
        repro_binary = _compile_repro(repro_source, arch, compile_script)
        if not repro_binary:
            result.verdict = "error"
            return result

    # ── Step 2: Push reproducer to target ────────────────────────────
    remote_repro = "/data/local/tmp/repro_gdb_test" if use_adb else "/tmp/repro_gdb_test"
    if repro_binary:
        if use_adb:
            if not _adb_push(repro_binary, remote_repro, adb_port):
                result.verdict = "error"
                return result
        elif ssh_host:
            if not _ssh_push(repro_binary, remote_repro, ssh_host, ssh_port, ssh_user, ssh_key):
                result.verdict = "error"
                return result

    # ── Step 3: Build a focused GDB config ───────────────────────────
    # Locate the syz_trace GDB script shipped with SyzVerify
    gdb_script_src = Path(__file__).resolve().parents[1] / "SyzVerify" / "gdb.py"
    if not gdb_script_src.exists():
        gdb_script_src = Path(__file__).resolve().parent.parent / "SyzVerify" / "gdb.py"
    if not gdb_script_src.exists():
        result.verdict = "error"
        return result

    work_dir = tempfile.mkdtemp(prefix="feasibility_gdb_")
    results_json = os.path.join(work_dir, "gdb_path_results.json")
    config_json = os.path.join(work_dir, "gdb_config.json")
    script_path = str(gdb_script_src)
    gdb_log = os.path.join(work_dir, "gdb.log")

    # Resolve crash-stack addresses from System.map (if available)
    crash_stack_addrs: Dict[str, str] = {}
    if system_map_path and os.path.isfile(system_map_path):
        smap: Dict[str, int] = {}
        with open(system_map_path, "r") as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) >= 3:
                    try:
                        smap[parts[2]] = int(parts[0], 16)
                    except ValueError:
                        continue
        for fn in crash_stack_functions:
            base = fn.split("+")[0].split(".")[0].strip()
            if base in smap:
                crash_stack_addrs[base] = f"0x{smap[base]:x}"

    config_data = {
        "poc_entry": "syz_executor",
        "fault_addr": None,
        "fault_insn": None,
        "access_type": "any",
        "access_size": 0,
        "monitor_mode": False,
        "reproducer_path": remote_repro,
        "guest_ssh_port": ssh_port,
        "guest_ssh_user": ssh_user,
        "guest_ssh_key": str(ssh_key) if ssh_key else None,
        "crash_stack_funcs": [fn.split("+")[0].split(".")[0].strip()
                              for fn in crash_stack_functions],
        "crash_stack_addrs": crash_stack_addrs,
    }
    with open(config_json, "w") as f:
        json.dump(config_data, f, indent=2)

    # ── Step 4: Launch GDB ───────────────────────────────────────────
    gdb_cmd: List[str] = ["gdb", "-q", "-batch"]

    # Symbol file / relocation
    if vmlinux_path and os.path.isfile(vmlinux_path):
        gdb_cmd += ["-ex", f"file {vmlinux_path}"]

    gdb_cmd += [
        "-ex", f"set logging file {gdb_log}",
        "-ex", "set logging overwrite on",
        "-ex", "set logging enabled on",
        "-ex", "set pagination off",
        "-ex", "set confirm off",
        "-ex", "set non-stop off",
        "-ex", "set breakpoint pending on",
        "-ex", f'set $export_path = "{results_json}"',
        "-ex", "set tcp connect-timeout 30",
        "-ex", f"target remote :{gdb_port}",
        "-ex", "interrupt",
        "-ex", "python import time; time.sleep(1)",
        "-ex", f"source {script_path}",
        "-ex", f"syz_load_config {config_json}",
        "-ex", "syz_safe_continue",
    ]

    try:
        gdb_proc = subprocess.Popen(
            gdb_cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except FileNotFoundError:
        result.verdict = "error"
        _cleanup_dir(work_dir)
        return result

    # ── Step 5: Run reproducer while GDB is tracing ──────────────────
    time.sleep(5)  # Let GDB attach, install breakpoints, continue

    repro_timeout = min(timeout, 120)
    if use_adb:
        try:
            subprocess.run(
                ["adb", "-s", f"0.0.0.0:{adb_port}", "shell",
                 f"timeout {repro_timeout} {remote_repro} || true"],
                capture_output=True, timeout=repro_timeout + 30,
            )
        except Exception:
            pass
    elif ssh_host:
        try:
            _ssh_cmd(ssh_host, ssh_port, ssh_user, ssh_key,
                     f"timeout {repro_timeout} {remote_repro} || true")
        except Exception:
            pass

    # Give GDB time to capture remaining events
    time.sleep(5)

    # ── Step 6: Export results and terminate GDB ─────────────────────
    try:
        if gdb_proc.stdin:
            gdb_proc.stdin.write(f"export_results {results_json}\n")
            gdb_proc.stdin.write("quit\n")
            gdb_proc.stdin.flush()
    except Exception:
        pass

    try:
        gdb_proc.wait(timeout=30)
    except subprocess.TimeoutExpired:
        gdb_proc.kill()
        try:
            gdb_proc.wait(timeout=5)
        except Exception:
            pass

    # ── Step 7: Parse results JSON ───────────────────────────────────
    _parse_gdb_path_results(result, results_json, crash_stack_functions)

    # ── Compute hit ratio and verdict ────────────────────────────────
    total = len(crash_stack_functions)
    hit = len(result.hit_functions)
    result.hit_ratio = hit / total if total > 0 else 0.0

    if hit == 0 and result.events_captured == 0:
        result.verdict = "error"
    elif result.hit_ratio >= 0.6:
        result.verdict = "path_confirmed"
    elif result.hit_ratio >= 0.3:
        result.verdict = "partial_path"
    elif hit > 0:
        result.verdict = "partial_path"
    else:
        result.verdict = "path_diverged"

    _cleanup_dir(work_dir)
    return result


def _parse_gdb_path_results(
    result: GdbPathCheckResult,
    results_json: str,
    crash_stack_functions: List[str],
) -> None:
    """Parse the GDB export JSON file and populate the result object."""
    if not os.path.isfile(results_json):
        return

    try:
        with open(results_json, "r") as f:
            data = json.load(f)
    except Exception:
        return

    # func_hits: {func_name: count}
    func_hits = data.get("func_hits", {})
    result.func_hit_counts = dict(func_hits)
    result.events_captured = data.get("summary", {}).get("total_events", 0)

    # Map expected functions to their base names for matching
    expected_bases: Dict[str, str] = {}
    for fn in crash_stack_functions:
        base = fn.split("+")[0].split(".")[0].strip()
        expected_bases[base] = fn

    # Check func_hits first
    for base, original in expected_bases.items():
        if func_hits.get(base, 0) > 0:
            result.hit_functions.append(original)
        else:
            result.missed_functions.append(original)

    # Also scan events for func_hit type entries
    events = data.get("events", [])
    for ev in events:
        if ev.get("type") == "func_hit":
            fn = ev.get("func", "")
            if fn in expected_bases:
                orig = expected_bases[fn]
                if orig not in result.hit_functions:
                    result.hit_functions.append(orig)
                    result.missed_functions = [
                        m for m in result.missed_functions
                        if m.split("+")[0].split(".")[0].strip() != fn
                    ]

    # Check for crash in events
    for ev in events:
        if ev.get("type") in ("stop", "kernel_panic", "oops"):
            result.crash_detected = True
            bt = ev.get("backtrace") or ev.get("bt") or []
            if isinstance(bt, list):
                result.crash_backtrace = bt[:20]
            break


def _cleanup_dir(path: str) -> None:
    """Remove a temporary directory, ignoring errors."""
    try:
        shutil.rmtree(path, ignore_errors=True)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _compile_repro(source_path: str, arch: str, compile_script: Optional[str]) -> Optional[str]:
    """Compile the reproducer C source into a static binary."""
    if not os.path.isfile(source_path):
        return None

    output_path = source_path.replace(".c", "") + "_feasibility_test"

    # Use provided compile script if available
    if compile_script and os.path.isfile(compile_script):
        try:
            cp = subprocess.run(
                [compile_script, source_path, output_path],
                capture_output=True, text=True, timeout=120,
            )
            if cp.returncode == 0 and os.path.isfile(output_path):
                return output_path
        except Exception:
            pass

    # Default: cross-compile with GCC
    cc = "aarch64-linux-gnu-gcc" if arch == "arm64" else "gcc"
    try:
        cp = subprocess.run(
            [cc, "-static", "-o", output_path, source_path, "-lpthread"],
            capture_output=True, text=True, timeout=120,
        )
        if cp.returncode == 0 and os.path.isfile(output_path):
            return output_path
    except Exception:
        pass

    return None


def _adb_push(local: str, remote: str, adb_port: int) -> bool:
    """Push a file to the device via adb."""
    try:
        cp = subprocess.run(
            ["adb", "-s", f"0.0.0.0:{adb_port}", "push", local, remote],
            capture_output=True, text=True, timeout=30,
        )
        if cp.returncode == 0:
            subprocess.run(
                ["adb", "-s", f"0.0.0.0:{adb_port}", "shell", f"chmod 755 {remote}"],
                capture_output=True, timeout=10,
            )
            return True
    except Exception:
        pass
    return False


def _ssh_push(local: str, remote: str, host: str, port: int, user: str, key: Optional[str]) -> bool:
    """Push a file via scp."""
    cmd = ["scp", "-o", "StrictHostKeyChecking=no", "-P", str(port)]
    if key:
        cmd += ["-i", key]
    cmd += [local, f"{user}@{host}:{remote}"]
    try:
        cp = subprocess.run(cmd, capture_output=True, timeout=30)
        if cp.returncode == 0:
            _ssh_cmd(host, port, user, key, f"chmod 755 {remote}")
            return True
    except Exception:
        pass
    return False


def _ssh_cmd(host: str, port: int, user: str, key: Optional[str], cmd: str) -> Optional[str]:
    """Run a command via SSH, return stdout or None."""
    ssh = ["ssh", "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=10"]
    if key:
        ssh += ["-i", key]
    ssh += ["-p", str(port), f"{user}@{host}", cmd]
    try:
        cp = subprocess.run(ssh, capture_output=True, text=True, timeout=30)
        if cp.returncode == 0:
            return cp.stdout
    except Exception:
        pass
    return None


def _get_dmesg(
    ssh_host: Optional[str], ssh_port: int, ssh_user: str, ssh_key: Optional[str],
    adb_port: int, use_adb: bool,
) -> Optional[str]:
    """Read dmesg from the target device."""
    if use_adb:
        try:
            cp = subprocess.run(
                ["adb", "-s", f"0.0.0.0:{adb_port}", "shell", "dmesg"],
                capture_output=True, text=True, timeout=30,
            )
            if cp.returncode == 0:
                return cp.stdout
        except Exception:
            pass
    if ssh_host:
        return _ssh_cmd(ssh_host, ssh_port, ssh_user, ssh_key, "dmesg")
    return None


def _run_repro_remote(
    ssh_host: Optional[str], ssh_port: int, ssh_user: str, ssh_key: Optional[str],
    adb_port: int, use_adb: bool, timeout: int,
) -> None:
    """Run the reproducer on the remote device (fire and forget — the crash may kill SSH)."""
    if use_adb:
        try:
            subprocess.run(
                ["adb", "-s", f"0.0.0.0:{adb_port}", "shell",
                 f"timeout {timeout} /data/local/tmp/repro_test || true"],
                capture_output=True, timeout=timeout + 30,
            )
        except Exception:
            pass  # Expected — crash may kill the shell
    elif ssh_host:
        try:
            _ssh_cmd(ssh_host, ssh_port, ssh_user, ssh_key,
                      f"timeout {timeout} /tmp/repro_test || true")
        except Exception:
            pass


def _dmesg_diff(before: str, after: str) -> str:
    """Return lines in ``after`` that weren't in ``before``."""
    before_lines = set(before.splitlines())
    new_lines = [l for l in after.splitlines() if l not in before_lines]
    return "\n".join(new_lines)


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def assess_feasibility(
    bug_id: str,
    parsed_crash: Dict[str, Any],
    *,
    original_kernel: str = "",
    target_kernel: str = "",
    repro_source: Optional[str] = None,
    fix_commits: Optional[List[str]] = None,
    vulnerable_functions: Optional[List[str]] = None,
    arch: str = "arm64",
    # Symbol check sources
    kallsyms_path: Optional[str] = None,
    system_map_path: Optional[str] = None,
    vmlinux_path: Optional[str] = None,
    # Target device connectivity
    ssh_host: Optional[str] = None,
    ssh_port: int = 22,
    ssh_user: str = "root",
    ssh_key: Optional[str] = None,
    adb_port: int = 6520,
    use_adb: bool = True,
    # Kernel tree for backport detection
    kernel_tree_path: Optional[str] = None,
    changelog_path: Optional[str] = None,
    target_branch: str = "HEAD",
    # Compile options
    compile_script: Optional[str] = None,
    timeout: int = 120,
    # GDB path verification
    gdb_port: int = 1234,
    # Control which checks to run
    skip_symbol_check: bool = False,
    skip_fix_check: bool = False,
    skip_live_test: bool = False,
    skip_gdb_path_check: bool = False,
) -> FeasibilityReport:
    """Run all feasibility checks and produce an overall report.

    Args:
        bug_id: Syzbot bug identifier.
        parsed_crash: Parsed crash log dict (from crash_analyzer.parse_crash_log).
        original_kernel: Kernel version the bug was originally found on.
        target_kernel: Kernel version we're checking feasibility for.
        repro_source: Path to the syzbot C reproducer source.
        fix_commits: List of known fix commit hashes.
        vulnerable_functions: Functions from the crash stack trace to check.
            If None, extracted automatically from parsed_crash.
        arch: Target architecture ("arm64" or "x86_64").
        ... (connection & compile params for each sub-check)

    Returns:
        FeasibilityReport with per-check results and overall verdict.
    """
    report = FeasibilityReport(
        bug_id=bug_id,
        original_kernel=original_kernel,
        target_kernel=target_kernel,
    )

    # Auto-extract vulnerable functions from parsed crash if not provided
    if not vulnerable_functions:
        vulnerable_functions = _extract_crash_functions(parsed_crash)
    if not vulnerable_functions:
        report.notes.append("No vulnerable functions identified from crash data")

    # ── Check 1: Symbol presence ─────────────────────────────────────
    if not skip_symbol_check and vulnerable_functions:
        report.symbol_check = check_symbols(
            vulnerable_functions,
            kallsyms_path=kallsyms_path,
            system_map_path=system_map_path,
            vmlinux_path=vmlinux_path,
            ssh_host=ssh_host,
            ssh_port=ssh_port,
            ssh_user=ssh_user,
            ssh_key=ssh_key,
        )
        if report.symbol_check.verdict == "absent":
            report.notes.append("All vulnerable functions are MISSING from the target — "
                                "code path likely removed or renamed")
        elif report.symbol_check.verdict == "present":
            report.notes.append("All vulnerable functions are PRESENT in the target kernel")

    # ── Check 2: Fix backport ────────────────────────────────────────
    if not skip_fix_check and fix_commits:
        report.fix_check = check_fix_backported(
            fix_commits,
            kernel_tree_path=kernel_tree_path,
            changelog_path=changelog_path,
            target_branch=target_branch,
        )
        if report.fix_check.verdict == "patched":
            report.notes.append(f"Fix has been backported: {report.fix_check.evidence[:200]}")

    # ── Check 3: Live reproducer test ────────────────────────────────
    if not skip_live_test and repro_source and os.path.isfile(repro_source):
        crash_funcs = vulnerable_functions or []
        report.live_test = run_live_test(
            repro_source,
            crash_funcs,
            arch=arch,
            ssh_host=ssh_host,
            ssh_port=ssh_port,
            ssh_user=ssh_user,
            ssh_key=ssh_key,
            adb_port=adb_port,
            compile_script=compile_script,
            timeout=timeout,
            use_adb=use_adb,
        )
        if report.live_test.verdict == "triggered":
            report.notes.append("Reproducer triggered the SAME crash on the target kernel!")
        elif report.live_test.verdict == "no_crash":
            report.notes.append("Reproducer did NOT crash the target kernel")
        elif report.live_test.verdict == "different_crash":
            report.notes.append("Reproducer crashed the target but with a DIFFERENT signature")

    # ── Check 4: GDB path verification ───────────────────────────────
    if not skip_gdb_path_check and repro_source and os.path.isfile(repro_source):
        crash_funcs = vulnerable_functions or []
        if crash_funcs:
            report.gdb_path_check = run_gdb_path_check(
                crash_funcs,
                repro_source=repro_source,
                arch=arch,
                gdb_port=gdb_port,
                ssh_host=ssh_host,
                ssh_port=ssh_port,
                ssh_user=ssh_user,
                ssh_key=ssh_key,
                adb_port=adb_port,
                use_adb=use_adb,
                vmlinux_path=vmlinux_path,
                system_map_path=system_map_path,
                timeout=timeout,
                compile_script=compile_script,
            )
            gpc = report.gdb_path_check
            if gpc.verdict == "path_confirmed":
                report.notes.append(
                    f"GDB path CONFIRMED: {len(gpc.hit_functions)}/"
                    f"{len(gpc.expected_functions)} crash-stack functions hit "
                    f"(ratio={gpc.hit_ratio:.0%})")
            elif gpc.verdict == "partial_path":
                report.notes.append(
                    f"GDB path PARTIAL: {len(gpc.hit_functions)}/"
                    f"{len(gpc.expected_functions)} crash-stack functions hit")
            elif gpc.verdict == "path_diverged":
                report.notes.append(
                    "GDB path DIVERGED: none of the expected crash-stack "
                    "functions were hit — code path has changed")
            elif gpc.verdict == "error":
                report.notes.append("GDB path check encountered an error")

    # ── Compute overall verdict ──────────────────────────────────────
    report.overall_verdict, report.confidence = _compute_verdict(report)

    return report


def _extract_crash_functions(parsed_crash: Dict[str, Any]) -> List[str]:
    """Extract the stack-trace function names from a parsed crash log."""
    funcs = []
    seen = set()
    # Try several common key names from crash_analyzer output
    frames = (parsed_crash.get("frames") or
              parsed_crash.get("stack_frames") or
              parsed_crash.get("call_trace") or [])
    for frame in frames[:15]:
        if isinstance(frame, dict):
            func = frame.get("func") or frame.get("function") or ""
        elif isinstance(frame, str):
            func = frame
        else:
            continue
        base = func.split("+")[0].split(".")[0].strip()
        if base and base not in seen:
            seen.add(base)
            funcs.append(base)
    return funcs


def _compute_verdict(report: FeasibilityReport) -> Tuple[str, float]:
    """Combine sub-check results into an overall verdict and confidence."""
    # Weights: live test is strongest signal, then fix check, then symbols
    score = 0.5  # neutral start
    confidence_parts = []

    # Fix check is strong negative signal
    if report.fix_check:
        if report.fix_check.verdict == "patched":
            score -= 0.4
            confidence_parts.append(0.8)
        elif report.fix_check.verdict == "unpatched":
            score += 0.1
            confidence_parts.append(0.6)

    # Symbol check
    if report.symbol_check:
        if report.symbol_check.verdict == "present":
            score += 0.15
            confidence_parts.append(0.5)
        elif report.symbol_check.verdict == "absent":
            score -= 0.3
            confidence_parts.append(0.7)
        elif report.symbol_check.verdict == "partial":
            score -= 0.1
            confidence_parts.append(0.4)

    # Live test is the strongest signal
    if report.live_test:
        if report.live_test.verdict == "triggered":
            score += 0.4
            confidence_parts.append(0.95)
        elif report.live_test.verdict == "no_crash":
            score -= 0.3
            confidence_parts.append(0.75)
        elif report.live_test.verdict == "different_crash":
            score -= 0.15
            confidence_parts.append(0.5)

    # GDB path verification — strong signal for code-path reachability
    if report.gdb_path_check:
        gpc = report.gdb_path_check
        if gpc.verdict == "path_confirmed":
            score += 0.35
            confidence_parts.append(0.9)
        elif gpc.verdict == "partial_path":
            score += 0.1
            confidence_parts.append(0.6)
        elif gpc.verdict == "path_diverged":
            score -= 0.35
            confidence_parts.append(0.85)
        # "error" verdict doesn't shift score

    # Clamp
    score = max(0.0, min(1.0, score))

    if score >= 0.55:
        verdict = "likely_feasible"
    elif score <= 0.35:
        verdict = "likely_patched"
    else:
        verdict = "inconclusive"

    # Confidence is the average of the individual check confidences
    confidence = sum(confidence_parts) / len(confidence_parts) if confidence_parts else 0.3

    return verdict, round(confidence, 2)
