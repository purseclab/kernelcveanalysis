"""
analysis.feasibility — Cross-version feasibility assessment.

Determines whether a vulnerability found on kernel version A is likely
to exist (and be exploitable) on target kernel version B.

Checks:
    1. **Symbol presence** — fuzzy matching against kallsyms / System.map /
       vmlinux, with ``.isra`` / ``.constprop`` suffix stripping.
    2. **Fix backport detection** — three strategies: ``git merge-base
       --is-ancestor``, ``git log --grep``, cherry-pick tag search, plus
       optional changelog scanning.
    3. **Source-level diff** — ``git diff`` of the vulnerable file/function
       between the original and target kernel tags.  Identical source is
       a strong positive signal.
    4. **Live crash test** — compile & push the reproducer, capture dmesg
       *before and after*, check for crash signature match.
    5. **GDB path verification** — set breakpoints on crash-stack functions,
       run the reproducer, parse hit/miss JSON.
    6. **Continuous weighted scoring** — each check shifts a float score
       (start 0.5); final verdict is ``likely_feasible`` / ``likely_patched``
       / ``inconclusive``.
"""

from __future__ import annotations

import difflib
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ..core.config import Config, load_config
from ..core.log import console
from ..core.models import (
    CrashReport,
    DmesgLogAnalysis,
    FeasibilityReport,
    FixBackportResult,
    GdbPathCheckResult,
    LiveTestResult,
    SourceDiffResult,
    SymbolCheckResult,
)

# =====================================================================
# 1.  Symbol / code-path analysis  (fuzzy matching)
# =====================================================================


def _strip_symbol_decorations(name: str) -> str:
    """Strip compiler-generated suffixes for fuzzy symbol matching.

    GCC may rename functions with ``.isra``, ``.constprop``, ``.part``,
    etc.  Crash logs may include ``+0xoffset/size``.  We strip all of
    these so that ``do_something.isra.0+0x1b8/0x2e0`` matches
    ``do_something`` in the symbol table.
    """
    # Strip +offset/size first
    base = name.split("+")[0]
    # Strip .isra.N, .constprop.N, .part.N, .cold, etc.
    base = re.split(r"\.(isra|constprop|part|cold|lto_priv)\b", base)[0]
    return base.strip()


def check_symbols(
    symbols: List[str],
    *,
    kallsyms_path: Optional[str] = None,
    system_map_path: Optional[str] = None,
    vmlinux_path: Optional[str] = None,
    ssh_host: Optional[str] = None,
    ssh_port: int = 22,
    ssh_user: str = "root",
    ssh_key: Optional[str] = None,
) -> SymbolCheckResult:
    """Check which crash-path symbols exist on the target kernel.

    Uses **fuzzy matching**: ``.isra`` / ``.constprop`` / ``+offset``
    suffixes are stripped before comparison.

    Tries (in order): remote ``/proc/kallsyms`` via SSH, local kallsyms
    file, System.map, vmlinux via ``nm``.
    """
    result = SymbolCheckResult(symbols_checked=list(symbols))
    all_syms: set[str] = set()

    # --- Remote kallsyms via SSH ---
    if ssh_host and not all_syms:
        text = _read_remote_kallsyms(ssh_host, ssh_port, ssh_user, ssh_key)
        if text:
            _parse_symbol_text(text, all_syms)
            if all_syms:
                result.source = "remote_kallsyms"

    # --- Local kallsyms file ---
    if not all_syms and kallsyms_path:
        p = Path(kallsyms_path)
        if p.exists():
            _parse_symbol_text(p.read_text(), all_syms)
            if all_syms:
                result.source = "local_kallsyms"

    # --- System.map ---
    if not all_syms and system_map_path:
        p = Path(system_map_path)
        if p.exists():
            _parse_symbol_text(p.read_text(), all_syms)
            if all_syms:
                result.source = "system_map"

    # --- vmlinux via nm ---
    if not all_syms and vmlinux_path:
        try:
            out = subprocess.run(
                ["nm", vmlinux_path], capture_output=True, text=True, timeout=120,
            )
            if out.returncode == 0:
                _parse_symbol_text(out.stdout, all_syms)
                if all_syms:
                    result.source = "vmlinux_nm"
        except Exception:
            pass

    if not all_syms:
        result.source = "none"
        result.verdict = "unknown"
        return result

    # --- Fuzzy match ---
    for sym in symbols:
        base = _strip_symbol_decorations(sym)
        if base in all_syms:
            result.symbols_found.append(sym)
        else:
            result.symbols_missing.append(sym)

    total = len(symbols)
    found = len(result.symbols_found)
    result.hit_ratio = found / total if total else 0.0

    if found == total:
        result.verdict = "present"
    elif found == 0:
        result.verdict = "absent"
    else:
        result.verdict = "partial"

    return result


def _read_remote_kallsyms(
    host: str, port: int, user: str, key: Optional[str],
) -> Optional[str]:
    """Read ``/proc/kallsyms`` from a remote device via SSH."""
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


def _parse_symbol_text(text: str, out: set[str]) -> None:
    """Parse kallsyms / System.map / nm output into a set of base symbol names."""
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 3:
            raw = parts[2].split("\t")[0]
            out.add(_strip_symbol_decorations(raw))
        elif len(parts) == 2:
            out.add(_strip_symbol_decorations(parts[1]))


# =====================================================================
# 2.  Fix-commit backport detection  (3 strategies + changelog)
# =====================================================================


def check_fix_backported(
    fix_commits: List[str],
    *,
    kernel_tree_path: Optional[str] = None,
    changelog_path: Optional[str] = None,
    target_branch: str = "HEAD",
) -> FixBackportResult:
    """Check if any fix commits have been back-ported into the target tree.

    Strategies (tried in order):

    1. ``git merge-base --is-ancestor`` — commit is a direct ancestor.
    2. ``git log --grep`` — commit hash mentioned in a log message.
    3. Cherry-pick tag — ``"cherry picked from commit <hash>"``.
    4. Changelog scan — short hash appears in a plaintext changelog.

    Returns a :class:`FixBackportResult`.
    """
    result = FixBackportResult(fix_commits=list(fix_commits))

    if not fix_commits:
        result.verdict = "unknown"
        return result

    tree = kernel_tree_path
    is_git = tree and os.path.isdir(os.path.join(tree, ".git"))

    for commit in fix_commits:
        # ── Strategy 1: merge-base ──
        if is_git:
            found, evidence = _git_has_commit(tree, commit, target_branch)  # type: ignore[arg-type]
            if found:
                result.backported = True
                result.strategy = "merge_base"
                result.evidence = evidence
                result.verdict = "patched"
                return result

        # ── Strategy 2: git log --grep ──
        if is_git:
            found, evidence = _git_grep_search(tree, commit, target_branch)  # type: ignore[arg-type]
            if found:
                result.backported = True
                result.strategy = "grep"
                result.evidence = evidence
                result.verdict = "patched"
                return result

        # ── Strategy 3: cherry-pick tag ──
        if is_git:
            found, evidence = _git_cherry_pick_search(tree, commit, target_branch)  # type: ignore[arg-type]
            if found:
                result.backported = True
                result.strategy = "cherry_pick"
                result.evidence = evidence
                result.verdict = "patched"
                return result

    # ── Strategy 4: changelog scanning ──
    if changelog_path and os.path.isfile(changelog_path):
        with open(changelog_path, "r") as f:
            changelog = f.read()
        for commit in fix_commits:
            short = commit[:12]
            if short in changelog:
                result.backported = True
                result.strategy = "changelog"
                result.evidence = f"Fix {short} found in changelog"
                result.verdict = "patched"
                return result

    # Nothing found → assume unpatched (but low confidence)
    result.verdict = "unpatched"
    return result


def _git_has_commit(tree: str, commit_hash: str, branch: str) -> Tuple[bool, str]:
    """Check if *commit_hash* is an ancestor of *branch*."""
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


def _git_grep_search(tree: str, commit_hash: str, branch: str) -> Tuple[bool, str]:
    """Search ``git log`` for a message mentioning the commit hash."""
    try:
        cp = subprocess.run(
            ["git", "log", "--oneline", "--grep", commit_hash[:12], branch, "--", "."],
            cwd=tree, capture_output=True, text=True, timeout=30,
        )
        if cp.returncode == 0 and cp.stdout.strip():
            return True, f"Grep match: {cp.stdout.strip()[:200]}"
    except Exception:
        pass
    return False, ""


def _git_cherry_pick_search(tree: str, commit_hash: str, branch: str) -> Tuple[bool, str]:
    """Search for ``(cherry picked from commit <hash>)`` tags."""
    short = commit_hash[:12]
    try:
        cp = subprocess.run(
            ["git", "log", "--all", "--grep",
             f"cherry picked from commit {short}",
             "--oneline", branch],
            cwd=tree, capture_output=True, text=True, timeout=30,
        )
        if cp.returncode == 0 and cp.stdout.strip():
            return True, f"Cherry-pick tag found: {cp.stdout.strip()[:200]}"
    except Exception:
        pass
    return False, ""


# =====================================================================
# 3.  Source-level diff  (static analysis — NEW)
# =====================================================================


def check_source_diff(
    vulnerable_files: List[str],
    vulnerable_functions: List[str],
    *,
    kernel_tree_path: str,
    original_tag: str,
    target_tag: str,
) -> SourceDiffResult:
    """Compare the vulnerable files / functions between two kernel versions.

    Uses ``git diff <original_tag>..<target_tag> -- <file>`` to detect
    source-level changes in the code paths that contain the bug.

    If the vulnerable function body is *identical* across versions, the
    bug is almost certainly still present (strong positive signal).  If
    significant changes exist, the bug may have been incidentally fixed
    or the code path may have diverged.

    Args:
        vulnerable_files: Paths (relative to tree root) of the source
            files that contain the vulnerable code, e.g.
            ``["fs/io_uring.c", "net/core/sock.c"]``.
        vulnerable_functions: Function names to look at inside those files.
        kernel_tree_path: Path to a local kernel git checkout.
        original_tag: Git ref for the kernel the bug was found on.
        target_tag: Git ref for the kernel we're checking.

    Returns:
        :class:`SourceDiffResult` with per-file and per-function status.
    """
    result = SourceDiffResult(
        files_checked=list(vulnerable_files),
        functions_checked=list(vulnerable_functions),
    )
    tree = Path(kernel_tree_path)
    if not (tree / ".git").is_dir():
        result.verdict = "unknown"
        return result

    # ── Per-file diff ────────────────────────────────────────────────
    total_diff_lines = 0
    for fpath in vulnerable_files:
        # Check if the file exists in the target tag
        try:
            exists = subprocess.run(
                ["git", "cat-file", "-e", f"{target_tag}:{fpath}"],
                cwd=tree, capture_output=True, timeout=10,
            )
            if exists.returncode != 0:
                result.files_missing.append(fpath)
                continue
        except Exception:
            result.files_missing.append(fpath)
            continue

        try:
            diff_cp = subprocess.run(
                ["git", "diff", f"{original_tag}..{target_tag}", "--", fpath],
                cwd=tree, capture_output=True, text=True, timeout=30,
            )
            diff_text = diff_cp.stdout.strip()
        except Exception:
            result.files_missing.append(fpath)
            continue

        if not diff_text:
            # Empty diff → identical
            result.files_unchanged.append(fpath)
        else:
            result.files_changed.append(fpath)
            n_lines = sum(
                1 for l in diff_text.splitlines()
                if l.startswith(("+", "-")) and not l.startswith(("+++", "---"))
            )
            total_diff_lines += n_lines
            result.diff_excerpts[fpath] = diff_text[:2000]

    result.total_diff_lines = total_diff_lines

    # ── Per-function analysis (within changed files) ─────────────────
    for func in vulnerable_functions:
        func_changed = _check_function_changed(
            func, vulnerable_files, tree, original_tag, target_tag,
        )
        if func_changed is None:
            # Could not determine — skip silently
            pass
        elif func_changed:
            result.functions_changed.append(func)
        else:
            result.functions_unchanged.append(func)

    # ── Compute similarity ratio ─────────────────────────────────────
    n_files = len(vulnerable_files)
    n_funcs = len(vulnerable_functions)
    if n_files > 0:
        file_sim = len(result.files_unchanged) / n_files
    else:
        file_sim = 0.0

    if n_funcs > 0:
        func_sim = len(result.functions_unchanged) / n_funcs
    else:
        func_sim = file_sim  # fall back to file-level if no functions provided

    # Weight function-level more heavily (0.7) than file-level (0.3)
    result.similarity_ratio = round(0.3 * file_sim + 0.7 * func_sim, 3) if n_funcs else file_sim

    # ── Verdict ──────────────────────────────────────────────────────
    if result.files_missing and len(result.files_missing) == n_files:
        result.verdict = "missing"
    elif result.similarity_ratio >= 0.95:
        result.verdict = "identical"
    elif result.similarity_ratio >= 0.7:
        result.verdict = "minor_changes"
    else:
        result.verdict = "major_changes"

    return result


def _check_function_changed(
    func_name: str,
    files: List[str],
    tree: Path,
    old_tag: str,
    new_tag: str,
) -> Optional[bool]:
    """Check if a specific function body changed between two tags.

    Uses ``git diff -U0 --function-context`` so that only hunks inside
    the function are shown.  Returns ``True`` if changed, ``False`` if
    identical, or ``None`` if the function could not be found.
    """
    base = _strip_symbol_decorations(func_name)
    for fpath in files:
        try:
            cp = subprocess.run(
                ["git", "diff", "-U0", "--function-context",
                 f"{old_tag}..{new_tag}", "--", fpath],
                cwd=tree, capture_output=True, text=True, timeout=30,
            )
            if cp.returncode != 0:
                continue
            diff_text = cp.stdout
            if not diff_text.strip():
                # No diff at all in this file — function is unchanged
                # But we need to verify the function exists
                try:
                    old_src = subprocess.run(
                        ["git", "show", f"{old_tag}:{fpath}"],
                        cwd=tree, capture_output=True, text=True, timeout=15,
                    )
                    if base in old_src.stdout:
                        return False  # Function exists and is unchanged
                except Exception:
                    pass
                continue

            # Check if any hunk mentions the function name
            # Look for function header in diff context or +/- lines
            in_func = False
            func_has_changes = False
            for line in diff_text.splitlines():
                # @@ ... @@ function_name(  — GCC-style function context
                if line.startswith("@@") and base in line:
                    in_func = True
                    continue
                if in_func and line.startswith("@@"):
                    in_func = False
                if in_func and line.startswith(("+", "-")) and not line.startswith(("+++", "---")):
                    func_has_changes = True

            if func_has_changes:
                return True

            # Function not in any diff hunk — it's unchanged
            # Verify it exists in the file
            try:
                old_src = subprocess.run(
                    ["git", "show", f"{old_tag}:{fpath}"],
                    cwd=tree, capture_output=True, text=True, timeout=15,
                )
                if base in old_src.stdout:
                    return False
            except Exception:
                pass

        except Exception:
            continue

    return None  # Couldn't find the function in any file


def _extract_function_body(source: str, func_name: str) -> Optional[str]:
    """Extract a C function body from *source* by brace counting.

    Returns the text from the function signature through the closing
    brace, or ``None`` if the function is not found.
    """
    pattern = re.compile(
        rf"(?:^|\n)[^\n]*?\b{re.escape(func_name)}\s*\([^)]*\)\s*\{{",
        re.DOTALL,
    )
    m = pattern.search(source)
    if not m:
        return None
    start = m.start()
    brace_start = source.index("{", m.start())
    depth = 0
    i = brace_start
    while i < len(source):
        if source[i] == "{":
            depth += 1
        elif source[i] == "}":
            depth -= 1
            if depth == 0:
                return source[start : i + 1]
        i += 1
    return None


def compute_function_similarity(old_body: str, new_body: str) -> float:
    """Return a 0.0-1.0 similarity ratio between two function bodies.

    Uses :func:`difflib.SequenceMatcher` on normalised source (comments
    and blank lines stripped) for a robust comparison.
    """
    def _normalise(s: str) -> List[str]:
        lines = []
        for line in s.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("//") or stripped.startswith("/*"):
                continue
            lines.append(stripped)
        return lines

    return difflib.SequenceMatcher(None, _normalise(old_body), _normalise(new_body)).ratio()


# =====================================================================
# 4.  Live crash test  (dmesg before/after + crash signature matching)
# =====================================================================


def run_live_test(
    reproducer_path: str,
    expected_crash_functions: List[str],
    *,
    arch: str = "x86_64",
    ssh_host: Optional[str] = None,
    ssh_port: int = 22,
    ssh_user: str = "root",
    ssh_key: Optional[str] = None,
    adb_port: int = 6520,
    use_adb: bool = False,
    compile_script: Optional[str] = None,
    timeout: int = 120,
) -> LiveTestResult:
    """Compile and run the reproducer on the target, check dmesg diff.

    Improvements over v1:
    * Captures dmesg **before and after** to isolate new messages.
    * Matches crash stack functions against the new dmesg (signature match).
    * Supports both SSH and ADB connectivity.
    """
    result = LiveTestResult(expected_functions=list(expected_crash_functions))

    # ── Step 1: Compile ──────────────────────────────────────────────
    repro_binary = _compile_repro(reproducer_path, arch, compile_script)
    if not repro_binary:
        result.verdict = "compile_fail"
        return result
    result.repro_compiled = True

    # ── Step 2: Push to device ───────────────────────────────────────
    remote_path = "/data/local/tmp/repro_test" if use_adb else "/tmp/syzploit_repro"
    if use_adb:
        if not _adb_push(repro_binary, remote_path, adb_port):
            result.verdict = "unknown"
            return result
    elif ssh_host:
        if not _ssh_push(repro_binary, remote_path, ssh_host, ssh_port, ssh_user, ssh_key):
            result.verdict = "unknown"
            return result
    else:
        result.verdict = "unknown"
        return result

    # ── Step 3: Capture dmesg BEFORE ─────────────────────────────────
    dmesg_before = _get_dmesg(ssh_host, ssh_port, ssh_user, ssh_key, adb_port, use_adb) or ""

    # ── Step 4: Run the reproducer ───────────────────────────────────
    _run_repro_remote(ssh_host, ssh_port, ssh_user, ssh_key, adb_port, use_adb, remote_path, timeout)
    result.repro_ran = True

    time.sleep(3)  # let crash propagate to dmesg

    # ── Step 5: Capture dmesg AFTER and compute diff ─────────────────
    dmesg_after = _get_dmesg(ssh_host, ssh_port, ssh_user, ssh_key, adb_port, use_adb) or ""
    new_dmesg = _dmesg_diff(dmesg_before, dmesg_after)
    result.crash_log_excerpt = new_dmesg[:4000]

    # ── Step 6: Analyse crash indicators ─────────────────────────────
    _CRASH_INDICATORS = [
        "BUG:", "KASAN:", "WARNING:", "general protection fault",
        "unable to handle kernel", "kernel panic", "Oops:",
        "Call Trace:", "RIP:", "PC is at",
    ]
    for indicator in _CRASH_INDICATORS:
        if indicator.lower() in new_dmesg.lower():
            result.crash_triggered = True
            break

    if result.crash_triggered and expected_crash_functions:
        for func in expected_crash_functions:
            base = _strip_symbol_decorations(func)
            if base and base in new_dmesg:
                result.matched_functions.append(func)

        if result.matched_functions:
            result.crash_signature_match = True
            result.verdict = "triggered"
        else:
            result.verdict = "different_crash"
    elif result.crash_triggered:
        result.verdict = "triggered"
    else:
        result.verdict = "no_crash"

    return result


# =====================================================================
# 5.  GDB path verification
# =====================================================================


def run_gdb_path_check(
    crash_stack_functions: List[str],
    *,
    repro_source: Optional[str] = None,
    arch: str = "x86_64",
    gdb_port: int = 1234,
    ssh_host: Optional[str] = None,
    ssh_port: int = 22,
    ssh_user: str = "root",
    ssh_key: Optional[str] = None,
    adb_port: int = 6520,
    use_adb: bool = False,
    vmlinux_path: Optional[str] = None,
    system_map_path: Optional[str] = None,
    timeout: int = 180,
    compile_script: Optional[str] = None,
) -> GdbPathCheckResult:
    """Attach GDB to a running kernel, set breakpoints on crash-stack
    functions, run the reproducer, and check which breakpoints fire.

    Workflow:

    1. Compile the reproducer (if source provided).
    2. Push it to the target device.
    3. Generate a lightweight GDB config with crash-stack breakpoints.
    4. Launch ``gdb`` in batch mode via the GDB stub.
    5. Run the reproducer while GDB is tracing.
    6. Parse the JSON results to compute hit/miss ratios.

    Returns:
        :class:`GdbPathCheckResult` with hit/miss details and verdict.
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

    # ── Step 2: Push to target ───────────────────────────────────────
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

    # ── Step 3: Build GDB config ─────────────────────────────────────
    # Locate the GDB tracing script (shipped with syzploit)
    gdb_script_src = Path(__file__).resolve().parents[1] / "infra" / "gdb_trace.py"
    if not gdb_script_src.exists():
        # Fallback: run with inline breakpoints only
        gdb_script_src = None

    work_dir = tempfile.mkdtemp(prefix="feasibility_gdb_")
    results_json = os.path.join(work_dir, "gdb_path_results.json")
    config_json = os.path.join(work_dir, "gdb_config.json")
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
            base = _strip_symbol_decorations(fn)
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
        "crash_stack_funcs": [_strip_symbol_decorations(fn) for fn in crash_stack_functions],
        "crash_stack_addrs": crash_stack_addrs,
    }
    with open(config_json, "w") as f:
        json.dump(config_data, f, indent=2)

    # ── Step 4: Launch GDB ───────────────────────────────────────────
    gdb_binary = "gdb-multiarch" if arch == "arm64" else "gdb"
    gdb_cmd: List[str] = [gdb_binary, "-q", "-batch"]

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
    ]

    if gdb_script_src:
        gdb_cmd += [
            "-ex", f"source {gdb_script_src}",
            "-ex", f"syz_load_config {config_json}",
            "-ex", "syz_safe_continue",
        ]
    else:
        # Fallback: manual breakpoints
        for fn in crash_stack_functions:
            base = _strip_symbol_decorations(fn)
            gdb_cmd += ["-ex", f"break {base}"]
        gdb_cmd += ["-ex", "continue"]

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
    time.sleep(5)  # let GDB attach + install breakpoints

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

    time.sleep(5)  # let GDB capture remaining events

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

    # ── Hit ratio + verdict ──────────────────────────────────────────
    total = len(crash_stack_functions)
    hit = len(result.hit_functions)
    result.hit_ratio = hit / total if total > 0 else 0.0

    if hit == 0 and result.events_captured == 0:
        result.verdict = "error"
    elif result.hit_ratio >= 0.6:
        result.verdict = "path_confirmed"
    elif result.hit_ratio >= 0.3 or hit > 0:
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
    """Parse the GDB export JSON and populate *result*."""
    if not os.path.isfile(results_json):
        return

    try:
        with open(results_json, "r") as f:
            data = json.load(f)
    except Exception:
        return

    func_hits = data.get("func_hits", {})
    result.func_hit_counts = dict(func_hits)
    result.events_captured = data.get("summary", {}).get("total_events", 0)

    # Map expected functions -> base names for fuzzy matching
    expected_bases: Dict[str, str] = {}
    for fn in crash_stack_functions:
        base = _strip_symbol_decorations(fn)
        expected_bases[base] = fn

    for base, original in expected_bases.items():
        if func_hits.get(base, 0) > 0:
            result.hit_functions.append(original)
        else:
            result.missed_functions.append(original)

    # Also scan events for func_hit entries
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
                        if _strip_symbol_decorations(m) != fn
                    ]

    # Check for crash in events
    for ev in events:
        if ev.get("type") in ("stop", "kernel_panic", "oops"):
            result.crash_detected = True
            bt = ev.get("backtrace") or ev.get("bt") or []
            if isinstance(bt, list):
                result.crash_backtrace = bt[:20]
            break


# =====================================================================
# Internal helpers
# =====================================================================


def _compile_repro(
    source_path: str, arch: str, compile_script: Optional[str],
) -> Optional[str]:
    """Compile a C reproducer into a static binary."""
    if not os.path.isfile(source_path):
        return None

    output_path = source_path.replace(".c", "") + "_feasibility_test"

    # Custom compile script
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
    """Push a file to the device via ADB."""
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


def _ssh_push(
    local: str, remote: str, host: str, port: int, user: str, key: Optional[str],
) -> bool:
    """Push a file via SCP."""
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


def _ssh_cmd(
    host: str, port: int, user: str, key: Optional[str], cmd: str,
) -> Optional[str]:
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
    adb_port: int, use_adb: bool, remote_path: str, timeout: int,
) -> None:
    """Run the reproducer on the remote device (fire and forget)."""
    if use_adb:
        try:
            subprocess.run(
                ["adb", "-s", f"0.0.0.0:{adb_port}", "shell",
                 f"timeout {timeout} {remote_path} || true"],
                capture_output=True, timeout=timeout + 30,
            )
        except Exception:
            pass
    elif ssh_host:
        try:
            _ssh_cmd(ssh_host, ssh_port, ssh_user, ssh_key,
                     f"timeout {timeout} {remote_path} || true")
        except Exception:
            pass


def _dmesg_diff(before: str, after: str) -> str:
    """Return lines in *after* that were not in *before*."""
    before_lines = set(before.splitlines())
    new_lines = [line for line in after.splitlines() if line not in before_lines]
    return "\n".join(new_lines)


def _cleanup_dir(path: str) -> None:
    """Remove a temporary directory, ignoring errors."""
    try:
        shutil.rmtree(path, ignore_errors=True)
    except Exception:
        pass


# =====================================================================
# 6.  Continuous weighted scoring
# =====================================================================


def _compute_verdict(report: FeasibilityReport) -> Tuple[str, float]:
    """Combine sub-check results into an overall verdict and confidence.

    Scoring starts at 0.5 (neutral) and is shifted by each check:

    =============================  ==============  ============
    Check / result                 Score shift     Confidence
    =============================  ==============  ============
    fix_check -> patched           -0.40           0.80
    fix_check -> unpatched         +0.10           0.60
    symbol_check -> present        +0.15           0.50
    symbol_check -> absent         -0.30           0.70
    symbol_check -> partial        -0.10           0.40
    source_diff -> identical       +0.25           0.75
    source_diff -> minor_changes   +0.10           0.50
    source_diff -> major_changes   -0.25           0.70
    source_diff -> missing         -0.35           0.80
    live_test -> triggered         +0.40           0.95
    live_test -> no_crash          -0.30           0.75
    live_test -> different_crash   -0.15           0.50
    gdb_path -> path_confirmed     +0.35           0.90
    gdb_path -> partial_path       +0.10           0.60
    gdb_path -> path_diverged      -0.35           0.85
    =============================  ==============  ============

    Final:
        >= 0.55 -> ``likely_feasible``
        <= 0.35 -> ``likely_patched``
        else    -> ``inconclusive``

    Confidence = average of per-check confidence values.
    """
    score = 0.5
    confidence_parts: List[float] = []

    # ── Fix check (strong negative) ──────────────────────────────────
    if report.fix_check:
        if report.fix_check.verdict == "patched":
            score -= 0.40
            confidence_parts.append(0.80)
        elif report.fix_check.verdict == "unpatched":
            score += 0.10
            confidence_parts.append(0.60)

    # ── Symbol check ─────────────────────────────────────────────────
    if report.symbol_check:
        if report.symbol_check.verdict == "present":
            score += 0.15
            confidence_parts.append(0.50)
        elif report.symbol_check.verdict == "absent":
            score -= 0.30
            confidence_parts.append(0.70)
        elif report.symbol_check.verdict == "partial":
            score -= 0.10
            confidence_parts.append(0.40)

    # ── Source diff (NEW) ────────────────────────────────────────────
    if report.source_diff:
        v = report.source_diff.verdict
        if v == "identical":
            score += 0.25
            confidence_parts.append(0.75)
        elif v == "minor_changes":
            score += 0.10
            confidence_parts.append(0.50)
        elif v == "major_changes":
            score -= 0.25
            confidence_parts.append(0.70)
        elif v == "missing":
            score -= 0.35
            confidence_parts.append(0.80)

    # ── Live test (strongest signal) ─────────────────────────────────
    if report.live_test:
        if report.live_test.verdict == "triggered":
            score += 0.40
            confidence_parts.append(0.95)
        elif report.live_test.verdict == "no_crash":
            score -= 0.30
            confidence_parts.append(0.75)
        elif report.live_test.verdict == "different_crash":
            score -= 0.15
            confidence_parts.append(0.50)

    # ── GDB path verification ────────────────────────────────────────
    if report.gdb_path_check:
        gpc = report.gdb_path_check
        if gpc.verdict == "path_confirmed":
            score += 0.35
            confidence_parts.append(0.90)
        elif gpc.verdict == "partial_path":
            score += 0.10
            confidence_parts.append(0.60)
        elif gpc.verdict == "path_diverged":
            score -= 0.35
            confidence_parts.append(0.85)

    # ── Dynamic log analysis (when KASAN is disabled) ────────────────
    if report.dynamic_log_analysis:
        dla = report.dynamic_log_analysis
        if dla.verdict == "strong_evidence":
            score += 0.30
            confidence_parts.append(0.85)
        elif dla.verdict == "weak_evidence":
            score += 0.10
            confidence_parts.append(0.50)
        elif dla.verdict == "no_evidence":
            score -= 0.10
            confidence_parts.append(0.40)

    # Clamp to [0, 1]
    score = max(0.0, min(1.0, score))

    if score >= 0.55:
        verdict = "likely_feasible"
    elif score <= 0.35:
        verdict = "likely_patched"
    else:
        verdict = "inconclusive"

    confidence = (
        sum(confidence_parts) / len(confidence_parts)
        if confidence_parts
        else 0.3
    )

    return verdict, round(confidence, 2)


# =====================================================================
# 7.  Dmesg / GDB log analysis  (for non-KASAN targets)
# =====================================================================


# Patterns that indicate kernel memory allocation activity
_ALLOC_PATTERNS = [
    re.compile(r"kmalloc|kzalloc|kmem_cache_alloc|__alloc_pages", re.IGNORECASE),
    re.compile(r"slab.*alloc|cache.*alloc", re.IGNORECASE),
    re.compile(r"binder_alloc_buf|binder_transaction\b", re.IGNORECASE),
]

# Patterns for free / release activity
_FREE_PATTERNS = [
    re.compile(r"kfree|kmem_cache_free|__free_pages", re.IGNORECASE),
    re.compile(r"slab.*free|cache.*free", re.IGNORECASE),
    re.compile(r"binder_free_buf|binder_transaction_buffer_release", re.IGNORECASE),
]

# Subsystem activity patterns — keyed by subsystem name
_SUBSYSTEM_PATTERNS: Dict[str, re.Pattern] = {
    "binder": re.compile(
        r"binder:|binder_ioctl|binder_thread|binder_proc|binder_transaction|"
        r"binder_alloc|binder_free|binder_node|binder_ref",
        re.IGNORECASE,
    ),
    "io_uring": re.compile(r"io_uring|io_wq|io_submit|io_getevents", re.IGNORECASE),
    "netfilter": re.compile(r"nf_|netfilter|nft_|iptables", re.IGNORECASE),
    "usb": re.compile(r"usb\s|usbcore|xhci|ehci|gadget", re.IGNORECASE),
    "filesystem": re.compile(r"ext4|btrfs|f2fs|jbd2|vfs_|do_sys_open", re.IGNORECASE),
    "pipe": re.compile(r"pipe_|splice_|do_splice", re.IGNORECASE),
    "futex": re.compile(r"futex|do_futex|futex_wait|futex_wake", re.IGNORECASE),
    "memory": re.compile(r"mmap|munmap|page_fault|do_mmap|vm_area", re.IGNORECASE),
}


def _analyse_dmesg_for_evidence(
    new_dmesg: str,
    crash_functions: List[str],
) -> DmesgLogAnalysis:
    """Analyse new dmesg lines for allocation/free patterns and
    subsystem activity related to the vulnerability.

    This is the main analysis for dynamic feasibility when KASAN is
    disabled — we can't rely on crash messages, so we look for
    indirect evidence that the vulnerable code path was exercised.
    """
    analysis = DmesgLogAnalysis()
    analysis.dmesg_excerpt = new_dmesg[:4000]

    lines = new_dmesg.splitlines()
    analysis.dmesg_new_lines = lines[:200]  # cap for model size

    # ── Check for alloc patterns ─────────────────────────────────────
    for line in lines:
        for pat in _ALLOC_PATTERNS:
            if pat.search(line):
                if line.strip() not in analysis.alloc_patterns:
                    analysis.alloc_patterns.append(line.strip())
                break

    # ── Check for free patterns ──────────────────────────────────────
    for line in lines:
        for pat in _FREE_PATTERNS:
            if pat.search(line):
                if line.strip() not in analysis.free_patterns:
                    analysis.free_patterns.append(line.strip())
                break

    # ── Subsystem activity ───────────────────────────────────────────
    # Determine which subsystem the crash was in (from function names)
    relevant_subsystems: set[str] = set()
    for func in crash_functions:
        base = _strip_symbol_decorations(func)
        for subsys, pat in _SUBSYSTEM_PATTERNS.items():
            if pat.search(base):
                relevant_subsystems.add(subsys)

    # Also check dmesg for subsystem activity
    for line in lines:
        for subsys, pat in _SUBSYSTEM_PATTERNS.items():
            if pat.search(line):
                tag = f"[{subsys}] {line.strip()}"
                if tag not in analysis.subsystem_activity:
                    analysis.subsystem_activity.append(tag)
                break

    # ── Check for crash function names in dmesg ──────────────────────
    crash_func_seen = 0
    for func in crash_functions:
        base = _strip_symbol_decorations(func)
        if base and base in new_dmesg:
            crash_func_seen += 1

    # ── Compute evidence score ───────────────────────────────────────
    score = 0.0
    n_notes: List[str] = []

    # Allocation / free patterns → sign of target subsystem activity
    if analysis.alloc_patterns:
        score += min(0.2, len(analysis.alloc_patterns) * 0.05)
        n_notes.append(f"Found {len(analysis.alloc_patterns)} allocation patterns in dmesg")
    if analysis.free_patterns:
        score += min(0.15, len(analysis.free_patterns) * 0.05)
        n_notes.append(f"Found {len(analysis.free_patterns)} free/release patterns in dmesg")

    # Subsystem activity matching crash subsystem
    relevant_activity = [
        a for a in analysis.subsystem_activity
        if any(s in a.lower() for s in relevant_subsystems)
    ]
    if relevant_activity:
        score += min(0.25, len(relevant_activity) * 0.05)
        n_notes.append(
            f"Found {len(relevant_activity)} relevant subsystem "
            f"({', '.join(relevant_subsystems)}) messages"
        )

    # Crash function names appearing in dmesg
    if crash_func_seen > 0:
        score += min(0.3, crash_func_seen * 0.1)
        n_notes.append(f"{crash_func_seen} crash-stack function names appear in dmesg")

    # New dmesg activity at all → at least the reproducer did something
    if len(lines) > 5:
        score += 0.05
        n_notes.append(f"Reproducer generated {len(lines)} new dmesg lines")

    analysis.evidence_score = min(1.0, score)
    analysis.notes = n_notes

    if analysis.evidence_score >= 0.5:
        analysis.verdict = "strong_evidence"
    elif analysis.evidence_score >= 0.2:
        analysis.verdict = "weak_evidence"
    else:
        analysis.verdict = "no_evidence"

    return analysis


def _analyse_gdb_log_for_evidence(
    gdb_log: str,
    crash_functions: List[str],
    analysis: DmesgLogAnalysis,
) -> DmesgLogAnalysis:
    """Parse GDB log output for breakpoint hits and add to the analysis.

    Looks for patterns like:
    - ``Breakpoint N, function_name ...``
    - ``Thread N hit Breakpoint N, ...``
    - ``Hardware watchpoint N: ...``
    """
    analysis.gdb_log_excerpt = gdb_log[:4000]

    bp_hit_re = re.compile(
        r"(?:Thread \d+ )?(?:hit )?Breakpoint \d+,?\s*(\S+)",
        re.IGNORECASE,
    )
    watchpoint_re = re.compile(r"Hardware (?:access |read )?watchpoint \d+:", re.IGNORECASE)

    expected_bases = {_strip_symbol_decorations(fn) for fn in crash_functions}

    for line in gdb_log.splitlines():
        m = bp_hit_re.search(line)
        if m:
            hit_func = m.group(1).rstrip("()")
            hit_base = _strip_symbol_decorations(hit_func)
            tag = f"Breakpoint hit: {hit_base}"
            if tag not in analysis.gdb_breakpoint_hits:
                analysis.gdb_breakpoint_hits.append(tag)
            if hit_base in expected_bases:
                analysis.notes.append(f"GDB: breakpoint on crash-stack function '{hit_base}' was HIT")
        if watchpoint_re.search(line):
            tag = f"Watchpoint: {line.strip()}"
            if tag not in analysis.gdb_breakpoint_hits:
                analysis.gdb_breakpoint_hits.append(tag)

    # Update evidence score with GDB data
    if analysis.gdb_breakpoint_hits:
        # Count how many are for crash-stack functions
        crash_bp_hits = sum(
            1 for h in analysis.gdb_breakpoint_hits
            if any(b in h for b in expected_bases)
        )
        bp_boost = min(0.35, crash_bp_hits * 0.15) + min(0.1, len(analysis.gdb_breakpoint_hits) * 0.03)
        analysis.evidence_score = min(1.0, analysis.evidence_score + bp_boost)
        analysis.notes.append(
            f"GDB: {len(analysis.gdb_breakpoint_hits)} breakpoint hits "
            f"({crash_bp_hits} on crash-stack functions)"
        )

    # Recompute verdict
    if analysis.evidence_score >= 0.5:
        analysis.verdict = "strong_evidence"
    elif analysis.evidence_score >= 0.2:
        analysis.verdict = "weak_evidence"
    else:
        analysis.verdict = "no_evidence"

    return analysis


# =====================================================================
# Helper: extract vulnerability info from context
# =====================================================================


def extract_vuln_info(
    crash: Optional[CrashReport] = None,
    root_cause: Optional["RootCauseAnalysis"] = None,
    *,
    extra_functions: Optional[List[str]] = None,
    extra_files: Optional[List[str]] = None,
) -> Tuple[List[str], List[str], Optional[List[str]]]:
    """Extract function names, file paths, and fix commits from
    whatever analysis data is available.

    Works with:
    - A ``CrashReport`` (has stack_frames with function + file)
    - A ``RootCauseAnalysis`` (has kernel_functions, vulnerable_file,
      fix_commit — from CVE or blog analysis)
    - Both together (merged, deduplicated)
    - Neither (returns the extra_* lists as-is)

    Returns:
        ``(symbols, vulnerable_files, fix_commits)``
    """
    from ..core.models import RootCauseAnalysis  # avoid circular at module level

    symbols: List[str] = list(extra_functions or [])
    vuln_files: List[str] = list(extra_files or [])
    fix_commits: List[str] = []

    # ── From crash report ────────────────────────────────────────────
    if crash is not None:
        for f in crash.stack_frames:
            if f.function and f.function not in symbols:
                symbols.append(f.function)
            if f.file and not f.file.startswith("<") and f.file not in vuln_files:
                vuln_files.append(f.file)

    # ── From root cause analysis (CVE / blog) ────────────────────────
    if root_cause is not None:
        for fn in root_cause.kernel_functions:
            if fn and fn not in symbols:
                symbols.append(fn)
        if root_cause.vulnerable_function:
            fn = root_cause.vulnerable_function
            if fn not in symbols:
                symbols.append(fn)
        if root_cause.vulnerable_file:
            vf = root_cause.vulnerable_file
            if vf not in vuln_files:
                vuln_files.append(vf)
        if root_cause.fix_commit:
            fix_commits.append(root_cause.fix_commit)

    return symbols, vuln_files, fix_commits if fix_commits else None


# =====================================================================
# Static feasibility orchestrator
# =====================================================================


def assess_feasibility_static(
    crash: Optional[CrashReport] = None,
    root_cause: Optional["RootCauseAnalysis"] = None,
    *,
    bug_id: str = "",
    original_kernel: str = "",
    target_kernel: str = "",
    # Fix commits
    fix_commits: Optional[List[str]] = None,
    # Kernel tree (for backport detection + source diff)
    kernel_tree_path: Optional[str] = None,
    changelog_path: Optional[str] = None,
    target_branch: str = "HEAD",
    original_tag: Optional[str] = None,
    target_tag: Optional[str] = None,
    # Symbol check sources
    kallsyms_path: Optional[str] = None,
    system_map_path: Optional[str] = None,
    vmlinux_path: Optional[str] = None,
    # Source diff
    vulnerable_files: Optional[List[str]] = None,
    vulnerable_functions: Optional[List[str]] = None,
    # SSH for remote kallsyms only (not for running anything)
    ssh_host: Optional[str] = None,
    ssh_port: int = 22,
    ssh_user: str = "root",
    ssh_key: Optional[str] = None,
    # Control
    skip_symbol_check: bool = False,
    skip_fix_check: bool = False,
    skip_source_diff: bool = False,
    cfg: Optional[Config] = None,
) -> FeasibilityReport:
    """Run **static** feasibility checks (no VM required).

    Checks:
        1. Symbol presence — fuzzy matching against kallsyms / System.map / vmlinux
        2. Fix backport detection — git-based strategies
        3. Source-level diff — ``git diff`` of vulnerable files / functions

    These checks determine whether the vulnerability code is still present
    in the target kernel without needing to boot or access the device.

    Accepts either a ``CrashReport``, a ``RootCauseAnalysis`` (from CVE/blog
    analysis), or both.  When only root_cause is available, function names
    and file paths are extracted from it instead of from crash stack frames.

    Args:
        crash: Parsed crash report (optional if root_cause is provided).
        root_cause: Root cause analysis from CVE/blog (optional if crash provided).
        vulnerable_functions: Explicit function names to check (merged with
            those extracted from crash/root_cause).
        vulnerable_files: Explicit file paths to check.
        fix_commits: Known fix commit hashes (merged with root_cause.fix_commit).
        ... (see ``assess_feasibility`` for remaining param docs)

    Returns:
        :class:`FeasibilityReport` with static check results and verdict.
    """
    report = FeasibilityReport(
        bug_id=bug_id,
        original_kernel=original_kernel,
        target_kernel=target_kernel,
    )

    # ── Collect symbols + files from all available sources ───────────
    crash_symbols, auto_vuln_files, auto_fix_commits = extract_vuln_info(
        crash, root_cause,
        extra_functions=vulnerable_functions,
        extra_files=vulnerable_files,
    )
    # Merge explicit fix_commits with auto-discovered ones
    if fix_commits:
        all_fix_commits = list(fix_commits)
        if auto_fix_commits:
            for c in auto_fix_commits:
                if c not in all_fix_commits:
                    all_fix_commits.append(c)
    else:
        all_fix_commits = auto_fix_commits

    # Use auto-discovered files unless explicitly overridden
    if not vulnerable_files:
        vulnerable_files = auto_vuln_files

    if not crash_symbols:
        report.notes.append(
            "No function names available from crash or root-cause analysis — "
            "symbol and source-diff checks will be limited"
        )

    # ── Check 1: Symbol presence ─────────────────────────────────────
    if not skip_symbol_check and crash_symbols and (
        kallsyms_path or system_map_path or vmlinux_path or ssh_host
    ):
        console.print("  [dim]Static check 1/3: Symbol presence...[/]")
        report.symbol_check = check_symbols(
            crash_symbols,
            kallsyms_path=kallsyms_path,
            system_map_path=system_map_path,
            vmlinux_path=vmlinux_path,
            ssh_host=ssh_host,
            ssh_port=ssh_port,
            ssh_user=ssh_user,
            ssh_key=ssh_key,
        )
        if report.symbol_check.verdict == "absent":
            report.notes.append(
                "All vulnerable functions are MISSING — code path likely removed or renamed"
            )
        elif report.symbol_check.verdict == "present":
            report.notes.append("All vulnerable functions are PRESENT in the target kernel")

    # ── Check 2: Fix backport ────────────────────────────────────────
    if not skip_fix_check and all_fix_commits:
        console.print("  [dim]Static check 2/3: Fix backport detection...[/]")
        report.fix_check = check_fix_backported(
            all_fix_commits,
            kernel_tree_path=kernel_tree_path,
            changelog_path=changelog_path,
            target_branch=target_branch,
        )
        if report.fix_check.verdict == "patched":
            report.notes.append(
                f"Fix has been backported ({report.fix_check.strategy}): "
                f"{report.fix_check.evidence[:200]}"
            )

    # ── Check 3: Source-level diff ───────────────────────────────────
    if (
        not skip_source_diff
        and kernel_tree_path
        and original_tag
        and target_tag
        and (vulnerable_files or crash_symbols)
    ):
        console.print("  [dim]Static check 3/3: Source-level diff...[/]")
        report.source_diff = check_source_diff(
            vulnerable_files or [],
            crash_symbols,
            kernel_tree_path=kernel_tree_path,
            original_tag=original_tag,
            target_tag=target_tag,
        )
        sd = report.source_diff
        if sd.verdict == "identical":
            report.notes.append(
                "Source code is IDENTICAL between versions — bug almost certainly present"
            )
        elif sd.verdict == "minor_changes":
            report.notes.append(
                f"Source has MINOR changes (similarity={sd.similarity_ratio:.0%}) — "
                "bug likely still present"
            )
        elif sd.verdict == "major_changes":
            report.notes.append(
                f"Source has MAJOR changes ({sd.total_diff_lines} diff lines, "
                f"similarity={sd.similarity_ratio:.0%}) — bug may have been incidentally fixed"
            )
        elif sd.verdict == "missing":
            report.notes.append("Vulnerable source files are MISSING in the target tree")

    # ── Compute overall verdict (static checks only) ─────────────────
    report.verdict, report.confidence = _compute_verdict(report)

    return report


# =====================================================================
# Dynamic feasibility orchestrator
# =====================================================================


def assess_feasibility_dynamic(
    crash: Optional[CrashReport] = None,
    root_cause: Optional["RootCauseAnalysis"] = None,
    *,
    bug_id: str = "",
    original_kernel: str = "",
    target_kernel: str = "",
    # Reproducer
    reproducer_path: Optional[str] = None,
    compile_script: Optional[str] = None,
    arch: str = "arm64",
    # Target device connectivity
    ssh_host: Optional[str] = None,
    ssh_port: int = 22,
    ssh_user: str = "root",
    ssh_key: Optional[str] = None,
    adb_port: int = 6520,
    use_adb: bool = True,
    instance: Optional[int] = None,
    # VM lifecycle
    start_cmd: Optional[str] = None,
    stop_cmd: Optional[str] = None,
    setup_tunnels: bool = True,
    # GDB
    gdb_port: int = 1234,
    vmlinux_path: Optional[str] = None,
    system_map_path: Optional[str] = None,
    # Extra function info (when no crash report)
    vulnerable_functions: Optional[List[str]] = None,
    # Control
    timeout: int = 180,
    skip_live_test: bool = False,
    skip_gdb_path_check: bool = False,
    # Pre-existing static report to merge into
    existing_report: Optional[FeasibilityReport] = None,
    cfg: Optional[Config] = None,
) -> FeasibilityReport:
    """Run **dynamic** feasibility checks — requires a running VM.

    Boots the target VM (if start_cmd provided), runs the reproducer,
    and analyses GDB logs and dmesg for evidence that the vulnerable
    code path was exercised.

    Because KASAN is typically not enabled on production-like targets,
    an actual crash is unlikely.  Instead this check looks for:

    - **GDB breakpoint hits** on crash-stack functions → the vulnerable
      code path was executed.
    - **dmesg allocation/free patterns** → kmalloc/kfree activity in
      the relevant subsystem.
    - **Subsystem activity** → binder transactions, io_uring submissions,
      etc. matching the vulnerability's subsystem.
    - **Crash function names in dmesg** → even without KASAN, some
      functions log to dmesg when exercised.

    This check reuses the ADB/GDB infrastructure from
    ``infra.verification`` for proper tunnel management.

    Accepts either a ``CrashReport``, a ``RootCauseAnalysis``, or both.
    Function names for GDB breakpoints are extracted from whichever
    source is available.

    Args:
        crash: Parsed crash report (optional if root_cause provided).
        root_cause: Root cause analysis from CVE/blog (optional).
        reproducer_path: Path to the reproducer C source.
        start_cmd: Command to start the VM (e.g. ``gdb_run.sh``).
        vulnerable_functions: Explicit function names for GDB breakpoints.
        ... (see ``assess_feasibility`` for detailed param docs)
        existing_report: If a static report was already computed, merge
            dynamic results into it rather than creating a new one.

    Returns:
        :class:`FeasibilityReport` with dynamic check results and verdict.
    """
    # Use existing report or create fresh
    if existing_report is not None:
        report = existing_report
    else:
        report = FeasibilityReport(
            bug_id=bug_id,
            original_kernel=original_kernel,
            target_kernel=target_kernel,
        )

    # Extract symbols from all available sources
    crash_symbols, _, _ = extract_vuln_info(
        crash, root_cause, extra_functions=vulnerable_functions,
    )

    if not reproducer_path:
        report.notes.append("dynamic: no reproducer path — skipping dynamic checks")
        report.verdict, report.confidence = _compute_verdict(report)
        return report

    if not ssh_host and not use_adb:
        report.notes.append("dynamic: no SSH host or ADB — skipping dynamic checks")
        report.verdict, report.confidence = _compute_verdict(report)
        return report

    # ── Import verification helpers ──────────────────────────────────
    from ..infra.verification import (
        _adb_exe,
        _adb_is_alive,
        _adb_push as v_adb_push,
        _adb_run as v_adb_run,
        _adb_target,
        _calc_adb_port,
        _dmesg_diff as v_dmesg_diff,
        _is_gdb_start,
        _kill_proc,
        _run_start_cmd,
        _run_stop_cmd,
        _send_gdb_continue,
        _setup_adb_tunnel,
    )

    # Calculate ADB port
    actual_adb_port = _calc_adb_port(instance, adb_port)

    # ── VM lifecycle ─────────────────────────────────────────────────
    vm_proc: Optional[subprocess.Popen] = None
    adb_tunnel: Optional[subprocess.Popen] = None
    gdb_was_sent = False

    try:
        # ── Step 0: Start VM if needed ───────────────────────────────
        if start_cmd:
            console.print("  [dim]Dynamic: starting VM…[/]")
            _ok, vm_proc = _run_start_cmd(
                start_cmd, ssh_host=ssh_host or "", ssh_port=ssh_port,
            )
            if not _ok or vm_proc is None:
                report.notes.append("dynamic: failed to start VM")
                report.verdict, report.confidence = _compute_verdict(report)
                return report

            time.sleep(10)  # initial boot delay

        # ── Step 0a: GDB continue (if gdb_run.sh) ───────────────────
        if start_cmd and _is_gdb_start(start_cmd) and gdb_port:
            console.print("  [dim]Dynamic: sending GDB continue…[/]")
            gdb_was_sent = _send_gdb_continue(
                ssh_host=ssh_host or "",
                ssh_port=ssh_port,
                gdb_port=gdb_port,
            )
            if gdb_was_sent:
                console.print("  [dim]Dynamic: GDB continue sent, waiting for boot…[/]")
                time.sleep(60)  # wait for kernel to boot
            else:
                console.print("  [yellow]Dynamic: GDB continue failed[/]")
                report.notes.append("dynamic: GDB continue failed — VM may not boot")

        # ── Step 0b: Set up ADB tunnel ───────────────────────────────
        if use_adb and setup_tunnels and ssh_host:
            console.print(f"  [dim]Dynamic: setting up ADB tunnel (port {actual_adb_port})…[/]")
            adb_tunnel = _setup_adb_tunnel(actual_adb_port, ssh_host, ssh_port)
            if adb_tunnel:
                time.sleep(3)  # let tunnel establish

        # ── Step 0c: Wait for ADB ────────────────────────────────────
        if use_adb:
            console.print("  [dim]Dynamic: waiting for ADB…[/]")
            adb_alive = False
            for attempt in range(12):
                if _adb_is_alive(actual_adb_port):
                    adb_alive = True
                    console.print("  [dim]Dynamic: ADB connected[/]")
                    break
                time.sleep(10)
            if not adb_alive:
                report.notes.append("dynamic: ADB never came up — cannot run dynamic checks")
                report.verdict, report.confidence = _compute_verdict(report)
                return report

        # ── Step 1: Compile the reproducer ───────────────────────────
        console.print("  [dim]Dynamic: compiling reproducer…[/]")
        repro_binary = _compile_repro(reproducer_path, arch, compile_script)
        if not repro_binary:
            report.notes.append("dynamic: reproducer compilation failed")
            report.verdict, report.confidence = _compute_verdict(report)
            return report

        # ── Step 2: Push to device ───────────────────────────────────
        remote_path = "/data/local/tmp/repro_dynamic_test"
        console.print("  [dim]Dynamic: pushing reproducer to device…[/]")
        if use_adb:
            pushed = v_adb_push(repro_binary, remote_path, actual_adb_port)
            if pushed:
                v_adb_run(f"chmod 755 {remote_path}", actual_adb_port, timeout=10)
        elif ssh_host:
            pushed = _ssh_push(
                repro_binary, remote_path,
                ssh_host, ssh_port, ssh_user, ssh_key,
            )
        else:
            pushed = False

        if not pushed:
            report.notes.append("dynamic: failed to push reproducer to device")
            report.verdict, report.confidence = _compute_verdict(report)
            return report

        # ── Step 3: Capture dmesg BEFORE ─────────────────────────────
        console.print("  [dim]Dynamic: capturing dmesg before…[/]")
        if use_adb:
            _, dmesg_before, _ = v_adb_run("dmesg", actual_adb_port, timeout=30)
        elif ssh_host:
            dmesg_before = _ssh_cmd(ssh_host, ssh_port, ssh_user, ssh_key, "dmesg") or ""
        else:
            dmesg_before = ""

        # ── Step 4: GDB breakpoint setup (optional) ──────────────────
        gdb_proc: Optional[subprocess.Popen] = None
        gdb_log_path: Optional[str] = None
        gdb_results_json: Optional[str] = None

        if not skip_gdb_path_check and crash_symbols and gdb_port:
            console.print("  [dim]Dynamic: setting up GDB breakpoints…[/]")
            work_dir_gdb = tempfile.mkdtemp(prefix="dynamic_gdb_")
            gdb_log_path = os.path.join(work_dir_gdb, "gdb.log")
            gdb_results_json = os.path.join(work_dir_gdb, "gdb_path_results.json")

            gdb_script_src = Path(__file__).resolve().parents[1] / "infra" / "gdb_trace.py"

            # Build GDB config
            config_json = os.path.join(work_dir_gdb, "gdb_config.json")
            config_data = {
                "poc_entry": "syz_executor",
                "fault_addr": None,
                "fault_insn": None,
                "access_type": "any",
                "access_size": 0,
                "monitor_mode": False,
                "reproducer_path": remote_path,
                "guest_ssh_port": ssh_port,
                "guest_ssh_user": ssh_user,
                "guest_ssh_key": str(ssh_key) if ssh_key else None,
                "crash_stack_funcs": [_strip_symbol_decorations(fn) for fn in crash_symbols],
                "crash_stack_addrs": {},
            }
            with open(config_json, "w") as f:
                json.dump(config_data, f, indent=2)

            gdb_binary = "gdb-multiarch" if arch == "arm64" else "gdb"

            # For remote GDB, we need to tunnel through SSH
            gdb_target = f":{gdb_port}"
            if ssh_host and setup_tunnels:
                # Set up GDB tunnel
                gdb_tunnel_cmd = [
                    "ssh", "-o", "StrictHostKeyChecking=no",
                    "-p", str(ssh_port),
                    "-L", f"127.0.0.1:{gdb_port}:127.0.0.1:{gdb_port}",
                    "-N", ssh_host,
                ]
                try:
                    gdb_tunnel_proc = subprocess.Popen(
                        gdb_tunnel_cmd,
                        stdin=subprocess.DEVNULL,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                    )
                    time.sleep(2)
                except Exception:
                    gdb_tunnel_proc = None  # type: ignore[assignment]
            else:
                gdb_tunnel_proc = None  # type: ignore[assignment]

            gdb_cmd: List[str] = [gdb_binary, "-q", "-batch"]
            if vmlinux_path and os.path.isfile(vmlinux_path):
                gdb_cmd += ["-ex", f"file {vmlinux_path}"]

            gdb_cmd += [
                "-ex", f"set logging file {gdb_log_path}",
                "-ex", "set logging overwrite on",
                "-ex", "set logging enabled on",
                "-ex", "set pagination off",
                "-ex", "set confirm off",
                "-ex", "set non-stop off",
                "-ex", "set breakpoint pending on",
                "-ex", f'set $export_path = "{gdb_results_json}"',
                "-ex", "set tcp connect-timeout 30",
                "-ex", f"target remote {gdb_target}",
                "-ex", "interrupt",
            ]

            if gdb_script_src and gdb_script_src.exists():
                gdb_cmd += [
                    "-ex", f"source {gdb_script_src}",
                    "-ex", f"syz_load_config {config_json}",
                    "-ex", "syz_safe_continue",
                ]
            else:
                for fn in crash_symbols:
                    base = _strip_symbol_decorations(fn)
                    gdb_cmd += ["-ex", f"break {base}"]
                gdb_cmd += ["-ex", "continue"]

            try:
                gdb_proc = subprocess.Popen(
                    gdb_cmd,
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                time.sleep(5)  # let GDB attach + install breakpoints
            except FileNotFoundError:
                console.print(f"  [yellow]Dynamic: {gdb_binary} not found[/]")
                gdb_proc = None

        # ── Step 5: Run the reproducer ───────────────────────────────
        console.print("  [dim]Dynamic: running reproducer…[/]")
        repro_timeout = min(timeout, 120)

        if use_adb:
            v_adb_run(
                f"timeout {repro_timeout} {remote_path} || true",
                actual_adb_port,
                timeout=repro_timeout + 30,
            )
        elif ssh_host:
            _ssh_cmd(
                ssh_host, ssh_port, ssh_user, ssh_key,
                f"timeout {repro_timeout} {remote_path} || true",
            )

        time.sleep(5)  # let dmesg / GDB catch up

        # ── Step 6: Capture dmesg AFTER ──────────────────────────────
        console.print("  [dim]Dynamic: capturing dmesg after…[/]")
        if use_adb:
            _, dmesg_after, _ = v_adb_run("dmesg", actual_adb_port, timeout=30)
        elif ssh_host:
            dmesg_after = _ssh_cmd(ssh_host, ssh_port, ssh_user, ssh_key, "dmesg") or ""
        else:
            dmesg_after = ""

        new_dmesg = v_dmesg_diff(dmesg_before, dmesg_after)

        # ── Step 7: Live test result (crash check) ───────────────────
        if not skip_live_test:
            live = LiveTestResult(expected_functions=list(crash_symbols))
            live.repro_compiled = True
            live.repro_ran = True
            live.crash_log_excerpt = new_dmesg[:4000]

            _CRASH_INDICATORS = [
                "BUG:", "KASAN:", "WARNING:", "general protection fault",
                "unable to handle kernel", "kernel panic", "Oops:",
                "Call Trace:", "RIP:", "PC is at",
            ]
            for indicator in _CRASH_INDICATORS:
                if indicator.lower() in new_dmesg.lower():
                    live.crash_triggered = True
                    break

            if live.crash_triggered:
                for func in crash_symbols:
                    base = _strip_symbol_decorations(func)
                    if base and base in new_dmesg:
                        live.matched_functions.append(func)
                live.crash_signature_match = bool(live.matched_functions)
                live.verdict = "triggered" if live.crash_signature_match else "different_crash"
            else:
                live.verdict = "no_crash"

            report.live_test = live
            if live.verdict == "triggered":
                report.notes.append("Reproducer triggered the SAME crash on the target kernel!")
            elif live.verdict == "no_crash":
                report.notes.append(
                    "Reproducer did NOT crash the target (expected if KASAN disabled)"
                )

        # ── Step 8: Collect GDB results ──────────────────────────────
        if gdb_proc is not None:
            console.print("  [dim]Dynamic: collecting GDB results…[/]")
            try:
                if gdb_proc.stdin:
                    if gdb_results_json:
                        gdb_proc.stdin.write(f"export_results {gdb_results_json}\n")
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

            # Parse GDB path results
            gdb_path = GdbPathCheckResult(expected_functions=list(crash_symbols))
            if gdb_results_json:
                _parse_gdb_path_results(gdb_path, gdb_results_json, crash_symbols)

            total = len(crash_symbols)
            hit = len(gdb_path.hit_functions)
            gdb_path.hit_ratio = hit / total if total > 0 else 0.0

            if hit == 0 and gdb_path.events_captured == 0:
                gdb_path.verdict = "error"
            elif gdb_path.hit_ratio >= 0.6:
                gdb_path.verdict = "path_confirmed"
            elif gdb_path.hit_ratio >= 0.3 or hit > 0:
                gdb_path.verdict = "partial_path"
            else:
                gdb_path.verdict = "path_diverged"

            report.gdb_path_check = gdb_path

            if gdb_path.verdict == "path_confirmed":
                report.notes.append(
                    f"GDB path CONFIRMED: {hit}/{total} crash-stack functions hit "
                    f"(ratio={gdb_path.hit_ratio:.0%})"
                )
            elif gdb_path.verdict == "partial_path":
                report.notes.append(
                    f"GDB path PARTIAL: {hit}/{total} crash-stack functions hit"
                )

            # Kill GDB tunnel if we made one
            if gdb_tunnel_proc is not None:  # type: ignore[possibly-undefined]
                _kill_proc(gdb_tunnel_proc)

            # Clean up
            if gdb_log_path and os.path.dirname(gdb_log_path):
                gdb_log_text = ""
                if os.path.isfile(gdb_log_path):
                    try:
                        with open(gdb_log_path, "r") as f:
                            gdb_log_text = f.read()
                    except Exception:
                        pass
                _cleanup_dir(os.path.dirname(gdb_log_path))
            else:
                gdb_log_text = ""
        else:
            gdb_log_text = ""

        # ── Step 9: Log analysis (main value for non-KASAN) ─────────
        console.print("  [dim]Dynamic: analysing logs for evidence…[/]")
        log_analysis = _analyse_dmesg_for_evidence(new_dmesg, crash_symbols)
        if gdb_log_text:
            log_analysis = _analyse_gdb_log_for_evidence(gdb_log_text, crash_symbols, log_analysis)
        report.dynamic_log_analysis = log_analysis

        if log_analysis.verdict == "strong_evidence":
            report.notes.append(
                f"Dynamic log analysis: STRONG evidence of vulnerability exercised "
                f"(score={log_analysis.evidence_score:.0%})"
            )
        elif log_analysis.verdict == "weak_evidence":
            report.notes.append(
                f"Dynamic log analysis: WEAK evidence "
                f"(score={log_analysis.evidence_score:.0%})"
            )
        else:
            report.notes.append(
                "Dynamic log analysis: NO evidence of vulnerability in logs"
            )

    finally:
        # ── Cleanup: stop VM ─────────────────────────────────────────
        if adb_tunnel is not None:
            _kill_proc(adb_tunnel)
        if vm_proc is not None and stop_cmd:
            _run_stop_cmd(stop_cmd, ssh_host=ssh_host or "", ssh_port=ssh_port)
        elif vm_proc is not None:
            _kill_proc(vm_proc)

    # ── Compute overall verdict ──────────────────────────────────────
    report.verdict, report.confidence = _compute_verdict(report)

    return report


# =====================================================================
# Top-level orchestrator (original — runs all checks)
# =====================================================================


def assess_feasibility(
    crash: CrashReport,
    *,
    bug_id: str = "",
    original_kernel: str = "",
    target_kernel: str = "",
    # Fix commits
    fix_commits: Optional[List[str]] = None,
    # Kernel tree (for backport detection + source diff)
    kernel_tree_path: Optional[str] = None,
    changelog_path: Optional[str] = None,
    target_branch: str = "HEAD",
    original_tag: Optional[str] = None,
    target_tag: Optional[str] = None,
    # Symbol check sources
    kallsyms_path: Optional[str] = None,
    system_map_path: Optional[str] = None,
    vmlinux_path: Optional[str] = None,
    # Source diff
    vulnerable_files: Optional[List[str]] = None,
    # Target device connectivity
    ssh_host: Optional[str] = None,
    ssh_port: int = 22,
    ssh_user: str = "root",
    ssh_key: Optional[str] = None,
    adb_port: int = 6520,
    use_adb: bool = False,
    # Reproducer
    reproducer_path: Optional[str] = None,
    compile_script: Optional[str] = None,
    arch: str = "x86_64",
    timeout: int = 120,
    # GDB
    gdb_port: int = 1234,
    # Control which checks to run
    skip_symbol_check: bool = False,
    skip_fix_check: bool = False,
    skip_source_diff: bool = False,
    skip_live_test: bool = False,
    skip_gdb_path_check: bool = False,
    cfg: Optional[Config] = None,
) -> FeasibilityReport:
    """Run all feasibility checks and produce an overall report.

    Checks are run in order (cheapest first); each is skipped if required
    inputs are missing.  The final verdict is a continuous weighted score.

    Args:
        crash: The parsed crash report from the original kernel.
        bug_id: Syzbot bug identifier.
        original_kernel: Kernel version the bug was found on.
        target_kernel: Kernel version we are checking.
        fix_commits: Known fix commit hashes.
        kernel_tree_path: Path to a local kernel git checkout.
        vulnerable_files: Paths of vulnerable source files (relative to tree).
        original_tag / target_tag: Git refs for source diff.
        ... (connection, compile, GDB params)

    Returns:
        :class:`FeasibilityReport` with per-check results and overall verdict.
    """
    report = FeasibilityReport(
        bug_id=bug_id,
        original_kernel=original_kernel,
        target_kernel=target_kernel,
    )

    # Collect symbols from crash stack
    crash_symbols = [f.function for f in crash.stack_frames if f.function]
    # Auto-derive vulnerable files from crash frames
    if not vulnerable_files:
        vulnerable_files = list({
            f.file for f in crash.stack_frames
            if f.file and not f.file.startswith("<")
        })

    # ── Check 1: Symbol presence ─────────────────────────────────────
    if not skip_symbol_check and crash_symbols and (
        kallsyms_path or system_map_path or vmlinux_path or ssh_host
    ):
        console.print("  [dim]Check 1/5: Symbol presence...[/]")
        report.symbol_check = check_symbols(
            crash_symbols,
            kallsyms_path=kallsyms_path,
            system_map_path=system_map_path,
            vmlinux_path=vmlinux_path,
            ssh_host=ssh_host,
            ssh_port=ssh_port,
            ssh_user=ssh_user,
            ssh_key=ssh_key,
        )
        if report.symbol_check.verdict == "absent":
            report.notes.append(
                "All vulnerable functions are MISSING — code path likely removed or renamed"
            )
        elif report.symbol_check.verdict == "present":
            report.notes.append("All vulnerable functions are PRESENT in the target kernel")

    # ── Check 2: Fix backport ────────────────────────────────────────
    if not skip_fix_check and fix_commits:
        console.print("  [dim]Check 2/5: Fix backport detection...[/]")
        report.fix_check = check_fix_backported(
            fix_commits,
            kernel_tree_path=kernel_tree_path,
            changelog_path=changelog_path,
            target_branch=target_branch,
        )
        if report.fix_check.verdict == "patched":
            report.notes.append(
                f"Fix has been backported ({report.fix_check.strategy}): "
                f"{report.fix_check.evidence[:200]}"
            )

    # ── Check 3: Source-level diff ───────────────────────────────────
    if (
        not skip_source_diff
        and kernel_tree_path
        and original_tag
        and target_tag
        and (vulnerable_files or crash_symbols)
    ):
        console.print("  [dim]Check 3/5: Source-level diff...[/]")
        report.source_diff = check_source_diff(
            vulnerable_files or [],
            crash_symbols,
            kernel_tree_path=kernel_tree_path,
            original_tag=original_tag,
            target_tag=target_tag,
        )
        sd = report.source_diff
        if sd.verdict == "identical":
            report.notes.append(
                "Source code is IDENTICAL between versions — bug almost certainly present"
            )
        elif sd.verdict == "minor_changes":
            report.notes.append(
                f"Source has MINOR changes (similarity={sd.similarity_ratio:.0%}) — "
                "bug likely still present"
            )
        elif sd.verdict == "major_changes":
            report.notes.append(
                f"Source has MAJOR changes ({sd.total_diff_lines} diff lines, "
                f"similarity={sd.similarity_ratio:.0%}) — bug may have been incidentally fixed"
            )
        elif sd.verdict == "missing":
            report.notes.append("Vulnerable source files are MISSING in the target tree")

    # ── Check 4: Live crash test ─────────────────────────────────────
    if not skip_live_test and reproducer_path and (ssh_host or use_adb):
        console.print("  [dim]Check 4/5: Live crash test...[/]")
        report.live_test = run_live_test(
            reproducer_path,
            crash_symbols,
            arch=arch,
            ssh_host=ssh_host,
            ssh_port=ssh_port,
            ssh_user=ssh_user,
            ssh_key=ssh_key,
            adb_port=adb_port,
            use_adb=use_adb,
            compile_script=compile_script,
            timeout=timeout,
        )
        if report.live_test.verdict == "triggered":
            report.notes.append(
                "Reproducer triggered the SAME crash on the target kernel!"
            )
        elif report.live_test.verdict == "no_crash":
            report.notes.append("Reproducer did NOT crash the target kernel")
        elif report.live_test.verdict == "different_crash":
            report.notes.append(
                "Reproducer crashed the target but with a DIFFERENT signature"
            )

    # ── Check 5: GDB path verification ───────────────────────────────
    if not skip_gdb_path_check and reproducer_path and crash_symbols:
        console.print("  [dim]Check 5/5: GDB path verification...[/]")
        report.gdb_path_check = run_gdb_path_check(
            crash_symbols,
            repro_source=reproducer_path,
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
                f"(ratio={gpc.hit_ratio:.0%})"
            )
        elif gpc.verdict == "partial_path":
            report.notes.append(
                f"GDB path PARTIAL: {len(gpc.hit_functions)}/"
                f"{len(gpc.expected_functions)} crash-stack functions hit"
            )
        elif gpc.verdict == "path_diverged":
            report.notes.append(
                "GDB path DIVERGED: none of the expected crash-stack "
                "functions were hit — code path has changed"
            )

    # ── Compute overall verdict ──────────────────────────────────────
    report.verdict, report.confidence = _compute_verdict(report)

    return report
