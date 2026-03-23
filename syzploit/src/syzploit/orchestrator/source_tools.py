"""
orchestrator.source_tools — Source manipulation & diagnostic tools.

This module adds a new class of *fine-grained* tools that let the
agent **read, edit, and recompile** individual exploit source files
and **run diagnostic commands** on the target device.

Without these tools the agent is stuck in a coarse loop:
  exploit (full-regen) → verify → (fail) → exploit (full-regen) → …

With them it can do:
  exploit → verify → read_exploit_source → edit_exploit_module →
  recompile_exploit → verify → …

Tool inventory:
  read_exploit_source    — Read a single source file from the project.
  edit_exploit_module    — LLM-targeted edit of one module with error
                           context (e.g. fix one function, one type
                           error, one wrong offset).
  recompile_exploit      — Incremental recompile of the current project
                           (no full regeneration).
  show_compilation_errors— Show current/last compilation errors to the
                           agent so it can decide what to fix.
  run_target_command     — Execute an arbitrary command on the target
                           device (SSH or ADB) and capture output.
  read_target_file       — Read a file from the target device (e.g.
                           /proc/slabinfo, /proc/kallsyms, dmesg).
  runtime_feedback       — Closed-loop: verify → diagnose → fix → recompile
                           → re-verify (wraps runtime_feedback.py).
  gdb_session            — Start/stop/status for persistent interactive GDB
                           session connected to QEMU GDB stub (DEFAULT mode).
  gdb_command            — Send any GDB command to the interactive session
                           and get its output.  Includes syz-* analysis
                           commands for UAF/OOB/cred detection.
"""

from __future__ import annotations

import re
import subprocess
import time as _time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ..core.config import Config
from ..core.log import console
from .context import TaskContext
from .tools import default_registry

# ── Module-level state for persistent VM / ADB across calls ──────────
_vm_proc: Optional[subprocess.Popen] = None
_adb_tunnel_proc: Optional[subprocess.Popen] = None
_adb_port_active: Optional[int] = None


# ═══════════════════════════════════════════════════════════════════════
# 1. read_exploit_source
# ═══════════════════════════════════════════════════════════════════════

@default_registry.register(
    name="read_exploit_source",
    description=(
        "Read the contents of a specific exploit source file "
        "(e.g. trigger.c, spray.c, exploit.h).  Returns the full "
        "source code of ONE file from the current exploit project.  "
        "If no filename is specified, lists all files in the project.  "
        "Use this to inspect generated code before editing."
    ),
)
def tool_read_exploit_source(
    ctx: TaskContext, cfg: Config, **kwargs: Any
) -> TaskContext:
    if not ctx.exploit_result or not ctx.exploit_result.source_path:
        ctx.errors.append("read_exploit_source: no exploit project exists yet")
        ctx.log("source_tools", "read_exploit_source", "no project")
        return ctx

    src_dir = Path(ctx.exploit_result.source_path)
    filename = kwargs.get("filename", "")

    # No filename → list project contents
    if not filename:
        files = sorted(
            f.name for f in src_dir.iterdir()
            if f.is_file() and not f.name.startswith(".")
        )
        listing = "\n".join(f"  {f}" for f in files)
        ctx.analysis_data["exploit_file_listing"] = files
        ctx.log(
            "source_tools", "list_project",
            f"{len(files)} files in {src_dir}",
        )
        console.print(
            f"  Exploit project ({src_dir}):\n{listing}"
        )
        return ctx

    # Read specific file
    file_path = src_dir / filename
    if not file_path.exists():
        # Try fuzzy match
        candidates = [f.name for f in src_dir.iterdir() if f.is_file()]
        close = [c for c in candidates if filename.lower() in c.lower()]
        msg = f"File not found: {filename}"
        if close:
            msg += f". Did you mean: {', '.join(close)}?"
        ctx.errors.append(f"read_exploit_source: {msg}")
        ctx.log("source_tools", "read_exploit_source", msg)
        return ctx

    content = file_path.read_text()
    # Store in analysis_data so the agent's reflection can see it
    ctx.analysis_data[f"source:{filename}"] = content
    ctx.log(
        "source_tools", "read_exploit_source",
        f"read {filename} ({len(content)} chars)",
    )
    console.print(
        f"  Read {filename}: {len(content)} chars, "
        f"{content.count(chr(10))+1} lines"
    )
    return ctx


# ═══════════════════════════════════════════════════════════════════════
# 2. edit_exploit_module
# ═══════════════════════════════════════════════════════════════════════

@default_registry.register(
    name="edit_exploit_module",
    description=(
        "Use the LLM to make a TARGETED edit to a single exploit "
        "source file.  Provide: filename (e.g. 'trigger.c'), and "
        "instruction (what to fix/change).  The LLM receives the "
        "full file, compilation errors, verification feedback, and "
        "your instruction.  It returns the corrected file.  This is "
        "much faster than regenerating the entire exploit from scratch."
    ),
)
def tool_edit_exploit_module(
    ctx: TaskContext, cfg: Config, **kwargs: Any
) -> TaskContext:
    filename = kwargs.get("filename", "")
    instruction = kwargs.get("instruction", "")

    if not filename:
        ctx.errors.append("edit_exploit_module: 'filename' is required")
        return ctx
    if not instruction:
        ctx.errors.append("edit_exploit_module: 'instruction' is required")
        return ctx

    if not ctx.exploit_result or not ctx.exploit_result.source_path:
        ctx.errors.append("edit_exploit_module: no exploit project exists")
        return ctx

    src_dir = Path(ctx.exploit_result.source_path)
    file_path = src_dir / filename

    if not file_path.exists():
        ctx.errors.append(
            f"edit_exploit_module: {filename} not found in {src_dir}"
        )
        return ctx

    original = file_path.read_text()

    # Gather context for the LLM
    context_parts: list[str] = []

    # The exploit.h header (always useful for type definitions)
    exploit_h = (ctx.exploit_result.source_files or {}).get("exploit.h", "")
    if exploit_h:
        context_parts.append(f"/* exploit.h */\n{exploit_h}")

    # Kernel offsets (if available)
    offsets_h = (ctx.exploit_result.source_files or {}).get(
        "kernel_offsets.h", ""
    )
    if not offsets_h:
        offsets_h = ctx.kernel_offsets_header or ""
    if offsets_h:
        context_parts.append(f"/* kernel_offsets.h */\n{offsets_h}")

    # Last compilation errors
    last_errors = ctx.analysis_data.get("last_compilation_errors", "")
    if last_errors:
        context_parts.append(f"COMPILATION ERRORS:\n{last_errors}")

    # Last verification feedback
    if ctx.verification_history:
        last_v = ctx.verification_history[-1]
        if not last_v.success:
            vfb_parts: list[str] = []
            if last_v.failure_reason:
                vfb_parts.append(f"Failure: {last_v.failure_reason}")
            if last_v.exploit_output:
                vfb_parts.append(
                    f"Output:\n{last_v.exploit_output[-1500:]}"
                )
            if last_v.dmesg_new:
                vfb_parts.append(f"dmesg:\n{last_v.dmesg_new[-1000:]}")
            if last_v.gdb_functions_hit:
                vfb_parts.append(
                    f"GDB hit: {', '.join(last_v.gdb_functions_hit)}"
                )
            if last_v.gdb_functions_missed:
                vfb_parts.append(
                    f"GDB missed: {', '.join(last_v.gdb_functions_missed)}"
                )
            if vfb_parts:
                context_parts.append(
                    "VERIFICATION FEEDBACK:\n" + "\n".join(vfb_parts)
                )

    # Dynamic exploitation notes
    dyn_notes = ctx.analysis_data.get("dynamic_exploitation_notes", "")
    if dyn_notes:
        context_parts.append(f"EXPLOITATION NOTES:\n{dyn_notes}")

    # Sibling file synopsis (other .c files, first 30 lines each)
    source_files = ctx.exploit_result.source_files or {}
    for sib_name, sib_content in sorted(source_files.items()):
        if sib_name == filename or not sib_name.endswith(".c"):
            continue
        # Show function signatures only
        sigs = []
        for line in sib_content.splitlines():
            stripped = line.strip()
            if (
                stripped
                and not stripped.startswith("//")
                and not stripped.startswith("/*")
                and not stripped.startswith("*")
                and not stripped.startswith("#")
                and "(" in stripped
                and "{" in stripped
            ):
                sigs.append(stripped.split("{")[0].strip() + ";")
        if sigs:
            context_parts.append(
                f"/* {sib_name} — function signatures */\n"
                + "\n".join(sigs[:20])
            )

    context_block = "\n\n".join(context_parts)

    # Build the edit prompt
    prompt = f"""\
You are editing a single exploit source file.  Apply the requested change
and return the COMPLETE corrected file.  Do NOT omit any functions or
code — return the full file content even if you only changed one line.

═══ FILE: {filename} ═══
{original}

═══ PROJECT CONTEXT ═══
{context_block}

═══ EDIT INSTRUCTION ═══
{instruction}

═══ RULES ═══
- Return ONLY C source code, no markdown fences, no explanation.
- Preserve all existing #include directives unless the instruction says
  otherwise.
- Do NOT add a main() function unless this is main.c.
- If you add new struct types or functions, ensure they don't conflict
  with exploit.h or kernel_offsets.h.
- Make the MINIMAL change needed.  Do NOT refactor unrelated code.
"""

    from ..core.llm import LLMClient
    llm = LLMClient(cfg).for_task("codegen")

    try:
        edited = llm.chat(
            [
                {
                    "role": "system",
                    "content": (
                        "You are a kernel exploit developer making a "
                        "targeted code edit.  Return only C source code."
                    ),
                },
                {"role": "user", "content": prompt},
            ],
            temperature=0.15,
            max_tokens=16384,
        )

        # Strip markdown fences if present
        edited = re.sub(
            r"^```(?:c|cpp|h)?\s*\n", "", edited.strip()
        )
        edited = re.sub(r"\n```\s*$", "", edited.strip())

        # Sanity check: must contain at least one function or #include
        if not (
            "#include" in edited
            or re.search(r"\w+\s+\w+\s*\(", edited)
        ):
            ctx.errors.append(
                "edit_exploit_module: LLM returned non-C output"
            )
            ctx.log(
                "source_tools", "edit_exploit_module",
                "LLM returned invalid content",
            )
            return ctx

        # Strip rogue main() from non-main.c files
        if filename != "main.c" and re.search(
            r"^(?:int|void)\s+main\s*\(", edited, re.MULTILINE
        ):
            from ..exploit.generator import _sanitize_no_main
            edited = _sanitize_no_main(edited, filename)

        # Write back
        file_path.write_text(edited)

        # Update in-memory source_files
        if ctx.exploit_result and ctx.exploit_result.source_files:
            ctx.exploit_result.source_files[filename] = edited

        ctx.log(
            "source_tools", "edit_exploit_module",
            f"edited {filename}: {len(original)} → {len(edited)} chars",
        )
        console.print(
            f"  [green]Edited {filename}:[/] "
            f"{len(original)} → {len(edited)} chars"
        )

    except Exception as exc:
        ctx.errors.append(f"edit_exploit_module failed: {exc}")
        ctx.log("source_tools", "edit_exploit_module", f"error: {exc}")
        console.print(f"  [red]Edit failed: {exc}[/]")

    return ctx


# ═══════════════════════════════════════════════════════════════════════
# 3. recompile_exploit
# ═══════════════════════════════════════════════════════════════════════

@default_registry.register(
    name="recompile_exploit",
    description=(
        "Recompile the current exploit project WITHOUT regenerating any "
        "source code.  Use after edit_exploit_module to check if the "
        "edit fixed compilation errors.  Optionally runs the type "
        "checker first (auto_fix=True by default).  Updates "
        "exploit_result.binary_path on success."
    ),
)
def tool_recompile_exploit(
    ctx: TaskContext, cfg: Config, **kwargs: Any
) -> TaskContext:
    if not ctx.exploit_result or not ctx.exploit_result.source_path:
        ctx.errors.append("recompile_exploit: no exploit project exists")
        return ctx

    src_dir = Path(ctx.exploit_result.source_path)
    if not src_dir.exists():
        ctx.errors.append(f"recompile_exploit: {src_dir} does not exist")
        return ctx

    run_type_check = kwargs.get("type_check", True)
    arch_str = (
        ctx.target_arch.value
        if hasattr(ctx.target_arch, "value")
        else str(ctx.target_arch or "arm64")
    )

    # Optional pre-compilation type check
    if run_type_check:
        try:
            from ..exploit.type_checker import check_types
            tc = check_types(str(src_dir), auto_fix=True)
            if tc.auto_fixed:
                console.print(
                    f"  [green]Type checker auto-fixed: "
                    f"{', '.join(tc.auto_fixed)}[/]"
                )
                # Re-read fixed files into source_files
                for fname in tc.auto_fixed:
                    fpath = src_dir / fname
                    if fpath.exists() and ctx.exploit_result.source_files:
                        ctx.exploit_result.source_files[fname] = (
                            fpath.read_text()
                        )
        except Exception as exc:
            console.print(f"  [dim]Type check skipped: {exc}[/]")

    # Compile
    from ..exploit.exploit_compiler import ExploitCompiler
    ec = ExploitCompiler(arch=arch_str, cfg=cfg)
    success, error = ec.compile_make(str(src_dir), output_binary="exploit")

    if success:
        binary_path = str(src_dir / "exploit")
        ctx.exploit_result.binary_path = binary_path
        ctx.exploit_result.success = True

        # Clear stale compilation errors
        ctx.analysis_data.pop("last_compilation_errors", None)

        ctx.log(
            "source_tools", "recompile_exploit",
            f"compiled successfully: {binary_path}",
        )
        console.print(f"  [green]Recompiled: {binary_path}[/]")
    else:
        # Store errors for the agent to inspect
        ctx.analysis_data["last_compilation_errors"] = error or ""
        ctx.exploit_result.success = False
        ctx.exploit_result.binary_path = None

        ctx.errors.append(f"Recompilation failed: {error[:300]}")
        ctx.log("source_tools", "recompile_exploit", f"failed: {error[:200]}")
        console.print(f"  [red]Recompilation failed: {error[:200]}[/]")

    return ctx


# ═══════════════════════════════════════════════════════════════════════
# 4. show_compilation_errors
# ═══════════════════════════════════════════════════════════════════════

@default_registry.register(
    name="show_compilation_errors",
    description=(
        "Show the last compilation errors from the exploit project.  "
        "The agent can use these to decide which file to edit with "
        "edit_exploit_module.  Also runs incremental per-file "
        "compilation to isolate errors per source file."
    ),
)
def tool_show_compilation_errors(
    ctx: TaskContext, cfg: Config, **kwargs: Any
) -> TaskContext:
    if not ctx.exploit_result or not ctx.exploit_result.source_path:
        ctx.errors.append(
            "show_compilation_errors: no exploit project exists"
        )
        return ctx

    src_dir = Path(ctx.exploit_result.source_path)
    arch_str = (
        ctx.target_arch.value
        if hasattr(ctx.target_arch, "value")
        else str(ctx.target_arch or "arm64")
    )

    # Run incremental compilation to get per-file errors
    from ..exploit.exploit_compiler import ExploitCompiler
    ec = ExploitCompiler(arch=arch_str, cfg=cfg)

    per_file_errors: Dict[str, str] = {}
    try:
        per_file_errors = ec._compile_incremental(str(src_dir))
    except Exception as exc:
        console.print(f"  [yellow]Incremental compile failed: {exc}[/]")

    if per_file_errors:
        # Format for agent consumption
        error_report_parts: list[str] = []
        for fname, errs in sorted(per_file_errors.items()):
            error_report_parts.append(f"═══ {fname} ═══\n{errs}")

        error_report = "\n\n".join(error_report_parts)
        ctx.analysis_data["last_compilation_errors"] = error_report
        ctx.analysis_data["compilation_error_files"] = list(
            per_file_errors.keys()
        )
        ctx.log(
            "source_tools", "show_compilation_errors",
            f"{len(per_file_errors)} files with errors: "
            f"{', '.join(per_file_errors.keys())}",
        )
        console.print(
            f"  [yellow]{len(per_file_errors)} files with errors:[/] "
            f"{', '.join(per_file_errors.keys())}"
        )
    else:
        ctx.analysis_data.pop("last_compilation_errors", None)
        ctx.analysis_data.pop("compilation_error_files", None)
        ctx.log(
            "source_tools", "show_compilation_errors",
            "no compilation errors",
        )
        console.print("  [green]No compilation errors[/]")

    return ctx


# ═══════════════════════════════════════════════════════════════════════
# 5. run_target_command  (with auto-boot)
# ═══════════════════════════════════════════════════════════════════════

def _ensure_device_ready(
    ctx: TaskContext,
    cfg: Config,
) -> Tuple[bool, int, str]:
    """Ensure the target device is booted and ADB-reachable.

    Returns ``(ok, adb_port, error_msg)``.

    1. Checks if ADB is already alive → fast path.
    2. Otherwise: stop stale VM, start VM, GDB continue, ADB tunnel,
       wait for ADB — reusing the same helpers as ``collect_target_info``
       and ``identify_slab_cache``.
    3. VM and tunnel processes are stored in module-level state so
       subsequent calls reuse the running instance.
    """
    global _vm_proc, _adb_tunnel_proc, _adb_port_active  # noqa: PLW0603

    from ..infra.verification import (
        _adb_is_alive,
        _calc_adb_port,
        _check_remote_port,
        _is_gdb_start,
        _run_start_cmd,
        _run_stop_cmd,
        _send_gdb_continue,
        _setup_adb_tunnel,
    )

    adb_port = _calc_adb_port(ctx.instance, getattr(cfg, "adb_port", 6520))

    # ── Fast path: ADB already reachable ─────────────────────────────
    if _adb_is_alive(adb_port):
        _adb_port_active = adb_port
        console.print("  [dim]run_target_command: ADB already alive[/]")
        return True, adb_port, ""

    # ── Need to boot the VM ──────────────────────────────────────────
    ssh_host = ctx.ssh_host or ""
    start_cmd = ctx.exploit_start_cmd or ctx.start_cmd
    if not start_cmd:
        return False, adb_port, (
            "ADB device not reachable and no start_cmd / "
            "exploit_start_cmd configured — cannot boot VM"
        )
    if not ssh_host:
        return False, adb_port, (
            "ADB device not reachable and no ssh_host configured"
        )

    console.print(
        "  [dim]run_target_command: device not reachable — booting VM…[/]"
    )

    # ── Stop stale VM ────────────────────────────────────────────────
    if ctx.stop_cmd:
        console.print("  [dim]run_target_command: stopping stale VM…[/]")
        _run_stop_cmd(
            ctx.stop_cmd, ssh_host=ssh_host, ssh_port=ctx.ssh_port,
        )
        _time.sleep(3)

    # ── Start VM ─────────────────────────────────────────────────────
    console.print(f"  [dim]run_target_command: starting VM ({start_cmd[:60]})…[/]")
    ok, vm_proc = _run_start_cmd(
        start_cmd, ssh_host=ssh_host, ssh_port=ctx.ssh_port,
    )
    if not ok:
        return False, adb_port, "failed to start VM"
    _vm_proc = vm_proc
    _time.sleep(5)

    # ── GDB continue (if start_cmd is gdb_run.sh) ───────────────────
    if _is_gdb_start(start_cmd) and ctx.gdb_port:
        console.print("  [dim]run_target_command: sending GDB continue…[/]")
        gdb_ok = _send_gdb_continue(
            ctx.gdb_port,
            ssh_host=ssh_host,
            ssh_port=ctx.ssh_port,
            setup_tunnels=ctx.setup_tunnels,
            instance=ctx.instance or 20,
        )
        if gdb_ok:
            console.print(
                "  [dim]run_target_command: waiting for kernel boot…[/]"
            )
            _time.sleep(30)
        else:
            console.print(
                "  [yellow]run_target_command: GDB continue failed — "
                "VM may not boot[/]"
            )

    # ── ADB tunnel ───────────────────────────────────────────────────
    if ctx.setup_tunnels and ssh_host:
        console.print(
            f"  [dim]run_target_command: setting up ADB tunnel "
            f"port {adb_port}…[/]"
        )
        tunnel = _setup_adb_tunnel(adb_port, ssh_host, ctx.ssh_port)
        if tunnel:
            _adb_tunnel_proc = tunnel
            _time.sleep(3)

    # ── Wait for ADB ─────────────────────────────────────────────────
    # GDB boots are very slow (~7 min wall clock on 1-CPU ARM64 QEMU).
    gdb_boot = bool(_is_gdb_start(start_cmd) and ctx.gdb_port)
    max_attempts = 60 if gdb_boot else 24  # 10 min vs 4 min
    console.print(
        f"  [dim]run_target_command: waiting for ADB "
        f"(up to {max_attempts * 10}s)…[/]"
    )
    for attempt in range(max_attempts):
        if _adb_is_alive(adb_port):
            _adb_port_active = adb_port
            console.print("  [green]run_target_command: ADB connected[/]")
            return True, adb_port, ""
        if attempt % 3 == 2:
            console.print(
                f"  [dim]  still waiting… ({(attempt + 1) * 10}s)[/]"
            )
        # Check VM process health every ~60s
        if attempt > 0 and attempt % 6 == 0 and _vm_proc is not None:
            rc = _vm_proc.poll()
            if rc is not None:
                console.print(
                    f"  [yellow]VM process exited (rc={rc}) — "
                    f"VM may have failed to start[/]"
                )
        # Check remote port every ~90s to verify the tunnel target
        if attempt > 0 and attempt % 9 == 0 and ssh_host:
            diag = _check_remote_port(adb_port, ssh_host, ctx.ssh_port)
            if diag:
                console.print(
                    f"  [dim]  remote port {adb_port} on "
                    f"{ssh_host}: {diag[:120]}[/]"
                )
        _time.sleep(10)

    return False, adb_port, "ADB device never became reachable after boot"


@default_registry.register(
    name="run_target_command",
    description=(
        "Execute a shell command on the target device (via SSH or ADB) "
        "and return stdout+stderr.  Use for diagnostic commands like "
        "'cat /proc/slabinfo', 'dmesg | tail -50', "
        "'cat /proc/sys/kernel/kptr_restrict', 'id', 'getenforce', "
        "'ls /proc/kallsyms', etc.  Command output is stored in "
        "analysis_data['target_command_output'].  "
        "SAFETY: destructive commands (rm, reboot, dd) are blocked."
    ),
)
def tool_run_target_command(
    ctx: TaskContext, cfg: Config, **kwargs: Any
) -> TaskContext:
    command = kwargs.get("command", "")
    if not command:
        ctx.errors.append("run_target_command: 'command' is required")
        return ctx

    # Safety: block dangerous commands
    _BLOCKED_PATTERNS = [
        r"\brm\s+-rf\b", r"\bmkfs\b", r"\bdd\s+if=", r"\breboot\b",
        r"\bshutdown\b", r"\bhalt\b", r"\bpoweroff\b", r"\bformat\b",
        r"\bfdisk\b", r"\bmkdir\s+-p\s+/\b",
    ]
    for pat in _BLOCKED_PATTERNS:
        if re.search(pat, command, re.IGNORECASE):
            ctx.errors.append(
                f"run_target_command: blocked dangerous command: {command}"
            )
            return ctx

    timeout = int(kwargs.get("timeout", 30))
    timeout = min(timeout, 120)  # hard cap

    use_adb = (
        ctx.target_platform.value == "android"
        and ctx.instance is not None
    )

    returncode = -1
    stdout = ""
    stderr = ""

    if use_adb:
        from ..infra.verification import _adb_run

        # ── Ensure device is booted and ADB is reachable ─────────
        ready, adb_port, boot_err = _ensure_device_ready(ctx, cfg)
        if not ready:
            ctx.errors.append(
                f"run_target_command: device not reachable: {boot_err}"
            )
            return ctx

        try:
            returncode, stdout, stderr = _adb_run(
                command, adb_port, timeout=timeout
            )
        except Exception as exc:
            stderr = str(exc)
    else:
        ssh_host = ctx.ssh_host or getattr(cfg, "ssh_host", "")
        ssh_port = ctx.ssh_port or getattr(cfg, "ssh_port", 22)
        if not ssh_host:
            ctx.errors.append(
                "run_target_command: no SSH host or ADB instance configured"
            )
            return ctx
        try:
            r = subprocess.run(
                [
                    "ssh", "-o", "StrictHostKeyChecking=no",
                    "-o", "ConnectTimeout=10",
                    "-p", str(ssh_port),
                    ssh_host, command,
                ],
                capture_output=True, text=True, timeout=timeout,
            )
            returncode = r.returncode
            stdout = r.stdout
            stderr = r.stderr
        except subprocess.TimeoutExpired:
            stderr = "command timed out"
        except Exception as exc:
            stderr = str(exc)

    # Combine and store output
    output = stdout
    if stderr:
        output += ("\n" if output else "") + f"(stderr) {stderr}"

    # Truncate to avoid context explosion
    if len(output) > 8000:
        output = output[:8000] + f"\n... (truncated, {len(output)} total)"

    ctx.analysis_data["target_command_output"] = {
        "command": command,
        "returncode": returncode,
        "output": output,
    }
    ctx.log(
        "source_tools", "run_target_command",
        f"cmd='{command}' rc={returncode} "
        f"({len(stdout)} stdout, {len(stderr)} stderr)",
    )

    # Print summary
    if returncode == 0:
        console.print(
            f"  [green]Command OK:[/] {command}\n"
            f"  Output: {output[:300]}"
        )
    else:
        console.print(
            f"  [yellow]Command rc={returncode}:[/] {command}\n"
            f"  {output[:300]}"
        )

    return ctx


# ═══════════════════════════════════════════════════════════════════════
# 6. read_target_file
# ═══════════════════════════════════════════════════════════════════════

@default_registry.register(
    name="read_target_file",
    description=(
        "Read a file from the target device (via SSH or ADB).  "
        "Common files: /proc/slabinfo, /proc/kallsyms, "
        "/proc/version, /proc/sys/kernel/kptr_restrict, "
        "/sys/kernel/slab/<cache>/object_size.  "
        "Optionally specify 'max_lines' (default 200) and 'grep' to "
        "filter output.  Use for dynamic runtime diagnostics."
    ),
)
def tool_read_target_file(
    ctx: TaskContext, cfg: Config, **kwargs: Any
) -> TaskContext:
    filepath = kwargs.get("filepath", kwargs.get("path", ""))
    if not filepath:
        ctx.errors.append("read_target_file: 'filepath' is required")
        return ctx

    max_lines = int(kwargs.get("max_lines", 200))
    grep_filter = kwargs.get("grep", "")

    # Build the command
    if grep_filter:
        command = f"cat {filepath} 2>/dev/null | grep -i '{grep_filter}' | head -{max_lines}"
    else:
        command = f"head -{max_lines} {filepath} 2>/dev/null"

    # Reuse run_target_command logic
    result = tool_run_target_command(
        ctx, cfg, command=command, timeout=15
    )

    # Relabel the output with a nicer key
    if "target_command_output" in ctx.analysis_data:
        cmd_output = ctx.analysis_data["target_command_output"]
        ctx.analysis_data[f"target_file:{filepath}"] = (
            cmd_output.get("output", "")
        )
        ctx.log(
            "source_tools", "read_target_file",
            f"read {filepath}" + (f" (grep '{grep_filter}')" if grep_filter else ""),
        )

    return result


# ═══════════════════════════════════════════════════════════════════════
# 7. runtime_feedback
# ═══════════════════════════════════════════════════════════════════════

@default_registry.register(
    name="runtime_feedback",
    description=(
        "Run the exploit verification feedback loop.  Deploys the "
        "exploit, analyses which phase failed (trigger/spray/rw/"
        "cred_overwrite), regenerates only the failing module(s) "
        "with diagnostic-enriched context, recompiles, and retries "
        "up to max_attempts (default 3).  This is a FULL LOOP — it "
        "handles the verify→diagnose→fix→recompile→re-verify cycle "
        "automatically.  Prefer this over manually calling "
        "verify_exploit + edit_exploit_module + recompile_exploit "
        "for typical post-compilation verification."
    ),
)
def tool_runtime_feedback(
    ctx: TaskContext, cfg: Config, **kwargs: Any
) -> TaskContext:
    if not ctx.exploit_result or not ctx.exploit_result.binary_path:
        ctx.errors.append(
            "runtime_feedback: no compiled exploit binary exists"
        )
        return ctx

    if not Path(ctx.exploit_result.binary_path).exists():
        ctx.errors.append(
            f"runtime_feedback: binary not found: "
            f"{ctx.exploit_result.binary_path}"
        )
        return ctx

    max_attempts = int(kwargs.get("max_attempts", 5))

    from ..exploit.runtime_feedback import runtime_feedback_loop
    ctx = runtime_feedback_loop(ctx, cfg, max_attempts=max_attempts)

    # Log outcome
    if ctx.has_verified_exploit():
        ctx.log(
            "source_tools", "runtime_feedback",
            "EXPLOIT VERIFIED — privilege escalation confirmed!",
        )
    else:
        ctx.log(
            "source_tools", "runtime_feedback",
            "feedback loop completed without successful verification",
        )

    return ctx


# ── debug_exploit ──────────────────────────────────────────────────────
@default_registry.register(
    name="debug_exploit",
    description=(
        "Run a pre-scripted diagnostic sequence to determine WHY the "
        "exploit hangs or fails.  Checks: (1) binder device exists, "
        "(2) runs exploit with strace to capture blocking syscalls, "
        "(3) sets targeted GDB breakpoints on the exploit's code path, "
        "(4) captures exactly where execution stalls.  Returns a "
        "structured diagnostic report that can inform code fixes."
    ),
)
def tool_debug_exploit(
    ctx: TaskContext, cfg: Config, **kwargs: Any
) -> TaskContext:
    from ..infra.verification import _adb_run, _adb_is_alive, _adb_exe, _adb_target

    if not ctx.exploit_result or not ctx.exploit_result.binary_path:
        ctx.errors.append("debug_exploit: no compiled exploit binary")
        return ctx

    adb_port = 6519 + (ctx.instance or 1)
    if not _adb_is_alive(adb_port):
        ctx.errors.append("debug_exploit: ADB not connected")
        return ctx

    report_lines = ["═══ EXPLOIT DIAGNOSTIC REPORT ═══\n"]

    # 1. Check binder devices
    rc, out, _ = _adb_run("ls -la /dev/binder /dev/hwbinder /dev/vndbinder 2>&1", adb_port, timeout=10)
    report_lines.append("── Binder Devices ──")
    report_lines.append(out.strip() if out.strip() else "  No binder devices found!")
    report_lines.append("")

    # 2. Check process capabilities and SELinux context
    rc, out, _ = _adb_run("id; getenforce; cat /proc/self/attr/current 2>/dev/null", adb_port, timeout=10)
    report_lines.append("── Process Identity ──")
    report_lines.append(out.strip())
    report_lines.append("")

    # 3. Check if exploit binary runs at all (with timeout)
    remote_path = "/data/local/tmp/exploit"
    rc, out, _ = _adb_run(f"timeout 5 {remote_path} 2>&1 || echo EXIT_CODE=$?", adb_port, timeout=15)
    report_lines.append("── Exploit Quick-Run (5s timeout) ──")
    report_lines.append(out.strip() if out.strip() else "  No output (hung before any printf)")
    report_lines.append("")

    # 4. Run with strace to find blocking syscall
    rc, out, _ = _adb_run(
        f"timeout 10 strace -f -e trace=ioctl,read,write,openat,mmap,clone "
        f"-o /data/local/tmp/strace.log {remote_path} 2>&1; "
        f"tail -50 /data/local/tmp/strace.log 2>/dev/null",
        adb_port, timeout=25,
    )
    report_lines.append("── Strace (last 50 lines) ──")
    report_lines.append(out.strip() if out.strip() else "  strace not available or exploit didn't run")
    report_lines.append("")

    # 5. Check slab caches relevant to binder
    rc, out, _ = _adb_run(
        "cat /proc/slabinfo 2>/dev/null | head -1; "
        "cat /proc/slabinfo 2>/dev/null | grep -E 'binder|epitem|cred|task_struct|kmalloc-(128|192|256)'",
        adb_port, timeout=10,
    )
    report_lines.append("── Relevant Slab Caches ──")
    report_lines.append(out.strip() if out.strip() else "  /proc/slabinfo not readable")
    report_lines.append("")

    # 6. Check kernel config for exploit-critical flags
    rc, out, _ = _adb_run(
        "zcat /proc/config.gz 2>/dev/null | grep -E "
        "'CONFIG_SYSVIPC|CONFIG_USER_NS|CONFIG_USERFAULTFD|CONFIG_CROSS_MEMORY' || echo 'config.gz not available'",
        adb_port, timeout=10,
    )
    report_lines.append("── Kernel Config (exploit-relevant) ──")
    report_lines.append(out.strip())
    report_lines.append("")

    # 7. Check su binary availability
    rc, out, _ = _adb_run("ls -la /system/xbin/su /system/bin/su 2>&1; su 0 id 2>&1", adb_port, timeout=10)
    report_lines.append("── su Binary ──")
    report_lines.append(out.strip())
    report_lines.append("")

    # 8. Check network interfaces (for dst_entry exploits)
    rc, out, _ = _adb_run("ip link show; ip route show", adb_port, timeout=10)
    report_lines.append("── Network Interfaces ──")
    report_lines.append(out.strip())

    diagnostic_report = "\n".join(report_lines)
    ctx.analysis_data["debug_exploit_report"] = diagnostic_report
    ctx.log("source_tools", "debug_exploit", f"Diagnostic report ({len(report_lines)} lines)")

    # Print summary to console
    console.print(f"\n{diagnostic_report}\n")

    return ctx


# ── Module-level state for interactive GDB session ───────────────────
_interactive_gdb: Optional[Any] = None


# ═══════════════════════════════════════════════════════════════════════
# 8. gdb_session — Lifecycle management for interactive GDB
# ═══════════════════════════════════════════════════════════════════════

@default_registry.register(
    name="gdb_session",
    description=(
        "Manage an interactive GDB session connected to the target "
        "kernel's QEMU GDB stub.  Actions:\n"
        "  action='start'  — Start GDB, connect to VM, load analysis helpers.\n"
        "  action='stop'   — Disconnect and close GDB.\n"
        "  action='status' — Check if the session is alive.\n"
        "The session is persistent across tool calls.  After starting, "
        "use 'gdb_command' to send commands.  The session auto-loads "
        "syzploit analysis helpers (syz-* commands) for UAF/OOB/cred "
        "analysis.  This is the DEFAULT GDB mode — the batch monitor "
        "is used as a fallback when interactive mode is not needed."
    ),
)
def tool_gdb_session(
    ctx: TaskContext, cfg: Config, **kwargs: Any
) -> TaskContext:
    global _interactive_gdb  # noqa: PLW0603
    action = kwargs.get("action", "start").lower()

    if action == "stop":
        if _interactive_gdb is not None:
            _interactive_gdb.close()
            _interactive_gdb = None
            ctx.log("source_tools", "gdb_session", "interactive GDB stopped")
        else:
            ctx.log("source_tools", "gdb_session", "no active session")
        return ctx

    if action == "status":
        if _interactive_gdb is not None and _interactive_gdb.is_connected:
            ctx.analysis_data["gdb_session_status"] = "connected"
            ctx.log("source_tools", "gdb_session", "session active")
        else:
            ctx.analysis_data["gdb_session_status"] = "disconnected"
            ctx.log("source_tools", "gdb_session", "no active session")
        return ctx

    # action == "start" (default)
    if _interactive_gdb is not None and _interactive_gdb.is_connected:
        ctx.analysis_data["gdb_session_status"] = "already_connected"
        ctx.log("source_tools", "gdb_session", "session already active")
        return ctx

    from ..infra.gdb import InteractiveGDB

    # Resolve vmlinux path
    vmlinux = None
    if ctx.analysis_data.get("vmlinux_path"):
        vmlinux = ctx.analysis_data["vmlinux_path"]
    elif ctx.kernel_image:
        # Try standard vmlinux location next to the kernel image
        ki = Path(ctx.kernel_image)
        for candidate in [ki.parent / "vmlinux", ki.with_name("vmlinux")]:
            if candidate.is_file():
                vmlinux = str(candidate)
                break

    ssh_host = ctx.ssh_host or ""
    gdb_port = ctx.gdb_port or 1234

    try:
        # Compute transcript path for user-inspectable GDB logs
        _transcript_path = None
        if ctx.work_dir:
            _transcript_path = str(Path(ctx.work_dir) / "gdb_transcript.log")
        else:
            _transcript_path = "/tmp/syzploit_gdb_transcript.log"

        _interactive_gdb = InteractiveGDB(
            vmlinux=vmlinux,
            arch=ctx.target_arch.value if hasattr(ctx.target_arch, "value") else "arm64",
            host="localhost",
            port=gdb_port,
            ssh_host=ssh_host if ssh_host else None,
            ssh_port=ctx.ssh_port,
            setup_tunnel=ctx.setup_tunnels and bool(ssh_host),
            transcript_path=_transcript_path,
        )
        ok = _interactive_gdb.connect()
        if ok:
            ctx.analysis_data["gdb_session_status"] = "connected"
            ctx.log(
                "source_tools", "gdb_session",
                f"interactive GDB connected (port {gdb_port})"
            )

            # List available analysis commands for the LLM
            ctx.analysis_data["gdb_analysis_commands"] = (
                "syz-uaf-check <ptr> | syz-oob-check <ptr> <size> | "
                "syz-kasan-check <ptr> | syz-heap-dump <ptr> [n] | "
                "syz-cred-check [task] | syz-slab-info <ptr> | "
                "syz-task-info [task] | syz-vuln-state | "
                "syz-mem-diff <ptr> <size> | syz-mem-compare <ptr> <size> | "
                "syz-breakpoint-summary | syz-stack-vars"
            )
        else:
            ctx.errors.append(
                "gdb_session: failed to connect — check that the VM is "
                "running and GDB stub is enabled"
            )
            _interactive_gdb.close()
            _interactive_gdb = None
    except Exception as exc:
        ctx.errors.append(f"gdb_session: start failed: {exc}")
        if _interactive_gdb is not None:
            _interactive_gdb.close()
        _interactive_gdb = None

    return ctx


# ═══════════════════════════════════════════════════════════════════════
# 9. gdb_command — Send commands to interactive GDB
# ═══════════════════════════════════════════════════════════════════════

@default_registry.register(
    name="gdb_command",
    description=(
        "Send a command to the interactive GDB session and return its "
        "output.  Requires an active session (use gdb_session action='start' "
        "first).  If no session exists, one is started automatically.\n\n"
        "Standard GDB commands:\n"
        "  bt / backtrace         — Show call stack\n"
        "  info registers         — All register values\n"
        "  x/<n><f> <addr>        — Examine memory (e.g. x/16gx $sp)\n"
        "  stepi / nexti          — Step one instruction\n"
        "  break <func>           — Set software breakpoint (unlimited)\n"
        "  hbreak <func>          — Set hardware breakpoint (4 max, fallback)\n"
        "  continue               — Resume kernel execution\n"
        "  print <expr>           — Evaluate expression\n"
        "  info threads           — List vCPU threads\n\n"
        "Syzploit analysis commands (loaded automatically):\n"
        "  syz-uaf-check <ptr>         — Check pointer for use-after-free markers\n"
        "  syz-oob-check <ptr> <size>   — Check for out-of-bounds via redzones\n"
        "  syz-kasan-check <ptr>        — Read KASAN shadow bytes\n"
        "  syz-heap-dump <ptr> [n]      — Dump and classify heap memory\n"
        "  syz-cred-check [task_ptr]    — Inspect task credentials (UID/caps)\n"
        "  syz-task-info [task_ptr]     — Show task_struct fields\n"
        "  syz-vuln-state               — Full vulnerability state snapshot\n"
        "  syz-mem-diff <ptr> <size>    — Snapshot memory before an operation\n"
        "  syz-mem-compare <ptr> <size> — Compare memory after an operation\n"
        "  syz-slab-info <ptr>          — Show slab metadata for pointer\n"
        "  syz-stack-vars               — Show local variables and arguments\n"
        "  syz-breakpoint-summary       — List breakpoints with hit counts\n\n"
        "NOTE: Use 'break' (software breakpoints) — the interactive session "
        "connects after boot so symbols are resolved and SW BPs work.  "
        "No limit on SW breakpoints.  Use 'hbreak' (hardware, 4 max on "
        "ARM64) only as fallback if SW breakpoints don't fire.\n"
        "NOTE: 'continue' resumes the kernel — the GDB session stays open "
        "and you can interrupt with another command later.\n"
        "NOTE: 'stepi'/'nexti' are slow under KVM (single-steps trap to "
        "hypervisor). Use sparingly."
    ),
)
def tool_gdb_command(
    ctx: TaskContext, cfg: Config, **kwargs: Any
) -> TaskContext:
    global _interactive_gdb  # noqa: PLW0603

    command = kwargs.get("command", "")
    timeout = int(kwargs.get("timeout", 30))

    if not command:
        ctx.errors.append("gdb_command: 'command' kwarg is required")
        return ctx

    # Auto-start session if not active
    if _interactive_gdb is None or not _interactive_gdb.is_connected:
        console.print(
            "  [dim]gdb_command: no active session — auto-starting…[/]"
        )
        ctx = tool_gdb_session(ctx, cfg, action="start")
        if _interactive_gdb is None or not _interactive_gdb.is_connected:
            ctx.errors.append(
                "gdb_command: could not auto-start GDB session"
            )
            return ctx

    try:
        output = _interactive_gdb.execute(command, timeout=timeout)
    except ValueError as exc:
        # Command blocked by allow-list
        ctx.errors.append(f"gdb_command: {exc}")
        ctx.log("source_tools", "gdb_command", f"blocked: {command}")
        return ctx
    except RuntimeError as exc:
        ctx.errors.append(f"gdb_command: {exc}")
        return ctx
    except Exception as exc:
        ctx.errors.append(f"gdb_command: unexpected error: {exc}")
        return ctx

    # Store output for the LLM
    ctx.analysis_data["gdb_command_output"] = output
    ctx.analysis_data["gdb_last_command"] = command

    # Accumulate command history (capped at 20) so the decision LLM
    # can see what commands have already been tried and their results.
    from datetime import datetime, timezone
    history = ctx.analysis_data.get("gdb_command_history", [])
    history.append({
        "command": command,
        "output": output[:2000],
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })
    if len(history) > 20:
        history = history[-20:]
    ctx.analysis_data["gdb_command_history"] = history

    ctx.log("source_tools", "gdb_command", f"cmd={command[:60]}")
    return ctx
