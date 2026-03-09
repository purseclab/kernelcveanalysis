"""
reproducer.pipeline — End-to-end reproducer generation pipeline.

Orchestrates: generate code → compile → verify crash on target.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from ..core.config import Config, load_config
from ..core.log import console
from ..core.models import Arch, ReproducerResult, VerificationAttempt
from ..orchestrator.context import TaskContext
from .generator import generate_reproducer_code
from .compiler import compile_reproducer


def generate_reproducer(ctx: TaskContext, cfg: Config) -> TaskContext:
    """
    Full reproducer pipeline reading from and writing to *ctx*.

    Steps:
        1. Generate C code from root_cause (+ existing crash reproducer)
        2. Write to work_dir
        3. Compile for target arch
        4. Verify on target via SSH (if configured)
    """
    if not ctx.root_cause and not (ctx.crash_report and ctx.crash_report.reproducer_c):
        ctx.errors.append("Cannot generate reproducer: no root cause or existing reproducer")
        return ctx

    work_dir = ctx.work_dir or Path.cwd() / "syzploit_output"
    work_dir.mkdir(parents=True, exist_ok=True)

    arch_str = ctx.target_arch.value if ctx.target_arch else "arm64"

    # Step 1: Generate code
    console.print("  [bold]Generating reproducer code…[/]")

    # Gather feedback from previous reproducer verification attempts
    previous_feedback = ""
    previous_source = ""
    repro_attempts = ctx.reproducer_verification_attempts()
    if repro_attempts:
        last = repro_attempts[-1]
        parts = []
        if last.failure_reason:
            parts.append(f"Failure reason: {last.failure_reason}")
        if last.feedback:
            parts.append(f"Feedback: {last.feedback}")
        if last.exploit_output:
            parts.append(f"Program output: {last.exploit_output[:1500]}")
        if last.dmesg_new:
            parts.append(f"Kernel dmesg (new lines): {last.dmesg_new[:1500]}")
        if last.crash_log_excerpt:
            parts.append(f"Crash log: {last.crash_log_excerpt[:1000]}")
        # Include structured GDB diagnostic data
        if last.gdb_functions_hit:
            parts.append(
                f"GDB: functions REACHED: {', '.join(last.gdb_functions_hit)}"
            )
        if last.gdb_functions_missed:
            parts.append(
                f"GDB: functions NOT reached: {', '.join(last.gdb_functions_missed)}"
            )
        if last.gdb_crash_info:
            ci = last.gdb_crash_info
            parts.append(
                f"GDB crash site: {ci.get('crash_function', '?')} "
                f"at {ci.get('crash_address', '?')}"
            )
            if ci.get("backtrace"):
                parts.append(f"Backtrace:\n{ci['backtrace'][:600]}")
        previous_feedback = "\n".join(parts)
    # Include previous reproducer source so LLM can see what was tried
    if ctx.reproducer and ctx.reproducer.source_code:
        previous_source = ctx.reproducer.source_code

    if ctx.root_cause:
        code = generate_reproducer_code(
            ctx.root_cause,
            crash=ctx.crash_report,
            target_kernel=ctx.target_kernel,
            arch=arch_str,
            previous_feedback=previous_feedback,
            previous_source=previous_source,
            cfg=cfg,
        )
    elif ctx.crash_report and ctx.crash_report.reproducer_c:
        # Use existing reproducer directly
        code = ctx.crash_report.reproducer_c
    else:
        ctx.errors.append("No root cause or reproducer available")
        return ctx

    # Step 2: Write source
    source_path = work_dir / "reproducer.c"
    source_path.write_text(code)
    console.print(f"  Written to {source_path}")

    # Step 3: Compile
    binary_path = work_dir / "reproducer"
    console.print(f"  [bold]Compiling for {arch_str}…[/]")
    success, error = compile_reproducer(
        str(source_path),
        str(binary_path),
        arch=arch_str,
        cfg=cfg,
    )

    result = ReproducerResult(
        success=success,
        source_code=code,
        source_path=str(source_path),
        binary_path=str(binary_path) if success else None,
        target_kernel=ctx.target_kernel,
        arch=ctx.target_arch,
    )

    if not success:
        result.notes.append(f"Compilation failed: {error[:500]}")
        console.print(f"  [red]Compilation failed: {error[:200]}[/]")
    else:
        console.print(f"  [green]Compiled successfully: {binary_path}[/]")

    ctx.reproducer = result

    # Step 4: Verify on target (if SSH is configured)
    if success and ctx.ssh_host:
        console.print("  [bold]Verifying reproducer on target…[/]")
        ctx = _verify_reproducer_step(ctx, cfg, str(binary_path))

    return ctx


def _verify_reproducer_step(ctx: TaskContext, cfg: Config, binary_path: str) -> TaskContext:
    """Run reproducer verification and record the attempt."""
    from ..infra.verification import verify_reproducer

    attempt_num = len(ctx.reproducer_verification_attempts()) + 1

    expected_crash_type = ""
    expected_functions: list[str] = []
    if ctx.crash_report:
        expected_crash_type = ctx.crash_report.crash_type
        expected_functions = [f.function for f in ctx.crash_report.stack_frames[:5]]
    # Also include vulnerable functions from root cause analysis
    if ctx.root_cause:
        if ctx.root_cause.vulnerable_function:
            fn = ctx.root_cause.vulnerable_function
            if fn and fn not in expected_functions:
                expected_functions.append(fn)
        for fn in (ctx.root_cause.kernel_functions or [])[:5]:
            if fn and fn not in expected_functions:
                expected_functions.append(fn)

    use_adb = ctx.target_platform.value == "android" and ctx.instance is not None

    # Pass vmlinux/kallsyms for GDB-based path verification
    vmlinux = getattr(cfg, "vmlinux_path", None)
    kallsyms = None
    if ctx.target_system_info and ctx.target_system_info.kallsyms_path:
        kallsyms = ctx.target_system_info.kallsyms_path

    vresult = verify_reproducer(
        binary_path,
        ssh_host=ctx.ssh_host,
        ssh_port=ctx.ssh_port,
        instance=ctx.instance,
        expected_crash_type=expected_crash_type,
        expected_functions=expected_functions or None,
        start_cmd=ctx.start_cmd,
        stop_cmd=ctx.stop_cmd,
        gdb_port=ctx.gdb_port,
        setup_tunnels=ctx.setup_tunnels,
        persistent=ctx.persistent,
        use_adb=use_adb,
        vmlinux_path=vmlinux,
        kallsyms_path=kallsyms,
    )

    # Consider path_reached as a partial success (the bug is triggered)
    path_reached = vresult.get("path_reached", False)
    crash_triggered = vresult.get("crash_triggered", False)
    verification_success = crash_triggered or path_reached

    attempt = VerificationAttempt(
        attempt_number=attempt_num,
        target="reproducer",
        binary_path=binary_path,
        success=verification_success,
        crash_occurred=crash_triggered,
        crash_pattern=vresult.get("crash_log_excerpt", "")[:500],
        crash_log_excerpt=vresult.get("crash_log_excerpt", "")[:2000],
        device_stable=vresult.get("device_stable", True),
        failure_reason=vresult.get("failure_reason", ""),
        feedback=vresult.get("feedback", ""),
        exploit_output=vresult.get("reproducer_output", "")[:3000],
        dmesg_new=vresult.get("crash_log_excerpt", "")[:3000],
    )
    ctx.verification_history.append(attempt)

    if crash_triggered and ctx.reproducer:
        ctx.reproducer.crash_confirmed = True
        ctx.reproducer.crash_log = vresult.get("crash_log_excerpt", "")
        console.print("  [bold green]✓ Reproducer verified — crash triggered![/]")
    elif path_reached and ctx.reproducer:
        ctx.reproducer.crash_confirmed = False
        ctx.reproducer.notes.append(
            f"Vulnerable path reached via GDB (functions hit: "
            f"{vresult.get('gdb_functions_hit', [])}), but no crash on "
            f"non-instrumented kernel. The bug IS being triggered."
        )
        console.print(
            f"  [bold cyan]✓ Reproducer reached vulnerable code path! "
            f"(no crash expected on non-instrumented kernel)[/]"
        )
    elif ctx.reproducer:
        ctx.reproducer.notes.append(
            f"Verification failed: {vresult.get('failure_reason', 'no crash')}"
        )
        console.print(
            f"  [bold yellow]Verification: no crash triggered. "
            f"{vresult.get('failure_reason', '')}[/]"
        )

    return ctx
