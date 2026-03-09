"""
orchestrator.builtin_tools — Concrete tools registered for the Agent.

Each tool wraps one of the major sub-pipelines (analysis, feasibility,
reproducer, exploit) so the LLM-driven Agent can invoke them by name.

Import this module once (e.g. from ``__init__``) to populate
``default_registry``.
"""

from __future__ import annotations

from typing import Any

from ..core.config import Config
from ..core.log import console
from ..core.reporting import save_report
from .context import TaskContext
from .tools import default_registry


# ── analyze ───────────────────────────────────────────────────────────

@default_registry.register(
    name="analyze",
    description=(
        "Classify the input (CVE / syzbot / blog / crash log / PoC), "
        "parse crash data, perform root-cause analysis, and assess "
        "exploitability.  Populates crash_report, root_cause."
    ),
)
def tool_analyze(ctx: TaskContext, cfg: Config, **kwargs: Any) -> TaskContext:
    from ..analysis.dispatcher import analyze_input

    console.print("[dim]→ running analysis dispatcher…[/]")
    ctx = analyze_input(ctx, cfg)

    # ── Save analysis reports ─────────────────────────────────────
    meta = {"input_type": ctx.input_type, "input_value": ctx.input_value}
    if ctx.crash_report:
        save_report("crash_report", ctx.crash_report, ctx.work_dir, metadata=meta)
    if ctx.root_cause:
        save_report("root_cause_analysis", ctx.root_cause, ctx.work_dir, metadata=meta)
    return ctx


# ── collect_target_info ───────────────────────────────────────────────

@default_registry.register(
    name="collect_target_info",
    description=(
        "Boot the target VM and collect system information: kernel "
        "version, architecture, Android properties, SELinux status, "
        "loaded modules, KASAN availability, and /proc/kallsyms.  "
        "The kallsyms file is saved locally so subsequent feasibility "
        "checks can verify symbol presence without a running VM.  "
        "Populates target_system_info on the context.  "
        "Useful when only a CVE or blog was provided (no crash report)."
    ),
)
def tool_collect_target_info(ctx: TaskContext, cfg: Config, **kwargs: Any) -> TaskContext:
    from ..core.models import TargetSystemInfo
    from ..infra.verification import collect_target_system_info

    ssh_host = ctx.ssh_host or kwargs.get("ssh_host", getattr(cfg, "ssh_host", ""))
    if not ssh_host:
        ctx.errors.append(
            "collect_target_info: no SSH host configured — "
            "pass --ssh-host or set SYZPLOIT_SSH_HOST"
        )
        return ctx

    use_adb = ctx.target_platform.value == "android" and ctx.instance is not None

    console.print("[dim]→ collecting target system information…[/]")
    info_dict = collect_target_system_info(
        ssh_host=ssh_host,
        ssh_port=ctx.ssh_port,
        adb_port=kwargs.get("adb_port", 6520),
        use_adb=use_adb,
        instance=ctx.instance,
        start_cmd=ctx.start_cmd or kwargs.get("start_cmd", ""),
        stop_cmd=ctx.stop_cmd or kwargs.get("stop_cmd", ""),
        gdb_port=ctx.gdb_port,
        setup_tunnels=ctx.setup_tunnels,
        work_dir=ctx.work_dir,
    )

    if "error" in info_dict:
        ctx.errors.append(f"collect_target_info: {info_dict['error']}")
        return ctx

    # Build the model from collected data
    target_info = TargetSystemInfo(
        kernel_version=info_dict.get("kernel_version", ""),
        kernel_release=info_dict.get("kernel_release", ""),
        arch=info_dict.get("arch", ""),
        android_version=info_dict.get("android_version"),
        security_patch=info_dict.get("security_patch"),
        build_type=info_dict.get("build_type"),
        device_model=info_dict.get("device_model"),
        kallsyms_available=info_dict.get("kallsyms_available", False),
        kallsyms_path=info_dict.get("kallsyms_path"),
        symbol_count=info_dict.get("symbol_count", 0),
        loaded_modules=info_dict.get("loaded_modules", []),
        kasan_enabled=info_dict.get("kasan_enabled", False),
        config_gz_available=info_dict.get("config_gz_available", False),
        config_gz_path=info_dict.get("config_gz_path"),
        selinux_enforcing=info_dict.get("selinux_enforcing", False),
        selinux_mode=info_dict.get("selinux_mode", ""),
        uname_a=info_dict.get("uname_a", ""),
        dmesg_boot_excerpt=info_dict.get("dmesg_boot_excerpt"),
        notes=info_dict.get("notes", []),
    )

    ctx.target_system_info = target_info

    # Auto-fill target_kernel from collected info if not already set
    if not ctx.target_kernel and target_info.kernel_release:
        ctx.target_kernel = target_info.kernel_release
        console.print(f"  [dim]Auto-detected target kernel: {ctx.target_kernel}[/]")

    ctx.log("tool", "collect_target_info", target_info.summary())

    save_report(
        "target_system_info", target_info, ctx.work_dir,
        metadata={"kernel_release": target_info.kernel_release},
    )
    return ctx


# ── feasibility (static) ──────────────────────────────────────────────

@default_registry.register(
    name="check_feasibility_static",
    description=(
        "Check whether the vulnerability is present on the target kernel "
        "using STATIC analysis only (no VM required): verify symbols in "
        "kallsyms / vmlinux, look for back-ported fixes in the git tree, "
        "and compare vulnerable source code between kernel versions.  "
        "Populates feasibility with symbol_check, fix_check, source_diff."
    ),
)
def tool_feasibility_static(ctx: TaskContext, cfg: Config, **kwargs: Any) -> TaskContext:
    from ..analysis.feasibility import assess_feasibility_static

    if not ctx.has_vuln_info():
        ctx.errors.append(
            "check_feasibility_static: no vulnerability info available — "
            "run 'analyze' first (crash log, CVE, or blog)"
        )
        return ctx

    # Resolve kallsyms_path: explicit kwarg > target_system_info > None
    kallsyms_path = kwargs.get("kallsyms_path")
    if not kallsyms_path and ctx.target_system_info:
        kallsyms_path = ctx.target_system_info.kallsyms_path

    report = assess_feasibility_static(
        crash=ctx.crash_report,  # may be None for CVE/blog inputs
        root_cause=ctx.root_cause,
        target_kernel=ctx.target_kernel,
        # NOTE: Do NOT pass ssh_host here — static check should only use
        # locally-saved kallsyms from collect_target_info, never SSH to a
        # remote host (which would prompt for sudo password).
        vmlinux_path=kwargs.get("vmlinux_path"),
        system_map_path=kwargs.get("system_map_path"),
        kallsyms_path=kallsyms_path,
        kernel_tree_path=kwargs.get("kernel_tree_path") or kwargs.get("kernel_source"),
        original_tag=kwargs.get("original_tag"),
        target_tag=kwargs.get("target_tag"),
        fix_commits=kwargs.get("fix_commits"),
    )
    ctx.feasibility = report
    ctx.log("tool", "check_feasibility_static", f"verdict={report.verdict}")

    save_report(
        "feasibility_static", report, ctx.work_dir,
        metadata={"target_kernel": ctx.target_kernel},
    )
    return ctx


# ── feasibility (dynamic) ────────────────────────────────────────────

@default_registry.register(
    name="check_feasibility_dynamic",
    description=(
        "Run the reproducer on the target VM with GDB tracing and "
        "analyse GDB logs + dmesg for evidence that the vulnerable "
        "code path was exercised.  Does NOT require KASAN — looks for "
        "GDB breakpoint hits on crash-stack functions, allocation/free "
        "patterns, and subsystem activity in dmesg.  Populates "
        "feasibility with live_test, gdb_path_check, dynamic_log_analysis.  "
        "Should be called AFTER check_feasibility_static."
    ),
)
def tool_feasibility_dynamic(ctx: TaskContext, cfg: Config, **kwargs: Any) -> TaskContext:
    from ..analysis.feasibility import assess_feasibility_dynamic

    if not ctx.has_vuln_info():
        ctx.errors.append(
            "check_feasibility_dynamic: no vulnerability info available — "
            "run 'analyze' first (crash log, CVE, or blog)"
        )
        return ctx

    # Use reproducer if available; fall back to exploit binary as trigger
    reproducer_path = None
    if ctx.has_reproducer():
        reproducer_path = ctx.reproducer.source_path  # type: ignore[union-attr]
        if not reproducer_path:
            reproducer_path = ctx.reproducer.binary_path  # type: ignore[union-attr]

    if not reproducer_path and ctx.has_exploit():
        # The exploit binary can serve as a trigger for dynamic feasibility
        reproducer_path = ctx.exploit_result.binary_path  # type: ignore[union-attr]
        if reproducer_path:
            console.print(
                "  [dim]No reproducer — using exploit binary as "
                "dynamic feasibility trigger[/]"
            )

    if not reproducer_path:
        ctx.errors.append(
            "check_feasibility_dynamic: no reproducer or exploit "
            "binary available yet"
        )
        return ctx

    ssh_host = ctx.ssh_host or kwargs.get("ssh_host", getattr(cfg, "ssh_host", ""))
    if not ssh_host:
        ctx.errors.append(
            "check_feasibility_dynamic: no SSH host configured — "
            "pass --ssh-host or set SYZPLOIT_SSH_HOST"
        )
        return ctx

    use_adb = ctx.target_platform.value == "android" and ctx.instance is not None

    report = assess_feasibility_dynamic(
        crash=ctx.crash_report,  # may be None for CVE/blog inputs
        root_cause=ctx.root_cause,
        target_kernel=ctx.target_kernel,
        reproducer_path=reproducer_path,
        ssh_host=ssh_host,
        ssh_port=ctx.ssh_port,
        ssh_user=kwargs.get("ssh_user", getattr(cfg, "ssh_user", "root")),
        ssh_key=kwargs.get("ssh_key", getattr(cfg, "ssh_key", None)),
        adb_port=kwargs.get("adb_port", 6520),
        use_adb=use_adb,
        instance=ctx.instance,
        start_cmd=ctx.start_cmd or kwargs.get("start_cmd", ""),
        stop_cmd=ctx.stop_cmd or kwargs.get("stop_cmd", ""),
        setup_tunnels=ctx.setup_tunnels,
        gdb_port=ctx.gdb_port,
        vmlinux_path=kwargs.get("vmlinux_path"),
        system_map_path=kwargs.get("system_map_path"),
        timeout=kwargs.get("timeout", 180),
        existing_report=ctx.feasibility,  # merge into static results
    )
    ctx.feasibility = report
    ctx.log("tool", "check_feasibility_dynamic", f"verdict={report.verdict}")

    save_report(
        "feasibility_dynamic", report, ctx.work_dir,
        metadata={"target_kernel": ctx.target_kernel},
    )
    # Also save the merged full report
    save_report(
        "feasibility", report, ctx.work_dir,
        metadata={"target_kernel": ctx.target_kernel},
    )
    return ctx


# ── feasibility (legacy — runs both static + dynamic) ────────────────

@default_registry.register(
    name="check_feasibility",
    description=(
        "Legacy: run ALL feasibility checks (static + dynamic) in one "
        "step.  Prefer using check_feasibility_static and "
        "check_feasibility_dynamic separately for better control.  "
        "Populates feasibility."
    ),
)
def tool_feasibility(ctx: TaskContext, cfg: Config, **kwargs: Any) -> TaskContext:
    from ..analysis.feasibility import assess_feasibility

    if not ctx.has_crash():
        ctx.errors.append(
            "feasibility (legacy): no crash report — "
            "use check_feasibility_static / check_feasibility_dynamic "
            "which also work with CVE/blog inputs"
        )
        return ctx

    report = assess_feasibility(
        crash=ctx.crash_report,  # type: ignore[arg-type]
        target_kernel=ctx.target_kernel,
        ssh_host=kwargs.get("ssh_host", getattr(cfg, "ssh_host", "")),
        ssh_port=kwargs.get("ssh_port", getattr(cfg, "ssh_port", 22)),
        vmlinux_path=kwargs.get("vmlinux_path"),
        system_map_path=kwargs.get("system_map_path"),
        kernel_tree_path=kwargs.get("kernel_tree_path") or kwargs.get("kernel_source"),
        original_tag=kwargs.get("original_tag"),
        target_tag=kwargs.get("target_tag"),
        fix_commits=kwargs.get("fix_commits"),
        reproducer_path=kwargs.get("reproducer_path"),
    )
    ctx.feasibility = report
    ctx.log("tool", "check_feasibility", f"verdict={report.verdict}")

    # ── Save feasibility report ───────────────────────────────────
    save_report(
        "feasibility", report, ctx.work_dir,
        metadata={"target_kernel": ctx.target_kernel},
    )
    return ctx


# ── reproduce ─────────────────────────────────────────────────────────

@default_registry.register(
    name="reproduce",
    description=(
        "Generate a C reproducer for the vulnerability targeting the "
        "specified kernel version, cross-compile it for the target "
        "architecture, and optionally verify it via SSH.  Populates "
        "reproducer."
    ),
)
def tool_reproduce(ctx: TaskContext, cfg: Config, **kwargs: Any) -> TaskContext:
    from ..reproducer.pipeline import generate_reproducer

    console.print("[dim]→ running reproducer pipeline…[/]")
    ctx = generate_reproducer(ctx, cfg)

    # ── Save reproducer report ────────────────────────────────────
    if ctx.reproducer:
        save_report(
            "reproducer", ctx.reproducer, ctx.work_dir,
            metadata={"target_kernel": ctx.target_kernel},
        )
    return ctx


# ── exploit ───────────────────────────────────────────────────────────

@default_registry.register(
    name="exploit",
    description=(
        "Plan an exploitation strategy for the vulnerability, generate "
        "exploit C code using the selected technique, stitch in "
        "reliable primitives, and compile.  Populates exploit_plan "
        "and exploit_result."
    ),
)
def tool_exploit(ctx: TaskContext, cfg: Config, **kwargs: Any) -> TaskContext:
    from ..exploit.pipeline import generate_exploit

    console.print("[dim]→ running exploit pipeline…[/]")
    ctx = generate_exploit(ctx, cfg)

    # ── Save exploit reports ──────────────────────────────────────
    if ctx.exploit_plan:
        save_report(
            "exploit_plan", ctx.exploit_plan, ctx.work_dir,
            metadata={"target_kernel": ctx.target_kernel},
        )
    if ctx.exploit_result:
        save_report(
            "exploit_result", ctx.exploit_result, ctx.work_dir,
            metadata={"target_kernel": ctx.target_kernel},
        )
    return ctx


# ── resolve_kernel_offsets ────────────────────────────────────────────

@default_registry.register(
    name="resolve_kernel_offsets",
    description=(
        "Resolve real kernel symbol addresses and struct field offsets "
        "from vmlinux, kallsyms, or System.map.  Generates a "
        "kernel_offsets.h header with #defines for INIT_TASK, "
        "VMEMMAP_START, struct offsets, etc.  Should be called AFTER "
        "collect_target_info (needs kallsyms) and BEFORE exploit "
        "(provides concrete offsets instead of LLM-guessed values).  "
        "Populates kernel_offsets_header and resolved_symbols on context."
    ),
)
def tool_resolve_kernel_offsets(ctx: TaskContext, cfg: Config, **kwargs: Any) -> TaskContext:
    from ..exploit.kernel_resolver import resolve_kernel_offsets

    vmlinux = kwargs.get("vmlinux_path") or getattr(cfg, "vmlinux_path", None)
    target_info = ctx.target_system_info

    if not vmlinux and not (target_info and target_info.kallsyms_path):
        ctx.errors.append(
            "resolve_kernel_offsets: no vmlinux or kallsyms available — "
            "run collect_target_info first or provide vmlinux_path"
        )
        return ctx

    console.print("[dim]→ resolving kernel symbols and struct offsets…[/]")

    work_dir = ctx.work_dir
    try:
        resolver, header_text = resolve_kernel_offsets(
            target_info=target_info,
            vmlinux_path=vmlinux,
            work_dir=work_dir,
        )
        ctx.kernel_offsets_header = header_text
        ctx.resolved_symbols = {
            name: addr for name, addr in resolver._symbol_cache.items()
            if addr != 0
        }

        if work_dir:
            from pathlib import Path
            header_path = Path(work_dir) / "kernel_offsets.h"
            header_path.write_text(header_text)
            console.print(f"  Written kernel_offsets.h to {header_path}")

        ctx.log("tool", "resolve_kernel_offsets",
                f"resolved {len(ctx.resolved_symbols)} symbols")
    except Exception as exc:
        ctx.errors.append(f"resolve_kernel_offsets: {exc}")
        console.print(f"  [red]Kernel offset resolution failed: {exc}[/]")

    return ctx


# ── get_spray_strategy ────────────────────────────────────────────────

@default_registry.register(
    name="get_spray_strategy",
    description=(
        "Query the slab oracle for heap spray recommendations and "
        "cross-cache strategy for a given slab cache.  Useful before "
        "exploit generation to know which spray objects and techniques "
        "to use.  Populates spray_strategy on context."
    ),
)
def tool_get_spray_strategy(ctx: TaskContext, cfg: Config, **kwargs: Any) -> TaskContext:
    from ..analysis.slab_oracle import SlabOracle

    target_cache = kwargs.get("target_cache", "")
    target_size = kwargs.get("target_size", 0)

    # Try to auto-detect target cache from root cause
    if not target_cache and ctx.root_cause and ctx.root_cause.slab_caches:
        target_cache = ctx.root_cause.slab_caches[0]

    if not target_cache:
        ctx.errors.append(
            "get_spray_strategy: no target cache specified — "
            "pass target_cache kwarg or ensure root_cause has slab_caches"
        )
        return ctx

    # Collect slabinfo if available
    slabinfo = ""
    if ctx.target_system_info and hasattr(ctx.target_system_info, "slabinfo"):
        slabinfo = getattr(ctx.target_system_info, "slabinfo", "")

    console.print(f"[dim]→ querying slab oracle for {target_cache}…[/]")
    oracle = SlabOracle(slabinfo=slabinfo)

    spray_objs = oracle.recommend_spray_objects(target_cache)
    cross_cache = oracle.recommend_cross_cache_strategy(
        target_cache, target_size=target_size
    )

    ctx.spray_strategy = {
        "target_cache": target_cache,
        "spray_objects": spray_objs,
        "cross_cache_strategy": cross_cache,
    }

    ctx.log("tool", "get_spray_strategy",
            f"cache={target_cache}, {len(spray_objs)} spray objects recommended")
    console.print(
        f"  Found {len(spray_objs)} spray objects for {target_cache}"
    )

    return ctx


# ── get_kernel_source ─────────────────────────────────────────────────

@default_registry.register(
    name="get_kernel_source",
    description=(
        "Extract source code of vulnerable functions and struct definitions "
        "from a local kernel git checkout.  Provides real kernel source "
        "context to the LLM so exploit code matches actual APIs.  "
        "Requires kernel_tree_path to be configured.  "
        "Populates kernel_source_context on context."
    ),
)
def tool_get_kernel_source(ctx: TaskContext, cfg: Config, **kwargs: Any) -> TaskContext:
    from ..analysis.kernel_source import KernelSourceContext

    kernel_tree = kwargs.get("kernel_tree_path") or getattr(cfg, "kernel_tree_path", None)
    if not kernel_tree:
        msg = (
            "get_kernel_source: no kernel_tree_path configured — "
            "set SYZPLOIT_KERNEL_TREE_PATH or pass kernel_tree_path kwarg. "
            "Skipping (not a fatal error)."
        )
        ctx.errors.append(msg)
        console.print(f"  [yellow]{msg}[/]")
        # Mark the tool as "done" so the agent doesn't retry it
        ctx.log("tool", "get_kernel_source", "skipped: no kernel tree")
        return ctx

    console.print("[dim]→ extracting kernel source context…[/]")
    try:
        ksc = KernelSourceContext(kernel_tree)

        # Gather function names from root cause analysis
        funcs = []
        structs = []
        if ctx.root_cause:
            if ctx.root_cause.vulnerable_function:
                funcs.append(ctx.root_cause.vulnerable_function)
            funcs.extend(ctx.root_cause.kernel_functions[:5])
            structs = list(ctx.root_cause.affected_structs)

        # Also check crash report stack frames
        if ctx.crash_report:
            for frame in ctx.crash_report.stack_frames[:3]:
                if frame.function and frame.function not in funcs:
                    funcs.append(frame.function)

        if not funcs:
            ctx.errors.append("get_kernel_source: no function names to look up")
            return ctx

        source_ctx = ksc.format_context_for_prompt(
            funcs, structs, max_total_lines=500
        )
        ctx.kernel_source_context = source_ctx

        ctx.log("tool", "get_kernel_source",
                f"extracted context for {len(funcs)} functions, "
                f"{len(structs)} structs ({len(source_ctx)} chars)")
        console.print(
            f"  Extracted source for {len(funcs)} functions, "
            f"{len(structs)} structs"
        )
    except Exception as exc:
        ctx.errors.append(f"get_kernel_source: {exc}")
        console.print(f"  [red]Kernel source extraction failed: {exc}[/]")

    return ctx


# ── query_bug_db ──────────────────────────────────────────────────────

@default_registry.register(
    name="query_bug_db",
    description=(
        "Search the local syzbot bug database for bugs matching a "
        "keyword.  Returns matching bug metadata.  Useful when the "
        "agent needs to find related syzbot entries."
    ),
)
def tool_query_db(ctx: TaskContext, cfg: Config, **kwargs: Any) -> TaskContext:
    from ..data.bug_db import BugDatabase

    keyword = kwargs.get("keyword", ctx.input_value)

    # Derive kernel_name: explicit kwarg > target_kernel > sensible default
    kernel_name = kwargs.get("kernel_name", "")
    if not kernel_name and ctx.target_kernel:
        # Map version like "5.10.107" to syzbot tree names
        ver = ctx.target_kernel
        if "android" in ctx.target_platform.value.lower():
            # e.g. "android-5.10" for android targets
            major_minor = ".".join(ver.split(".")[:2]) if "." in ver else ver
            kernel_name = f"android-{major_minor}"
        else:
            kernel_name = "upstream"
    if not kernel_name:
        kernel_name = "upstream"

    console.print(f"  [dim]query_bug_db: kernel={kernel_name}, keyword={keyword[:80]}[/]")
    with BugDatabase(kernel_name) as db:
        bugs = db.search(keyword)
    ctx.log("tool", "query_bug_db", f"found {len(bugs)} matching bugs (db={kernel_name})")

    # Store results in context for the agent to use
    if bugs:
        bug_summaries = []
        for b in bugs[:10]:  # Limit to 10 most relevant
            summary = {
                "id": b.id,
                "title": b.title,
                "status": b.status,
                "crash_type": b.crash_type,
                "subsystem": b.subsystem,
                "syzbot_url": b.syzbot_url,
                "reproducer_url": b.reproducer_c_url or b.reproducer_url,
            }
            bug_summaries.append(summary)
        ctx.metadata["syzbot_matches"] = bug_summaries
        console.print(f"  [green]Found {len(bugs)} syzbot bugs matching '{keyword[:40]}'[/]")
    else:
        console.print(f"  [dim]No syzbot bugs found for '{keyword[:40]}' in {kernel_name}[/]")

    return ctx


# ── pull_syzbot ───────────────────────────────────────────────────────

@default_registry.register(
    name="pull_syzbot",
    description=(
        "Pull latest bug listings from syzbot for a specific kernel "
        "tree and upsert them into the local database."
    ),
)
def tool_pull_syzbot(ctx: TaskContext, cfg: Config, **kwargs: Any) -> TaskContext:
    from ..data.bug_db import BugDatabase
    from ..data.scraper import pull_bugs

    kernel_name = kwargs.get("kernel_name", "")
    if not kernel_name and ctx.target_kernel:
        ver = ctx.target_kernel
        if "android" in ctx.target_platform.value.lower():
            major_minor = ".".join(ver.split(".")[:2]) if "." in ver else ver
            kernel_name = f"android-{major_minor}"
        else:
            kernel_name = "upstream"
    if not kernel_name:
        kernel_name = "upstream"

    with BugDatabase(kernel_name) as db:
        count = pull_bugs(db, kernel_name)
    ctx.log("tool", "pull_syzbot", f"pulled {count} bugs for {kernel_name}")
    return ctx


# ── verify_exploit ────────────────────────────────────────────────────

@default_registry.register(
    name="verify_exploit",
    description=(
        "Deploy the compiled exploit to the target device via SSH, "
        "execute it with UID-checking wrapper, capture dmesg, and "
        "determine whether privilege escalation succeeded. Returns "
        "detailed feedback if it fails so you can adjust the exploit. "
        "Populates verification_history and updates exploit_result."
    ),
)
def tool_verify_exploit(ctx: TaskContext, cfg: Config, **kwargs: Any) -> TaskContext:
    from ..core.models import VerificationAttempt
    from ..infra.verification import verify_exploit

    if not ctx.has_exploit():
        ctx.errors.append("verify_exploit: no compiled exploit available")
        return ctx

    binary_path = ctx.exploit_result.binary_path  # type: ignore[union-attr]
    if not binary_path:
        ctx.errors.append("verify_exploit: exploit compiled but no binary path")
        return ctx

    ssh_host = ctx.ssh_host or kwargs.get("ssh_host", getattr(cfg, "ssh_host", ""))
    if not ssh_host:
        ctx.errors.append(
            "verify_exploit: no SSH host configured — "
            "pass --ssh-host or set SYZPLOIT_SSH_HOST"
        )
        return ctx

    attempt_num = len(ctx.exploit_verification_attempts()) + 1

    if not ctx.can_retry_exploit_verification():
        ctx.errors.append(
            f"verify_exploit: max attempts ({ctx.max_verification_attempts}) reached"
        )
        return ctx

    console.print(
        f"  [dim]→ verification attempt {attempt_num}/{ctx.max_verification_attempts}…[/]"
    )

    # Determine ADB usage for Android targets
    use_adb = ctx.target_platform.value == "android" and ctx.instance is not None

    # Build GDB monitor function list: defaults + vulnerable functions
    monitor_funcs = kwargs.get("monitor_functions")
    if monitor_funcs is None:
        # Start with the standard exploit-relevant functions
        monitor_funcs = [
            "commit_creds", "prepare_kernel_cred", "override_creds",
            "revert_creds", "copy_creds", "sel_write_enforce",
            "selinux_state", "__sys_setresuid", "__sys_setresgid",
        ]
        # Add vulnerable function + related kernel functions from root cause
        if ctx.root_cause:
            if ctx.root_cause.vulnerable_function:
                monitor_funcs.append(ctx.root_cause.vulnerable_function)
            for fn in (ctx.root_cause.kernel_functions or [])[:5]:
                if fn not in monitor_funcs:
                    monitor_funcs.append(fn)
        # Add crash-stack functions if available
        if ctx.crash_report and hasattr(ctx.crash_report, "stack_trace"):
            for frame in (ctx.crash_report.stack_trace or [])[:5]:
                fn = frame.function if hasattr(frame, "function") else str(frame)
                fn = fn.split("+")[0].strip()  # strip offset
                if fn and fn not in monitor_funcs:
                    monitor_funcs.append(fn)

    result = verify_exploit(
        binary_path,
        ssh_host=ssh_host,
        ssh_port=ctx.ssh_port,
        ssh_user=kwargs.get("ssh_user", getattr(cfg, "ssh_user", "root")),
        ssh_key=kwargs.get("ssh_key", getattr(cfg, "ssh_key", None)),
        instance=ctx.instance,
        start_cmd=ctx.start_cmd or kwargs.get("start_cmd", ""),
        stop_cmd=ctx.stop_cmd or kwargs.get("stop_cmd", ""),
        exploit_start_cmd=ctx.exploit_start_cmd or kwargs.get("exploit_start_cmd", ""),
        gdb_port=ctx.gdb_port,
        setup_tunnels=ctx.setup_tunnels,
        persistent=ctx.persistent,
        timeout=kwargs.get("timeout", 120),
        use_adb=use_adb,
        adb_port=kwargs.get("adb_port", 6520),
        vmlinux_path=getattr(ctx, "vmlinux_path", None) or kwargs.get("vmlinux_path"),
        kallsyms_path=getattr(ctx, "kallsyms_path", None) or kwargs.get("kallsyms_path"),
        arch=ctx.target_arch.value if hasattr(ctx, "target_arch") and ctx.target_arch else "arm64",
        monitor_functions=monitor_funcs,
    )

    # Record the attempt
    attempt = VerificationAttempt(
        attempt_number=attempt_num,
        target="exploit",
        binary_path=binary_path,
        success=result["success"],
        uid_before=result.get("uid_before"),
        uid_after=result.get("uid_after"),
        privilege_escalated=result.get("privilege_escalated", False),
        crash_occurred=result.get("crash_occurred", False),
        crash_pattern=result.get("crash_pattern", ""),
        device_stable=result.get("device_stable", True),
        failure_reason=result.get("failure_reason", ""),
        feedback=result.get("feedback", ""),
        exploit_output=result.get("exploit_output", "")[:3000],
        dmesg_new=result.get("dmesg_new", "")[:3000],
        gdb_functions_hit=result.get("gdb_functions_hit", []),
        gdb_functions_missed=result.get("gdb_functions_missed", []),
        gdb_crash_info=result.get("gdb_crash_info"),
    )
    ctx.verification_history.append(attempt)

    # Accumulate GDB trace results for the exploit generator prompt
    if result.get("gdb_functions_hit") or result.get("gdb_functions_missed"):
        ctx.gdb_trace_results.append({
            "target": "exploit",
            "attempt": attempt_num,
            "functions_hit": result.get("gdb_functions_hit", []),
            "functions_missed": result.get("gdb_functions_missed", []),
            "crash_info": result.get("gdb_crash_info"),
        })

    # Update exploit_result if successful
    if result["success"]:
        ctx.exploit_result.privilege_escalation_confirmed = True  # type: ignore[union-attr]
        ctx.exploit_result.uid_before = result.get("uid_before")  # type: ignore[union-attr]
        ctx.exploit_result.uid_after = result.get("uid_after")  # type: ignore[union-attr]
        ctx.exploit_result.verification_log = result.get("exploit_output", "")  # type: ignore[union-attr]
        console.print("  [bold green]✓ Exploit verified — privilege escalation confirmed![/]")
    else:
        console.print(
            f"  [bold yellow]✗ Attempt {attempt_num} failed: "
            f"{result.get('failure_reason', 'unknown')}[/]"
        )

    ctx.log(
        "tool", "verify_exploit",
        f"attempt={attempt_num} success={result['success']} "
        f"reason={result.get('failure_reason', 'ok')}"
    )

    # ── Save verification report ──────────────────────────────────
    save_report(
        "verification_exploit", attempt, ctx.work_dir,
        filename=f"verification_exploit_attempt_{attempt_num}.json",
        metadata={"attempt": attempt_num, "success": result["success"]},
    )
    # Also update the exploit result report with latest state
    if ctx.exploit_result:
        save_report(
            "exploit_result", ctx.exploit_result, ctx.work_dir,
            metadata={"target_kernel": ctx.target_kernel},
        )
    return ctx


# ── complete_exploit ──────────────────────────────────────────────────

@default_registry.register(
    name="complete_exploit",
    description=(
        "Analyse the current exploit source for incompleteness (stubs, "
        "placeholder offsets, empty functions, missing steps) and use "
        "the LLM to fill in the gaps.  Call this AFTER 'exploit' when "
        "the generated exploit has TODO markers, placeholder values, "
        "or missing exploitation steps.  Re-compiles the result (with "
        "up to 3 auto-fix attempts) and automatically verifies on the "
        "target device if SSH is configured.  Updates exploit_result "
        "with the completed source, binary, and verification outcome."
    ),
)
def tool_complete_exploit(ctx: TaskContext, cfg: Config, **kwargs: Any) -> TaskContext:
    from ..exploit.completer import complete_exploit

    console.print("[dim]→ running exploit completer…[/]")
    ctx = complete_exploit(ctx, cfg)

    # ── Save updated exploit reports ──────────────────────────────
    if ctx.exploit_plan:
        save_report(
            "exploit_plan", ctx.exploit_plan, ctx.work_dir,
            metadata={"target_kernel": ctx.target_kernel},
        )
    if ctx.exploit_result:
        save_report(
            "exploit_result", ctx.exploit_result, ctx.work_dir,
            metadata={
                "target_kernel": ctx.target_kernel,
                "completed": True,
            },
        )
    return ctx


# ── verify_reproducer ─────────────────────────────────────────────────

@default_registry.register(
    name="verify_reproducer",
    description=(
        "Deploy the compiled reproducer to the target device, run it, "
        "capture dmesg before and after, and check if the expected "
        "crash was triggered. Returns feedback on failure for the "
        "agent to iterate. Populates verification_history and updates "
        "reproducer."
    ),
)
def tool_verify_reproducer(ctx: TaskContext, cfg: Config, **kwargs: Any) -> TaskContext:
    from ..core.models import VerificationAttempt
    from ..infra.verification import verify_reproducer

    if not ctx.has_reproducer():
        ctx.errors.append("verify_reproducer: no compiled reproducer available")
        return ctx

    binary_path = ctx.reproducer.binary_path  # type: ignore[union-attr]
    if not binary_path:
        ctx.errors.append("verify_reproducer: reproducer compiled but no binary path")
        return ctx

    ssh_host = ctx.ssh_host or kwargs.get("ssh_host", getattr(cfg, "ssh_host", ""))
    if not ssh_host:
        ctx.errors.append(
            "verify_reproducer: no SSH host configured — "
            "pass --ssh-host or set SYZPLOIT_SSH_HOST"
        )
        return ctx

    attempt_num = len(ctx.reproducer_verification_attempts()) + 1

    if not ctx.can_retry_reproducer_verification():
        ctx.errors.append(
            f"verify_reproducer: max attempts ({ctx.max_verification_attempts}) reached"
        )
        return ctx

    console.print(
        f"  [dim]→ reproducer verification attempt "
        f"{attempt_num}/{ctx.max_verification_attempts}…[/]"
    )

    # Gather expected crash info for matching
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
    vmlinux = kwargs.get("vmlinux_path") or getattr(cfg, "vmlinux_path", None)
    kallsyms = None
    if ctx.target_system_info and ctx.target_system_info.kallsyms_path:
        kallsyms = ctx.target_system_info.kallsyms_path

    result = verify_reproducer(
        binary_path,
        ssh_host=ssh_host,
        ssh_port=ctx.ssh_port,
        ssh_user=kwargs.get("ssh_user", getattr(cfg, "ssh_user", "root")),
        ssh_key=kwargs.get("ssh_key", getattr(cfg, "ssh_key", None)),
        instance=ctx.instance,
        expected_crash_type=expected_crash_type,
        expected_functions=expected_functions or None,
        start_cmd=ctx.start_cmd or kwargs.get("start_cmd", ""),
        stop_cmd=ctx.stop_cmd or kwargs.get("stop_cmd", ""),
        gdb_port=ctx.gdb_port,
        setup_tunnels=ctx.setup_tunnels,
        persistent=ctx.persistent,
        timeout=kwargs.get("timeout", 60),
        use_adb=use_adb,
        adb_port=kwargs.get("adb_port", 6520),
        vmlinux_path=vmlinux,
        kallsyms_path=kallsyms,
        arch=ctx.target_arch.value if hasattr(ctx, "target_arch") and ctx.target_arch else "arm64",
    )

    # Consider path_reached as a partial success
    path_reached = result.get("path_reached", False)
    crash_triggered = result.get("crash_triggered", False)
    verification_success = crash_triggered or path_reached

    attempt = VerificationAttempt(
        attempt_number=attempt_num,
        target="reproducer",
        binary_path=binary_path,
        success=verification_success,
        crash_occurred=crash_triggered,
        crash_pattern=result.get("crash_log_excerpt", "")[:500],
        crash_log_excerpt=result.get("crash_log_excerpt", "")[:2000],
        device_stable=result.get("device_stable", True),
        failure_reason=result.get("failure_reason", ""),
        feedback=result.get("feedback", ""),
        gdb_functions_hit=result.get("gdb_functions_hit", []),
        gdb_functions_missed=result.get("gdb_functions_missed", []),
        gdb_crash_info=result.get("gdb_crash_info"),
    )
    ctx.verification_history.append(attempt)

    # Accumulate GDB trace results
    if result.get("gdb_functions_hit") or result.get("gdb_functions_missed"):
        ctx.gdb_trace_results.append({
            "target": "reproducer",
            "attempt": attempt_num,
            "functions_hit": result.get("gdb_functions_hit", []),
            "functions_missed": result.get("gdb_functions_missed", []),
            "crash_info": result.get("gdb_crash_info"),
        })

    # Update reproducer result
    if crash_triggered:
        ctx.reproducer.crash_confirmed = True  # type: ignore[union-attr]
        ctx.reproducer.crash_log = result.get("crash_log_excerpt", "")  # type: ignore[union-attr]
        console.print("  [bold green]✓ Reproducer verified — crash triggered![/]")
    elif path_reached:
        ctx.reproducer.notes.append(  # type: ignore[union-attr]
            f"Vulnerable path reached via GDB (functions hit: "
            f"{result.get('gdb_functions_hit', [])}), but no crash on "
            f"non-instrumented kernel."
        )
        console.print(
            f"  [bold cyan]✓ Reproducer reached vulnerable code path! "
            f"(no crash expected on non-instrumented kernel)[/]"
        )
    else:
        console.print(
            f"  [bold yellow]✗ Attempt {attempt_num} failed: "
            f"{result.get('failure_reason', 'no crash')}[/]"
        )

    ctx.log(
        "tool", "verify_reproducer",
        f"attempt={attempt_num} crash={result.get('crash_triggered', False)} "
        f"reason={result.get('failure_reason', 'ok')}"
    )

    # ── Save verification report ──────────────────────────────────
    save_report(
        "verification_reproducer", attempt, ctx.work_dir,
        filename=f"verification_reproducer_attempt_{attempt_num}.json",
        metadata={"attempt": attempt_num, "success": attempt.success},
    )
    # Also update the reproducer report with latest state
    if ctx.reproducer:
        save_report(
            "reproducer", ctx.reproducer, ctx.work_dir,
            metadata={"target_kernel": ctx.target_kernel},
        )
    return ctx


# =====================================================================
# kexploit integration tools
# =====================================================================

# ── query_struct_offsets ──────────────────────────────────────────────

@default_registry.register(
    name="query_struct_offsets",
    description=(
        "Query kernel struct field offsets from BTF data using the "
        "kexploit module.  Returns accurate byte offsets for every "
        "field in the struct, which is critical for exploit code that "
        "accesses struct fields at precise memory offsets.  Requires "
        "either a kexploit kernel name or a path to a btf_types.json "
        "file.  Can query multiple structs at once.  Also generates "
        "a C header with #define macros for the offsets."
    ),
)
def tool_query_struct_offsets(ctx: TaskContext, cfg: Config, **kwargs: Any) -> TaskContext:
    from ..analysis.kexploit_bridge import (
        is_available,
        import_error,
        query_struct_layout,
        query_multiple_structs,
        generate_offsets_header_from_btf,
    )

    if not is_available():
        ctx.errors.append(
            f"query_struct_offsets: kexploit not available — {import_error()}"
        )
        return ctx

    struct_names = kwargs.get("struct_names", [])
    kernel_name = kwargs.get("kernel_name")
    btf_json_path = kwargs.get("btf_json_path")

    # Auto-extract struct names from root cause if not specified
    if not struct_names and ctx.root_cause:
        struct_names = list(ctx.root_cause.affected_structs)
    if not struct_names:
        ctx.errors.append(
            "query_struct_offsets: no struct_names specified and none "
            "found in root_cause.affected_structs"
        )
        return ctx

    console.print(
        f"[dim]→ querying BTF struct offsets for {len(struct_names)} "
        f"structs…[/]"
    )

    results = query_multiple_structs(
        struct_names,
        kernel_name=kernel_name,
        btf_json_path=btf_json_path,
    )

    # Count successes
    ok = sum(1 for v in results.values() if "error" not in v)
    total = len(struct_names)

    # Generate offset header
    header = generate_offsets_header_from_btf(
        struct_names,
        kernel_name=kernel_name,
        btf_json_path=btf_json_path,
    )

    # Merge into existing kernel offsets header
    if header and ctx.kernel_offsets_header:
        ctx.kernel_offsets_header += "\n\n" + header
    elif header:
        ctx.kernel_offsets_header = header

    # Save header if work_dir exists
    if header and ctx.work_dir:
        from pathlib import Path
        btf_header_path = Path(ctx.work_dir) / "btf_offsets.h"
        btf_header_path.write_text(header)
        console.print(f"  Written BTF offsets to {btf_header_path}")

    # Store results for reference
    if not hasattr(ctx, "analysis_data") or ctx.analysis_data is None:
        ctx.analysis_data = {}
    ctx.analysis_data["btf_struct_layouts"] = results

    ctx.log(
        "tool", "query_struct_offsets",
        f"queried {total} structs, {ok} found"
    )
    console.print(f"  BTF struct offsets: {ok}/{total} structs resolved")

    return ctx


# ── query_codeql_allocations ─────────────────────────────────────────

@default_registry.register(
    name="query_codeql_allocations",
    description=(
        "Query a CodeQL database of the kernel source for kmalloc "
        "allocation sites.  Returns which structs are allocated from "
        "which slab caches, their sizes, flags, and whether they use "
        "flexible arrays.  This is critical for planning heap spray "
        "strategies when the slab oracle's static knowledge base is "
        "insufficient.  Requires a CodeQL database path."
    ),
)
def tool_query_codeql_allocations(ctx: TaskContext, cfg: Config, **kwargs: Any) -> TaskContext:
    from ..analysis.kexploit_bridge import (
        is_available,
        import_error,
        query_codeql_allocations,
        query_codeql_structs,
    )

    if not is_available():
        ctx.errors.append(
            f"query_codeql_allocations: kexploit not available — {import_error()}"
        )
        return ctx

    codeql_db = kwargs.get("codeql_db_path", "")
    struct_filter = kwargs.get("struct_filter", "")

    if not codeql_db:
        codeql_db = getattr(cfg, "codeql_db_path", "")
    if not codeql_db:
        ctx.errors.append(
            "query_codeql_allocations: no codeql_db_path provided — "
            "set it via --codeql-db or SYZPLOIT_CODEQL_DB_PATH"
        )
        return ctx

    console.print(
        f"[dim]→ querying CodeQL database for allocations"
        f"{f' (filter: {struct_filter})' if struct_filter else ''}…[/]"
    )

    alloc_results = query_codeql_allocations(
        codeql_db, struct_filter=struct_filter or None,
    )
    struct_results = query_codeql_structs(codeql_db)

    if "error" in alloc_results:
        ctx.errors.append(
            f"query_codeql_allocations: {alloc_results['error']}"
        )
        return ctx

    # Enrich spray strategy with CodeQL data
    if ctx.spray_strategy and alloc_results.get("allocations"):
        ctx.spray_strategy["codeql_allocations"] = alloc_results["allocations"]

    # Store in analysis_data
    if not hasattr(ctx, "analysis_data") or ctx.analysis_data is None:
        ctx.analysis_data = {}
    ctx.analysis_data["codeql_allocations"] = alloc_results
    if "error" not in struct_results:
        ctx.analysis_data["codeql_structs"] = struct_results

    total = alloc_results.get("total_calls", 0)
    ctx.log("tool", "query_codeql_allocations", f"found {total} allocation sites")
    console.print(f"  CodeQL: found {total} kmalloc allocation sites")

    return ctx


# ── adapt_exploit_offsets ─────────────────────────────────────────────

@default_registry.register(
    name="adapt_exploit_offsets",
    description=(
        "Translate kernel addresses, symbol offsets, and ROP gadgets "
        "from one kernel version to another using kexploit's binary "
        "analysis.  Uses ELF symbol matching and instruction pattern "
        "search to map exploit-specific constants between kernel "
        "builds.  Requires kexploit kernel ELFs for both source and "
        "target kernels.  Call AFTER resolve_kernel_offsets if you "
        "need to adapt an existing exploit from a reference kernel "
        "to the target.  Updates resolved_symbols and "
        "kernel_offsets_header on context."
    ),
)
def tool_adapt_exploit_offsets(ctx: TaskContext, cfg: Config, **kwargs: Any) -> TaskContext:
    from ..analysis.kexploit_bridge import (
        is_available,
        import_error,
        adapt_exploit_offsets,
    )

    if not is_available():
        ctx.errors.append(
            f"adapt_exploit_offsets: kexploit not available — {import_error()}"
        )
        return ctx

    source_kernel = kwargs.get("source_kernel", "")
    target_kernel = kwargs.get("target_kernel", "")
    addresses = kwargs.get("addresses")  # Dict[str, int]
    rop_gadgets = kwargs.get("rop_gadgets")  # Dict[str, {gadget, is_relative}]

    if not source_kernel or not target_kernel:
        ctx.errors.append(
            "adapt_exploit_offsets: must provide both source_kernel "
            "and target_kernel names"
        )
        return ctx

    if not addresses and not rop_gadgets:
        ctx.errors.append(
            "adapt_exploit_offsets: at least one of addresses or "
            "rop_gadgets must be provided"
        )
        return ctx

    console.print(
        f"[dim]→ adapting exploit offsets: {source_kernel} → "
        f"{target_kernel}…[/]"
    )

    result = adapt_exploit_offsets(
        source_kernel=source_kernel,
        target_kernel=target_kernel,
        addresses=addresses,
        rop_gadgets=rop_gadgets,
    )

    if "error" in result:
        ctx.errors.append(f"adapt_exploit_offsets: {result['error']}")
        return ctx

    # Update resolved symbols with translated addresses
    translations = result.get("translations", {})
    for label, info in translations.items():
        if "error" not in info and "translated" in info:
            try:
                addr = int(info["translated"], 16)
                ctx.resolved_symbols[label] = addr
            except ValueError:
                pass

    # Generate additional header defines for translated values
    header_lines = [
        f"\n/* Adapted offsets: {source_kernel} → {target_kernel} */",
    ]
    for label, info in translations.items():
        if "error" not in info and "translated" in info:
            header_lines.append(
                f"#define {label.upper()} {info['translated']}"
            )
    if len(header_lines) > 1:
        adapted_header = "\n".join(header_lines)
        if ctx.kernel_offsets_header:
            ctx.kernel_offsets_header += "\n" + adapted_header
        else:
            ctx.kernel_offsets_header = adapted_header

    err_count = len(result.get("errors", []))
    ok_count = len(translations) - err_count
    ctx.log(
        "tool", "adapt_exploit_offsets",
        f"translated {ok_count} values, {err_count} errors"
    )
    console.print(
        f"  Adapted {ok_count} offsets "
        f"({err_count} errors)"
    )

    # Store full results
    if not hasattr(ctx, "analysis_data") or ctx.analysis_data is None:
        ctx.analysis_data = {}
    ctx.analysis_data["offset_adaptation"] = result

    return ctx


# ══════════════════════════════════════════════════════════════════════
# New module tools (session 26)
# ══════════════════════════════════════════════════════════════════════


# ── get_rw_primitive ──────────────────────────────────────────────────

@default_registry.register(
    name="get_rw_primitive",
    description=(
        "Get C code templates for arbitrary read/write kernel primitives. "
        "Available primitives: pipe_buffer_rw (most common), dirty_pipe_rw, "
        "msg_msg_rw, kaslr_pipe_leak, task_walk_rw.  Can auto-recommend "
        "based on vuln_type (uaf/oob/overflow) and slab_cache."
    ),
)
def tool_get_rw_primitive(ctx: TaskContext, cfg: Config, **kwargs: Any) -> TaskContext:
    from ..exploit.rw_primitives import RWPrimitiveLibrary

    lib = RWPrimitiveLibrary()
    name = kwargs.get("name", "")
    vuln_type = kwargs.get("vuln_type", "")
    slab_cache = kwargs.get("slab_cache", "")

    if name:
        code = lib.get_code(name)
        if code:
            ctx.log("tool", "get_rw_primitive", f"retrieved '{name}' template")
            if not hasattr(ctx, "analysis_data") or ctx.analysis_data is None:
                ctx.analysis_data = {}
            ctx.analysis_data["rw_primitive"] = {"name": name, "code": code}
        else:
            avail = ", ".join(lib.list_all())
            ctx.errors.append(
                f"get_rw_primitive: unknown '{name}'. Available: {avail}"
            )
    elif vuln_type:
        recs = lib.recommend_for_vuln(vuln_type=vuln_type, slab_cache=slab_cache)
        prompt_text = lib.format_for_prompt(recs)
        if not hasattr(ctx, "analysis_data") or ctx.analysis_data is None:
            ctx.analysis_data = {}
        ctx.analysis_data["rw_primitive_recommendations"] = {
            "recommended": recs,
            "prompt_text": prompt_text,
        }
        ctx.log("tool", "get_rw_primitive", f"recommended {len(recs)} primitives for {vuln_type}")
    else:
        ctx.errors.append(
            "get_rw_primitive: provide 'name' for a specific template "
            "or 'vuln_type' for recommendations"
        )

    return ctx


# ── scaffold_exploit ──────────────────────────────────────────────────

@default_registry.register(
    name="scaffold_exploit",
    description=(
        "Generate a multi-file exploit project scaffold with Makefile, "
        "header, and modular C source files (main, trigger, spray, "
        "rw_primitive, post_exploit, util, kernel_offsets).  "
        "The scaffold uses a shared exploit_ctx_t struct for passing "
        "state between modules.  Set write_to_disk=true to write files."
    ),
)
def tool_scaffold_exploit(ctx: TaskContext, cfg: Config, **kwargs: Any) -> TaskContext:
    from ..exploit.scaffold import ExploitScaffold
    import os

    # Determine output directory
    scaffold_dir = ""
    write_to_disk = kwargs.get("write_to_disk", False)
    if write_to_disk and ctx.work_dir:
        scaffold_dir = os.path.join(str(ctx.work_dir), "exploit_scaffold")
    else:
        scaffold_dir = str(ctx.work_dir or ".")

    # Derive CVE ID from context
    cve_id = ctx.input_value or kwargs.get("cve_id", "CVE-XXXX-XXXXX")
    arch = kwargs.get("target_arch", "arm64")
    if hasattr(ctx, "target_arch") and ctx.target_arch:
        arch = ctx.target_arch.value
    platform = ctx.target_platform.value if hasattr(ctx, "target_platform") and ctx.target_platform else "android"

    scaffold = ExploitScaffold(
        output_dir=scaffold_dir,
        cve_id=cve_id,
        arch=arch,
        platform=platform,
    )

    if write_to_disk and ctx.work_dir:
        created = scaffold.write()
        ctx.log("tool", "scaffold_exploit", f"wrote {len(created)} files to {scaffold_dir}")
        console.print(f"  Scaffold: {len(created)} files → {scaffold_dir}")
    else:
        files = scaffold.generate()
        if not hasattr(ctx, "analysis_data") or ctx.analysis_data is None:
            ctx.analysis_data = {}
        ctx.analysis_data["exploit_scaffold"] = files
        ctx.log("tool", "scaffold_exploit", f"generated {len(files)} scaffold files")

    return ctx


# ── plan_kaslr_bypass ─────────────────────────────────────────────────

@default_registry.register(
    name="plan_kaslr_bypass",
    description=(
        "Recommend KASLR bypass techniques based on vulnerability type "
        "and slab cache.  Available techniques: pipe_buf_ops_leak "
        "(highest reliability), file_fop_leak, shm_file_leak, "
        "dmesg_leak, prefetch_side_channel.  Returns ranked list with "
        "C code snippets."
    ),
)
def tool_plan_kaslr_bypass(ctx: TaskContext, cfg: Config, **kwargs: Any) -> TaskContext:
    from ..analysis.kaslr_oracle import KASLROracle

    oracle = KASLROracle()
    vuln_type = kwargs.get("vuln_type", "uaf")
    slab_cache = kwargs.get("slab_cache", "")

    recs = oracle.recommend(vuln_type=vuln_type, slab_cache=slab_cache)
    prompt_text = oracle.format_for_prompt(
        [r["name"] for r in recs[:3]]  # top 3
    )

    if not hasattr(ctx, "analysis_data") or ctx.analysis_data is None:
        ctx.analysis_data = {}
    ctx.analysis_data["kaslr_bypass"] = {
        "recommendations": recs,
        "prompt_text": prompt_text,
    }

    top_names = [r["name"] for r in recs[:3]]
    ctx.log("tool", "plan_kaslr_bypass", f"top recommendations: {top_names}")
    console.print(f"  KASLR bypass: {', '.join(top_names)}")

    return ctx


# ── get_race_template ─────────────────────────────────────────────────

@default_registry.register(
    name="get_race_template",
    description=(
        "Get C code templates for race condition exploitation. "
        "Available: cpu_pinning, thread_barrier, timer_race, "
        "retry_loop, thread_exit_race, fd_table_shaping.  "
        "Can auto-recommend based on race_type (toctou/uaf_race/double_free)."
    ),
)
def tool_get_race_template(ctx: TaskContext, cfg: Config, **kwargs: Any) -> TaskContext:
    from ..exploit.race_primitives import RacePrimitiveLibrary

    lib = RacePrimitiveLibrary()
    name = kwargs.get("name", "")
    race_type = kwargs.get("race_type", "")

    if name:
        code = lib.get_code(name)
        if code:
            if not hasattr(ctx, "analysis_data") or ctx.analysis_data is None:
                ctx.analysis_data = {}
            ctx.analysis_data["race_template"] = {"name": name, "code": code}
            ctx.log("tool", "get_race_template", f"retrieved '{name}'")
        else:
            avail = ", ".join(lib.list_all())
            ctx.errors.append(
                f"get_race_template: unknown '{name}'. Available: {avail}"
            )
    elif race_type:
        recs = lib.recommend_for_race_type(race_type)
        prompt_text = lib.format_for_prompt(recs)
        if not hasattr(ctx, "analysis_data") or ctx.analysis_data is None:
            ctx.analysis_data = {}
        ctx.analysis_data["race_recommendations"] = {
            "recommended": recs,
            "prompt_text": prompt_text,
        }
        ctx.log("tool", "get_race_template", f"recommended {len(recs)} for {race_type}")
    else:
        ctx.errors.append(
            "get_race_template: provide 'name' or 'race_type'"
        )

    return ctx


# ── generate_device_config ────────────────────────────────────────────

@default_registry.register(
    name="generate_device_config",
    description=(
        "Generate a C header (device_config.h) with kernel offsets, "
        "symbol addresses, and memory layout constants for a target "
        "device.  Built-in profiles: cuttlefish_5.10, pixel6_5.10, "
        "pixel7_5.10.  Optionally populate from kallsyms dump or "
        "BTF data.  Set write_to_disk=true to write to work_dir."
    ),
)
def tool_generate_device_config(ctx: TaskContext, cfg: Config, **kwargs: Any) -> TaskContext:
    from ..infra.device_profile import DeviceProfileRegistry
    import os

    registry = DeviceProfileRegistry()
    profile_name = kwargs.get("profile", "cuttlefish_5.10")
    kallsyms_path = kwargs.get("kallsyms_path", "")
    btf_data = kwargs.get("btf_data")

    # Also try loading from work_dir/profiles/
    if ctx.work_dir:
        profiles_dir = os.path.join(ctx.work_dir, "profiles")
        registry.load_from_dir(profiles_dir)

    header = registry.generate_device_config(
        profile_name,
        kallsyms_path=kallsyms_path or None,
        btf_data=btf_data,
    )

    if header is None:
        avail = ", ".join(registry.list_profiles())
        ctx.errors.append(
            f"generate_device_config: unknown profile '{profile_name}'. "
            f"Available: {avail}"
        )
        return ctx

    write_to_disk = kwargs.get("write_to_disk", False)
    if write_to_disk and ctx.work_dir:
        out_path = os.path.join(ctx.work_dir, "device_config.h")
        with open(out_path, "w") as f:
            f.write(header)
        ctx.log("tool", "generate_device_config", f"wrote {out_path}")
        console.print(f"  Device config → {out_path}")
    else:
        ctx.kernel_offsets_header = header
        ctx.log("tool", "generate_device_config", f"generated header for {profile_name}")

    return ctx


# ── get_multiprocess_scaffold ─────────────────────────────────────────

@default_registry.register(
    name="get_multiprocess_scaffold",
    description=(
        "Get multi-process exploit coordination templates. "
        "Available: fork_parent_target (badnode pattern), "
        "fork_shared_memory (badspin pattern), pipeline_processes, "
        "watchdog_pattern (retry + crash recovery).  "
        "Can auto-recommend based on exploit characteristics."
    ),
)
def tool_get_multiprocess_scaffold(ctx: TaskContext, cfg: Config, **kwargs: Any) -> TaskContext:
    from ..exploit.multi_process import MultiProcessLibrary

    lib = MultiProcessLibrary()
    name = kwargs.get("name", "")

    if name:
        code = lib.get_code(name)
        if code:
            if not hasattr(ctx, "analysis_data") or ctx.analysis_data is None:
                ctx.analysis_data = {}
            ctx.analysis_data["multiprocess_template"] = {"name": name, "code": code}
            ctx.log("tool", "get_multiprocess_scaffold", f"retrieved '{name}'")
        else:
            avail = ", ".join(lib.list_all())
            ctx.errors.append(
                f"get_multiprocess_scaffold: unknown '{name}'. Available: {avail}"
            )
    else:
        # Auto-recommend
        overwrites_parent = kwargs.get("overwrites_parent", False)
        needs_retry = kwargs.get("needs_retry", False)
        num_phases = kwargs.get("num_phases", 2)
        recs = lib.recommend_for_exploit(
            overwrites_parent=overwrites_parent,
            needs_retry=needs_retry,
            num_phases=num_phases,
        )
        prompt_text = lib.format_for_prompt(recs)
        if not hasattr(ctx, "analysis_data") or ctx.analysis_data is None:
            ctx.analysis_data = {}
        ctx.analysis_data["multiprocess_recommendations"] = {
            "recommended": recs,
            "prompt_text": prompt_text,
        }
        ctx.log("tool", "get_multiprocess_scaffold", f"recommended: {recs}")

    return ctx


# ── map_attack_surface ────────────────────────────────────────────────

@default_registry.register(
    name="map_attack_surface",
    description=(
        "Map the Android kernel attack surface reachable from a given "
        "SELinux context (default: untrusted_app).  Shows accessible "
        "device nodes, allowed syscalls, binder services, and known "
        "CVEs per surface.  Can check exploit feasibility against "
        "a required set of syscalls and surfaces."
    ),
)
def tool_map_attack_surface(ctx: TaskContext, cfg: Config, **kwargs: Any) -> TaskContext:
    from ..android.surface_analyzer import AttackSurfaceAnalyzer

    analyzer = AttackSurfaceAnalyzer()
    selinux_context = kwargs.get("selinux_context", "untrusted_app")

    # Check feasibility if requirements provided
    required_syscalls = kwargs.get("required_syscalls", [])
    required_surfaces = kwargs.get("required_surfaces", [])

    if required_syscalls or required_surfaces:
        result = analyzer.check_exploit_feasibility(
            required_syscalls=required_syscalls,
            required_surfaces=required_surfaces,
            selinux_context=selinux_context,
        )
        if not hasattr(ctx, "analysis_data") or ctx.analysis_data is None:
            ctx.analysis_data = {}
        ctx.analysis_data["attack_surface_feasibility"] = result
        feasible = "feasible" if result["feasible"] else "NOT feasible"
        ctx.log("tool", "map_attack_surface", f"{feasible} from {selinux_context}")
        console.print(f"  Attack surface: {feasible}")
    else:
        # General enumeration
        surfaces = analyzer.get_reachable_surfaces(selinux_context)
        prompt_text = analyzer.format_for_prompt(selinux_context)
        if not hasattr(ctx, "analysis_data") or ctx.analysis_data is None:
            ctx.analysis_data = {}
        ctx.analysis_data["attack_surface"] = {
            "context": selinux_context,
            "reachable_count": len(surfaces),
            "surfaces": [s["name"] for s in surfaces],
            "prompt_text": prompt_text,
        }
        ctx.log("tool", "map_attack_surface",
                f"{len(surfaces)} surfaces from {selinux_context}")
        console.print(f"  {len(surfaces)} reachable surfaces from {selinux_context}")

    return ctx


# ── generate_binder_trigger ───────────────────────────────────────────

@default_registry.register(
    name="generate_binder_trigger",
    description=(
        "Generate C code for binder transactions to trigger kernel "
        "vulnerabilities via /dev/binder.  Templates: basic_transaction, "
        "flat_binder_object (refcount bugs), scatter_gather_uaf "
        "(CVE-2023-20938 pattern), service_manager_lookup.  "
        "Can auto-recommend based on CVE ID."
    ),
)
def tool_generate_binder_trigger(ctx: TaskContext, cfg: Config, **kwargs: Any) -> TaskContext:
    from ..android.binder_fuzzer import BinderFuzzer

    fuzzer = BinderFuzzer()
    name = kwargs.get("name", "")
    cve_id = kwargs.get("cve_id", "")

    if name:
        code = fuzzer.get_code(name)
        if code:
            if not hasattr(ctx, "analysis_data") or ctx.analysis_data is None:
                ctx.analysis_data = {}
            ctx.analysis_data["binder_trigger"] = {"name": name, "code": code}
            ctx.log("tool", "generate_binder_trigger", f"retrieved '{name}'")
        else:
            avail = ", ".join(fuzzer.list_all())
            ctx.errors.append(
                f"generate_binder_trigger: unknown '{name}'. Available: {avail}"
            )
    elif cve_id:
        recs = fuzzer.recommend_for_cve(cve_id)
        prompt_text = fuzzer.format_for_prompt(recs)
        if not hasattr(ctx, "analysis_data") or ctx.analysis_data is None:
            ctx.analysis_data = {}
        ctx.analysis_data["binder_recommendations"] = {
            "cve": cve_id,
            "recommended": recs,
            "prompt_text": prompt_text,
        }
        ctx.log("tool", "generate_binder_trigger", f"recommended {recs} for {cve_id}")
    else:
        ctx.errors.append(
            "generate_binder_trigger: provide 'name' or 'cve_id'"
        )

    return ctx


# ── resolve_symbol_address ────────────────────────────────────────────

@default_registry.register(
    name="resolve_symbol_address",
    description=(
        "Look up a kernel symbol's address and offset from kernel base "
        "using kexploit's ELF parser.  Requires a kexploit kernel_name "
        "(e.g. '5.15.123-android14-11-g…') and a symbol_name (e.g. "
        "'commit_creds', 'init_cred', 'selinux_state').  Returns "
        "absolute address, offset from kernel base, and the kernel "
        "base address.  Useful for patching hardcoded addresses in "
        "exploits when adapting between kernel versions."
    ),
)
def tool_resolve_symbol_address(ctx: TaskContext, cfg: Config, **kwargs: Any) -> TaskContext:
    from ..analysis.kexploit_bridge import get_symbol_address

    kernel_name = kwargs.get("kernel_name", "")
    symbol_name = kwargs.get("symbol_name", "")

    if not kernel_name:
        # Try to infer from context
        kernel_name = getattr(ctx, "target_kernel", "") or ""
    if not kernel_name:
        ctx.errors.append(
            "resolve_symbol_address: provide 'kernel_name' "
            "(e.g. '5.15.123-android14-11-gabcdef')"
        )
        return ctx

    if not symbol_name:
        ctx.errors.append("resolve_symbol_address: provide 'symbol_name'")
        return ctx

    result = get_symbol_address(kernel_name, symbol_name)

    if result.get("error"):
        ctx.errors.append(f"resolve_symbol_address: {result['error']}")
        return ctx

    # Store in analysis_data for downstream use
    if not hasattr(ctx, "analysis_data") or ctx.analysis_data is None:
        ctx.analysis_data = {}
    resolved = ctx.analysis_data.setdefault("resolved_symbols", {})
    resolved[symbol_name] = result

    console.print(
        f"  [green]{symbol_name}[/]: addr={result['address']} "
        f"offset={result['offset']} base={result['kernel_base']}"
    )
    ctx.log(
        "tool", "resolve_symbol_address",
        f"{symbol_name}={result['address']} (kernel={kernel_name})"
    )

    return ctx
