"""
orchestrator.builtin_tools — Concrete tools registered for the Agent.

Each tool wraps one of the major sub-pipelines (analysis, feasibility,
reproducer, exploit) so the LLM-driven Agent can invoke them by name.

Import this module once (e.g. from ``__init__``) to populate
``default_registry``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ..core.config import Config
from ..core.log import console
from ..core.reporting import save_report
from .context import TaskContext
from .tools import default_registry


# ── Helper: auto-fetch kernel source for affected functions ───────────

def _auto_fetch_kernel_source(ctx: TaskContext, kernel_version: str) -> None:
    """Pre-fetch upstream source for vulnerable functions.

    Called during collect_target_info when root cause is available.
    Populates ctx.kernel_source_context so GDB and LLM have source context.
    """
    try:
        from ..analysis.kernel_source_fetcher import (
            fetch_function_source,
            parse_kernel_version,
            resolve_and_fetch,
        )
    except ImportError:
        return

    funcs = []
    structs = []
    vuln_file = ""
    if ctx.root_cause:
        if ctx.root_cause.vulnerable_function:
            funcs.append(ctx.root_cause.vulnerable_function)
        funcs.extend(ctx.root_cause.kernel_functions[:5])
        structs = list(ctx.root_cause.affected_structs)
        vuln_file = ctx.root_cause.vulnerable_file or ""

    if not funcs:
        return

    try:
        ver_info = parse_kernel_version(kernel_version)
    except Exception:
        return

    console.print(
        f"  [dim]Auto-fetching kernel source for {len(funcs)} "
        f"function(s)…[/]"
    )

    parts = []
    for fn in funcs[:5]:
        try:
            result = fetch_function_source(
                fn, ver_info, known_file=vuln_file,
            )
            if result:
                body, fpath, ref = result
                parts.append(
                    f"// === {fn} from {fpath} ({ref}) ===\n{body}"
                )
        except Exception:
            continue

    # Also try to fetch struct definitions
    for struct_name in structs[:3]:
        for hfile in [
            f"include/net/{struct_name.lower()}.h",
            f"include/linux/{struct_name.lower()}.h",
        ]:
            try:
                content, ref = resolve_and_fetch(hfile, ver_info)
                if content:
                    # Extract struct definition
                    import re as _re
                    pat = _re.compile(
                        rf'struct\s+{_re.escape(struct_name)}\s*\{{',
                        _re.MULTILINE,
                    )
                    m = pat.search(content)
                    if m:
                        # Find matching closing brace
                        depth, i = 0, m.start()
                        while i < len(content):
                            if content[i] == '{':
                                depth += 1
                            elif content[i] == '}':
                                depth -= 1
                                if depth == 0:
                                    parts.append(
                                        f"// === struct {struct_name} from "
                                        f"{hfile} ({ref}) ===\n"
                                        f"{content[m.start():i+2]}"
                                    )
                                    break
                            i += 1
                    break
            except Exception:
                continue

    if parts:
        ctx.kernel_source_context = "\n\n".join(parts)
        console.print(
            f"  [dim]Fetched source for {len(parts)} symbol(s) "
            f"({len(ctx.kernel_source_context)} chars)[/]"
        )
    else:
        console.print(
            "  [dim]Could not fetch kernel source (upstream "
            "may not have this version)[/]"
        )


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

    # ── Idempotency: skip if root_cause already populated ─────────
    if (
        ctx.root_cause is not None
        and not kwargs.get("force", False)
    ):
        console.print(
            "[dim]→ analyze: already completed "
            "(root_cause present). Pass force=True to re-run.[/]"
        )
        ctx.log("tool", "analyze", "skipped: already completed")
        return ctx

    console.print("[dim]→ running analysis dispatcher…[/]")
    ctx = analyze_input(ctx, cfg)

    # ── Save analysis reports ─────────────────────────────────────
    meta = {"input_type": ctx.input_type, "input_value": ctx.input_value}
    if ctx.crash_report:
        save_report("crash_report", ctx.crash_report, ctx.work_dir, metadata=meta)
    if ctx.root_cause:
        save_report("root_cause_analysis", ctx.root_cause, ctx.work_dir, metadata=meta)
    return ctx


# ── investigate ───────────────────────────────────────────────────────

@default_registry.register(
    name="investigate",
    description=(
        "Perform comprehensive CVE investigation via web scraping. "
        "Given a CVE ID, automatically searches for existing exploits "
        "(GitHub, Exploit-DB), discovers blog posts and write-ups, "
        "locates kernel patches and fix commits, fetches the affected "
        "kernel source code, and synthesises all findings with LLM. "
        "Populates root_cause and stores the full investigation report "
        "in analysis_data. More thorough than 'analyze' for CVE inputs."
    ),
)
def tool_investigate(ctx: TaskContext, cfg: Config, **kwargs: Any) -> TaskContext:
    import re as _re
    from ..analysis.investigate import investigate_cve
    from ..core.reporting import save_report as _save

    # Extract CVE ID from the input
    cve_id = ctx.input_value
    m = _re.search(r"(CVE-\d{4}-\d+)", cve_id, _re.IGNORECASE)
    if m:
        cve_id = m.group(1).upper()
    else:
        ctx.errors.append(f"investigate: could not extract CVE ID from '{ctx.input_value}'")
        return ctx

    # ── Idempotency: skip if investigation already completed ──────
    if (
        ctx.analysis_data
        and ctx.analysis_data.get("investigation_report")
        and ctx.root_cause
        and not kwargs.get("force", False)
    ):
        console.print(
            f"[dim]→ investigate: already completed for {cve_id} "
            f"(root_cause + investigation_report present). "
            f"Pass force=True to re-run.[/]"
        )
        ctx.log("tool", "investigate", "skipped: data already present")
        return ctx

    console.print(f"[dim]→ investigating {cve_id}…[/]")
    report = investigate_cve(
        cve_id,
        cfg=cfg,
        blog_urls=ctx.blog_urls if ctx.blog_urls else None,
    )

    if report.root_cause:
        ctx.root_cause = report.root_cause
    inv_dict = report.to_dict()
    ctx.analysis_data["investigation_report"] = inv_dict

    # Build structured investigation briefing for downstream LLM prompts
    from ..analysis.investigation_briefing import InvestigationBriefing
    ctx.investigation_briefing = InvestigationBriefing.from_investigation_report(
        inv_dict, root_cause=ctx.root_cause,
    )

    # Save reports
    meta = {"cve_id": cve_id}
    if ctx.root_cause:
        _save("root_cause_analysis", ctx.root_cause, ctx.work_dir, metadata=meta)

    # Save full investigation report
    if ctx.work_dir:
        import json
        inv_path = ctx.work_dir / "investigation_report.json"
        inv_path.write_text(json.dumps(report.to_dict(), indent=2, default=str))
        console.print(f"  [dim]Investigation report: {inv_path}[/]")

        # Save structured briefing
        if ctx.investigation_briefing:
            briefing_path = ctx.work_dir / "investigation_briefing.json"
            briefing_path.write_text(json.dumps(
                ctx.investigation_briefing.to_dict(), indent=2, default=str
            ))
            console.print(f"  [dim]Investigation briefing: {briefing_path}[/]")

    ctx.log("analysis", "investigate_cve", f"exploits={len(report.exploit_references)} patches={len(report.patch_info)}")

    # ── Pre-boot VM in background (saves ~5 min on next step) ────
    # Start the VM boot now so it's ready by the time collect_target_info
    # is called. This parallelizes investigation LLM calls with VM boot.
    if ctx.ssh_host and ctx.start_cmd and not getattr(ctx, "_vm_preboot_started", False):
        try:
            import subprocess as _sub
            from ..infra.verification import _run_lifecycle_cmd
            ssh_host = ctx.ssh_host
            ssh_port = ctx.ssh_port or 22
            # Stop any stale instance first
            if ctx.stop_cmd:
                console.print("  [dim]collect_target_info: stopping stale instance…[/]")
                _run_lifecycle_cmd(ctx.stop_cmd, ssh_host=ssh_host,
                                   ssh_port=ssh_port, timeout=30)
            # Start VM in background via SSH Popen
            console.print("  [dim]collect_target_info: starting VM (pre-boot)…[/]")
            _sub.Popen(
                ["ssh", "-o", "StrictHostKeyChecking=no",
                 "-p", str(ssh_port), ssh_host, ctx.start_cmd],
                stdin=_sub.DEVNULL, stdout=_sub.DEVNULL, stderr=_sub.DEVNULL,
            )
            ctx._vm_preboot_started = True
        except Exception:
            pass  # Non-critical — collect_target_info will boot if needed

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

    # ── Idempotency: skip if target info already collected ────────
    if (
        ctx.target_system_info is not None
        and not kwargs.get("force", False)
    ):
        console.print(
            "[dim]→ collect_target_info: already collected "
            "(target_system_info present). Pass force=True to re-run.[/]"
        )
        ctx.log("tool", "collect_target_info", "skipped: already collected")
        return ctx

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
        keep_alive=True,
        kernel_image=ctx.kernel_image or getattr(cfg, "kernel_image", None),
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

    # Validate: reject host kernel on Android targets
    if (ctx.target_kernel and ctx.target_platform
            and ctx.target_platform.value == "android"):
        _kr = ctx.target_kernel
        if any(p in _kr for p in ["-generic", "-cloud", "-aws", "-azure"]):
            console.print(
                f"  [red]ERROR: Detected host kernel ({_kr}) on Android target![/]"
            )
            console.print(
                "  [red]ADB failed to connect — cannot collect real target info.[/]"
            )
            ctx.target_kernel = ""
            target_info.kernel_release = ""
            ctx.errors.append(
                f"collect_target_info: got host kernel {_kr} instead of "
                "target device kernel. ADB connection likely failed."
            )

    # Propagate extracted vmlinux path to analysis data + config so
    # downstream tools (gdb_session, verify_reproducer, etc.) can find it.
    if info_dict.get("vmlinux_path"):
        ctx.analysis_data["vmlinux_path"] = info_dict["vmlinux_path"]
        if not getattr(cfg, "vmlinux_path", None):
            cfg.vmlinux_path = info_dict["vmlinux_path"]

    # ── Auto-fetch kernel source for affected functions ───────────
    # When we know the kernel version and the root cause analysis has
    # identified vulnerable functions, pre-fetch their source code.
    # This populates kernel_source_context for GDB and LLM prompts.
    if (
        not ctx.kernel_source_context
        and ctx.root_cause
        and target_info.kernel_release
    ):
        _auto_fetch_kernel_source(ctx, target_info.kernel_release)

    # ── Android constraint probing ────────────────────────────────
    # Probe for specific capabilities that affect exploit technique selection.
    # Run quick syscall tests via adb shell and annotate target_info.notes.
    if use_adb and ctx.instance is not None:
        _probe_android_constraints(ctx, info_dict)

    ctx.log("tool", "collect_target_info", target_info.summary())

    save_report(
        "target_system_info", target_info, ctx.work_dir,
        metadata={"kernel_release": target_info.kernel_release},
    )
    return ctx


def _probe_android_constraints(ctx: "TaskContext", info_dict: dict) -> None:
    """Run quick constraint probes on Android device and annotate ctx.analysis_data.

    Probes:
    - CONFIG_SYSVIPC (msg_msg availability)
    - RTM_NEWLINK permission (CAP_NET_ADMIN / SELinux)
    - setxattr availability
    - Raw socket access
    - User namespace support
    - Setuid su binary availability (/system/xbin/su or /system/bin/su)
    - Single-CPU detection (affects spray thread count)
    - Default network interface and gateway (for dst_entry trigger)
    - nokaslr in cmdline (affects offset strategy)

    Results are stored in ctx.analysis_data["android_constraints"] and
    appended as human-readable notes.
    """
    from ..infra.verification import _adb_run, _calc_adb_port
    adb_port = _calc_adb_port(ctx.instance)

    constraints: dict = {}

    # -- Check CONFIG_SYSVIPC --
    rc, out, _ = _adb_run(
        "cat /proc/config.gz 2>/dev/null | zcat 2>/dev/null | grep CONFIG_SYSVIPC || echo NOT_SET",
        adb_port,
        timeout=10,
    )
    constraints["sysvipc"] = "CONFIG_SYSVIPC=y" in out
    constraints["msg_msg_available"] = constraints["sysvipc"]

    # -- Check RTM_NEWLINK --
    # Write a small test program, compile it on host (not possible here), so
    # instead use a Python one-liner to test NETLINK_ROUTE socket + send
    rtm_test_cmd = (
        "python3 -c \""
        "import socket, errno, struct;"
        "s=socket.socket(16,3,0);"  # AF_NETLINK=16, SOCK_RAW=3, NETLINK_ROUTE=0
        "req=struct.pack('IHHIII IIHHi',20,16,0x601,1,0, 1,0,0,1,0,0);"  # RTM_NEWLINK minimal
        "r=s.send(req) if True else -1;"
        "print('RTM_OK' if r>0 else 'RTM_FAIL:'+str(s.fileno()));"
        "s.close()"
        "\" 2>/dev/null || echo RTM_NO_PYTHON"
    )
    # Simpler approach: use netcat trick
    simple_rtm_cmd = (
        "exec 3<>/dev/null && "
        "cat /proc/sys/net/ipv4/conf/lo/rp_filter 2>/dev/null && echo RTM_READ_OK || echo RTM_READ_FAIL"
    )
    # Most reliable: check if shell context can RTM_NEWLINK by looking at SELinux policy
    selinux_check_cmd = "getenforce 2>/dev/null || echo unknown"
    rc, out, _ = _adb_run(selinux_check_cmd, adb_port, timeout=5)
    constraints["selinux_enforcing"] = "Enforcing" in out

    # If SELinux enforcing + shell domain, RTM_NEWLINK is almost certainly blocked
    uid_rc, uid_out, _ = _adb_run("id", adb_port, timeout=5)
    in_shell_domain = "u:r:shell:s0" in uid_out or "uid=2000" in uid_out
    constraints["rtm_newlink_likely_blocked"] = (
        constraints["selinux_enforcing"] and in_shell_domain
    )

    # -- Check setxattr --
    xattr_cmd = (
        "touch /data/local/tmp/.syzploit_xtest 2>/dev/null && "
        "setfattr -n user.x -v v /data/local/tmp/.syzploit_xtest 2>/dev/null && echo XATTR_OK || "
        # Fallback: use raw syscall number (226 = setxattr on arm64)
        "python3 -c \"import ctypes; r=ctypes.CDLL(None).syscall(226,b'/data/local/tmp/.syzploit_xtest',b'user.x',b'v',1,0); print('XATTR_OK' if r==0 else 'XATTR_FAIL:'+str(r))\" 2>/dev/null || echo XATTR_UNKNOWN"
    )
    rc, out, _ = _adb_run(xattr_cmd, adb_port, timeout=10)
    constraints["setxattr_available"] = "XATTR_OK" in out

    # -- Check CONFIG_USER_NS --
    rc, out, _ = _adb_run(
        "cat /proc/config.gz 2>/dev/null | zcat 2>/dev/null | grep CONFIG_USER_NS= || echo NOT_SET",
        adb_port,
        timeout=10,
    )
    constraints["user_ns"] = "CONFIG_USER_NS=y" in out

    # -- Check for setuid su binary (CRITICAL for interface toggle on Android) --
    su_check_cmd = (
        "ls -la /system/xbin/su 2>/dev/null || "
        "ls -la /system/bin/su 2>/dev/null || "
        "echo SU_NOT_FOUND"
    )
    rc, out, _ = _adb_run(su_check_cmd, adb_port, timeout=5)
    su_found = "SU_NOT_FOUND" not in out and ("rws" in out or "-rwsr" in out)
    su_path = "/system/xbin/su"
    if "SU_NOT_FOUND" not in out and "/system/bin/su" in out:
        su_path = "/system/bin/su"
    constraints["su_binary_available"] = su_found
    constraints["su_binary_path"] = su_path if su_found else None
    # Even if not setuid, check if it exists and is executable
    if not su_found:
        rc2, out2, _ = _adb_run(
            "test -x /system/xbin/su && echo SU_EX || test -x /system/bin/su && echo SU_EX2 || echo NO_SU",
            adb_port, timeout=5,
        )
        if "SU_EX" in out2:
            constraints["su_binary_available"] = True
            constraints["su_binary_path"] = "/system/xbin/su" if "SU_EX2" not in out2 else "/system/bin/su"

    # -- Check single-CPU (affects spray thread count) --
    rc, out, _ = _adb_run("cat /sys/devices/system/cpu/online 2>/dev/null || echo unknown", adb_port, timeout=5)
    out = out.strip()
    constraints["single_cpu"] = out in ("0", "0\n")
    constraints["cpu_online"] = out

    # -- Detect default network interface and gateway --
    rc, out, _ = _adb_run("ip route 2>/dev/null | grep default | head -1 || echo NO_ROUTE", adb_port, timeout=5)
    out = out.strip()
    default_iface = None
    default_gw = None
    if out and "NO_ROUTE" not in out:
        # "default via 192.168.97.1 dev buried_eth0 ..."
        parts = out.split()
        for i, p in enumerate(parts):
            if p == "via" and i + 1 < len(parts):
                default_gw = parts[i + 1]
            if p == "dev" and i + 1 < len(parts):
                default_iface = parts[i + 1]
    constraints["default_iface"] = default_iface
    constraints["default_gateway"] = default_gw

    # -- Check nokaslr in cmdline --
    rc, out, _ = _adb_run("cat /proc/cmdline 2>/dev/null || echo unknown", adb_port, timeout=5)
    constraints["nokaslr"] = "nokaslr" in out

    # -- Build human-readable summary --
    notes = []
    if not constraints.get("msg_msg_available"):
        notes.append(
            "CONSTRAINT: CONFIG_SYSVIPC not set — msg_msg spray UNAVAILABLE. "
            "Use setxattr or sk_buff spray instead."
        )
    if constraints.get("rtm_newlink_likely_blocked"):
        if constraints.get("su_binary_available"):
            su = constraints.get("su_binary_path", "/system/xbin/su")
            iface = constraints.get("default_iface") or "eth0"
            gw = constraints.get("default_gateway") or "192.168.1.1"
            notes.append(
                f"TRIGGER: RTM_NEWLINK blocked by SELinux. "
                f"Use setuid su binary at {su} for interface toggle ONLY: "
                f"'su 0 ip link set {iface} down/up'. "
                f"Connect sockets to gateway {gw} (NOT loopback). "
                f"IMPORTANT: su is for the trigger only — privesc MUST come from kernel cred overwrite."
            )
        else:
            notes.append(
                "CONSTRAINT: RTM_NEWLINK likely blocked by SELinux (shell domain, Enforcing). "
                "No su binary found. Use ICMP redirect or route expiry as trigger fallback."
            )
    if constraints.get("su_binary_available") and not constraints.get("rtm_newlink_likely_blocked"):
        su = constraints.get("su_binary_path", "/system/xbin/su")
        notes.append(
            f"AVAILABLE: setuid su binary at {su} — can exec 'su 0 <cmd>' for TRIGGER SETUP only. "
            f"DO NOT use su for the final privilege escalation — use kernel cred overwrite."
        )
    if constraints.get("setxattr_available"):
        notes.append("AVAILABLE: setxattr spray — allocates kernel kmalloc buffers of controlled size.")
    if not constraints.get("user_ns"):
        notes.append(
            "CONSTRAINT: CONFIG_USER_NS not set — cannot use network namespace "
            "to get CAP_NET_ADMIN for interface manipulation."
        )
    if constraints.get("single_cpu"):
        notes.append(
            "CONSTRAINT: Single-CPU target (cpu/online=0). "
            "Limit spray threads to ≤4 to avoid scheduling overhead and VM timeout."
        )
    if constraints.get("default_iface"):
        notes.append(
            f"NETWORK: Default interface={constraints['default_iface']}, "
            f"gateway={constraints.get('default_gateway', 'unknown')}. "
            f"Connect sockets to gateway for dst_entry UAF (NOT loopback)."
        )
    if constraints.get("nokaslr"):
        notes.append(
            "KASLR: nokaslr in /proc/cmdline — compile-time kernel addresses are valid (slide=0). "
            "Skip /proc/kallsyms scan; use vmlinux symbols directly."
        )

    # ── Kernel hardening analysis ──
    hardening_configs = [
        "SLAB_FREELIST_HARDENED", "SLAB_FREELIST_RANDOM",
        "KASAN_HW_TAGS", "KASAN", "HARDENED_USERCOPY",
        "CFI_CLANG", "SHADOW_CALL_STACK",
    ]
    hc_cmd = "zcat /proc/config.gz 2>/dev/null | grep -E '" + "|".join(hardening_configs) + "'"
    hc_rc, hc_out, _ = _adb_run(hc_cmd, adb_port, timeout=10)
    constraints["slab_freelist_hardened"] = "SLAB_FREELIST_HARDENED=y" in hc_out
    constraints["slab_freelist_random"] = "SLAB_FREELIST_RANDOM=y" in hc_out
    constraints["kasan_hw_tags"] = "KASAN_HW_TAGS=y" in hc_out
    constraints["hardened_usercopy"] = "HARDENED_USERCOPY=y" in hc_out
    constraints["cfi_enabled"] = "CFI_CLANG=y" in hc_out

    # Check for dedicated slab caches that affect exploitation
    slab_rc, slab_out, _ = _adb_run(
        "cat /proc/slabinfo | grep -E 'cred_jar|io_kiocb|filp ' | awk '{print $1}'",
        adb_port, timeout=10,
    )
    constraints["dedicated_slab_caches"] = [
        c.strip() for c in slab_out.strip().split("\n") if c.strip()
    ]

    if constraints["slab_freelist_hardened"]:
        notes.append(
            "HARDENING: SLAB_FREELIST_HARDENED=y — generic freelist corruption attacks are blocked. "
            "Exploitation requires subsystem-specific techniques (binder cross-cache, pipe_buffer via driver bug)."
        )
    if constraints["kasan_hw_tags"]:
        notes.append(
            "HARDENING: KASAN_HW_TAGS=y (MTE) — hardware use-after-free detection active. "
            "UAF exploits may be detected/blocked by memory tagging."
        )

    ctx.analysis_data["android_constraints"] = constraints

    # ── Exploit classification: what privesc primitives are available? ──
    classification = _classify_exploit_constraints(constraints)
    ctx.analysis_data["exploit_classification"] = classification
    notes.extend(classification.get("notes", []))

    if notes:
        console.print("  [yellow]Android constraints detected:[/]")
        for note in notes:
            console.print(f"    [yellow]• {note}[/]")
        # Append to target_info notes if it's a mutable list
        if ctx.target_system_info and hasattr(ctx.target_system_info, "notes"):
            ctx.target_system_info.notes.extend(notes)


def _classify_exploit_constraints(constraints: dict) -> dict:
    """Classify what exploitation primitives are available on this target.

    Returns a dict with:
      - race_feasible: whether CPU races can fire
      - cap_net_admin: whether we have CAP_NET_ADMIN (or su workaround)
      - user_ns: whether user namespaces are available
      - su_available: whether su binary exists
      - privesc_methods: list of available privilege escalation methods
      - blocked_cve_classes: list of CVE classes that cannot be fully exploited
      - notes: human-readable classification notes
    """
    single_cpu = constraints.get("single_cpu", False)
    user_ns = constraints.get("user_ns", False)
    su_avail = constraints.get("su_binary_available", False)
    cap_net_admin = not constraints.get("rtm_newlink_likely_blocked", True)
    nokaslr = constraints.get("nokaslr", False)

    result: dict = {
        "race_feasible": not single_cpu,
        "cap_net_admin_direct": cap_net_admin,
        "cap_net_admin_via_su": su_avail and not cap_net_admin,
        "user_ns": user_ns,
        "su_available": su_avail,
        "nokaslr": nokaslr,
        "privesc_methods": [],
        "blocked_cve_classes": [],
        "notes": [],
    }

    # ── Determine available privesc methods ──
    # Method 1: kernel cred overwrite (always possible if vuln triggers)
    result["privesc_methods"].append("kernel_cred_overwrite")

    # Method 2: su binary (if available)
    if su_avail:
        result["privesc_methods"].append("su_binary")

    # ── Classify blocked CVE classes ──
    if single_cpu:
        result["blocked_cve_classes"].append({
            "class": "cpu_race",
            "reason": "Single-CPU target — kernel thread races cannot fire. "
                      "io_uring races, perf_event races, and similar require ≥2 CPUs.",
            "affected_cves": [
                "CVE-2022-1786", "CVE-2022-29582", "CVE-2022-20409",
                "CVE-2022-1729", "CVE-2023-0266",
            ],
            "workaround": "Use serialization-based bugs (binder, filesystem) instead, "
                          "or reconfigure VM with smp≥2.",
        })
        result["notes"].append(
            "EXPLOIT-CLASS: CPU race conditions (io_uring, perf_event) are NOT "
            "exploitable on single-CPU. Only serialization bugs (binder IPC, "
            "filesystem) can achieve real root."
        )

    if not user_ns:
        result["blocked_cve_classes"].append({
            "class": "user_ns_required",
            "reason": "CONFIG_USER_NS not set — vulnerabilities requiring unprivileged "
                      "user namespace creation cannot be triggered.",
            "affected_cves": ["CVE-2022-0185"],
            "workaround": "Enable CONFIG_USER_NS in kernel config.",
        })

    if not cap_net_admin and not su_avail:
        result["blocked_cve_classes"].append({
            "class": "cap_net_admin_required",
            "reason": "No CAP_NET_ADMIN and no su binary — network subsystem "
                      "vulnerabilities requiring interface manipulation, XFRM, or tc "
                      "commands cannot be triggered.",
            "affected_cves": [
                "CVE-2024-36971", "CVE-2022-27666", "CVE-2023-1829",
            ],
            "workaround": "Provide su binary or enable CONFIG_USER_NS for CAP_NET_ADMIN via userns.",
        })
    elif not cap_net_admin and su_avail:
        result["notes"].append(
            "EXPLOIT-CLASS: Network CVEs (dst_entry, XFRM, tc) need CAP_NET_ADMIN. "
            "su binary available for trigger setup but privesc MUST come from "
            "kernel cred overwrite, not su."
        )

    # ── Kernel hardening analysis ──
    slab_hardened = constraints.get("slab_freelist_hardened", False)
    kasan_hw = constraints.get("kasan_hw_tags", False)
    cfi_enabled = constraints.get("cfi_enabled", False)
    dedicated_caches = constraints.get("dedicated_slab_caches", [])

    result["hardening"] = {
        "slab_freelist_hardened": slab_hardened,
        "slab_freelist_random": constraints.get("slab_freelist_random", False),
        "kasan_hw_tags": kasan_hw,
        "hardened_usercopy": constraints.get("hardened_usercopy", False),
        "cfi": cfi_enabled,
        "dedicated_caches": dedicated_caches,
    }

    # Determine which exploitation techniques are viable
    result["viable_techniques"] = []
    result["blocked_techniques"] = []

    # Freelist corruption (classic slab exploit)
    if slab_hardened:
        result["blocked_techniques"].append({
            "technique": "freelist_corruption",
            "reason": "SLAB_FREELIST_HARDENED=y — freelist pointers are XOR'd with random canary",
        })
    else:
        result["viable_techniques"].append("freelist_corruption")

    # Cross-cache attack (DirtyCred style)
    if "cred_jar" in dedicated_caches:
        result["blocked_techniques"].append({
            "technique": "direct_cred_spray",
            "reason": "cred_jar is a dedicated slab cache — kmalloc spray cannot reclaim freed creds. "
                      "Requires cross-cache page-level attack (exhaust slab pages → reclaim as different cache).",
        })
    else:
        result["viable_techniques"].append("direct_cred_spray")

    # Binder cross-cache (used by badnode — works despite hardening)
    result["viable_techniques"].append("binder_cross_cache")
    result["notes"].append(
        "EXPLOIT-TECHNIQUE: Binder cross-cache attack works despite SLAB_FREELIST_HARDENED "
        "because it exploits the binder driver's own allocation patterns, not generic slab techniques."
    )

    # pipe_buffer technique (bad_io_uring style)
    if not slab_hardened:
        result["viable_techniques"].append("pipe_buffer_overwrite")
    else:
        result["notes"].append(
            "EXPLOIT-TECHNIQUE: pipe_buffer overwrite requires corrupting pipe_buffer.ops pointer. "
            "On hardened kernels, this needs a subsystem-specific bug (not generic slab corruption)."
        )

    # modprobe_path technique
    if nokaslr:
        result["viable_techniques"].append("modprobe_path_overwrite")
        result["notes"].append(
            f"EXPLOIT-TECHNIQUE: modprobe_path overwrite viable (KASLR disabled). "
            f"Requires arbitrary kernel write to a known address."
        )

    # Summarize exploitation difficulty
    if slab_hardened and kasan_hw and "cred_jar" in dedicated_caches:
        result["exploitation_difficulty"] = "VERY_HARD"
        result["notes"].append(
            "HARDENING: This kernel has SLAB_FREELIST_HARDENED + KASAN_HW_TAGS + dedicated cred cache. "
            "Generic slab exploitation techniques are blocked. Only subsystem-specific bugs "
            "(binder cross-cache, driver-specific alloc patterns) can achieve R/W primitives."
        )
    elif slab_hardened:
        result["exploitation_difficulty"] = "HARD"
    else:
        result["exploitation_difficulty"] = "MODERATE"

    return result


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
        "reliable primitives, and compile.  Does NOT verify on the "
        "target — call verify_exploit separately after this succeeds.  "
        "This tool is safe to call multiple times; each invocation "
        "regenerates code using feedback from previous verify_exploit "
        "results.  Populates exploit_plan and exploit_result."
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


# ── load_prebuilt_exploit ─────────────────────────────────────────────

@default_registry.register(
    name="load_prebuilt_exploit",
    description=(
        "Load a pre-built exploit binary into the pipeline context "
        "without LLM code generation. Used in replay/demo mode to "
        "skip the codegen phase and go directly to verification. "
        "Requires kwargs: binary_path (path to pre-compiled exploit)."
    ),
)
def tool_load_prebuilt_exploit(ctx: TaskContext, cfg: Config, **kwargs: Any) -> TaskContext:
    from pathlib import Path
    from ..core.models import ExploitResult, ExploitPlan, VulnType, Arch, Platform

    binary_path = kwargs.get("binary_path", "")
    if not binary_path:
        # Try to find exploit in the work dir
        candidate = Path(ctx.work_dir) / "exploit_src" / "exploit"
        if candidate.exists():
            binary_path = str(candidate)
        else:
            ctx.errors.append("load_prebuilt_exploit: no binary_path specified")
            return ctx

    bp = Path(binary_path)
    if not bp.exists():
        ctx.errors.append(f"load_prebuilt_exploit: binary not found: {binary_path}")
        return ctx

    console.print(f"[dim]→ loading pre-built exploit: {binary_path}[/]")

    # Ensure exploit_src dir exists and binary is copied there
    exploit_dir = Path(ctx.work_dir) / "exploit_src"
    exploit_dir.mkdir(parents=True, exist_ok=True)
    target = exploit_dir / "exploit"
    if str(bp.resolve()) != str(target.resolve()):
        import shutil
        shutil.copy2(str(bp), str(target))
        target.chmod(0o755)
        console.print(f"  Copied to {target}")

    # Create minimal exploit plan if not already present
    if not ctx.exploit_plan:
        ctx.exploit_plan = ExploitPlan(
            vulnerability_type=VulnType.UAF,
            target_struct="binder_node",
            slab_cache="kmalloc-256",
            technique="binder_uaf_cross_cache",
            goal="privilege_escalation",
            platform=Platform.ANDROID,
            target_arch=Arch.ARM64,
            target_kernel=ctx.target_kernel or "5.10.107",
            notes=["Pre-built exploit loaded (replay/demo mode)"],
        )

    # Set exploit result
    ctx.exploit_result = ExploitResult(
        success=True,
        binary_path=str(target),
        target_kernel=ctx.target_kernel or "5.10.107",
        arch=Arch.ARM64,
        notes=["Pre-built exploit binary loaded for verification"],
    )
    console.print(
        f"  [green]Exploit loaded: {target} "
        f"({target.stat().st_size / 1024:.0f} KB)[/]"
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

    # ── Idempotency: skip if offsets already resolved ─────────────
    if (
        ctx.kernel_offsets_header
        and ctx.resolved_symbols
        and not kwargs.get("force", False)
    ):
        console.print(
            f"[dim]→ resolve_kernel_offsets: already resolved "
            f"({len(ctx.resolved_symbols)} symbols). "
            f"Pass force=True to re-run.[/]"
        )
        ctx.log("tool", "resolve_kernel_offsets", "skipped: already resolved")
        return ctx

    vmlinux = kwargs.get("vmlinux_path") or getattr(cfg, "vmlinux_path", None) or ctx.analysis_data.get("vmlinux_path")
    target_info = ctx.target_system_info

    if not vmlinux and not target_info:
        ctx.errors.append(
            "resolve_kernel_offsets: no vmlinux, kallsyms, or target_info — "
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

    # ── Idempotency: skip if spray strategy for this cache exists ─
    if (
        ctx.spray_strategy
        and ctx.spray_strategy.get("target_cache") == target_cache
        and ctx.spray_strategy.get("spray_objects")
        and not kwargs.get("force", False)
    ):
        console.print(
            f"[dim]→ get_spray_strategy: already have strategy for "
            f"{target_cache} ({len(ctx.spray_strategy['spray_objects'])} "
            f"objects). Pass force=True to re-run.[/]"
        )
        ctx.log("tool", "get_spray_strategy", "skipped: already resolved")
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
        "Extract source code of vulnerable functions and struct definitions. "
        "Uses a local kernel git checkout if kernel_tree_path is configured; "
        "otherwise fetches the closest matching upstream source from "
        "android.googlesource.com or git.kernel.org based on the target's "
        "kernel version.  Populates kernel_source_context on context."
    ),
)
def tool_get_kernel_source(ctx: TaskContext, cfg: Config, **kwargs: Any) -> TaskContext:
    kernel_tree = kwargs.get("kernel_tree_path") or getattr(cfg, "kernel_tree_path", None)

    # Gather function names from root cause analysis
    funcs: list[str] = []
    structs: list[str] = []
    vuln_file = ""
    if ctx.root_cause:
        if ctx.root_cause.vulnerable_function:
            funcs.append(ctx.root_cause.vulnerable_function)
        funcs.extend(ctx.root_cause.kernel_functions[:5])
        structs = list(ctx.root_cause.affected_structs)
        vuln_file = ctx.root_cause.vulnerable_file or ""

    # Also check crash report stack frames
    if ctx.crash_report:
        for frame in ctx.crash_report.stack_frames[:3]:
            if frame.function and frame.function not in funcs:
                funcs.append(frame.function)

    if not funcs:
        ctx.errors.append("get_kernel_source: no function names to look up")
        return ctx

    # ── Path A: Local kernel git tree ─────────────────────────────────
    if kernel_tree:
        from ..analysis.kernel_source import KernelSourceContext

        console.print("[dim]-> extracting kernel source context (local tree)...[/]")
        try:
            ksc = KernelSourceContext(kernel_tree)
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
            return ctx
        except Exception as exc:
            ctx.errors.append(f"get_kernel_source (local): {exc}")
            console.print(f"  [yellow]Local tree extraction failed: {exc}[/]")
            console.print("  [dim]Falling back to upstream fetch...[/]")

    # ── Path B: Fetch from upstream repos ─────────────────────────────
    kernel_ver = ""
    if ctx.target_system_info and ctx.target_system_info.kernel_release:
        kernel_ver = ctx.target_system_info.kernel_release
    elif ctx.crash_report and ctx.crash_report.kernel_version:
        kernel_ver = ctx.crash_report.kernel_version

    if not kernel_ver:
        msg = (
            "get_kernel_source: no kernel_tree_path and no kernel version "
            "available -- cannot fetch upstream source. "
            "Run collect_target_info first or set SYZPLOIT_KERNEL_TREE_PATH."
        )
        ctx.errors.append(msg)
        console.print(f"  [yellow]{msg}[/]")
        ctx.log("tool", "get_kernel_source", "skipped: no version or tree")
        return ctx

    from ..analysis.kernel_source_fetcher import (
        fetch_function_source,
        parse_kernel_version,
        resolve_and_fetch,
        _extract_function_from_source,
    )

    console.print(
        f"[dim]-> fetching kernel source from upstream "
        f"(kernel {kernel_ver})...[/]"
    )

    version = parse_kernel_version(kernel_ver)
    sections: list[str] = []
    total_lines = 0
    max_lines = 500

    # Fetch functions
    for func_name in funcs:
        if total_lines >= max_lines:
            break
        result = fetch_function_source(
            func_name,
            version,
            known_file=vuln_file,
            struct_name=structs[0] if structs else "",
        )
        if result:
            body, fpath, ref = result
            header = f"// == {func_name}() from {fpath} ({ref}) =="
            section = f"{header}\n{body}"
            lines = section.count("\n") + 1
            sections.append(section)
            total_lines += lines
            console.print(
                f"  [dim]+ {func_name}() from {fpath} ({lines} lines)[/]"
            )

    # Fetch struct definitions
    for struct_name in structs:
        if total_lines >= max_lines:
            break
        # Try to find struct definition in header files
        header_files = [
            f"include/linux/{struct_name}.h",
            f"include/net/{struct_name}.h",
        ]
        # Also add from the known struct source files mapping
        from ..analysis.kernel_source_fetcher import _STRUCT_SOURCE_FILES
        if struct_name in _STRUCT_SOURCE_FILES:
            for f in _STRUCT_SOURCE_FILES[struct_name]:
                if f.endswith(".h") and f not in header_files:
                    header_files.append(f)

        for hfile in header_files:
            content, ref = resolve_and_fetch(
                hfile, version, prefer_android=version.is_android
            )
            if not content:
                continue
            # Search for struct definition
            import re as _re
            pattern = _re.compile(
                rf"struct\s+{_re.escape(struct_name)}\s*\{{",
                _re.MULTILINE,
            )
            m = pattern.search(content)
            if not m:
                continue
            # Extract the struct body
            start_line = content[:m.start()].count("\n")
            lines_list = content.splitlines()
            depth = 0
            block: list[str] = []
            started = False
            for i in range(start_line, min(start_line + 150, len(lines_list))):
                line = lines_list[i]
                block.append(line)
                depth += line.count("{") - line.count("}")
                if "{" in line:
                    started = True
                if started and depth <= 0:
                    break
            if block:
                header = f"// == struct {struct_name} from {hfile} ({ref}) =="
                body = "\n".join(block)
                section = f"{header}\n{body}"
                n = section.count("\n") + 1
                sections.append(section)
                total_lines += n
                console.print(
                    f"  [dim]+ struct {struct_name} from {hfile} ({n} lines)[/]"
                )
            break  # Found it, no need to try more header files

    if sections:
        source_ctx = (
            "=== Kernel Source Context (upstream fetch) ===\n"
            + "\n\n".join(sections)
        )
        ctx.kernel_source_context = source_ctx
        ctx.log("tool", "get_kernel_source",
                f"fetched {len(sections)} sections from upstream "
                f"({total_lines} lines, kernel {version.base_version})")
        console.print(
            f"  Fetched source for {len(funcs)} functions, "
            f"{len(structs)} structs from upstream"
        )
    else:
        ctx.errors.append(
            "get_kernel_source: could not fetch any source from upstream"
        )
        console.print("  [yellow]No source fetched from upstream[/]")

    return ctx


# ── lookup_kernel_struct ──────────────────────────────────────────────

@default_registry.register(
    name="lookup_kernel_struct",
    description=(
        "Look up the concrete definition of a kernel struct (field names, "
        "types, and byte offsets).  Uses BTF data from vmlinux when "
        "available, otherwise fetches and parses upstream kernel source.  "
        "Also knows template library structs like task_struct_offsets_t.  "
        "Use this BEFORE writing exploit code that accesses struct fields "
        "to ensure you use the correct field names.  "
        "Pass struct_names as a comma-separated list of struct names "
        "(e.g. 'dst_entry,task_struct,cred')."
    ),
)
def tool_lookup_kernel_struct(ctx: TaskContext, cfg: Config, **kwargs: Any) -> TaskContext:
    from ..analysis.kernel_struct_extractor import (
        lookup_struct,
        format_struct_definitions_for_prompt,
        extract_template_structs,
    )

    raw_names = kwargs.get("struct_names", "")
    if not raw_names:
        ctx.errors.append("lookup_kernel_struct: no struct_names provided")
        return ctx

    names = [n.strip() for n in raw_names.split(",") if n.strip()]

    # Determine kernel version
    kernel_ver = ""
    if ctx.target_system_info and ctx.target_system_info.kernel_release:
        kernel_ver = ctx.target_system_info.kernel_release
    elif ctx.crash_report and ctx.crash_report.kernel_version:
        kernel_ver = ctx.crash_report.kernel_version
    elif hasattr(ctx, "target_kernel") and ctx.target_kernel:
        kernel_ver = ctx.target_kernel

    # Check for vmlinux
    vmlinux = getattr(cfg, "vmlinux_path", "") or ""

    console.print(
        f"[dim]-> looking up kernel structs: {', '.join(names)} "
        f"(kernel={kernel_ver or 'unknown'}, vmlinux={'yes' if vmlinux else 'no'})...[/]"
    )

    found: dict[str, Any] = {}
    for name in names:
        defn = lookup_struct(
            name,
            kernel_version=kernel_ver,
            vmlinux_path=vmlinux,
        )
        if defn:
            found[name] = defn
            console.print(
                f"  [green]Found struct {name}: "
                f"{len(defn.fields)} fields (source={defn.source})[/]"
            )
        else:
            console.print(f"  [yellow]Struct {name} not found[/]")

    if found:
        formatted = format_struct_definitions_for_prompt(found)
        # Store in context for use by downstream tools
        if not hasattr(ctx, "struct_definitions_context"):
            ctx.struct_definitions_context = ""
        ctx.struct_definitions_context = formatted

        # Also append to kernel_source_context for immediate use
        if ctx.kernel_source_context:
            ctx.kernel_source_context += "\n\n" + formatted
        else:
            ctx.kernel_source_context = formatted

        ctx.log("tool", "lookup_kernel_struct",
                f"found {len(found)}/{len(names)} structs: "
                f"{', '.join(found.keys())}")

        return ctx

    ctx.errors.append(
        f"lookup_kernel_struct: could not find any of: {', '.join(names)}"
    )
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
    # NOTE: order matters — functions are listed highest-priority first
    # because ARM64 hardware breakpoint limit (typically 4) means only
    # the first N survive.
    monitor_funcs = kwargs.get("monitor_functions")
    prim_verifier = None
    if monitor_funcs is None:
        # Start with the vulnerable function (highest priority — confirms
        # the trigger reaches the right kernel code path)
        monitor_funcs = []
        if ctx.root_cause and ctx.root_cause.vulnerable_function:
            monitor_funcs.append(ctx.root_cause.vulnerable_function)

        # Core priv-esc indicators (2nd priority)
        monitor_funcs.extend([
            "commit_creds", "prepare_kernel_cred",
        ])

        # UID-change syscalls (3rd priority)
        monitor_funcs.extend([
            "__sys_setresuid", "__sys_setresgid",
        ])

        # Supporting functions (lower priority — may be trimmed on ARM64)
        # NOTE: copy_creds excluded — fires on every fork/clone in the
        # kernel, producing hundreds of noise hits that overwhelm GDB
        # and make ADB unresponsive.
        monitor_funcs.extend([
            "override_creds", "revert_creds",
            "sel_write_enforce",
        ])
        # Add related kernel functions from root cause (lowest priority)
        if ctx.root_cause:
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

        # ── PrimitiveVerifier: merge technique-specific functions + generate GDB scripts
        try:
            from ..exploit.gdb_verifier import PrimitiveVerifier

            technique = ""
            if ctx.exploit_plan:
                technique = getattr(ctx.exploit_plan, "technique", "")
            prim_verifier = PrimitiveVerifier(
                plan=ctx.exploit_plan,
                technique=technique,
                arch=ctx.target_arch.value if hasattr(ctx, "target_arch") and ctx.target_arch else "arm64",
            )
            verifier_funcs = prim_verifier.get_monitor_functions()
            # Merge: technique-specific functions first, then existing defaults
            merged = []
            seen: set = set()
            for fn in verifier_funcs + monitor_funcs:
                if fn not in seen:
                    merged.append(fn)
                    seen.add(fn)
            monitor_funcs = merged

            # Generate detailed GDB verification scripts
            work_dir = ctx.work_dir or Path(binary_path).parent
            verify_dir = Path(work_dir) / "gdb_verify"
            try:
                prim_verifier.generate_all_scripts(str(verify_dir))
            except Exception:
                pass
        except Exception:
            pass

    # Resolve kallsyms_path: ctx attribute > target_system_info > kwarg
    _kallsyms = getattr(ctx, "kallsyms_path", None)
    if not _kallsyms and ctx.target_system_info:
        _kallsyms = ctx.target_system_info.kallsyms_path
    if not _kallsyms:
        _kallsyms = kwargs.get("kallsyms_path")
    # Also try work_dir/kallsyms as fallback (saved by collect_target_info)
    if not _kallsyms and ctx.work_dir:
        _candidate = Path(ctx.work_dir) / "kallsyms"
        if _candidate.exists():
            _kallsyms = str(_candidate)

    # ── Generate ExploitMonitor scripts alongside standard monitoring ─
    # Filter out hot-path functions that would overwhelm GDB.
    _HOT_PATH = {
        "__kmalloc", "kmalloc", "kmem_cache_alloc", "kmem_cache_alloc_trace",
        "kmem_cache_free", "kfree", "kfree_sensitive", "vfree",
        "kzalloc", "__kmalloc_node",
        "pipe_read", "pipe_write", "copy_page_to_iter", "copy_page_from_iter",
        "copy_from_user", "copy_to_user", "_raw_spin_lock", "_raw_spin_unlock",
    }
    monitor_funcs = [f for f in monitor_funcs if f not in _HOT_PATH]

    # Allow callers (e.g., replay mode) to skip GDB monitoring entirely
    # for pre-built exploits where GDB overhead disrupts the exploit timing.
    # Also skip for direct reference adaptations — the multi-process
    # coordination is timing-sensitive and GDB breakpoints cause hangs.
    if kwargs.get("skip_gdb_monitor") or getattr(ctx, "_direct_adaptation", False):
        monitor_funcs = []
        if getattr(ctx, "_direct_adaptation", False):
            console.print("  [dim]GDB monitoring disabled (direct reference adaptation — timing-sensitive)[/]")
        else:
            console.print("  [dim]GDB monitoring disabled (skip_gdb_monitor=True)[/]")

    _exploit_monitor = None
    _monitor_dir: Optional[Path] = None
    try:
        from ..exploit.gdb_exploit_monitor import ExploitMonitor
        _vmlinux = getattr(cfg, "vmlinux_path", None) or ctx.analysis_data.get("vmlinux_path") or kwargs.get("vmlinux_path")
        _exploit_monitor = ExploitMonitor(
            kallsyms_path=_kallsyms,
            vmlinux_path=_vmlinux,
            arch=ctx.target_arch.value if hasattr(ctx, "target_arch") and ctx.target_arch else "arm64",
            target_symbols=monitor_funcs,
            heap_tracking=False,
        )
        _monitor_dir = Path(ctx.work_dir or Path(binary_path).parent) / "exploit_monitor"
        _monitor_dir.mkdir(parents=True, exist_ok=True)
        _exploit_monitor.generate_monitor_script(str(_monitor_dir))
        _exploit_monitor.generate_commands_file(
            str(_monitor_dir), port=ctx.gdb_port or 1234,
        )
    except Exception:
        _monitor_dir = None  # type: ignore[assignment]

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
        timeout=kwargs.get("timeout", 300 if getattr(ctx, "_direct_adaptation", False) else 120),
        use_adb=use_adb,
        adb_port=kwargs.get("adb_port", 6520),
        vmlinux_path=_vmlinux,
        kallsyms_path=_kallsyms,
        arch=ctx.target_arch.value if hasattr(ctx, "target_arch") and ctx.target_arch else "arm64",
        monitor_functions=monitor_funcs,
        monitor_script_dir=str(_monitor_dir) if _monitor_dir else None,
        keep_alive=True,
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
        crash_severity=result.get("crash_severity", "none"),
        device_stable=result.get("device_stable", True),
        failure_reason=result.get("failure_reason", ""),
        feedback=result.get("feedback", ""),
        exploit_output=result.get("exploit_output", "")[:6000],
        dmesg_new=result.get("dmesg_new", "")[:6000],
        kernel_warnings=result.get("kernel_warnings", []),
        kernel_log=result.get("kernel_log", "")[:4000],
        gdb_functions_hit=result.get("gdb_functions_hit", []),
        gdb_functions_missed=result.get("gdb_functions_missed", []),
        gdb_crash_info=result.get("gdb_crash_info"),
        kernel_state_diff=result.get("kernel_state_diff", ""),
        monitor_feedback=result.get("monitor_feedback", ""),
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

    # ── Parse PrimitiveVerifier GDB script results ────────────────
    if prim_verifier is not None:
        try:
            verify_dir = Path(ctx.work_dir or Path(binary_path).parent) / "gdb_verify"
            prim_results = prim_verifier.parse_verification_results(str(verify_dir))
            if prim_results:
                prim_feedback = prim_verifier.format_verification_feedback(prim_results)
                if prim_feedback:
                    # Attach to the attempt so it's included in future prompts
                    attempt.feedback = (attempt.feedback or "") + "\n" + prim_feedback
                    ctx.log("tool", "verify_exploit_gdb", prim_feedback[:300])
        except Exception:
            pass

    # ── Parse ExploitMonitor results ──────────────────────────────
    if _exploit_monitor is not None:
        try:
            _monitor_dir = Path(ctx.work_dir or Path(binary_path).parent) / "exploit_monitor"
            monitor_parsed = _exploit_monitor.parse_monitor_results(str(_monitor_dir))
            if monitor_parsed:
                monitor_feedback = _exploit_monitor.format_results_for_prompt(monitor_parsed)
                if monitor_feedback:
                    attempt.feedback = (attempt.feedback or "") + "\n" + monitor_feedback
                    ctx.log("tool", "verify_exploit_monitor", monitor_feedback[:300])
                if not hasattr(ctx, "gdb_trace_results") or ctx.gdb_trace_results is None:
                    ctx.gdb_trace_results = []
                ctx.gdb_trace_results.append({
                    "attempt": attempt_num,
                    "monitor_data": monitor_parsed,
                })
        except Exception:
            pass

    # Update exploit_result if successful
    if result["success"]:
        ctx.exploit_result.privilege_escalation_confirmed = True  # type: ignore[union-attr]
        ctx.exploit_result.uid_before = result.get("uid_before")  # type: ignore[union-attr]
        ctx.exploit_result.uid_after = result.get("uid_after")  # type: ignore[union-attr]
        ctx.exploit_result.verification_log = result.get("exploit_output", "")  # type: ignore[union-attr]

        # ── Classify privesc method ──
        exploit_output = result.get("exploit_output", "")
        privesc_method = "unknown"
        if "context=?" in exploit_output or "context=u:r:kernel" in exploit_output:
            privesc_method = "kernel_cred_overwrite"
        # Don't classify as su_binary just from SELinux context or su
        # mentions in output — the source code analysis below is more
        # accurate at distinguishing su-for-trigger vs su-for-privesc.
        # Check source code for su usage
        exploit_src = ""
        import glob as _glob
        from pathlib import Path as _Path
        # Try multiple locations for source files
        search_dirs = []
        if ctx.exploit_result and ctx.exploit_result.binary_path:  # type: ignore[union-attr]
            bp = _Path(ctx.exploit_result.binary_path)  # type: ignore[union-attr]
            search_dirs.append(str(bp.parent))
        if ctx.work_dir:
            search_dirs.append(str(_Path(ctx.work_dir) / "exploit_src"))
        for src_dir in search_dirs:
            for src_file in _glob.glob(f"{src_dir}/*.c"):
                try:
                    with open(src_file) as f:
                        exploit_src += f.read()
                except Exception:
                    pass
            if exploit_src:
                break
        if exploit_src:
            # Count su references that are ACTUALLY privesc (not setup/trigger).
            # "su 0 ip ..." and "su 0 sysctl ..." are trigger/setup commands,
            # not privilege escalation. Only count su used for shells/exec.
            import re as _class_re
            # su-for-privesc: su 0 sh, su 0 id, execl("su",...), su -c
            su_privesc_refs = len(_class_re.findall(
                r'su\s+0\s+(?:sh|id|/system/bin/sh)|execl\s*\([^)]*"su"',
                exploit_src
            ))
            # su-for-trigger: su 0 ip ..., su 0 sysctl ..., su 0 echo
            su_trigger_refs = len(_class_re.findall(
                r'su\s+0\s+(?:ip\s|sysctl\s|echo\s|cat\s)',
                exploit_src
            ))
            cred_refs = (exploit_src.count("zero_address")
                         + exploit_src.count("cred_addr")
                         + exploit_src.count("overwrite_cred")
                         + exploit_src.count("swap_cred")
                         + exploit_src.count("commit_creds")
                         + exploit_src.count("prepare_kernel_cred"))
            if su_privesc_refs > 0 and cred_refs == 0:
                privesc_method = "su_binary"
            elif cred_refs > 0:
                if su_trigger_refs > 0:
                    privesc_method = "kernel_cred_overwrite+su_trigger"
                else:
                    privesc_method = "kernel_cred_overwrite"
            elif su_trigger_refs > 0 and su_privesc_refs == 0:
                # su only used for trigger setup, not privesc
                privesc_method = "kernel_cred_overwrite+su_trigger"

        ctx.exploit_result.privesc_method = privesc_method  # type: ignore[union-attr]

        if privesc_method == "kernel_cred_overwrite":
            console.print("  [bold green]✓ Exploit verified — kernel privilege escalation (cred overwrite)[/]")
        elif privesc_method == "kernel_cred_overwrite+su_trigger":
            console.print("  [bold green]✓ Exploit verified — kernel cred overwrite (su used for trigger setup only)[/]")
        elif privesc_method == "su_binary":
            # This is NOT a real exploit — su did the privesc, not the vulnerability
            console.print("  [yellow]✗ Root achieved via su binary, NOT via kernel vulnerability[/]")
            console.print("  [yellow]  The exploit must achieve privesc through kernel cred overwrite, not su.[/]")
            result["success"] = False
            ctx.exploit_result.privilege_escalation_confirmed = False  # type: ignore[union-attr]
        else:
            console.print("  [bold green]✓ Exploit verified — privilege escalation confirmed[/]")

        # Report blocked CVE classes if applicable
        classification = ctx.analysis_data.get("exploit_classification", {})
        blocked = classification.get("blocked_cve_classes", [])
        if blocked and privesc_method == "su_binary":
            for bc in blocked:
                cve_id = getattr(ctx.root_cause, "cve_id", "") or (
                    getattr(ctx, "input_value", "") if ctx.root_cause else ""
                )
                if any(cve_id.upper().replace("-", "").endswith(c.replace("CVE-", "").replace("-", ""))
                       for c in bc.get("affected_cves", [])):
                    console.print(f"  [yellow]⚠ {bc['reason']}[/]")
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
        crash_log_excerpt=result.get("crash_log_excerpt", "")[:4000],
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

    # ── Idempotency: skip if R/W primitive already resolved ──────
    if (
        ctx.analysis_data
        and (
            ctx.analysis_data.get("rw_primitive")
            or ctx.analysis_data.get("rw_primitive_recommendations")
        )
        and not kwargs.get("force", False)
    ):
        existing = ctx.analysis_data.get("rw_primitive") or ctx.analysis_data.get("rw_primitive_recommendations")
        label = existing.get("name", "") if isinstance(existing, dict) else "recommendations"
        console.print(
            f"[dim]→ get_rw_primitive: already have R/W primitive data "
            f"({label}). Pass force=True to re-run.[/]"
        )
        ctx.log("tool", "get_rw_primitive", "skipped: already resolved")
        return ctx

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
        recs = lib.recommend_for_vuln(vuln_type=vuln_type)
        prompt_text = lib.format_for_prompt([r["name"] for r in recs] if recs else None)
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


# ── adapt_templates ───────────────────────────────────────────────────

@default_registry.register(
    name="adapt_templates",
    description=(
        "Adapt template library code (post_exploit, arb_rw, heap_spray) "
        "for the specific CVE, kernel version, and exploitation technique.  "
        "Uses root cause analysis, kernel offsets, reference exploit code, "
        "and exploitation technique details to modify the tested template "
        "C source files so they work correctly for the target.  "
        "Call this AFTER analyze and resolve_kernel_offsets, BEFORE exploit.  "
        "Stores adapted templates in analysis_data['adapted_templates']."
    ),
)
def tool_adapt_templates(ctx: TaskContext, cfg: Config, **kwargs: Any) -> TaskContext:
    from ..exploit.generator import adapt_template_code
    from ..exploit.template_manager import find_relevant_templates

    if not ctx.root_cause:
        ctx.errors.append("adapt_templates: no root cause analysis available")
        return ctx

    plan = getattr(ctx, "exploit_plan", None)
    technique = kwargs.get("technique", "")
    target_struct = kwargs.get("target_struct", "")
    slab_cache = kwargs.get("slab_cache", "")
    vuln_type = kwargs.get("vuln_type", "")

    # Use plan attributes if available
    if plan:
        technique = technique or plan.technique
        target_struct = target_struct or (plan.target_struct or "")
        slab_cache = slab_cache or (plan.slab_cache or "")
        vuln_type = vuln_type or (
            plan.vulnerability_type.value
            if hasattr(plan.vulnerability_type, "value")
            else str(plan.vulnerability_type)
        )
    elif ctx.root_cause:
        vuln_type = vuln_type or (ctx.root_cause.vulnerability_type or "")
        if ctx.root_cause.affected_structs:
            target_struct = target_struct or ctx.root_cause.affected_structs[0]

    # Determine steps from plan
    steps = None
    if plan and plan.steps:
        steps = [s.name for s in plan.steps]

    # Find relevant template categories
    categories = find_relevant_templates(
        technique=technique,
        target_struct=target_struct,
        slab_cache=slab_cache,
        vuln_type=vuln_type,
        steps=steps,
    )

    # Filter to only adaptable categories (not util/binder_client/multi_process)
    adaptable = {"post_exploit", "arb_rw", "heap_spray"}
    categories = [c for c in categories if c in adaptable]

    if not categories:
        console.print("  [dim]No adaptable templates found for this exploit[/]")
        ctx.log("tool", "adapt_templates", "no relevant templates")
        return ctx

    console.print(
        f"  [bold]Adapting templates: {', '.join(categories)}[/]"
    )

    # Gather context
    arch_str = "arm64"
    if hasattr(ctx, "target_arch") and ctx.target_arch:
        arch_str = ctx.target_arch.value if hasattr(ctx.target_arch, "value") else str(ctx.target_arch)

    kernel_offsets_header = ""
    if hasattr(ctx, "kernel_offsets_header") and ctx.kernel_offsets_header:
        kernel_offsets_header = ctx.kernel_offsets_header

    target_cve = ctx.input_value or ""

    # Exploitation technique context from root cause
    exploitation_technique_context = ""
    if ctx.root_cause and ctx.root_cause.exploitation_details:
        details = ctx.root_cause.exploitation_details
        if isinstance(details, dict):
            parts = []
            for k, v in details.items():
                parts.append(f"{k}: {v}")
            exploitation_technique_context = "\n".join(parts)
        else:
            exploitation_technique_context = str(details)

    # Reference exploit context — try multiple sources
    reference_exploit_context = ""
    if hasattr(ctx, "analysis_data") and ctx.analysis_data:
        ref = ctx.analysis_data.get("reference_exploit", "")
        if ref:
            reference_exploit_context = str(ref)[:30000]
    if not reference_exploit_context:
        # Try to find a reference exploit via the pipeline's search logic
        try:
            from ..exploit.pipeline import _find_reference_exploit
            reference_exploit_context = _find_reference_exploit(ctx)
        except Exception:
            pass

    # Previous feedback
    previous_feedback = ""
    exploit_attempts = ctx.exploit_verification_attempts()
    if exploit_attempts:
        last = exploit_attempts[-1]
        parts = []
        if hasattr(last, "compilation_errors") and last.compilation_errors:
            parts.append(f"Compilation errors:\n{last.compilation_errors}")
        if hasattr(last, "runtime_output") and last.runtime_output:
            parts.append(f"Runtime output:\n{last.runtime_output}")
        previous_feedback = "\n".join(parts)[:6000]

    # Kernel source context
    kernel_source_context = ""
    if hasattr(ctx, "analysis_data") and ctx.analysis_data:
        ksc = ctx.analysis_data.get("kernel_source_context", "")
        if ksc:
            kernel_source_context = str(ksc)[:10000]

    # Adapt each category
    all_adapted = {}
    for cat in categories:
        adapted = adapt_template_code(
            cat,
            plan=plan,
            root_cause=ctx.root_cause,
            kernel_offsets_header=kernel_offsets_header,
            kernel_source_context=kernel_source_context,
            reference_exploit_context=reference_exploit_context,
            exploitation_technique_context=exploitation_technique_context,
            previous_feedback=previous_feedback,
            target_cve=target_cve,
            arch=arch_str,
            cfg=cfg,
        )
        if adapted:
            all_adapted[cat] = adapted
            console.print(
                f"  [green]Adapted {cat}: "
                f"{', '.join(f'{k} ({len(v)} chars)' for k, v in adapted.items())}[/]"
            )

    # Store adapted templates in context for use by exploit pipeline
    if not hasattr(ctx, "analysis_data") or ctx.analysis_data is None:
        ctx.analysis_data = {}
    ctx.analysis_data["adapted_templates"] = all_adapted

    ctx.log(
        "tool", "adapt_templates",
        f"adapted {len(all_adapted)} categories: {', '.join(all_adapted.keys())}",
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

    # Derive technique/struct/slab from plan or kwargs for template matching
    technique = kwargs.get("technique", "")
    target_struct = kwargs.get("target_struct", "")
    slab_cache = kwargs.get("slab_cache", "")
    vuln_type = kwargs.get("vuln_type", "")
    plan = getattr(ctx, "exploit_plan", None)
    if plan:
        technique = technique or plan.technique
        target_struct = target_struct or (plan.target_struct or "")
        slab_cache = slab_cache or (plan.slab_cache or "")
        vuln_type = vuln_type or (
            plan.vulnerability_type.value
            if hasattr(plan.vulnerability_type, "value")
            else str(plan.vulnerability_type)
        )

    if write_to_disk and ctx.work_dir:
        created = scaffold.write()
        ctx.log("tool", "scaffold_exploit", f"wrote {len(created)} files to {scaffold_dir}")
        console.print(f"  Scaffold: {len(created)} files → {scaffold_dir}")
    else:
        files = scaffold.generate_with_templates(
            technique=technique,
            target_struct=target_struct,
            slab_cache=slab_cache,
            vuln_type=vuln_type,
        )
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
        vuln_type=vuln_type, slab_cache=slab_cache or None,
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
        "Available: fork_parent_target (child-corrupts-parent), "
        "fork_shared_memory (shared mmap IPC), pipeline_processes, "
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
        "(scatter-gather UAF pattern), service_manager_lookup.  "
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


# ── analyze_conditions ────────────────────────────────────────────────

@default_registry.register(
    name="analyze_conditions",
    description=(
        "Extract pre/post conditions for the current vulnerability.  "
        "Preconditions include input constraints (syscall args, ioctl "
        "commands, timing windows), kernel state requirements (CONFIG "
        "options, slab cache existence, SELinux mode), and process "
        "requirements (capabilities, namespaces).  Postconditions "
        "describe what capabilities each exploit phase yields (dangling "
        "pointer, controlled data, arbitrary R/W, cred overwrite).  "
        "Results are stored in ctx.vuln_conditions and automatically "
        "injected into planner and generator prompts."
    ),
)
def tool_analyze_conditions(ctx: TaskContext, cfg: Config, **kwargs: Any) -> TaskContext:
    import re as _re
    from ..analysis.vuln_conditions import extract_conditions

    # ── Idempotency: skip if conditions already extracted ─────────
    if (
        ctx.vuln_conditions is not None
        and not kwargs.get("force", False)
    ):
        console.print(
            "[dim]→ analyze_conditions: already completed "
            "(vuln_conditions present). Pass force=True to re-run.[/]"
        )
        ctx.log("tool", "analyze_conditions", "skipped: already completed")
        return ctx

    if not ctx.root_cause:
        ctx.errors.append(
            "analyze_conditions: no root cause analysis available — "
            "run 'analyze' or 'investigate' first"
        )
        return ctx

    cve_id = ""
    m = _re.search(r"(CVE-\d{4}-\d+)", ctx.root_cause.summary or "", _re.IGNORECASE)
    if m:
        cve_id = m.group(1)
    if not cve_id and ctx.input_value:
        m = _re.search(r"(CVE-\d{4}-\d+)", ctx.input_value, _re.IGNORECASE)
        if m:
            cve_id = m.group(1)

    console.print("[dim]→ extracting vulnerability pre/post conditions…[/]")

    conditions = extract_conditions(
        cve_id=cve_id,
        vuln_type=ctx.root_cause.vulnerability_type.value,
        subsystem=ctx.root_cause.affected_subsystem,
        crash_report=ctx.crash_report,
        root_cause=ctx.root_cause,
        exploit_plan=ctx.exploit_plan,
    )

    ctx.vuln_conditions = conditions

    pre_count = len(conditions.preconditions)
    post_count = len(conditions.postconditions)

    console.print(
        f"  {pre_count} preconditions, {post_count} postconditions extracted"
    )

    if conditions.required_configs:
        console.print(
            f"  Required configs: {', '.join(conditions.required_configs)}"
        )
    if conditions.required_devices:
        console.print(
            f"  Required devices: {', '.join(conditions.required_devices[:5])}"
        )

    # Store formatted context in analysis_data for reference
    if ctx.analysis_data is None:
        ctx.analysis_data = {}
    ctx.analysis_data["vuln_conditions"] = conditions.to_dict()
    ctx.analysis_data["vuln_conditions_planner"] = conditions.format_for_planner()
    ctx.analysis_data["vuln_conditions_generator"] = conditions.format_for_generator()
    gdb_checks = conditions.all_gdb_checks()
    if gdb_checks:
        ctx.analysis_data["vuln_conditions_gdb_checks"] = gdb_checks

    ctx.log(
        "tool", "analyze_conditions",
        f"{pre_count} pre, {post_count} post, cve={cve_id}"
    )

    return ctx


# ── analyze_struct ────────────────────────────────────────────────────

@default_registry.register(
    name="analyze_struct",
    description=(
        "Analyze kernel struct layouts from the target kernel image "
        "using pahole/DWARF/BTF — no CodeQL database needed.  Extracts "
        "field offsets, sizes, types, function pointer positions, "
        "list_head fields, and determines the slab cache for each "
        "struct.  Can find substitute objects that share the same slab "
        "cache and properties (useful when the original reclaim object "
        "is not available on the target kernel).  Pass struct_names to "
        "analyze, or leave empty to auto-detect from root cause.  "
        "Requires vmlinux with DWARF or BTF data."
    ),
)
def tool_analyze_struct(ctx: TaskContext, cfg: Config, **kwargs: Any) -> TaskContext:
    from ..analysis.image_struct_analyzer import ImageStructAnalyzer

    # ── Idempotency: skip if struct analysis already done ─────────
    existing = ctx.analysis_data.get("struct_layouts")
    if (
        existing
        and not kwargs.get("force", False)
    ):
        console.print(
            "[dim]→ analyze_struct: already completed "
            f"({len(existing)} struct(s) analyzed). Pass force=True to re-run.[/]"
        )
        ctx.log("tool", "analyze_struct", "skipped: already completed")
        return ctx

    vmlinux_path = kwargs.get("vmlinux_path") or getattr(cfg, "vmlinux_path", None)
    if not vmlinux_path:
        # Try work_dir/vmlinux
        if ctx.work_dir:
            candidate = Path(ctx.work_dir) / "vmlinux"
            if candidate.exists():
                vmlinux_path = str(candidate)
    if not vmlinux_path:
        ctx.errors.append(
            "analyze_struct: no vmlinux path — set via SYZPLOIT_VMLINUX_PATH "
            "or pass vmlinux_path"
        )
        return ctx

    struct_names = kwargs.get("struct_names", [])
    if isinstance(struct_names, str):
        struct_names = [s.strip() for s in struct_names.split(",") if s.strip()]
    find_substitutes = kwargs.get("find_substitutes", False)
    target_struct = kwargs.get("target_struct", "")

    # Auto-detect struct names from context
    if not struct_names:
        if ctx.exploit_plan and ctx.exploit_plan.target_struct:
            struct_names.append(
                ctx.exploit_plan.target_struct.replace("struct ", "")
            )
        if ctx.root_cause:
            for s in ctx.root_cause.affected_structs[:5]:
                clean = s.replace("struct ", "")
                if clean not in struct_names:
                    struct_names.append(clean)
    if not struct_names:
        ctx.errors.append(
            "analyze_struct: no struct names specified or detectable "
            "from root cause / exploit plan"
        )
        return ctx

    console.print(
        f"[dim]→ analyzing {len(struct_names)} struct(s) from vmlinux…[/]"
    )

    slabinfo_text = ""
    if ctx.target_system_info and hasattr(ctx.target_system_info, "slabinfo"):
        slabinfo_text = ctx.target_system_info.slabinfo or ""
    kallsyms = None
    if ctx.target_system_info:
        kallsyms = getattr(ctx.target_system_info, "kallsyms_path", None)

    analyzer = ImageStructAnalyzer(
        vmlinux_path=str(vmlinux_path),
        kallsyms_path=str(kallsyms) if kallsyms else None,
        slabinfo_text=slabinfo_text,
        btf_json_path=kwargs.get("btf_json_path") or getattr(cfg, "btf_json_path", None),
        image_label=kwargs.get("image_label", "target"),
    )

    results = {}
    for name in struct_names:
        layout = analyzer.get_struct_layout(name)
        if layout:
            props = analyzer.get_struct_properties(name)
            results[name] = {
                "layout": layout.to_dict(),
                "properties": props.to_dict() if props else None,
                "slab_cache": analyzer.get_slab_cache(name),
            }
            console.print(
                f"  {name}: {layout.size} bytes, cache={layout.kmalloc_cache()}, "
                f"func_ptrs={layout.has_function_pointers}, "
                f"fields={len(layout.fields)}"
            )
        else:
            results[name] = {"error": "struct not found in vmlinux DWARF/BTF"}
            console.print(f"  {name}: NOT FOUND in vmlinux")

    # Find substitutes if requested
    substitute_text = ""
    sub_target = target_struct or (struct_names[0] if struct_names else "")
    if find_substitutes and sub_target:
        substitute_text = analyzer.format_substitutes_for_prompt(sub_target)
        if substitute_text:
            console.print(f"  Substitutes for {sub_target} found")

    # Format for prompts
    struct_context = analyzer.format_for_prompt(struct_names=struct_names)
    if substitute_text:
        struct_context += "\n\n" + substitute_text

    # Store in analysis_data
    if ctx.analysis_data is None:
        ctx.analysis_data = {}
    ctx.analysis_data["struct_analysis"] = results
    ctx.analysis_data["struct_analysis_prompt"] = struct_context

    # Also store as kernel_source_context supplement
    if struct_context:
        ctx.kernel_source_context = (
            (ctx.kernel_source_context + "\n\n" + struct_context)
            if ctx.kernel_source_context
            else struct_context
        )

    ok = sum(1 for v in results.values() if "error" not in v)
    ctx.log(
        "tool", "analyze_struct",
        f"{ok}/{len(struct_names)} structs analyzed"
    )

    return ctx


# ── run_exploit_monitor ───────────────────────────────────────────────

@default_registry.register(
    name="run_exploit_monitor",
    description=(
        "Generate comprehensive GDB monitoring scripts for exploit "
        "debugging with heap tracking, phase detection, and state "
        "snapshots.  Unlike basic verify_exploit GDB tracing, this "
        "tracks EVERY heap allocation/free (via kmalloc/kfree "
        "breakpoints), detects reclaim success (freed pointer reused), "
        "double-free bugs, and exploit phase transitions (trigger → "
        "spray → reclaim → rw → privesc).  Uses HARDWARE breakpoints "
        "first (reliable under KVM, limited to 4 on ARM64) then falls "
        "back to software breakpoints for remaining functions.  "
        "Generates scripts in "
        "the work directory that can be used with gdb-multiarch.  Also "
        "parses existing monitor results if scripts have already been "
        "run."
    ),
)
def tool_run_exploit_monitor(ctx: TaskContext, cfg: Config, **kwargs: Any) -> TaskContext:
    from ..exploit.gdb_exploit_monitor import ExploitMonitor

    vmlinux_path = kwargs.get("vmlinux_path") or getattr(cfg, "vmlinux_path", None)

    # Resolve kallsyms
    kallsyms_path = getattr(ctx, "kallsyms_path", None)
    if not kallsyms_path and ctx.target_system_info:
        kallsyms_path = getattr(ctx.target_system_info, "kallsyms_path", None)
    if not kallsyms_path and ctx.work_dir:
        candidate = Path(ctx.work_dir) / "kallsyms"
        if candidate.exists():
            kallsyms_path = str(candidate)

    if not kallsyms_path and not vmlinux_path:
        ctx.errors.append(
            "run_exploit_monitor: need either kallsyms_path or vmlinux_path "
            "to resolve kernel symbols for breakpoints"
        )
        return ctx

    # Build symbol list
    target_symbols = kwargs.get("target_symbols", [])
    if isinstance(target_symbols, str):
        target_symbols = [s.strip() for s in target_symbols.split(",") if s.strip()]

    if not target_symbols:
        # Auto-populate from context
        target_symbols = [
            "commit_creds", "prepare_kernel_cred",
            "__sys_setresuid", "__sys_setresgid",
        ]
        if ctx.root_cause:
            if ctx.root_cause.vulnerable_function:
                target_symbols.insert(0, ctx.root_cause.vulnerable_function)
            for fn in (ctx.root_cause.kernel_functions or [])[:8]:
                if fn not in target_symbols:
                    target_symbols.append(fn)
        if ctx.exploit_plan:
            technique = getattr(ctx.exploit_plan, "technique", "")
            if "binder" in technique.lower():
                for fn in ["binder_transaction", "binder_free_node",
                           "binder_alloc_new_buf"]:
                    if fn not in target_symbols:
                        target_symbols.append(fn)

        # Add condition-derived symbols
        vuln_conditions = getattr(ctx, "vuln_conditions", None)
        if vuln_conditions:
            for check_entry in vuln_conditions.all_gdb_checks():
                check_str = (
                    check_entry.get("check", "")
                    if isinstance(check_entry, dict)
                    else str(check_entry)
                )
                for word in check_str.split():
                    if word.isidentifier() and word not in ("b", "p", "x", "info"):
                        if word not in target_symbols:
                            target_symbols.append(word)

    console.print(
        f"[dim]→ generating exploit monitor scripts "
        f"({len(target_symbols)} symbols)…[/]"
    )

    arch = (
        ctx.target_arch.value
        if hasattr(ctx, "target_arch") and ctx.target_arch
        else "arm64"
    )
    monitor = ExploitMonitor(
        kallsyms_path=str(kallsyms_path) if kallsyms_path else None,
        vmlinux_path=str(vmlinux_path) if vmlinux_path else None,
        arch=arch,
        target_symbols=target_symbols,
        heap_tracking=kwargs.get("heap_tracking", False),
        max_events=kwargs.get("max_events", 5000),
        throttle_per_bp=kwargs.get("throttle_per_bp", 100),
    )

    work_dir = ctx.work_dir or Path.cwd() / "syzploit_output"
    monitor_dir = Path(work_dir) / "exploit_monitor"
    monitor_dir.mkdir(parents=True, exist_ok=True)

    # Generate scripts
    script_path = monitor.generate_monitor_script(str(monitor_dir))
    commands_path = monitor.generate_commands_file(
        str(monitor_dir),
        port=ctx.gdb_port or 1234,
    )

    console.print(f"  Monitor script: {script_path}")
    console.print(f"  GDB commands: {commands_path}")
    console.print(
        f"  [dim]Run with: gdb-multiarch -x {commands_path}[/]"
    )

    # Parse existing results if available (from a previous run)
    parse_only = kwargs.get("parse_only", False)
    results_file = monitor_dir / "monitor_events.json"
    if parse_only or results_file.is_file():
        results = monitor.parse_monitor_results(str(monitor_dir))
        if results and results.get("events"):
            feedback = monitor.format_results_for_prompt(results)
            if feedback:
                console.print(f"  {results.get('total_events', 0)} events parsed")

                # Store results
                if ctx.analysis_data is None:
                    ctx.analysis_data = {}
                ctx.analysis_data["exploit_monitor_results"] = feedback
                ctx.analysis_data["exploit_monitor_raw"] = {
                    "bp_hits": results.get("bp_hits", {}),
                    "phase_history": results.get("phase_history", []),
                    "total_events": results.get("total_events", 0),
                }

                # Add to GDB trace accumulator
                ctx.gdb_trace_results.append({
                    "target": "exploit",
                    "attempt": len(ctx.gdb_trace_results) + 1,
                    "monitor_type": "exploit_monitor",
                    "heap_events": results.get("total_events", 0),
                    "phases_detected": results.get("phase_history", []),
                    "functions_hit": list(results.get("bp_hits", {}).keys()),
                    "functions_missed": [
                        s for s in target_symbols
                        if s not in results.get("bp_hits", {})
                    ],
                })
        else:
            console.print("  [dim]No monitor results found to parse[/]")

    ctx.log(
        "tool", "run_exploit_monitor",
        f"generated scripts in {monitor_dir}, "
        f"{len(target_symbols)} symbols"
    )

    return ctx


# ── review_exploit_code ───────────────────────────────────────────────

@default_registry.register(
    name="review_exploit_code",
    description=(
        "Review the generated exploit source code.  Returns every source "
        "file produced by the last 'exploit' or 'complete_exploit' call "
        "so you can inspect it, spot bugs, identify stub placeholders, "
        "or decide what to fix before running 'verify_exploit'.  Also "
        "shows compilation notes, binary path, and exploit plan summary."
    ),
)
def tool_review_exploit_code(
    ctx: TaskContext, cfg: Config, **kwargs: Any
) -> TaskContext:
    er = ctx.exploit_result
    if er is None:
        ctx.errors.append(
            "review_exploit_code: no exploit_result available — "
            "run 'exploit' or 'complete_exploit' first"
        )
        return ctx

    lines: list[str] = []
    lines.append("=== Exploit Code Review ===")
    lines.append(f"Compilation success: {er.success}")
    if er.binary_path:
        lines.append(f"Binary: {er.binary_path}")
    if er.target_kernel:
        lines.append(f"Target kernel: {er.target_kernel}")
    if er.notes:
        lines.append(f"Notes: {'; '.join(er.notes[:10])}")

    # Plan summary
    if er.plan:
        lines.append(f"\n--- Exploit Plan ---")
        lines.append(f"Technique: {er.plan.technique}")
        if er.plan.slab_cache:
            lines.append(f"Slab cache: {er.plan.slab_cache}")
        if er.plan.steps:
            for i, step in enumerate(er.plan.steps[:15], 1):
                lines.append(f"  Step {i}: {step}")

    # Source files (full content)
    if er.source_files:
        for fname, content in er.source_files.items():
            lines.append(f"\n--- {fname} ---")
            lines.append(content)
    elif er.source_code:
        lines.append(f"\n--- exploit source ---")
        lines.append(er.source_code)
    else:
        lines.append("\n(no source code stored in exploit_result)")

    review_text = "\n".join(lines)

    # Store review in analysis_data so it shows up in accumulated knowledge
    if ctx.analysis_data is None:
        ctx.analysis_data = {}
    ctx.analysis_data["exploit_code_review"] = review_text

    ctx.log(
        "tool", "review_exploit_code",
        f"reviewed {len(er.source_files)} source files, "
        f"success={er.success}"
    )

    return ctx


# ── reflect ───────────────────────────────────────────────────────────

@default_registry.register(
    name="reflect",
    description=(
        "Pause and reflect on all gathered data.  Runs a lightweight "
        "LLM interpretation that examines accumulated knowledge "
        "(root cause, investigation, feasibility, spray strategy, "
        "kernel offsets, verification results, errors) and produces a "
        "concise action brief with: COMPLETED phases, remaining GAPS, "
        "KEY INSIGHTS from the data, and RECOMMENDED NEXT STEPS.  "
        "Costs very few tokens.  Call this when unsure what to do next, "
        "or after gathering several pieces of data to synthesise them."
    ),
)
def tool_reflect(ctx: TaskContext, cfg: Config, **kwargs: Any) -> TaskContext:
    """Manually-triggered reflection — delegates to the Agent's
    ``_reflect`` method.  When invoked as a tool (outside the Agent
    loop), it runs a standalone reflection using a fresh LLM call.
    """
    from ..core.llm import LLMClient

    # Build a reflection prompt inline (same as Agent._reflect but
    # standalone so it works outside the agentic loop too)
    gathered = ctx.decision_context_summary() or "(no data gathered yet)"
    state = ctx.state_snapshot()
    state_lines = "\n".join(f"  {k}: {v}" for k, v in sorted(state.items()))
    gathered = f"State:\n{state_lines}\n\n{gathered}"

    history_lines = "\n".join(
        f"  {i+1}. {h['tool']} → {h['action'][:80]}"
        for i, h in enumerate(ctx.history[-15:])
    )
    errors = "; ".join(ctx.errors[-5:]) if ctx.errors else "none"

    prompt = f"""\
You are the syzploit orchestrator's reflection module, thinking like an
experienced **vulnerability researcher and exploit developer**.  Interpret
ALL gathered data through the lens of practical exploit development.

Target: {ctx.input_type} = {ctx.input_value[:200]}
Target kernel: {ctx.target_kernel or '(unknown)'}

──── GATHERED CONTEXT ────
{gathered}

──── TOOL HISTORY ────
{history_lines or '(none yet)'}

──── ERRORS ────
{errors}

Think like a vulnerability researcher.  For each exploit phase, assess
whether it's WORKING, PARTIAL, or BROKEN.  Check if kread64/kwrite64
are real implementations or stubs.  Check if the trigger actually
reaches the vulnerable code path.

Produce a brief (≤ 350 words) with these sections:

COMPLETED:
- Bullet list of phases/data that are done

EXPLOITATION CHAIN STATUS:
- Trigger: [WORKING|PARTIAL|BROKEN] — one-line assessment
- Reclaim/Spray: [WORKING|PARTIAL|BROKEN] — one-line assessment
- R/W Primitive: [WORKING|PARTIAL|BROKEN] — one-line assessment
- Privilege Escalation: [WORKING|PARTIAL|BROKEN] — one-line assessment

GAPS:
- What is still missing or incomplete (prioritised by exploit impact)

KEY INSIGHTS (VULNERABILITY RESEARCHER PERSPECTIVE):
- 1-3 technical observations a real exploit developer would make
- If exploit failed verification, explain WHY technically

RECOMMENDED NEXT STEPS:
1. Specific tool + technical reasoning
2. Second priority
3. (Optional) third

DO NOT suggest re-running tools whose data is already gathered.
If exploit has stub functions, recommend 'complete_exploit' FIRST.
"""

    try:
        llm = LLMClient(cfg)
        decision_llm = llm.for_task("decision")
        brief = decision_llm.ask(prompt, max_tokens=512, json_mode=False)
        ctx.reflection_brief = brief.strip()
        ctx.reflection_count += 1
        ctx.log("tool", "reflect", f"reflection #{ctx.reflection_count}")
        console.print(f"[bold blue]Reflection #{ctx.reflection_count}[/] completed")
    except Exception as exc:
        ctx.errors.append(f"reflect: LLM call failed: {exc}")
        ctx.log("tool", "reflect_error", str(exc))

    return ctx


# ── summarize_progress ────────────────────────────────────────────────

@default_registry.register(
    name="summarize_progress",
    description=(
        "Generate a comprehensive progress summary of the current run.  "
        "Shows accumulated knowledge: root cause analysis, feasibility, "
        "investigation findings, exploit plan, strategy tracker state, "
        "verification history, GDB traces, error log, and all keys in "
        "analysis_data.  Use this when you need to take stock of what "
        "you know so far and decide what to do next."
    ),
)
def tool_summarize_progress(
    ctx: TaskContext, cfg: Config, **kwargs: Any
) -> TaskContext:
    lines: list[str] = []
    lines.append("=== Progress Summary ===")
    lines.append(f"Input: {ctx.input_type} — {ctx.input_value}")

    # State snapshot
    snap = ctx.state_snapshot()
    flags = [k for k, v in snap.items() if v is True]
    lines.append(f"State flags: {', '.join(flags) if flags else '(none set)'}")

    # Decision context (the rich summary)
    summary = ctx.decision_context_summary()
    if summary:
        lines.append(f"\n{summary}")

    # Verification history
    ev = ctx.exploit_verification_attempts()
    if ev:
        lines.append(f"\n--- Verification History ({len(ev)} attempts) ---")
        for i, v in enumerate(ev, 1):
            lines.append(
                f"  #{i}: success={v.success}, "
                f"reason={v.failure_reason or 'n/a'}"
            )
            if v.feedback:
                lines.append(f"       feedback: {v.feedback[:300]}")

    # Error log
    if ctx.errors:
        lines.append(f"\n--- Errors ({len(ctx.errors)}) ---")
        for e in ctx.errors[-10:]:
            lines.append(f"  • {e[:200]}")

    progress_text = "\n".join(lines)

    if ctx.analysis_data is None:
        ctx.analysis_data = {}
    ctx.analysis_data["progress_summary"] = progress_text

    ctx.log("tool", "summarize_progress", f"generated progress summary")

    return ctx


# ── hunt_cves ─────────────────────────────────────────────────────────

@default_registry.register(
    name="hunt_cves",
    description=(
        "Search online for CVEs affecting the target kernel version.  "
        "Queries NVD, Android Security Bulletins, GitHub, and nomi-sec "
        "PoC aggregator, then uses LLM to rank candidates by "
        "exploitability.  Returns a prioritised list of CVE targets.  "
        "Use 'max_results' kwarg to limit (default 10).  Results are "
        "stored in analysis_data['hunted_cves']."
    ),
)
def tool_hunt_cves(ctx: TaskContext, cfg: Config, **kwargs: Any) -> TaskContext:
    from ..analysis.cve_hunter import hunt_cves

    kernel_version = ctx.target_kernel or kwargs.get("kernel_version", "")
    if not kernel_version:
        ctx.errors.append(
            "hunt_cves: no target kernel version. Set --kernel or pass kernel_version."
        )
        return ctx

    platform = ctx.target_platform.value if ctx.target_platform else "android"
    arch = ctx.target_arch.value if ctx.target_arch else "arm64"
    max_results = kwargs.get("max_results", 10)

    candidates = hunt_cves(
        kernel_version,
        platform=platform,
        arch=arch,
        max_results=max_results,
        cfg=cfg,
    )

    if ctx.analysis_data is None:
        ctx.analysis_data = {}
    ctx.analysis_data["hunted_cves"] = [c.to_dict() for c in candidates]

    ctx.log(
        "tool", "hunt_cves",
        f"found {len(candidates)} CVE targets for kernel {kernel_version}"
    )

    if candidates:
        console.print(f"  [bold green]{len(candidates)} CVE targets identified[/]")
    else:
        ctx.errors.append("hunt_cves: no CVE candidates found for this kernel")

    return ctx


# ── benchmark_exploit ─────────────────────────────────────────────────

@default_registry.register(
    name="benchmark_exploit",
    description=(
        "Run the exploit N times and collect reliability statistics: "
        "success rate, timing (mean/p50/p95/p99), crash rate, KASAN hit "
        "rate, and failure mode breakdown.  Results are stored in "
        "analysis_data['benchmark'].  Use 'iterations' kwarg (default 10)."
    ),
)
def tool_benchmark_exploit(ctx: TaskContext, cfg: Config, **kwargs: Any) -> TaskContext:
    from ..analysis.benchmark import benchmark_exploit

    if not ctx.has_exploit():
        ctx.errors.append("benchmark_exploit: no exploit available — run 'exploit' first")
        return ctx

    binary = ctx.exploit_result.binary_path  # type: ignore[union-attr]
    if not binary:
        ctx.errors.append("benchmark_exploit: exploit has no binary_path")
        return ctx

    iterations = kwargs.get("iterations", 10)
    console.print(f"[dim]→ benchmarking exploit ({iterations} iterations)…[/]")

    result = benchmark_exploit(
        binary_path=binary,
        iterations=iterations,
        ssh_host=ctx.ssh_host or "",
        ssh_port=ctx.ssh_port,
        instance=ctx.instance,
        adb_port=kwargs.get("adb_port", 6520),
        use_adb=ctx.target_platform and ctx.target_platform.value == "android",
        cooldown=kwargs.get("cooldown", 3.0),
        reboot_on_crash=kwargs.get("reboot_on_crash", True),
        cfg=cfg,
    )

    if ctx.analysis_data is None:
        ctx.analysis_data = {}
    ctx.analysis_data["benchmark"] = result.__dict__

    ctx.log("tool", "benchmark_exploit",
            f"success_rate={result.success_rate:.0%}, "
            f"crash_rate={result.crash_rate:.0%}, "
            f"p50={result.timing_p50:.1f}s")

    console.print(
        f"  [bold]Success: {result.success_rate:.0%} | "
        f"Crash: {result.crash_rate:.0%} | "
        f"p50: {result.timing_p50:.1f}s[/]"
    )
    return ctx


# ── analyze_kernel_config ─────────────────────────────────────────────

@default_registry.register(
    name="analyze_kernel_config",
    description=(
        "Analyse the target kernel's .config for exploitation-relevant "
        "mitigations (SLAB_FREELIST_HARDENED, CFI, KASLR, KASAN, etc.).  "
        "Can pull config from a running device via ADB or parse a "
        "provided config file.  Results stored in "
        "analysis_data['kernel_config']."
    ),
)
def tool_analyze_kernel_config(ctx: TaskContext, cfg: Config, **kwargs: Any) -> TaskContext:
    from ..analysis.kernel_config import analyze_kernel_config

    config_path = kwargs.get("config_path")
    use_adb = kwargs.get("use_adb", True)

    console.print("[dim]→ analysing kernel config…[/]")

    result = analyze_kernel_config(
        config_path=config_path,
        adb_port=kwargs.get("adb_port", 6520),
        instance=ctx.instance,
        use_adb=use_adb and ctx.target_platform
                and ctx.target_platform.value == "android",
    )

    if ctx.analysis_data is None:
        ctx.analysis_data = {}
    ctx.analysis_data["kernel_config"] = result.__dict__

    ctx.log("tool", "analyze_kernel_config",
            f"hardening={result.hardening_level}, "
            f"enabled={len(result.enabled_mitigations)}, "
            f"disabled={len(result.disabled_mitigations)}")

    console.print(
        f"  [bold]Hardening: {result.hardening_level} | "
        f"{len(result.enabled_mitigations)} mitigations enabled[/]"
    )
    return ctx


# ── measure_crash_stability ──────────────────────────────────────────

@default_registry.register(
    name="measure_crash_stability",
    description=(
        "Run the reproducer multiple times and measure crash trigger "
        "reliability: crash rate, signature consistency, timing jitter. "
        "Verdict is one of: deterministic, mostly_reliable, "
        "race_dependent, rare_trigger, no_crash.  Use 'iterations' "
        "kwarg (default 5).  Results in analysis_data['crash_stability']."
    ),
)
def tool_measure_crash_stability(ctx: TaskContext, cfg: Config, **kwargs: Any) -> TaskContext:
    from ..analysis.crash_stability import measure_crash_stability

    if not ctx.has_reproducer():
        ctx.errors.append("measure_crash_stability: no reproducer available")
        return ctx

    reproducer_path = ctx.reproducer.source_path or ctx.reproducer.binary_path  # type: ignore[union-attr]
    if not reproducer_path:
        ctx.errors.append("measure_crash_stability: reproducer has no path")
        return ctx

    iterations = kwargs.get("iterations", 5)
    console.print(f"[dim]→ measuring crash stability ({iterations} runs)…[/]")

    result = measure_crash_stability(
        reproducer_path=reproducer_path,
        iterations=iterations,
        ssh_host=ctx.ssh_host or "",
        ssh_port=ctx.ssh_port,
        instance=ctx.instance,
        adb_port=kwargs.get("adb_port", 6520),
        use_adb=ctx.target_platform and ctx.target_platform.value == "android",
        expected_signature=kwargs.get("expected_signature", ""),
        cooldown=kwargs.get("cooldown", 3.0),
        cfg=cfg,
    )

    if ctx.analysis_data is None:
        ctx.analysis_data = {}
    ctx.analysis_data["crash_stability"] = result.__dict__

    ctx.log("tool", "measure_crash_stability",
            f"verdict={result.stability_verdict}, "
            f"crash_rate={result.crash_rate:.0%}")

    console.print(
        f"  [bold]Stability: {result.stability_verdict} | "
        f"Crash rate: {result.crash_rate:.0%}[/]"
    )
    return ctx


# ── identify_slab_cache ──────────────────────────────────────────────

@default_registry.register(
    name="identify_slab_cache",
    description=(
        "Identify the slab cache used by the vulnerable object via two "
        "complementary methods: (1) empirical — snapshots /proc/slabinfo "
        "before/after running the reproducer and picks the cache with the "
        "largest delta; (2) source-level — fetches the closest matching "
        "upstream kernel source from android.googlesource.com or "
        "git.kernel.org and searches for kmem_cache_create / KMEM_CACHE / "
        "kmalloc patterns that allocate the target struct.  Cross-references "
        "both signals for high-confidence identification.  "
        "Populates analysis_data['slab_identification']."
    ),
)
def tool_identify_slab_cache(ctx: TaskContext, cfg: Config, **kwargs: Any) -> TaskContext:
    from ..analysis.slab_identifier import identify_slab_cache
    from ..infra.verification import (
        _run_start_cmd, _run_stop_cmd, _is_gdb_start,
        _send_gdb_continue, _setup_adb_tunnel,
        _adb_is_alive, _calc_adb_port,
    )
    import time as _time

    if not ctx.has_reproducer():
        ctx.errors.append("identify_slab_cache: no reproducer available")
        return ctx

    # Prefer binary (compiled ELF) for ADB push+execute; fall back
    # to source only if no binary exists.
    reproducer_path = ctx.reproducer.binary_path or ctx.reproducer.source_path  # type: ignore[union-attr]
    if not reproducer_path:
        ctx.errors.append("identify_slab_cache: reproducer has no path")
        return ctx
    # Ensure it's actually a compiled binary, not a .c source file
    if reproducer_path.endswith((".c", ".cpp", ".h")):
        ctx.errors.append(
            "identify_slab_cache: reproducer is a source file, not a "
            "compiled binary — compile it first with compile_and_push"
        )
        return ctx

    # Gather known struct names from root cause
    known_structs: list[str] = []
    vuln_function = ""
    vuln_file = ""
    if ctx.root_cause:
        known_structs.extend(ctx.root_cause.affected_structs)
        vuln_function = ctx.root_cause.vulnerable_function or ""
        vuln_file = ctx.root_cause.vulnerable_file or ""

    # Resolve kernel version from target system info or crash report
    kernel_ver = ""
    if ctx.target_system_info and ctx.target_system_info.kernel_release:
        kernel_ver = ctx.target_system_info.kernel_release
    elif ctx.crash_report and ctx.crash_report.kernel_version:
        kernel_ver = ctx.crash_report.kernel_version

    console.print("[dim]→ identifying slab cache (empirical + source)…[/]")

    # ── Boot the VM so ADB is available for empirical analysis ────
    ssh_host = ctx.ssh_host or ""
    vm_proc = None
    adb_tunnel = None
    adb_port_val = kwargs.get("adb_port", 6520)
    actual_adb_port = _calc_adb_port(ctx.instance, adb_port_val)

    try:
        # Stop any stale VM first
        if ctx.stop_cmd and ssh_host:
            console.print(
                f"  [dim]identify_slab_cache: stopping stale VM…[/]"
            )
            _run_stop_cmd(
                ctx.stop_cmd, ssh_host=ssh_host, ssh_port=ctx.ssh_port,
            )

        # Start VM
        start_cmd = ctx.exploit_start_cmd or ctx.start_cmd
        if start_cmd and ssh_host:
            console.print(
                f"  [dim]identify_slab_cache: starting VM…[/]"
            )
            ok, vm_proc = _run_start_cmd(
                start_cmd, ssh_host=ssh_host, ssh_port=ctx.ssh_port,
            )
            if not ok:
                ctx.errors.append(
                    "identify_slab_cache: failed to start VM"
                )
                # Fall through — source analysis can still work
            else:
                _time.sleep(5)

                # GDB continue if needed
                if ctx.start_cmd and _is_gdb_start(ctx.start_cmd):
                    # Use the gdb start command if exploit_start_cmd
                    # was preferred above but gdb is the other option
                    pass
                if _is_gdb_start(start_cmd) and ctx.gdb_port:
                    console.print(
                        "  [dim]identify_slab_cache: sending GDB continue…[/]"
                    )
                    _send_gdb_continue(
                        ctx.gdb_port, ssh_host=ssh_host,
                        ssh_port=ctx.ssh_port,
                        setup_tunnels=ctx.setup_tunnels,
                    )
                    _time.sleep(30)

                # Set up ADB tunnel
                if ctx.setup_tunnels and ssh_host:
                    adb_tunnel = _setup_adb_tunnel(
                        actual_adb_port, ssh_host, ctx.ssh_port,
                    )
                    if adb_tunnel:
                        _time.sleep(3)

                # Wait for ADB
                console.print(
                    "  [dim]identify_slab_cache: waiting for ADB…[/]"
                )
                for _attempt in range(18):  # up to 3 min
                    if _adb_is_alive(actual_adb_port):
                        console.print(
                            "  [dim]identify_slab_cache: ADB connected[/]"
                        )
                        break
                    _time.sleep(10)

        result = identify_slab_cache(
            reproducer_path=reproducer_path,
            target_structs=known_structs or None,
            kernel_version=kernel_ver,
            vulnerable_function=vuln_function,
            vulnerable_file=vuln_file,
            ssh_host=ctx.ssh_host or "",
            ssh_port=ctx.ssh_port,
            instance=ctx.instance,
            adb_port=adb_port_val,
        )
    finally:
        # ── Cleanup: stop VM ──────────────────────────────────────
        if adb_tunnel:
            try:
                adb_tunnel.kill()
            except Exception:
                pass
        if ctx.stop_cmd and ssh_host:
            _run_stop_cmd(
                ctx.stop_cmd, ssh_host=ssh_host, ssh_port=ctx.ssh_port,
            )
        if vm_proc:
            try:
                vm_proc.kill()
            except Exception:
                pass

    if ctx.analysis_data is None:
        ctx.analysis_data = {}
    ctx.analysis_data["slab_identification"] = result.__dict__

    ctx.log("tool", "identify_slab_cache",
            f"cache={result.target_cache}, confidence={result.confidence}")

    if result.target_cache:
        console.print(
            f"  [bold green]Target cache: {result.target_cache} "
            f"(confidence: {result.confidence})[/]"
        )
    else:
        console.print("  [yellow]Could not identify target slab cache[/]")

    return ctx


# ── discover_offsets ─────────────────────────────────────────────────

@default_registry.register(
    name="discover_offsets",
    description=(
        "Auto-discover kernel symbol addresses and struct field offsets "
        "from vmlinux (nm), /proc/kallsyms, and pahole.  Generates a "
        "kernel_offsets.h header suitable for #include in exploit code. "
        "Pass 'vmlinux_path' kwarg if available.  Results in "
        "analysis_data['offset_discovery'] and ctx.kernel_offsets_header."
    ),
)
def tool_discover_offsets(ctx: TaskContext, cfg: Config, **kwargs: Any) -> TaskContext:
    from ..analysis.offset_discovery import discover_offsets

    vmlinux = kwargs.get("vmlinux_path", "")
    console.print("[dim]→ discovering kernel offsets…[/]")

    result = discover_offsets(
        vmlinux_path=vmlinux,
        target_kernel=ctx.target_kernel or "",
        ssh_host=ctx.ssh_host or "",
        ssh_port=ctx.ssh_port,
        instance=ctx.instance,
        adb_port=kwargs.get("adb_port", 6520),
        use_adb=bool(ctx.target_platform and ctx.target_platform.value == "android"),
        extra_symbols=kwargs.get("extra_symbols", []),
        extra_struct_fields=kwargs.get("extra_struct_fields", {}),
    )

    if ctx.analysis_data is None:
        ctx.analysis_data = {}
    ctx.analysis_data["offset_discovery"] = result.__dict__

    if result.offsets_header:
        ctx.kernel_offsets_header = result.offsets_header

    ctx.log("tool", "discover_offsets",
            f"symbols={len(result.discovered_offsets)}, "
            f"struct_fields={len(result.struct_offsets)}")

    console.print(
        f"  [bold]{len(result.discovered_offsets)} symbols, "
        f"{len(result.struct_offsets)} struct fields discovered[/]"
    )
    return ctx


# ── minimize_exploit ─────────────────────────────────────────────────

@default_registry.register(
    name="minimize_exploit",
    description=(
        "Use LLM to simplify a working exploit: remove debug output, "
        "reduce spray counts, minimize sleeps, strip dead code.  "
        "Writes minimized files to output_dir/minimized/.  Only use "
        "AFTER the exploit is verified working."
    ),
)
def tool_minimize_exploit(ctx: TaskContext, cfg: Config, **kwargs: Any) -> TaskContext:
    from ..exploit.minimizer import minimize_exploit

    if not ctx.has_exploit():
        ctx.errors.append("minimize_exploit: no exploit available")
        return ctx

    source_dir = ctx.exploit_result.source_dir  # type: ignore[union-attr]
    if not source_dir:
        ctx.errors.append("minimize_exploit: exploit has no source_dir")
        return ctx

    output_dir = Path(ctx.work_dir) / "minimized" if ctx.work_dir else Path("minimized")
    console.print("[dim]→ minimizing exploit…[/]")

    result_dir = minimize_exploit(
        source_dir=source_dir,
        output_dir=str(output_dir),
        cfg=cfg,
    )

    if ctx.analysis_data is None:
        ctx.analysis_data = {}
    ctx.analysis_data["minimized_dir"] = result_dir

    ctx.log("tool", "minimize_exploit", f"output={result_dir}")
    console.print(f"  [bold green]Minimized exploit written to {result_dir}[/]")
    return ctx


# ── port_exploit ─────────────────────────────────────────────────────

@default_registry.register(
    name="port_exploit",
    description=(
        "Port a working exploit to a different architecture (arm64 ↔ "
        "x86_64).  Adjusts kernel addresses, syscall numbers, inline "
        "assembly, and struct offsets.  Pass 'target_arch' kwarg "
        "(default: opposite of current).  Writes to ported_{arch}/."
    ),
)
def tool_port_exploit(ctx: TaskContext, cfg: Config, **kwargs: Any) -> TaskContext:
    from ..exploit.arch_porter import port_exploit

    if not ctx.has_exploit():
        ctx.errors.append("port_exploit: no exploit available")
        return ctx

    source_dir = ctx.exploit_result.source_dir  # type: ignore[union-attr]
    if not source_dir:
        ctx.errors.append("port_exploit: exploit has no source_dir")
        return ctx

    current_arch = ctx.target_arch.value if ctx.target_arch else "arm64"
    target_arch = kwargs.get("target_arch")
    if not target_arch:
        target_arch = "x86_64" if current_arch == "arm64" else "arm64"

    output_dir = Path(ctx.work_dir) / f"ported_{target_arch}" if ctx.work_dir else Path(f"ported_{target_arch}")
    console.print(f"[dim]→ porting exploit to {target_arch}…[/]")

    result_dir = port_exploit(
        source_dir=source_dir,
        source_arch=current_arch,
        target_arch=target_arch,
        output_dir=str(output_dir),
        cfg=cfg,
    )

    if ctx.analysis_data is None:
        ctx.analysis_data = {}
    ctx.analysis_data[f"ported_{target_arch}_dir"] = result_dir

    ctx.log("tool", "port_exploit",
            f"target={target_arch}, output={result_dir}")
    console.print(f"  [bold green]Ported exploit to {target_arch}: {result_dir}[/]")
    return ctx


# ── validate_exploit_plan ────────────────────────────────────────────

@default_registry.register(
    name="validate_exploit_plan",
    description=(
        "Validate the current exploit plan against known constraints: "
        "slab/spray compatibility, platform limitations (Android vs "
        "Linux), architecture issues, kernel version constraints.  "
        "Returns errors and warnings.  Call BEFORE generating exploit "
        "code to catch plan bugs early."
    ),
)
def tool_validate_exploit_plan(ctx: TaskContext, cfg: Config, **kwargs: Any) -> TaskContext:
    from ..exploit.plan_validator import validate_exploit_plan

    if not ctx.exploit_plan:
        ctx.errors.append("validate_exploit_plan: no exploit plan available — run 'exploit' planner first")
        return ctx

    console.print("[dim]→ validating exploit plan…[/]")

    result = validate_exploit_plan(
        plan=ctx.exploit_plan,
        root_cause=ctx.root_cause,
    )

    if ctx.analysis_data is None:
        ctx.analysis_data = {}
    ctx.analysis_data["plan_validation"] = result.to_dict()

    for issue in result.issues:
        prefix = {"error": "❌", "warning": "⚠️", "info": "ℹ️"}.get(issue.severity, "")
        console.print(f"  {prefix} [{issue.category}] {issue.message}")
        if issue.suggestion:
            console.print(f"    → {issue.suggestion}")

    ctx.log("tool", "validate_exploit_plan",
            f"valid={result.valid}, errors={len(result.errors)}, "
            f"warnings={len(result.warnings)}")

    if not result.valid:
        ctx.errors.append(f"Plan validation failed: {result.summary}")

    return ctx


# ── refine_exploit_plan ──────────────────────────────────────────────

@default_registry.register(
    name="refine_exploit_plan",
    description=(
        "Refine the exploit plan based on verification feedback.  "
        "Uses LLM to revise technique, slab cache, spray strategy, "
        "or R/W primitive based on what went wrong (KASAN output, "
        "GDB traces, wrong slab hit, etc.).  Call after failed "
        "verification to improve the next attempt."
    ),
)
def tool_refine_exploit_plan(ctx: TaskContext, cfg: Config, **kwargs: Any) -> TaskContext:
    from ..core.llm import LLMClient

    if not ctx.exploit_plan:
        ctx.errors.append("refine_exploit_plan: no exploit plan to refine")
        return ctx

    # Collect feedback from verification history
    feedback_parts: list[str] = []
    for v in ctx.exploit_verification_attempts()[-3:]:
        part = f"Attempt #{v.attempt_number}: {'OK' if v.success else 'FAIL'}"
        if v.failure_reason:
            part += f" — {v.failure_reason}"
        if v.feedback:
            part += f"\n  Feedback: {v.feedback[:500]}"
        if v.dmesg_new:
            part += f"\n  dmesg: {v.dmesg_new[:400]}"
        if hasattr(v, "gdb_functions_hit") and v.gdb_functions_hit:
            part += f"\n  GDB hit: {', '.join(v.gdb_functions_hit)}"
        feedback_parts.append(part)

    if not feedback_parts and not kwargs.get("feedback"):
        ctx.errors.append("refine_exploit_plan: no verification feedback available")
        return ctx

    extra_feedback = kwargs.get("feedback", "")
    all_feedback = "\n\n".join(feedback_parts)
    if extra_feedback:
        all_feedback += f"\n\nAdditional feedback: {extra_feedback}"

    plan = ctx.exploit_plan
    plan_desc = (
        f"Technique: {plan.technique}\n"
        f"Target struct: {plan.target_struct}\n"
        f"Slab cache: {plan.slab_cache}\n"
        f"Vuln type: {plan.vulnerability_type.value}\n"
        f"Arch: {plan.target_arch.value}\n"
        f"Platform: {plan.platform.value}\n"
    )
    if plan.steps:
        plan_desc += "Steps:\n"
        for i, s in enumerate(plan.steps, 1):
            plan_desc += f"  {i}. {s.name}: {s.description}\n"

    prompt = (
        "You are refining a kernel exploit plan based on failed verification "
        "feedback.  The exploit was generated but did not succeed.  Analyse "
        "the feedback and suggest specific, actionable changes to the plan.\n\n"
        f"═══ CURRENT PLAN ═══\n{plan_desc}\n\n"
        f"═══ VERIFICATION FEEDBACK ═══\n{all_feedback}\n\n"
        "═══ INSTRUCTIONS ═══\n"
        "Respond in JSON with these fields:\n"
        '  "revised_technique": "updated technique description or null",\n'
        '  "revised_slab_cache": "corrected slab cache or null",\n'
        '  "revised_target_struct": "corrected struct or null",\n'
        '  "reasoning": "explanation of what went wrong and what to change",\n'
        '  "specific_fixes": ["list of specific changes to make"]\n'
    )

    console.print("[dim]→ refining exploit plan from feedback…[/]")

    llm = LLMClient(cfg)
    try:
        result = llm.ask_json(prompt, max_tokens=2048)
    except Exception as e:
        ctx.errors.append(f"refine_exploit_plan: LLM call failed: {e}")
        return ctx

    # Apply refinements
    if result.get("revised_technique"):
        plan.technique = result["revised_technique"]
    if result.get("revised_slab_cache"):
        plan.slab_cache = result["revised_slab_cache"]
    if result.get("revised_target_struct"):
        plan.target_struct = result["revised_target_struct"]

    if ctx.analysis_data is None:
        ctx.analysis_data = {}
    ctx.analysis_data["plan_refinement"] = result

    reasoning = result.get("reasoning", "")
    fixes = result.get("specific_fixes", [])

    ctx.log("tool", "refine_exploit_plan",
            f"reasoning={reasoning[:200]}, fixes={len(fixes)}")

    console.print(f"  [bold]Plan refined:[/] {reasoning[:300]}")
    for fix in fixes[:5]:
        console.print(f"    • {fix}")

    return ctx
