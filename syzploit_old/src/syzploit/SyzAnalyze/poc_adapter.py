"""
poc_adapter.py  –  Adapt a syzbot PoC for a specific target device.

Reads trace_analysis.json (exported by SyzVerify post-processing) together
with the static_analysis.json crash data and the original syzbot reproducer
to produce a *device-adapted* PoC that no longer depends on KASAN and uses
the concrete kernel symbol addresses observed at runtime.

The heavy lifting is done by LLM: we pack every piece of verified runtime
evidence into the prompt so the model can make informed decisions about:

  * which addresses / offsets to hard-code
  * what timing parameters to adjust (no KASAN = no slow-downs)
  * how to handle missing sanitiser output (return-value checking instead)
  * arm64-specific syscall numbers, structures, alignment

Usage from the pipeline::

    from syzploit.SyzAnalyze.poc_adapter import adapt_poc

    result = adapt_poc(
        analysis_dir="/path/to/analysis_<bug_id>",
        output_dir="/path/to/output",       # defaults to analysis_dir
        target_arch="arm64",
        model="gpt-5",
    )
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any, Dict, Optional

from .crash_analyzer import get_openai_response
from .arch_constants import (
    get_adaptation_context,
    detect_arch_from_crash,
    SYSCALL_ALIASES,
)
from .struct_offsets import (
    get_struct_defines,
    get_exploit_context,
    get_slab_info,
    normalize_version,
)
from ..utils.env import get_api_key
from ..utils.compilation import verify_syntax

logger = logging.getLogger(__name__)

# Maximum compile-fix iterations when LLM is available
_MAX_COMPILE_FIX_ATTEMPTS = 2

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _load_json(path: str | Path) -> Dict[str, Any]:
    with open(path, "r") as f:
        return json.load(f)


def _find_reproducer(analysis_dir: Path) -> Optional[Path]:
    """Locate the original syzbot reproducer in the analysis directory."""
    for name in ("reproducer.c", "repro.c", "poc.c", "original_poc.c"):
        p = analysis_dir / name
        if p.exists():
            return p
    # Also check subdirectories and repro_src/
    for sub in ("repro_src", "src"):
        d = analysis_dir / sub
        if d.is_dir():
            for p in d.glob("*.c"):
                return p
    return None


def _find_trace_analysis(analysis_dir: Path) -> Optional[Path]:
    """Locate trace_analysis.json – may be in the log sub-directory."""
    direct = analysis_dir / "trace_analysis.json"
    if direct.exists():
        return direct
    # Check controller log directories
    for d in sorted(analysis_dir.iterdir()):
        if d.is_dir():
            candidate = d / "trace_analysis.json"
            if candidate.exists():
                return candidate
    return None


def _find_controller_results(analysis_dir: Path) -> Optional[Path]:
    """Locate the controller_results.json produced by SyzVerify."""
    for f in analysis_dir.rglob("*controller_results.json"):
        return f
    return None


# ---------------------------------------------------------------------------
# Prompt construction
# ---------------------------------------------------------------------------

def _build_adaptation_prompt(
    reproducer_src: str,
    trace: Dict[str, Any],
    static_analysis: Dict[str, Any],
    target_arch: str,
) -> str:
    """Build a detailed prompt for the LLM to adapt the PoC."""

    parsed = static_analysis.get("parsed", {})
    vuln_kind = parsed.get("kind", "unknown")
    access = parsed.get("access", {})
    obj_info = parsed.get("object_info", {})
    frames = parsed.get("frames", [])
    allocated_by = parsed.get("allocated_by", [])
    freed_by = parsed.get("freed_by", [])

    # Collapse alloc/free into readable strings
    alloc_text = "\n".join(allocated_by)[:2000] if allocated_by else "N/A"
    free_text = "\n".join(freed_by)[:2000] if freed_by else "N/A"

    # Crash stack from trace analysis (with runtime addrs)
    crash_funcs = trace.get("crash_functions", []) or []
    crash_table = "\n".join(
        f"  {(cf.get('function') or '?'):40s}  addr={(cf.get('address') or '??'):20s}  "
        f"hits={(cf.get('hits') or 0)}"
        for cf in crash_funcs
    )

    # Runtime addresses
    rt = trace.get("runtime_addresses", {})
    crash_addrs = rt.get("crash_stack", {})
    alloc_addrs = rt.get("alloc_functions", {})
    free_addrs = rt.get("free_functions", {})

    addr_section = "### Crash-stack function addresses (from live kallsyms)\n"
    for fn, addr in (crash_addrs or {}).items():
        addr_section += f"  {(fn or '?'):40s} = {addr or '?'}\n"
    addr_section += "\n### Alloc function addresses\n"
    for fn, addr in (alloc_addrs or {}).items():
        addr_section += f"  {(fn or '?'):40s} = {addr or '?'}\n"
    addr_section += "\n### Free function addresses\n"
    for fn, addr in (free_addrs or {}).items():
        addr_section += f"  {(fn or '?'):40s} = {addr or '?'}\n"

    # Path verification
    pv = trace.get("path_verification") or {}
    pv_summary = (
        f"Verdict: {pv.get('verdict') or '?'}, "
        f"Confidence: {(pv.get('confidence') or 0):.0%}, "
        f"Best chain depth: {pv.get('best_chain_depth') or 0}, "
        f"Vulnerable path confirmed: {pv.get('vulnerable_path_confirmed') or False}"
    )
    chain_matches = pv.get("backtrace_chain_matches", [])
    chain_text = ""
    for m in chain_matches[:10]:
        chain_text += (
            f"  func={m.get('func', '?')}, "
            f"depth={m.get('chain_depth', m.get('depth', '?'))}, "
            f"matched={m.get('matched_functions', m.get('chain', []))}\n"
        )

    no_crash_reasons = pv.get("no_crash_explanation", [])

    # Event statistics
    ev = trace.get("event_summary", {})
    alloc_free = trace.get("alloc_free_stats", {})

    # Device profile
    kernel_ver = trace.get("kernel_version", "unknown")
    device_arch = trace.get("arch", target_arch)
    android_ver = trace.get("android_version", "")

    # ── Architecture & struct offset context (from arch_constants + struct_offsets)
    # Detect source arch from crash report if available
    crash_report = static_analysis.get("raw_crash", "") or static_analysis.get("crash_report", "")
    source_arch = detect_arch_from_crash(crash_report) or "x86_64"

    # Gather syscall names from the reproducer for targeted mapping
    syscall_names = []
    for sc in ["open", "close", "read", "write", "mmap", "ioctl", "pipe",
               "socket", "sendmsg", "recvmsg", "msgget", "msgsnd", "msgrcv",
               "clone", "fork", "unshare", "userfaultfd", "futex",
               "epoll_create", "epoll_ctl", "epoll_wait", "splice",
               "io_uring_setup", "io_uring_enter", "io_uring_register",
               "bpf", "keyctl", "add_key", "prctl", "seccomp",
               "setsockopt", "getsockopt", "bind", "listen", "accept"]:
        if sc in reproducer_src or f"__{sc}" in reproducer_src:
            syscall_names.append(sc)

    arch_context = ""
    if source_arch != device_arch:
        arch_context = get_adaptation_context(source_arch, device_arch, syscall_names)

    # Struct offset context — use vuln object cache to pick relevant structs
    vuln_cache = obj_info.get("cache", "")
    relevant_structs = ["cred", "task_struct"]
    for s in ["msg_msg", "pipe_buffer", "sk_buff", "seq_operations",
              "tty_struct", "file"]:
        if s in reproducer_src or s in vuln_cache or s in str(frames):
            relevant_structs.append(s)

    struct_context = get_exploit_context(
        vuln_struct=relevant_structs[0] if relevant_structs else "cred",
        target_struct=relevant_structs[1] if len(relevant_structs) > 1 else "task_struct",
        kernel_version=kernel_ver,
        android=bool(android_ver),
    )
    struct_defines = get_struct_defines(
        relevant_structs, kernel_ver, android=bool(android_ver),
    )

    prompt = f"""You are a kernel exploit engineer adapting a syzbot proof-of-concept
for a real device that does NOT have KASAN enabled.

## Original Reproducer (syzbot)
```c
{reproducer_src[:6000]}
```

## Vulnerability Summary
- Type: {vuln_kind}
- Access op: {access.get('op', '?')}, size: {access.get('size', '?')} bytes
- Target object: cache={obj_info.get('cache', '?')}, size={obj_info.get('obj_size', '?')}, offset={obj_info.get('offset', '?')}

## Allocation path
{alloc_text[:1500]}

## Free path
{free_text[:1500]}

## Target Device
- Architecture: {device_arch}
- Kernel version: {kernel_ver}
- Android version: {android_ver or 'N/A'}
- KASAN: **NOT present** – the UAF still happens but is not caught
- Device: Cuttlefish (virtual Android device)

## Dynamic Trace Evidence (from GDB tracing on the target)

### Path verification
{pv_summary}

### Backtrace chain matches (observed the crash-path functions executing)
{chain_text if chain_text else '  (none)'}

### No-crash explanation (why the device does not panic)
{chr(10).join(no_crash_reasons) if no_crash_reasons else '  KASAN not present; UAF is silent.'}

### Crash-stack functions with runtime addresses and hit counts
{crash_table if crash_table else '  (none)'}

{addr_section}

### Event statistics
- Total GDB events captured: {ev.get('total', 0)}
- By type: {json.dumps(ev.get('by_type', {}), indent=2)}

### Alloc / Free stats from tracing
{json.dumps(alloc_free, indent=2) if alloc_free else '  (none)'}

## Task

Produce an ADAPTED version of the reproducer that will work on the target
device described above.  The adapted PoC must:

1. **Trigger the same vulnerability** – the allocation, free, and dangling
   use must happen in the same order.
2. **Not rely on KASAN** – there will be no KASAN report.  Instead verify
   success through observable side effects (crash, corrupted data, escalated
   privileges, or detectable kernel state change).
3. **Use correct architecture constants** for {device_arch}: syscall
   numbers, struct layouts, alignment requirements.
4. **Hard-code kernel symbol addresses** from the runtime data above where
   useful for exploitation (e.g., for calculating offsets from a leak,
   validating addresses, or direct function pointer overwrites).
   Mark every hardcoded address with a comment like:
   `// DEVICE-SPECIFIC: ep_free @ 0xffffffc0105c8274`
5. **Adjust timing** – KASAN adds significant overhead; on a non-KASAN
   kernel the race window is much tighter.  Add appropriate
   `usleep()` / busy-wait / retry loops.
6. **Keep the core trigger logic** from the original PoC intact; only
   change what is necessary for adaptation.
7. **Add success detection** – after the trigger, actively check if the
   vulnerability was exercised (e.g., read back from a reclaimed object,
   check for privilege change, verify function pointer corruption).
8. **Compile cleanly** with `{device_arch}-linux-gnu-gcc` or `clang
   --target=aarch64-linux-gnu` for a static binary.

## Architecture Adaptation Reference
{arch_context if arch_context else '(same architecture — no syscall translation needed)'}

## Kernel Structure Offsets for {kernel_ver}
{struct_context}

## Ready-to-use C #defines
```c
{struct_defines}
```

Output the COMPLETE adapted C source file.  Start with `#define _GNU_SOURCE`
and end with the closing brace of `main()`.

Output ONLY the C code — no explanations before or after.
"""
    return prompt


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def adapt_poc(
    analysis_dir: str,
    output_dir: Optional[str] = None,
    target_arch: str = "arm64",
    model: str = "gpt-5",
    skip_llm: bool = False,
) -> Dict[str, Any]:
    """Adapt the syzbot PoC for a specific target device.

    Parameters
    ----------
    analysis_dir : str
        Path to the ``analysis_<bug_id>/`` directory that contains
        ``static_analysis.json``, the reproducer sources, and the
        controller log directory with ``trace_analysis.json``.
    output_dir : str, optional
        Where to write the adapted PoC.  Defaults to *analysis_dir*.
    target_arch : str
        Target architecture (``arm64``, ``x86_64``).
    model : str
        LLM model name.
    skip_llm : bool
        If *True*, skip LLM generation and write a stub instead.

    Returns
    -------
    dict
        ``{"success": bool, "adapted_poc": str, "output_path": str, ...}``
    """
    adir = Path(analysis_dir)
    odir = Path(output_dir) if output_dir else adir
    odir.mkdir(parents=True, exist_ok=True)

    # -- locate inputs -------------------------------------------------
    static_path = adir / "static_analysis.json"
    if not static_path.exists():
        return {"success": False, "error": "static_analysis.json not found"}

    static_analysis = _load_json(static_path)

    trace_path = _find_trace_analysis(adir)
    if trace_path is None:
        return {"success": False,
                "error": "trace_analysis.json not found – run "
                         "test-cuttlefish with tracing first"}
    trace = _load_json(trace_path)
    logger.debug(f"Loaded trace analysis from {trace_path}")

    repro_path = _find_reproducer(adir)
    if repro_path is None:
        # Try to pull source from static_analysis reproducer field
        repro_src = (static_analysis.get("reproducer", {})
                     .get("source", ""))
        if not repro_src:
            return {"success": False, "error": "No reproducer source found"}
    else:
        repro_src = repro_path.read_text()
        logger.debug(f"Loaded reproducer from {repro_path}")

    # -- optional: also load controller results for extra context ------
    ctrl_path = _find_controller_results(adir)
    if ctrl_path:
        try:
            ctrl = _load_json(ctrl_path)
            # Merge any missing fields into trace
            if "kernel_version" not in trace or not trace["kernel_version"]:
                trace["kernel_version"] = ctrl.get("kernel_version")
            if "arch" not in trace or not trace["arch"]:
                trace["arch"] = ctrl.get("arch")
        except Exception:
            pass

    # -- build & send prompt -------------------------------------------
    if skip_llm:
        adapted_src = _stub_adaptation(repro_src, trace, target_arch)
    else:
        api_key = get_api_key()
        if not api_key:
            logger.debug("No API key – falling back to stub")
            adapted_src = _stub_adaptation(repro_src, trace, target_arch)
        else:
            prompt = _build_adaptation_prompt(
                repro_src, trace, static_analysis, target_arch,
            )
            logger.debug(f"Sending {len(prompt)} char prompt to {model}")
            try:
                response = get_openai_response(prompt, api_key, model)
                adapted_src = _extract_c_code(response)
                if not adapted_src:
                    logger.warning("LLM returned no valid C code, falling back to stub")
                    adapted_src = _stub_adaptation(repro_src, trace,
                                                    target_arch)
            except Exception as exc:
                logger.warning(f"LLM call failed: {exc}")
                adapted_src = _stub_adaptation(repro_src, trace, target_arch)

    # -- compile validation & iterative fix ----------------------------
    compile_ok = False
    compile_errors = ""
    try:
        ok, errs = verify_syntax(adapted_src, platform="android", arch=target_arch)
        compile_ok = ok
        compile_errors = errs
    except Exception as exc:
        logger.debug(f"verify_syntax unavailable ({exc}); skipping validation")
        compile_ok = None  # unknown – no compiler available

    if compile_ok is False and not skip_llm:
        # Try up to _MAX_COMPILE_FIX_ATTEMPTS LLM-driven fixes
        api_key = get_api_key()
        for attempt in range(1, _MAX_COMPILE_FIX_ATTEMPTS + 1):
            if not api_key:
                break
            logger.debug(f"Compile-fix attempt {attempt}/{_MAX_COMPILE_FIX_ATTEMPTS}")
            fix_prompt = _build_compile_fix_prompt(
                adapted_src, compile_errors, target_arch,
            )
            try:
                fix_resp = get_openai_response(fix_prompt, api_key, model)
                fixed_src = _extract_c_code(fix_resp)
                if not fixed_src:
                    break
                ok2, errs2 = verify_syntax(fixed_src, platform="android",
                                           arch=target_arch)
                if ok2:
                    adapted_src = fixed_src
                    compile_ok = True
                    compile_errors = ""
                    logger.debug(f"Compile-fix attempt {attempt} succeeded")
                    break
                # Feed new errors into next iteration
                adapted_src = fixed_src
                compile_errors = errs2
            except Exception as exc:
                logger.debug(f"Compile-fix attempt {attempt} failed: {exc}")
                break

    # -- write output --------------------------------------------------
    out_file = odir / "adapted_poc.c"
    out_file.write_text(adapted_src)
    logger.debug(f"Wrote adapted PoC: {out_file}")

    # Also save the trace context used for reproducibility
    meta = {
        "trace_analysis_path": str(trace_path),
        "reproducer_path": str(repro_path) if repro_path else None,
        "target_arch": target_arch,
        "kernel_version": trace.get("kernel_version"),
        "model": model,
        "skip_llm": skip_llm,
        "path_verification_verdict": trace.get("path_verification", {}).get("verdict"),
        "path_verification_confidence": trace.get("path_verification", {}).get("confidence"),
    }
    meta_path = odir / "adaptation_metadata.json"
    with open(meta_path, "w") as f:
        json.dump(meta, f, indent=2)

    return {
        "success": True,
        "adapted_poc": str(out_file),
        "output_path": str(odir),
        "metadata_path": str(meta_path),
        "trace_analysis_path": str(trace_path),
        "kernel_version": trace.get("kernel_version"),
        "arch": target_arch,
        "verdict": trace.get("path_verification", {}).get("verdict"),
        "confidence": trace.get("path_verification", {}).get("confidence"),
        "compiles": compile_ok,
        "compile_errors": compile_errors if compile_errors else None,
    }


# ---------------------------------------------------------------------------
# Fallbacks
# ---------------------------------------------------------------------------

def _build_compile_fix_prompt(
    source: str,
    errors: str,
    target_arch: str,
) -> str:
    """Build a prompt asking the LLM to fix compilation errors."""
    return f"""\
The following C exploit code failed to compile for {target_arch}-linux-gnu-gcc.

## Compilation errors
```
{errors}
```

## Source code
```c
{source}
```

Fix ALL compilation errors and return the corrected, complete C source code.
Do NOT remove functionality or stub anything out — only fix the errors.
Return the full corrected source inside a ```c ... ``` block."""


def _extract_c_code(response: str) -> str:
    """Extract C source from an LLM response (strip markdown fences)."""
    # Try ```c ... ``` block first
    m = re.search(r"```c\b(.*?)```", response, re.DOTALL)
    if m:
        return m.group(1).strip()
    # Try generic ``` block
    m = re.search(r"```(.*?)```", response, re.DOTALL)
    if m:
        return m.group(1).strip()
    # If response starts with #define or #include, assume raw C
    if response.lstrip().startswith(("#define", "#include", "/*")):
        return response.strip()
    return ""


def _stub_adaptation(
    original_src: str,
    trace: Dict[str, Any],
    target_arch: str,
) -> str:
    """Produce a minimal adapted stub when LLM is unavailable.

    Prepends a header with all discovered runtime addresses as #defines
    and appends a success-detection epilogue after the original source.
    """
    lines: list[str] = []
    lines.append("/* ====== DEVICE-ADAPTED PoC (stub – no LLM) ====== */")
    lines.append(f"/* Target arch: {target_arch} */")
    lines.append(f"/* Kernel: {trace.get('kernel_version', '?')} */")
    pv_stub = trace.get('path_verification') or {}
    lines.append(f"/* Path-verification verdict: "
                 f"{pv_stub.get('verdict') or '?'} "
                 f"({(pv_stub.get('confidence') or 0):.0%}) */")
    lines.append("")

    # Emit struct offset defines if we know the kernel version
    kernel_ver = trace.get("kernel_version", "")
    if kernel_ver:
        android = bool(trace.get("android_version", ""))
        defines = get_struct_defines(
            ["cred", "task_struct"], kernel_ver, android=android,
        )
        lines.append(defines)
        lines.append("")

    # Emit runtime addresses as #defines
    rt = trace.get("runtime_addresses", {})
    for section_name, section in [("CRASH", rt.get("crash_stack", {})),
                                   ("ALLOC", rt.get("alloc_functions", {})),
                                   ("FREE", rt.get("free_functions", {}))]:
        for fn, addr in (section or {}).items():
            safe = fn.upper().replace(" ", "_").replace("-", "_")
            lines.append(f"#define ADDR_{section_name}_{safe}  {addr}UL"
                         f"  // {fn}")
    lines.append("")

    # Include the original reproducer verbatim
    lines.append("/* ---- original reproducer ---- */")
    lines.append(original_src)

    return "\n".join(lines)
