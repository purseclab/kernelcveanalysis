import json
import os
import re
import traceback
from pathlib import Path
from typing import List, Optional

import typer
from typing_extensions import Annotated

from . import SyzVerify
from . import SyzAnalyze
from . import Synthesizer
from .SyzVerify.bug_db import SyzkallBugDatabase
from .SyzVerify.cuttlefish import CuttlefishConfig
from .SyzVerify.run_bug import test_repro_crashes, test_repro_crashes_qemu, test_repro_with_cuttlefish_controller, verify_exploit_with_cuttlefish_controller
from .utils.adb import calculate_adb_port
from .utils.compilation import compile_exploit
from .utils.env import load_env

app = typer.Typer(help="Syzkall/Syzbot tooling for pulling, testing, and analyzing bugs.")


def _parse_crash_report_for_stack(crash_report: str) -> dict:
    """Parse a raw kernel crash report to extract stack frames for GDB breakpoints.
    
    Handles KASAN/UBSAN/KMSAN reports and generic kernel oops/panic stack traces.
    Returns a dict compatible with the parsed_crash format used by CuttlefishKernelGDB.
    """
    result = {
        'crash_type': '',
        'corrupted_function': '',
        'stack_frames': [],
        'access': {},
    }
    
    # Parse crash type and corrupted function
    bug_match = re.search(
        r'BUG:\s*(KASAN|UBSAN|KMSAN):\s*([^\n]+?)\s+in\s+(\S+)',
        crash_report
    )
    if bug_match:
        result['crash_type'] = f"{bug_match.group(1)}: {bug_match.group(2).split(' in ')[0].strip()}"
        func = bug_match.group(3).split('+')[0].split('.')[0]
        result['corrupted_function'] = func
    
    # Parse access info (read/write, address, size)
    access_match = re.search(r'(Read|Write) of size (\d+) at addr ([0-9a-fA-Fx]+)', crash_report)
    if access_match:
        result['access'] = {
            'type': access_match.group(1).lower(),
            'size': int(access_match.group(2)),
            'address': access_match.group(3),
        }
    
    # Extract stack frames from "Call Trace:" section
    # Look for lines like: " func_name+0x123/0x456  file.c:123"
    # or: " func_name+0x123/0x456"
    in_stack = False
    seen_funcs = set()
    
    for line in crash_report.split('\n'):
        stripped = line.strip()
        if 'Call Trace:' in stripped:
            in_stack = True
            continue
        if in_stack:
            # End of stack trace
            if stripped == '' or stripped.startswith('RIP:') or stripped.startswith('RSP:'):
                break
            
            # Match stack frame: " func+0xoffset/0xsize  file:line  [inline]"
            frame_match = re.match(
                r'(?:\?\s+)?(\w+)\+0x[0-9a-f]+/0x[0-9a-f]+\s*(?:(\S+):(\d+))?\s*(\[inline\])?',
                stripped
            )
            if frame_match:
                func_name = frame_match.group(1)
                source_file = frame_match.group(2) or ''
                line_num = int(frame_match.group(3)) if frame_match.group(3) else 0
                is_inline = bool(frame_match.group(4))
                
                if func_name not in seen_funcs:
                    seen_funcs.add(func_name)
                    result['stack_frames'].append({
                        'function': func_name,
                        'file': source_file,
                        'line': line_num,
                        'inline': is_inline,
                    })
    
    return result if result['stack_frames'] or result['corrupted_function'] else None


# ---------------------------------------------------------------------------
# Shared pipeline steps (compile → dynamic → post-process → adapt → synth → verify)
#
# Both pipeline-cuttlefish and pipeline-cve delegate to this after their own
# static/CVE analysis step so that fixes and features only need to live once.
# ---------------------------------------------------------------------------

def _run_shared_pipeline(
    *,
    bug_id: str,
    output_dir: Path,
    parsed_crash: Optional[dict],
    repro_bin: Optional[str],
    arch: str,
    root: bool,
    # Cuttlefish config fields
    ssh_host: str,
    ssh_port: int,
    ssh_user: Optional[str],
    ssh_password: Optional[str],
    ssh_key: Optional[str],
    persistent: bool,
    already_running: bool,
    start_cmd: Optional[str],
    run_cmd: Optional[str],
    stop_cmd: Optional[str],
    instance: Optional[int],
    gdb_port: int,
    adb_port: int,
    dynamic_analysis: bool,
    setup_tunnels: bool,
    runtime_logs_dir: Optional[str],
    kernel_image: Optional[str],
    vmlinux_path: Optional[str],
    system_map: Optional[str],
    extract_symbols: bool,
    extract_runtime_symbols: bool,
    # Pipeline options
    goal: str,
    platform: Optional[str],
    timeout: int,
    verify_exploit: bool,
    exploit_start_cmd: Optional[str],
    model: str,
    planner: str,
    debug: bool,
    verbose: bool,
    # Summary dict (mutated in place)
    summary: dict,
    # Step number offset (pipeline-cuttlefish starts at 3, pipeline-cve at 2)
    step_offset: int = 0,
) -> None:
    """Run the shared pipeline steps used by both pipeline-cuttlefish and pipeline-cve.

    Steps executed (numbers shown with *step_offset* applied):
      - Dynamic analysis with Cuttlefish
      - Post-processing results
      - PoC adaptation
      - Exploit synthesis (PDDL → LLM fallback)
      - Exploit verification
      - Pipeline summary save
    """
    s = step_offset  # shorthand for step numbering

    # ── Dynamic analysis with Cuttlefish ────────────────────────────────
    typer.echo(f"\n[STEP {s}] Dynamic Analysis with Cuttlefish...")

    actual_adb_port = adb_port
    if instance is not None:
        actual_adb_port = calculate_adb_port(instance)
        typer.echo(f"[+] Instance {instance}: using ADB port {actual_adb_port}")

    actual_run_cmd = run_cmd
    if not actual_run_cmd and start_cmd and 'gdb_run' in start_cmd:
        actual_run_cmd = start_cmd.replace('gdb_run', 'run')
        typer.echo(f"[+] Auto-derived --run-cmd: {actual_run_cmd}")

    config = CuttlefishConfig(
        ssh_host=ssh_host,
        ssh_port=ssh_port,
        ssh_user=ssh_user,
        ssh_password=ssh_password,
        ssh_key_path=ssh_key,
        persistent=persistent,
        already_running=already_running,
        start_command=start_cmd,
        run_command=actual_run_cmd,
        stop_command=stop_cmd,
        gdb_port=gdb_port,
        adb_port=actual_adb_port,
        enable_gdb=dynamic_analysis,
        setup_tunnels=setup_tunnels,
        cuttlefish_runtime_logs=runtime_logs_dir,
        kernel_image_path=kernel_image,
        vmlinux_path=vmlinux_path,
        system_map_path=system_map,
        extract_symbols=extract_symbols,
        extract_runtime_symbols=extract_runtime_symbols,
    )

    log_dir = str(output_dir)

    typer.echo(f"[+] Mode: {'persistent' if persistent else 'non-persistent'}")
    typer.echo(f"[+] Dynamic analysis (GDB): {'enabled' if dynamic_analysis else 'disabled'}")
    typer.echo(f"[+] SSH tunnels: {'enabled' if setup_tunnels else 'disabled'}")
    if kernel_image:
        typer.echo(f"[+] Kernel Image: {kernel_image}")
    if system_map:
        typer.echo(f"[+] System.map: {system_map}")

    if repro_bin:
        try:
            crashed, crash_type, results = test_repro_with_cuttlefish_controller(
                repro_path=str(repro_bin),
                bug_id=bug_id,
                cuttlefish_config=config,
                parsed_crash=parsed_crash,
                log_dir=log_dir,
                root=root,
                timeout=timeout,
                arch=arch,
                vmlinux_path=vmlinux_path,
            )

            if crashed:
                typer.echo(f"[✓] CRASH DETECTED (type: {crash_type})")
            else:
                typer.echo(f"[!] No crash detected")

            summary["steps"]["dynamic"] = {
                "success": True,
                "crashed": crashed,
                "crash_type": crash_type,
            }
        except Exception as e:
            typer.echo(f"[!] Dynamic analysis failed: {e}")
            summary["steps"]["dynamic"] = {"success": False, "error": str(e)}
    else:
        typer.echo("[!] No compiled reproducer — skipping dynamic analysis")
        summary["steps"]["dynamic"] = {"success": False, "error": "no reproducer binary"}

    # ── Post-process results ────────────────────────────────────────────
    typer.echo(f"\n[STEP {s + 1}] Post-processing results...")
    try:
        from .SyzVerify import post_process as pp
        dynamic_json = output_dir / "dynamic_analysis.json"
        if dynamic_json.exists():
            pp_out = output_dir / "dynamic_analysis_post.json"
            pp_res = pp.analyze(str(dynamic_json), str(pp_out), parsed_crash=parsed_crash)
            confidence = pp_res.get('confidence', 0)
            uaf_count = pp_res.get('summary', {}).get('uaf', 0)
            oob_count = pp_res.get('summary', {}).get('invalid-access', 0)
            uaf_free_count = pp_res.get('summary', {}).get('uaf-free', 0)

            typer.echo(f"[+] Post-processing: confidence={confidence}")
            typer.echo(f"[+] UAF={uaf_count} OOB={oob_count}")

            vuln_class = pp_res.get('vulnerability_classification', {})
            if vuln_class and vuln_class.get('type', 'unknown') != 'unknown':
                typer.echo(f"[+] Vulnerability type: {vuln_class['type']} "
                           f"(confidence: {vuln_class.get('confidence', 0):.0%})")
                typer.echo(f"    {vuln_class.get('description', '')}")
                for ev in vuln_class.get('evidence', [])[:3]:
                    typer.echo(f"    - {ev}")

            if uaf_count > 0:
                inference_note = pp_res.get('summary', {}).get('uaf_inference_note')
                if inference_note:
                    typer.echo(f"[✓] USE-AFTER-FREE DETECTED (inferred): {uaf_count} post-free crash-stack hits")
                    typer.echo(f"    {inference_note}")
                else:
                    typer.echo(f"[✓] USE-AFTER-FREE DETECTED: {uaf_count} UAF event(s) found!")
            elif uaf_free_count > 0:
                typer.echo(f"[~] {uaf_free_count} frees of tracked allocations observed (UAF window exists)")

            vulns = pp_res.get('vulnerabilities_detected', [])
            if vulns:
                typer.echo(f"[+] Vulnerabilities detected:")
                for vuln in vulns:
                    typer.echo(f"    - {vuln.get('type', 'unknown')}: {vuln.get('count', 0)} instance(s)")

            summary["steps"]["post_process"] = {
                "success": True,
                "confidence": confidence,
                "uaf_count": uaf_count,
                "oob_count": oob_count,
                "vulnerabilities": vulns,
                "vulnerability_classification": vuln_class,
            }
        else:
            typer.echo("[!] No dynamic_analysis.json found to post-process")
            summary["steps"]["post_process"] = {"success": False, "error": "no dynamic results"}
    except Exception as e:
        typer.echo(f"[!] Post-processing failed: {e}")
        summary["steps"]["post_process"] = {"success": False, "error": str(e)}

    # ── Adapt PoC for target device ─────────────────────────────────────
    typer.echo(f"\n[STEP {s + 1}b] Adapting PoC for target device...")
    try:
        from .SyzAnalyze.poc_adapter import adapt_poc

        adapt_result = adapt_poc(
            analysis_dir=str(output_dir),
            output_dir=str(output_dir),
            target_arch=arch,
            model=model,
        )
        if adapt_result.get("success"):
            typer.echo(f"[+] Adapted PoC written: {adapt_result['adapted_poc']}")
            typer.echo(f"    Kernel: {adapt_result.get('kernel_version', '?')}")
            typer.echo(f"    Verdict: {adapt_result.get('verdict', '?')} "
                       f"({(adapt_result.get('confidence') or 0):.0%})")
            summary["steps"]["adapt_poc"] = {
                "success": True,
                "adapted_poc": adapt_result["adapted_poc"],
                "verdict": adapt_result.get("verdict"),
                "confidence": adapt_result.get("confidence"),
            }
        else:
            typer.echo(f"[!] PoC adaptation failed: {adapt_result.get('error')}")
            summary["steps"]["adapt_poc"] = {
                "success": False,
                "error": adapt_result.get("error", "unknown"),
            }
    except Exception as e:
        typer.echo(f"[!] PoC adaptation failed: {e}")
        summary["steps"]["adapt_poc"] = {"success": False, "error": str(e)}

    # ── Synthesize exploit ──────────────────────────────────────────────
    exploit_path = None
    if goal:
        typer.echo(f"\n[STEP {s + 2}] Synthesizing exploit plan (planner={planner}, model={model})...")

        pddl_succeeded = False

        # Phase A: PDDL-based synthesis
        if planner in ("pddl", "auto"):
            typer.echo(f"[STEP {s + 2}a] Attempting PDDL-based synthesis...")
            try:
                synth_res = Synthesizer.synthesize(
                    bug_id=bug_id,
                    goal=goal,
                    kernel_research_path=None,
                    analysis_dir=str(output_dir),
                    vmlinux_path=None,
                    platform=platform,
                    planner="auto",
                    model=model,
                    debug=debug,
                    verbose=verbose,
                )

                exploit_files = synth_res.get("exploits", [])
                pl_result = synth_res.get("powerlifted", {})

                if exploit_files:
                    pddl_succeeded = True
                    typer.echo(f"[+] PDDL synthesis produced {len(exploit_files)} exploit file(s)")
                    for ef in exploit_files:
                        typer.echo(f"    - {ef}")
                    exploit_path = exploit_files[0] if exploit_files else None
                    summary["steps"]["synthesize"] = {
                        "success": True,
                        "planner": "pddl",
                        "exploits": exploit_files,
                        "pddl": synth_res.get("pddl", {}),
                    }
                elif pl_result.get("success") and pl_result.get("parsed_plans"):
                    pddl_succeeded = True
                    typer.echo(f"[+] PDDL planner found a plan (stitching may have produced synth_output)")
                    summary["steps"]["synthesize"] = {
                        "success": True,
                        "planner": "pddl",
                        "pddl": synth_res.get("pddl", {}),
                    }
                else:
                    typer.echo("[~] PDDL planner did not produce a viable plan")
                    if planner == "pddl":
                        summary["steps"]["synthesize"] = {"success": False, "error": "PDDL planner found no plan"}
            except Exception as e:
                typer.echo(f"[~] PDDL synthesis failed: {e}")
                if debug:
                    typer.echo(f"    {traceback.format_exc()}")
                if planner == "pddl":
                    summary["steps"]["synthesize"] = {"success": False, "error": str(e)}

        # Phase B: LLM-based synthesis
        if not pddl_succeeded and planner in ("llm", "auto"):
            if planner == "auto":
                typer.echo(f"[STEP {s + 2}b] Falling back to LLM-based exploit generation...")
            else:
                typer.echo(f"[STEP {s + 2}] Running LLM-based exploit generation...")
            try:
                from .Synthesizer.exploit_generator import generate_exploit

                result = generate_exploit(
                    analysis_dir=str(output_dir),
                    target_arch=arch,
                    kernel_version="",
                    output_dir=str(output_dir),
                    skip_llm=False,
                    model=model,
                    use_existing_plan=False,
                    use_reference=False,
                )

                if result.get('success'):
                    typer.echo(f"[+] Exploit generated successfully!")
                    typer.echo(f"    Vulnerability: {result.get('vulnerability_type')}")
                    typer.echo(f"    Target: {result.get('target_struct')}")
                    typer.echo(f"    Technique: {result.get('technique')}")
                    typer.echo(f"    Steps: {len(result.get('steps', []))}")
                    for step in result.get('steps', []):
                        typer.echo(f"      - {step}")
                    summary["steps"]["synthesize"] = {
                        "success": True,
                        "planner": "llm",
                        "vulnerability_type": result.get('vulnerability_type'),
                        "technique": result.get('technique'),
                        "steps": result.get('steps', []),
                    }

                    outputs = result.get('outputs', {})
                    if outputs.get('exploit'):
                        exploit_path = outputs['exploit']
                        typer.echo(f"[+] Generated exploit: {exploit_path}")
                else:
                    typer.echo(f"[!] Exploit generation failed")
                    summary["steps"]["synthesize"] = {"success": False, "error": "generation failed"}
            except Exception as e:
                typer.echo(f"[!] LLM synthesis failed: {e}")
                typer.echo(f"[!] Traceback: {traceback.format_exc()}")
                summary["steps"]["synthesize"] = {"success": False, "error": str(e)}

        # Check for compiled artifacts in synth_output (prefer binaries over source)
        synth_output = output_dir / 'synth_output'
        compiled_exploit = None
        if synth_output.exists():
            for p in synth_output.iterdir():
                if p.is_file() and os.access(p, os.X_OK) and not p.suffix:
                    compiled_exploit = str(p)
                    typer.echo(f"[+] Found compiled exploit: {compiled_exploit}")
                    break
        
        # If we have a compiled exploit, use it; otherwise check if exploit_path is source
        if compiled_exploit:
            exploit_path = compiled_exploit
        elif exploit_path and exploit_path.endswith('.c'):
            # We have source code, try to compile it using the shared compile function
            # (which integrates syscall_fixer for automatic error correction)
            typer.echo(f"[+] Compiling exploit source: {exploit_path}")
            exploit_src = Path(exploit_path)
            exploit_bin = str(exploit_src.with_suffix(''))
            
            success, error = compile_exploit(
                source_path=exploit_path,
                output_path=exploit_bin,
                arch=arch,
            )
            
            if success:
                exploit_path = exploit_bin
                typer.echo(f"[+] Compiled exploit binary: {exploit_path}")
            else:
                typer.echo(f"[!] Exploit compilation failed: {error[:200] if error else 'unknown'}")
        
        if not exploit_path:
            for p in output_dir.glob("exploit*.c"):
                typer.echo(f"[+] Found generated exploit source (not compiled): {p}")
                break

    # ── Verify exploit ──────────────────────────────────────────────────
    if verify_exploit:
        typer.echo(f"\n[STEP {s + 3}] Verifying exploit for privilege escalation...")

        if exploit_path:
            verify_config = CuttlefishConfig(
                ssh_host=ssh_host,
                ssh_port=ssh_port,
                ssh_user=ssh_user,
                ssh_password=ssh_password,
                ssh_key_path=ssh_key,
                persistent=persistent,
                already_running=already_running,
                start_command=exploit_start_cmd if exploit_start_cmd else start_cmd,
                stop_command=stop_cmd,
                gdb_port=gdb_port,
                adb_port=actual_adb_port,
                enable_gdb=False,
                setup_tunnels=setup_tunnels,
                cuttlefish_runtime_logs=runtime_logs_dir,
                kernel_image_path=None,
                vmlinux_path=None,
                system_map_path=None,
                extract_symbols=False,
                extract_runtime_symbols=False,
            )

            verify_result = verify_exploit_with_cuttlefish_controller(
                exploit_path=exploit_path,
                cuttlefish_config=verify_config,
                log_dir=str(output_dir / 'verification'),
                timeout=timeout,
            )

            if verify_result.get('success'):
                typer.echo("\n[✓] EXPLOIT VERIFICATION PASSED")
                typer.echo("    Privilege escalation achieved!")
                typer.echo(f"    Initial UID: {verify_result.get('initial_uid')}")
                typer.echo(f"    Final UID: {verify_result.get('final_uid')}")
                summary["steps"]["verify"] = {"success": True, "initial_uid": verify_result.get('initial_uid'), "final_uid": verify_result.get('final_uid')}
            else:
                typer.echo("\n[✗] EXPLOIT VERIFICATION FAILED")
                if verify_result.get('error'):
                    typer.echo(f"    Error: {verify_result['error']}")
                if verify_result.get('crash_occurred'):
                    typer.echo("    Note: A crash was detected during execution")
                summary["steps"]["verify"] = {"success": False, "error": verify_result.get('error', 'unknown')}
        else:
            typer.echo("[!] No exploit binary found to verify")
            summary["steps"]["verify"] = {"success": False, "error": "no exploit binary"}

    # ── Save pipeline summary ───────────────────────────────────────────
    summary_path = output_dir / "pipeline_summary.json"
    with open(summary_path, 'w') as f:
        json.dump(summary, f, indent=2)
    typer.echo(f"\n[+] Pipeline summary saved: {summary_path}")
    typer.echo(f"[+] Results in: {output_dir}")


# TODO: decide if this will even be apart of kexploit
@app.command()
def pull(
    syzkall_kernel: Annotated[str, typer.Option(help='Kernel name to pull bugs for')] = 'android-5-10',
    all_bugs: Annotated[bool, typer.Option('--all', help='Pull all bugs without filtering for memory unsafety')] = False,
):
    """Pull bugs from syzbot for a given kernel version"""
    SyzVerify.pull(syzkall_kernel, apply_filter=not all_bugs)


@app.command()
def pull_bug(
    bug_id: Annotated[str, typer.Argument(help='Bug ID to pull from syzbot')],
    syzkall_kernel: Annotated[str, typer.Option(help='Kernel name for database')] = 'android-5-10',
    force: Annotated[bool, typer.Option(help='Re-download even if already in database')] = False,
):
    """
    Pull a single bug directly from syzbot by its ID.
    
    This is faster than pulling all bugs when you only need one specific bug.
    The bug ID is the hex string from the syzbot URL (e.g., 283ce5a46486d6acdbaf).
    
    Examples:
        syzploit pull-bug 283ce5a46486d6acdbaf
        syzploit pull-bug 283ce5a46486d6acdbaf --force
    """
    from .SyzVerify.scrape import pull_single_bug
    
    db = SyzkallBugDatabase(syzkall_kernel)
    metadata = pull_single_bug(db, bug_id, force=force)
    
    if metadata:
        typer.echo(f"[✓] Bug pulled successfully:")
        typer.echo(f"    ID: {metadata.bug_id}")
        typer.echo(f"    Title: {metadata.title}")
        typer.echo(f"    Kernel: {metadata.kernel_name}")
        typer.echo(f"    C Repro: {'Yes' if metadata.c_repro_url else 'No'}")
        typer.echo(f"    Syz Repro: {'Yes' if metadata.syz_repro_url else 'No'}")
    else:
        typer.echo(f"[!] Failed to pull bug {bug_id}")
        raise typer.Exit(code=1)


# Probably temprorary command
@app.command()
def query(
    syzkall_kernel: Annotated[str, typer.Option(help='Kernel name to pull bugs for')] = 'android-5-10',
):
    """Query downloaded syzbot database for bugs"""
    SyzVerify.query(syzkall_kernel)

# Probably temprorary command
@app.command()
def test(
    bug_id: Annotated[str, typer.Argument(help='Bug ID to test')],
    local: Annotated[bool, typer.Option(help='Use local cuttlefish instance')] = True,
    root: Annotated[bool, typer.Option(help='Run repro as root user in VM')] = True,
    arch: Annotated[str, typer.Option(help='Architecture of kernel to test bugs on')] = 'x86_64',
    syzkall_kernel: Annotated[str, typer.Option(help='Kernel name to pull bugs for')] = 'android-5-10',
    qemu: Annotated[bool, typer.Option(help='Use QEMU VM instead of cuttlefish')]=False,
    source_image: Annotated[Path, typer.Option(help='Path to source image')] = None,
    source_disk: Annotated[Path, typer.Option(help='Path to source disk')] = None,
    outdir_name: Annotated[Optional[str], typer.Option(help='Output directory name for crash artifacts')] = "syzkall_crashes",
    dynamic_analysis: Annotated[bool, typer.Option(help='Enable GDB-based dynamic analysis')] = False,
    gdb_port: Annotated[int, typer.Option(help='GDB port for dynamic analysis')] = 1234,
):
    """Test a specific bug from syzbot"""
    SyzVerify.test(bug_id, local, arch, root, syzkall_kernel, qemu, source_disk, source_image, outdir_name, dynamic_analysis, gdb_port)

# Probably temprorary command
@app.command()
def testall(
    local: Annotated[bool, typer.Option(help='Use local cuttlefish instance')] = False,
    arch: Annotated[str, typer.Option(help='Architecture of kernel to test bugs on')] = 'x86_64',
    syzkall_kernel: Annotated[str, typer.Option(help='Kernel name to pull bugs for')] = 'android-5-10',
    qemu: Annotated[bool, typer.Option(help='Use QEMU VM instead of cuttlefish')]=False,
    source_image: Annotated[Path, typer.Option(help='Path to source image')] = None,
    source_disk: Annotated[Path, typer.Option(help='Path to source disk')] = None,
    source: Annotated[bool, typer.Option(help='Test bugs from syzbot source image')] = False,
    root: Annotated[bool, typer.Option(help='Run repro as root user in VM')] = False,
    outdir_name: Annotated[Optional[str], typer.Option(help='Output directory name for crash artifacts')] = "syzkall_crashes",
    dynamic_analysis: Annotated[bool, typer.Option(help='Enable GDB-based dynamic analysis')] = False,
    gdb_port: Annotated[int, typer.Option(help='GDB port for dynamic analysis')] = 1234,
    # Kernel GDB options
    kernel_gdb: Annotated[bool, typer.Option(help='Enable kernel GDB tracing for allocation tracking')] = False,
    kernel_gdb_port: Annotated[int, typer.Option(help='Kernel GDB port (crosvm)')] = 1234,
    vmlinux_path: Annotated[Optional[str], typer.Option(help='Path to vmlinux with debug symbols')] = None,
    # CuttlefishController options (use_cuttlefish_controller mode)
    use_cuttlefish_controller: Annotated[bool, typer.Option(help='Use CuttlefishController for Cuttlefish with runtime symbol extraction')] = False,
    ssh_host: Annotated[str, typer.Option(help='SSH host for Cuttlefish (can be a ~/.ssh/config alias)')] = 'localhost',
    ssh_port: Annotated[int, typer.Option(help='SSH port for Cuttlefish')] = 22,
    ssh_user: Annotated[Optional[str], typer.Option(help='SSH user (optional, uses ssh config if not set)')] = None,
    ssh_key: Annotated[Optional[str], typer.Option(help='SSH key path (optional, uses ssh config if not set)')] = None,
    adb_port: Annotated[int, typer.Option(help='ADB port for Cuttlefish device')] = 6520,
    instance: Annotated[Optional[int], typer.Option(help='Cuttlefish instance number (auto-calculates ADB port: 6520 + instance - 1)')] = None,
    persistent: Annotated[bool, typer.Option(help='Persistent mode (keep Cuttlefish running)')] = True,
    already_running: Annotated[bool, typer.Option(help='Cuttlefish is already running')] = True,
    setup_tunnels: Annotated[bool, typer.Option(help='Set up SSH tunnels for remote ADB/GDB access')] = False,
    extract_runtime_symbols: Annotated[bool, typer.Option(help='Extract kallsyms from running VM at runtime for accurate symbol addresses')] = True,
    # Lifecycle commands (for non-already-running mode)
    start_cmd: Annotated[Optional[str], typer.Option(help='Command to start Cuttlefish (run once at beginning if --no-already-running)')] = None,
    stop_cmd: Annotated[Optional[str], typer.Option(help='Command to stop Cuttlefish (run once at end)')] = None,
    runtime_logs_dir: Annotated[Optional[str], typer.Option(help='Path to cuttlefish runtime logs dir (e.g., ~/cuttlefish/cuttlefish_runtime.5/logs)')] = None,
    # LLM fix options
    use_llm_fix: Annotated[bool, typer.Option('--llm-fix/--no-llm-fix', help='Use LLM to fix compilation errors (uses cached fixes if available)')] = True,
):
    """
    Test all bugs from syzbot for a given kernel version.
    
    CUTTLEFISH CONTROLLER MODE (--use-cuttlefish-controller):
    - Uses CuttlefishController for advanced Cuttlefish management
    - Extracts runtime kallsyms from running VM for accurate breakpoint addresses
    - Enables GDB-based memory analysis (UAF/OOB detection)
    - Outputs crashes and analysis results with GDB traces
    
    Example:
        # Test all bugs with runtime symbol extraction on Cuttlefish
        syzploit testall --use-cuttlefish-controller --already-running --gdb-port 1234 \\
            --vmlinux-path ./vmlinux --extract-runtime-symbols
        
        # Boot Cuttlefish once at start, test all bugs, stop at end
        syzploit testall --use-cuttlefish-controller --persistent --no-already-running \\
            --ssh-host INGOTS-ARM --setup-tunnels --instance 20 \\
            --start-cmd "cd ~/cuttlefish && ./gdb_run.sh 20" \\
            --stop-cmd "cd ~/cuttlefish && ./stop.sh 20" \\
            --syzkall-kernel upstream --arch arm64
    """
    SyzVerify.test_all(
        local=local,
        arch=arch,
        kernel_name=syzkall_kernel,
        qemu=qemu,
        root=root,
        source_image=source_image,
        source_disk=source_disk,
        source=source,
        outdir_name=outdir_name,
        dynamic_analysis=dynamic_analysis,
        gdb_port=gdb_port,
        kernel_gdb=kernel_gdb,
        kernel_gdb_port=kernel_gdb_port,
        vmlinux_path=vmlinux_path,
        use_cuttlefish_controller=use_cuttlefish_controller,
        ssh_host=ssh_host,
        ssh_port=ssh_port,
        ssh_user=ssh_user,
        ssh_key=ssh_key,
        adb_port=adb_port,
        instance=instance,
        persistent=persistent,
        already_running=already_running,
        setup_tunnels=setup_tunnels,
        extract_runtime_symbols=extract_runtime_symbols,
        start_cmd=start_cmd,
        stop_cmd=stop_cmd,
        runtime_logs_dir=runtime_logs_dir,
        use_llm_fix=use_llm_fix,
    )


@app.command()
def testall_both(
    arch: Annotated[str, typer.Option(help='Architecture of kernel to test bugs on')] = 'x86_64',
    syzkall_kernel: Annotated[str, typer.Option(help='Kernel name to pull bugs for')] = 'android-5-10',
    outdir_name: Annotated[str, typer.Option(help='Base output directory name (will append _root and _nonroot)')] = "android-5.10_crashes",
    # CuttlefishController options
    use_cuttlefish_controller: Annotated[bool, typer.Option(help='Use CuttlefishController for Cuttlefish with runtime symbol extraction')] = False,
    ssh_host: Annotated[str, typer.Option(help='SSH host for Cuttlefish (can be a ~/.ssh/config alias)')] = 'localhost',
    instance: Annotated[Optional[int], typer.Option(help='Cuttlefish instance number')] = None,
    persistent: Annotated[bool, typer.Option(help='Persistent mode (keep Cuttlefish running)')] = True,
    already_running: Annotated[bool, typer.Option(help='Cuttlefish is already running')] = True,
    setup_tunnels: Annotated[bool, typer.Option(help='Set up SSH tunnels for remote ADB/GDB access')] = False,
    extract_runtime_symbols: Annotated[bool, typer.Option(help='Extract kallsyms from running VM (only if GDB enabled)')] = False,
    start_cmd: Annotated[Optional[str], typer.Option(help='Command to start Cuttlefish')] = None,
    stop_cmd: Annotated[Optional[str], typer.Option(help='Command to stop Cuttlefish')] = None,
    runtime_logs_dir: Annotated[Optional[str], typer.Option(help='Path to cuttlefish runtime logs dir')] = None,
    # GDB options
    enable_gdb: Annotated[bool, typer.Option('--gdb/--no-gdb', help='Enable GDB analysis (slower but more detailed)')] = False,
    # Connectivity check options
    pre_check_device: Annotated[bool, typer.Option('--pre-check/--no-pre-check', help='Check device connectivity before each test')] = True,
    pre_check_wait: Annotated[int, typer.Option(help='Max seconds to wait for device if offline')] = 60,
    # LLM fix options
    use_llm_fix: Annotated[bool, typer.Option('--llm-fix/--no-llm-fix', help='Use LLM to fix compilation errors (uses cached fixes if available)')] = True,
):
    """
    Test all bugs TWICE - once as root and once as non-root.
    
    This runs testall with --root first, then with --no-root, using separate
    output directories for each run.
    
    By default, GDB is disabled for faster execution. Use --gdb to enable
    GDB-based dynamic analysis.
    
    A pre-execution device connectivity check is performed before each test.
    If the device is offline, it waits up to --pre-check-wait seconds, then
    offers options to restart or skip.
    
    Example (fast mode without GDB):
        syzploit testall-both --use-cuttlefish-controller --arch arm64 \\
            --ssh-host INGOTS-ARM --setup-tunnels --instance 20 --persistent \\
            --already-running \\
            --start-cmd "cd ~/cuttlefish && HOME=/home/osboxes nohup ./gdb_run.sh 20 &" \\
            --stop-cmd "cd ~/cuttlefish && ./stop.sh 20"
    
    Example (with GDB analysis):
        syzploit testall-both --use-cuttlefish-controller --arch arm64 \\
            --ssh-host INGOTS-ARM --setup-tunnels --instance 20 --persistent \\
            --no-already-running --gdb --extract-runtime-symbols \\
            --start-cmd "cd ~/cuttlefish && ./gdb_run.sh 20" \\
            --stop-cmd "cd ~/cuttlefish && ./stop.sh 20" \\
            --runtime-logs-dir ~/cuttlefish/cuttlefish_runtime.20/logs
    """
    gdb_mode = "with GDB analysis" if enable_gdb else "without GDB (fast mode)"
    typer.echo("=" * 60)
    typer.echo(f"PHASE 1: Testing all bugs as ROOT ({gdb_mode})")
    typer.echo("=" * 60)
    
    SyzVerify.test_all(
        local=False,
        arch=arch,
        kernel_name=syzkall_kernel,
        qemu=False,
        root=True,  # ROOT
        source_image=None,
        source_disk=None,
        source=False,
        outdir_name=f"{outdir_name}_root",
        dynamic_analysis=enable_gdb,
        gdb_port=1234,
        kernel_gdb=enable_gdb,
        kernel_gdb_port=1234,
        vmlinux_path=None,
        use_cuttlefish_controller=use_cuttlefish_controller,
        ssh_host=ssh_host,
        ssh_port=22,
        ssh_user=None,
        ssh_key=None,
        adb_port=6520,
        instance=instance,
        persistent=persistent,
        already_running=already_running,
        setup_tunnels=setup_tunnels,
        extract_runtime_symbols=extract_runtime_symbols if enable_gdb else False,
        start_cmd=start_cmd,
        stop_cmd=stop_cmd,  # Pass stop_cmd to allow restart on crash
        runtime_logs_dir=runtime_logs_dir,
        pre_check_device=pre_check_device,
        pre_check_wait=pre_check_wait,
        use_llm_fix=use_llm_fix,
    )
    
    typer.echo("")
    typer.echo("=" * 60)
    typer.echo(f"PHASE 2: Testing all bugs as NON-ROOT ({gdb_mode})")
    typer.echo("=" * 60)
    
    SyzVerify.test_all(
        local=False,
        arch=arch,
        kernel_name=syzkall_kernel,
        qemu=False,
        root=False,  # NON-ROOT
        source_image=None,
        source_disk=None,
        source=False,
        outdir_name=f"{outdir_name}_nonroot",
        dynamic_analysis=enable_gdb,
        gdb_port=1234,
        kernel_gdb=enable_gdb,
        kernel_gdb_port=1234,
        vmlinux_path=None,
        use_cuttlefish_controller=use_cuttlefish_controller,
        ssh_host=ssh_host,
        ssh_port=22,
        ssh_user=None,
        ssh_key=None,
        adb_port=6520,
        instance=instance,
        persistent=persistent,
        already_running=True,  # Already running from first phase
        setup_tunnels=setup_tunnels,
        extract_runtime_symbols=extract_runtime_symbols if enable_gdb else False,
        start_cmd=start_cmd,  # Pass start_cmd to allow restart on crash
        stop_cmd=stop_cmd,  # Stop at end and allow restart on crash
        runtime_logs_dir=runtime_logs_dir,
        pre_check_device=pre_check_device,
        pre_check_wait=pre_check_wait,
        use_llm_fix=use_llm_fix,
    )
    
    typer.echo("")
    typer.echo("=" * 60)
    typer.echo("BOTH PHASES COMPLETE")
    typer.echo(f"  Root results:     {outdir_name}_root/")
    typer.echo(f"  Non-root results: {outdir_name}_nonroot/")
    typer.echo("=" * 60)


# Probably temprorary command
@app.command()
def collectstats(
    syzkall_kernel: Annotated[str, typer.Option(help='Kernel name to pull bugs for')] = 'android-5-10',
    outfile: Annotated[str, typer.Option(help='Output file to write stats to')] = 'syzkall_stats',
):
    """ Collect stats on bugs from syzbot """
    SyzVerify.collect_stats(syzkall_kernel, outfile)


@app.command()
def test_cuttlefish(
    bug_id: Annotated[str, typer.Argument(help='Bug ID to test')],
    syzkall_kernel: Annotated[str, typer.Option(help='Kernel name for bug')] = 'android-5-10',
    arch: Annotated[str, typer.Option(help='Architecture (arm64/x86_64)')] = 'arm64',
    root: Annotated[bool, typer.Option(help='Run reproducer as root')] = True,
    # Cuttlefish instance settings
    ssh_host: Annotated[str, typer.Option(help='SSH host for Cuttlefish (can be a ~/.ssh/config alias)')] = 'localhost',
    ssh_port: Annotated[int, typer.Option(help='SSH port for Cuttlefish')] = 22,
    ssh_user: Annotated[Optional[str], typer.Option(help='SSH user (optional, uses ssh config if not set)')] = None,
    ssh_key: Annotated[Optional[str], typer.Option(help='SSH key path (optional, uses ssh config if not set)')] = None,
    ssh_password: Annotated[Optional[str], typer.Option(help='SSH password (if no key)')] = None,
    # Persistence mode
    persistent: Annotated[bool, typer.Option(help='Persistent mode (keep Cuttlefish running)')] = True,
    already_running: Annotated[bool, typer.Option(help='Cuttlefish is already running')] = True,
    start_cmd: Annotated[Optional[str], typer.Option(help='Command to start Cuttlefish with GDB (e.g. ./gdb_run.sh)')] = None,
    run_cmd: Annotated[Optional[str], typer.Option(help='Command to start Cuttlefish WITHOUT GDB (e.g. ./run.sh). Used for symbol extraction.')] = None,
    stop_cmd: Annotated[Optional[str], typer.Option(help='Command to stop Cuttlefish (non-persistent)')] = None,
    # Connection settings
    instance: Annotated[Optional[int], typer.Option(help='Cuttlefish instance number (auto-calculates ADB port: 6520 + instance - 1)')] = None,
    gdb_port: Annotated[int, typer.Option(help='Crosvm kernel GDB port')] = 1234,
    adb_port: Annotated[int, typer.Option(help='ADB port for Cuttlefish device (overridden by --instance)')] = 6520,
    dynamic_analysis: Annotated[bool, typer.Option(help='Enable GDB-based dynamic analysis (alias for --enable-gdb)')] = True,
    setup_tunnels: Annotated[bool, typer.Option(help='Set up SSH tunnels for remote ADB/GDB access')] = False,
    # Cuttlefish runtime logs
    runtime_logs_dir: Annotated[Optional[str], typer.Option(help='Path to cuttlefish runtime logs dir (e.g., ~/cuttlefish/cuttlefish_runtime.5/logs). If not set, inferred from start command')] = None,
    # Kernel symbol extraction options
    kernel_image: Annotated[Optional[str], typer.Option(help='Path to kernel Image file (local or remote). Used to extract vmlinux with symbols via vmlinux-to-elf')] = None,
    vmlinux_path: Annotated[Optional[str], typer.Option(help='Path to vmlinux with debug symbols (local). If not set and --kernel-image is provided, vmlinux will be auto-extracted')] = None,
    system_map: Annotated[Optional[str], typer.Option(help='Path to System.map for symbol resolution. Use this if you have a pre-generated System.map (e.g., from /proc/kallsyms)')] = None,
    remote_vmlinux_path: Annotated[Optional[str], typer.Option(help='DEPRECATED: Path to vmlinux on remote server (GDB now runs locally via tunnel)')] = None,
    extract_symbols: Annotated[bool, typer.Option(help='Auto-extract vmlinux from kernel Image using vmlinux-to-elf')] = True,
    extract_runtime_symbols: Annotated[bool, typer.Option(help='Extract kallsyms from running VM at runtime for accurate symbol addresses')] = True,
    # Other options
    timeout: Annotated[int, typer.Option(help='Test timeout in seconds')] = 120,
    output_dir: Annotated[Optional[Path], typer.Option(help='Output directory for logs')] = None,
):
    """
    Test a bug reproducer on Cuttlefish with support for persistent and non-persistent modes.
    
    PERSISTENT MODE (default):
    - Use when Cuttlefish is already running or should stay up between tests
    - Set --persistent --already-running for an already-booted instance
    - Set --persistent --no-already-running with --start-cmd to boot once and keep running
    
    NON-PERSISTENT MODE:
    - Use when Cuttlefish should start/stop for each test
    - Set --no-persistent with --start-cmd and --stop-cmd
    
    SYMBOL EXTRACTION:
    - Provide --kernel-image to auto-extract vmlinux with symbols using vmlinux-to-elf
    - This enables proper symbol resolution for GDB breakpoints and backtraces
    - The kernel Image can be local or remote (downloaded via SSH if remote)
    - Alternatively, provide --vmlinux-path directly if you already have vmlinux
    
    Examples:
        # Test on already-running local Cuttlefish with auto symbol extraction
        syzploit test-cuttlefish abc123 --persistent --already-running --gdb-port 1234 \\
            --kernel-image ./package/kernel/Image
        
        # Test on remote Cuttlefish via SSH with symbol extraction
        syzploit test-cuttlefish abc123 --ssh-host cuttlefish2 --setup-tunnels \\
            --instance 5 --kernel-image /home/user/cuttlefish/package/kernel/Image \\
            --start-cmd "cd ~/cuttlefish && ./gdb_run.sh 5" \\
            --stop-cmd "cd ~/cuttlefish && ./stop.sh 5"
        
        # Test with pre-extracted vmlinux
        syzploit test-cuttlefish abc123 --persistent --already-running \\
            --vmlinux-path ./symbols/vmlinux
    """
    from .SyzVerify.scrape import pull_single_bug
    
    # Initialize DB and get bug metadata
    db = SyzkallBugDatabase(syzkall_kernel)
    md = db.get_bug_metadata(bug_id)
    if md is None:
        typer.echo(f"[+] Bug {bug_id} not in local database, pulling from syzbot...")
        md = pull_single_bug(db, bug_id)
        if md is None:
            typer.echo(f"[!] Failed to pull bug {bug_id} from syzbot")
            raise typer.Exit(code=1)
        typer.echo(f"[+] Successfully pulled: {md.title}")
    
    # Compile reproducer
    typer.echo(f"[+] Compiling reproducer for {arch}...")
    repro_bin = md.compile_repro(arch)
    typer.echo(f"[+] Reproducer binary: {repro_bin}")
    
    # Calculate ADB port from instance number if provided
    actual_adb_port = adb_port
    if instance is not None:
        actual_adb_port = calculate_adb_port(instance)
        typer.echo(f"[+] Instance {instance}: using ADB port {actual_adb_port}")
    
    # Auto-derive run_cmd from start_cmd if not explicitly provided
    actual_run_cmd = run_cmd
    if not actual_run_cmd and start_cmd and 'gdb_run' in start_cmd:
        actual_run_cmd = start_cmd.replace('gdb_run', 'run')
    
    # Create Cuttlefish configuration
    config = CuttlefishConfig(
        ssh_host=ssh_host,
        ssh_port=ssh_port,
        ssh_user=ssh_user,
        ssh_password=ssh_password,
        ssh_key_path=ssh_key,
        persistent=persistent,
        already_running=already_running,
        start_command=start_cmd,
        run_command=actual_run_cmd,
        stop_command=stop_cmd,
        gdb_port=gdb_port,
        adb_port=actual_adb_port,
        enable_gdb=dynamic_analysis,
        setup_tunnels=setup_tunnels,
        # Cuttlefish runtime logs directory
        cuttlefish_runtime_logs=runtime_logs_dir,
        # Kernel symbol extraction
        kernel_image_path=kernel_image,
        vmlinux_path=vmlinux_path,
        system_map_path=system_map,
        extract_symbols=extract_symbols,
        extract_runtime_symbols=extract_runtime_symbols,
    )
    
    # Determine output directory
    log_dir = str(output_dir) if output_dir else f"cuttlefish_test_{bug_id}"
    
    # Get parsed crash info if available (optional attribute)
    parsed_crash = None
    if hasattr(md, 'crash_parser_results') and md.crash_parser_results:
        parsed_crash = md.crash_parser_results
    
    # If no parsed crash but we have a crash report text, parse it for stack trace
    if not parsed_crash and hasattr(md, 'crash_report') and md.crash_report:
        typer.echo("[+] Parsing crash report for stack trace breakpoints...")
        parsed_crash = _parse_crash_report_for_stack(md.crash_report)
        if parsed_crash and parsed_crash.get('stack_frames'):
            typer.echo(f"[+] Extracted {len(parsed_crash['stack_frames'])} stack frames from crash report")
        else:
            typer.echo("[+] No stack frames extracted from crash report")
    
    # Run test
    typer.echo(f"[+] Running test with Cuttlefish controller...")
    typer.echo(f"[+] Mode: {'persistent' if persistent else 'non-persistent'}")
    typer.echo(f"[+] Dynamic analysis (GDB): {'enabled' if dynamic_analysis else 'disabled'}")
    typer.echo(f"[+] SSH tunnels: {'enabled' if setup_tunnels else 'disabled'}")
    if kernel_image:
        typer.echo(f"[+] Kernel Image: {kernel_image}")
    if vmlinux_path:
        typer.echo(f"[+] vmlinux: {vmlinux_path}")
    if system_map:
        typer.echo(f"[+] System.map: {system_map}")
    
    crashed, crash_type, results = test_repro_with_cuttlefish_controller(
        repro_path=str(repro_bin),
        bug_id=bug_id,
        cuttlefish_config=config,
        parsed_crash=parsed_crash,
        log_dir=log_dir,
        root=root,
        timeout=timeout,
        arch=arch,
        vmlinux_path=vmlinux_path,
        remote_vmlinux_path=remote_vmlinux_path,
    )
    
    # Report results
    if crashed:
        typer.echo(f"[✓] CRASH DETECTED (type: {crash_type})")
    else:
        typer.echo(f"[!] No crash detected")
    
    typer.echo(f"[+] Results saved to: {log_dir}")

@app.command()
def analyze(
    bug_id: Annotated[str, typer.Argument(help='Bug ID to analyze')],
    syzkall_kernel: Annotated[str, typer.Option(help='Kernel name for bug')] = 'android-5-10',
    qemu: Annotated[bool, typer.Option(help='Use QEMU VM')] = False,
    source_image: Annotated[Path, typer.Option(help='Path to kernel image')] = None,
    source_disk: Annotated[Path, typer.Option(help='Path to disk image')] = None,
    dynamic_analysis: Annotated[bool, typer.Option(help='Enable GDB-based dynamic analysis')] = True,
    gdb_port: Annotated[int, typer.Option(help='GDB port')] = 1234,
    arch: Annotated[str, typer.Option(help='Architecture of kernel to analyze')] = 'x86_64',
    output_dir: Annotated[Optional[Path], typer.Option(help='Output directory for analysis results')] = None,
    skip_static: Annotated[bool, typer.Option(help='Skip static analysis and reuse prior results')] = False,
    ignore_exploitability: Annotated[bool, typer.Option(help='Run dynamic even if static exploitability is low/unknown')] = False,
    dynamic_only: Annotated[bool, typer.Option(help='Convenience flag: skip static and ignore exploitability gating')] = False,
    # Feasibility options
    check_feasibility: Annotated[bool, typer.Option(help='Run cross-version feasibility check')] = False,
    target_kernel_version: Annotated[Optional[str], typer.Option(help='Target kernel version for feasibility check')] = None,
    fix_commits: Annotated[Optional[str], typer.Option(help='Comma-separated fix commit SHAs')] = None,
    kallsyms_path: Annotated[Optional[Path], typer.Option(help='Path to target /proc/kallsyms dump')] = None,
    system_map_path: Annotated[Optional[Path], typer.Option(help='Path to target System.map')] = None,
    vmlinux_path: Annotated[Optional[Path], typer.Option(help='Path to target vmlinux')] = None,
    kernel_tree_path: Annotated[Optional[Path], typer.Option(help='Path to target kernel git tree')] = None,
    feas_ssh_host: Annotated[Optional[str], typer.Option(help='SSH host for feasibility remote checks')] = None,
    feas_ssh_port: Annotated[int, typer.Option(help='SSH port for feasibility')] = 22,
    feas_ssh_user: Annotated[str, typer.Option(help='SSH user for feasibility')] = 'root',
    feas_ssh_key: Annotated[Optional[Path], typer.Option(help='SSH key for feasibility')] = None,
    feas_adb_port: Annotated[Optional[int], typer.Option(help='ADB port for feasibility')] = None,
    feas_use_adb: Annotated[bool, typer.Option(help='Use ADB for feasibility live test')] = False,
    skip_gdb_path_check: Annotated[bool, typer.Option(help='Skip GDB path verification in feasibility')] = False,
):
    """Analyze a specific bug with static and optional dynamic analysis"""
    if dynamic_only:
        skip_static = True
        ignore_exploitability = True
    fix_list = [c.strip() for c in fix_commits.split(",")] if fix_commits else None
    SyzAnalyze.analyze_bug(
        bug_id,
        syzkall_kernel,
        qemu,
        source_image,
        source_disk,
        dynamic_analysis,
        gdb_port,
        arch,
        output_dir,
        skip_static=skip_static,
        ignore_exploitability=ignore_exploitability,
        reuse_dir=output_dir,
        check_feasibility=check_feasibility,
        target_kernel_version=target_kernel_version,
        fix_commits=fix_list,
        kallsyms_path=str(kallsyms_path) if kallsyms_path else None,
        system_map_path=str(system_map_path) if system_map_path else None,
        vmlinux_path=str(vmlinux_path) if vmlinux_path else None,
        kernel_tree_path=str(kernel_tree_path) if kernel_tree_path else None,
        ssh_host=feas_ssh_host,
        ssh_port=feas_ssh_port,
        ssh_user=feas_ssh_user,
        ssh_key=str(feas_ssh_key) if feas_ssh_key else None,
        adb_port=feas_adb_port,
        use_adb=feas_use_adb,
        skip_gdb_path_check=skip_gdb_path_check,
    )


@app.command(name="check-feasibility")
def check_feasibility(
    bug_id: Annotated[str, typer.Argument(help='Bug ID to check feasibility for')],
    syzkall_kernel: Annotated[str, typer.Option(help='Kernel name for bug')] = 'android-5-10',
    target_kernel_version: Annotated[Optional[str], typer.Option(help='Target kernel version string (e.g. 5.15.100)')] = None,
    fix_commits: Annotated[Optional[str], typer.Option(help='Comma-separated fix commit SHAs')] = None,
    kallsyms_path: Annotated[Optional[Path], typer.Option(help='Path to target /proc/kallsyms dump')] = None,
    system_map_path: Annotated[Optional[Path], typer.Option(help='Path to target System.map')] = None,
    vmlinux_path: Annotated[Optional[Path], typer.Option(help='Path to target vmlinux')] = None,
    kernel_tree_path: Annotated[Optional[Path], typer.Option(help='Path to target kernel git tree')] = None,
    ssh_host: Annotated[Optional[str], typer.Option(help='SSH host for remote symbol lookup')] = None,
    ssh_port: Annotated[int, typer.Option(help='SSH port')] = 22,
    ssh_user: Annotated[str, typer.Option(help='SSH user')] = 'root',
    ssh_key: Annotated[Optional[Path], typer.Option(help='SSH private key path')] = None,
    adb_port: Annotated[Optional[int], typer.Option(help='ADB port for Android target')] = None,
    use_adb: Annotated[bool, typer.Option(help='Push reproducer via ADB instead of SSH')] = False,
    gdb_port: Annotated[int, typer.Option(help='GDB port for path verification')] = 1234,
    skip_gdb_path_check: Annotated[bool, typer.Option(help='Skip GDB path verification')] = False,
    output_dir: Annotated[Optional[Path], typer.Option(help='Output directory for feasibility report')] = None,
):
    """Check if a bug is feasible on a different kernel version.

    Performs symbol presence checks, fix-commit backport detection,
    optionally runs a live reproducer test, and GDB-based crash path
    verification on the target.
    """
    from .SyzAnalyze.feasibility import assess_feasibility
    from .SyzAnalyze import crash_analyzer as _canalyzer
    from rich.console import Console

    console = Console()
    db = SyzVerify.BugDatabase()
    entry = db.get_entry(bug_id, syzkall_kernel)
    if entry is None:
        console.print(f"[red]Bug {bug_id} not found in database[/red]")
        raise typer.Exit(code=1)

    crash_log = entry.get("crash_log", "")
    reproducer = entry.get("syz_repro") or entry.get("c_repro") or ""

    # Parse crash log using the crash analyzer
    parsed_crash = _canalyzer.parse_crash_log(crash_log) if crash_log else {}

    fix_list = [c.strip() for c in fix_commits.split(",")] if fix_commits else []

    console.print(f"[bold]Checking feasibility for bug {bug_id}[/bold]")
    if fix_list:
        console.print(f"  Fix commits: {', '.join(fix_list)}")

    out = Path(output_dir) if output_dir else Path(f"analysis_{bug_id}")
    out.mkdir(parents=True, exist_ok=True)

    result = assess_feasibility(
        bug_id=bug_id,
        parsed_crash=parsed_crash,
        original_kernel=syzkall_kernel,
        target_kernel=target_kernel_version or "",
        repro_source=reproducer if reproducer and os.path.isfile(reproducer) else None,
        fix_commits=fix_list,
        kallsyms_path=str(kallsyms_path) if kallsyms_path else None,
        system_map_path=str(system_map_path) if system_map_path else None,
        vmlinux_path=str(vmlinux_path) if vmlinux_path else None,
        kernel_tree_path=str(kernel_tree_path) if kernel_tree_path else None,
        ssh_host=ssh_host,
        ssh_port=ssh_port,
        ssh_user=ssh_user,
        ssh_key=str(ssh_key) if ssh_key else None,
        adb_port=adb_port or 6520,
        use_adb=use_adb,
        gdb_port=gdb_port,
        skip_gdb_path_check=skip_gdb_path_check,
    )

    import json
    report_path = out / "feasibility_report.json"
    with open(report_path, "w") as f:
        json.dump(result.to_dict(), f, indent=2)
    console.print(f"[green]✓[/green] Report saved: {report_path}")

    # Display results
    verdict_color = {
        "likely_feasible": "green",
        "likely_patched": "red",
        "inconclusive": "yellow",
    }.get(result.overall_verdict, "white")
    console.print(f"\n[bold {verdict_color}]Verdict: {result.overall_verdict} "
                  f"(confidence: {result.confidence:.0%})[/bold {verdict_color}]")

    if result.symbol_check:
        sc = result.symbol_check
        console.print(f"  Symbol check: {sc.verdict}")
        if sc.functions_found:
            console.print(f"    Present: {', '.join(sc.functions_found[:5])}")
        if sc.functions_missing:
            console.print(f"    Absent: {', '.join(sc.functions_missing[:5])}")
    if result.fix_check:
        console.print(f"  Fix backport: {result.fix_check.verdict}")
    if result.live_test:
        lt = result.live_test
        console.print(f"  Live test: {lt.verdict}")
        if lt.matched_functions:
            console.print(f"    Matched: {', '.join(lt.matched_functions[:5])}")
    if result.gdb_path_check:
        gpc = result.gdb_path_check
        console.print(f"  GDB path check: {gpc.verdict} "
                      f"({len(gpc.hit_functions)}/{len(gpc.expected_functions)} hit, "
                      f"ratio={gpc.hit_ratio:.0%})")
        if gpc.hit_functions:
            console.print(f"    Hit: {', '.join(gpc.hit_functions[:5])}")
        if gpc.missed_functions:
            console.print(f"    Missed: {', '.join(gpc.missed_functions[:5])}")
    for note in result.notes:
        console.print(f"  [dim]{note}[/dim]")


@app.command()
def pipeline_cuttlefish(
    bug_id: Annotated[str, typer.Argument(help='Bug ID for end-to-end pipeline')],
    syzkall_kernel: Annotated[str, typer.Option(help='Kernel name for bug')] = 'android-5-10',
    arch: Annotated[str, typer.Option(help='Architecture (arm64/x86_64)')] = 'arm64',
    root: Annotated[bool, typer.Option(help='Run reproducer as root')] = True,
    # Cuttlefish instance settings
    ssh_host: Annotated[str, typer.Option(help='SSH host for Cuttlefish (can be a ~/.ssh/config alias)')] = 'localhost',
    ssh_port: Annotated[int, typer.Option(help='SSH port for Cuttlefish')] = 22,
    ssh_user: Annotated[Optional[str], typer.Option(help='SSH user (optional, uses ssh config if not set)')] = None,
    ssh_key: Annotated[Optional[str], typer.Option(help='SSH key path (optional, uses ssh config if not set)')] = None,
    ssh_password: Annotated[Optional[str], typer.Option(help='SSH password (if no key)')] = None,
    # Persistence mode
    persistent: Annotated[bool, typer.Option(help='Persistent mode (keep Cuttlefish running)')] = True,
    already_running: Annotated[bool, typer.Option(help='Cuttlefish is already running')] = True,
    start_cmd: Annotated[Optional[str], typer.Option(help='Command to start Cuttlefish with GDB (e.g. ./gdb_run.sh)')] = None,
    run_cmd: Annotated[Optional[str], typer.Option(help='Command to start Cuttlefish WITHOUT GDB (e.g. ./run.sh). Used for symbol extraction. Auto-derived from --start-cmd if not set.')] = None,
    stop_cmd: Annotated[Optional[str], typer.Option(help='Command to stop Cuttlefish (non-persistent)')] = None,
    # Connection settings
    instance: Annotated[Optional[int], typer.Option(help='Cuttlefish instance number (auto-calculates ADB port: 6520 + instance - 1)')] = None,
    gdb_port: Annotated[int, typer.Option(help='Crosvm kernel GDB port')] = 1234,
    adb_port: Annotated[int, typer.Option(help='ADB port for Cuttlefish device (overridden by --instance)')] = 6520,
    dynamic_analysis: Annotated[bool, typer.Option(help='Enable GDB-based dynamic analysis')] = True,
    setup_tunnels: Annotated[bool, typer.Option(help='Set up SSH tunnels for remote ADB/GDB access')] = False,
    # Cuttlefish runtime logs
    runtime_logs_dir: Annotated[Optional[str], typer.Option(help='Path to cuttlefish runtime logs dir')] = None,
    # Kernel symbol extraction options
    kernel_image: Annotated[Optional[str], typer.Option(help='Path to kernel Image file (local or remote)')] = None,
    vmlinux_path: Annotated[Optional[str], typer.Option(help='Path to vmlinux with debug symbols')] = None,
    system_map: Annotated[Optional[str], typer.Option(help='Path to System.map for symbol resolution')] = None,
    extract_symbols: Annotated[bool, typer.Option(help='Auto-extract vmlinux from kernel Image')] = True,
    extract_runtime_symbols: Annotated[bool, typer.Option(help='Extract kallsyms from running VM at runtime for accurate symbol addresses')] = True,
    # Pipeline options
    skip_static: Annotated[bool, typer.Option(help='Skip static analysis')] = False,
    ignore_exploitability: Annotated[bool, typer.Option(help='Run dynamic even if exploitability is low')] = False,
    goal: Annotated[str, typer.Option(help='Exploit goal for synthesis')] = 'privilege_escalation',
    platform: Annotated[Optional[str], typer.Option(help='Target platform: linux, android, or generic')] = None,
    timeout: Annotated[int, typer.Option(help='Test timeout in seconds')] = 120,
    output_dir: Annotated[Optional[Path], typer.Option(help='Output directory for logs')] = None,
    # Exploit verification
    verify_exploit: Annotated[bool, typer.Option('--verify/--no-verify', help='Verify exploit for privilege escalation at the end')] = True,
    # Exploit verification start command (non-GDB)
    exploit_start_cmd: Annotated[Optional[str], typer.Option(help='Command to start Cuttlefish for exploit verification (without GDB). If provided, used instead of start_cmd for Step 6')] = None,
    model: Annotated[str, typer.Option(help='LLM model to use (e.g. gpt-4o, openrouter/anthropic/claude-sonnet-4-20250514)')] = 'gpt-4o',
    planner: Annotated[str, typer.Option(help='Planner strategy: pddl (PDDL+LLM stitcher), llm (pure LLM), auto (PDDL first, LLM fallback)')] = 'auto',
    debug: Annotated[bool, typer.Option(help='Enable debug output')] = False,
    verbose: Annotated[bool, typer.Option(help='Print planner output')] = False,
):
    """
    Full pipeline with Cuttlefish: analyze crash, run dynamic analysis, synthesize exploit, and verify.
    
    Combines the functionality of test_cuttlefish + analyze + synthesize + verify into a single command
    that properly passes crash stack trace information from static analysis to dynamic analysis.
    
    Steps:
    1) Static analysis (LLM-based crash analysis)
    2) Parse crash log to extract stack trace functions
    3) Run reproducer with GDB breakpoints on stack trace functions
    4) Collect alloc/free events and function hits
    5) Post-process for UAF/OOB detection
    6) Synthesize exploit plan
    7) Verify exploit achieves privilege escalation
    
    EXPLOIT VERIFICATION:
    Use --exploit-start-cmd to provide a separate start command for exploit verification (Step 6).
    This is useful when your main --start-cmd starts the instance with GDB support (slower boot),
    but for exploit verification you want to start without GDB for faster testing.
    
    Example:
        # Normal run with GDB tracing
        syzploit pipeline-cuttlefish abc123 --ssh-host cuttlefish2 --setup-tunnels \\
            --instance 5 --kernel-image /home/user/cuttlefish/package/kernel/Image
        
        # Full pipeline with separate start commands for GDB tracing vs exploit verification
        syzploit pipeline-cuttlefish abc123 --ssh-host INGOTS-ARM --setup-tunnels --instance 20 \\
            --start-cmd "cd ~/challenge-4 && ./gdb_run.sh 20" \\
            --exploit-start-cmd "cd ~/challenge-4 && ./run.sh 20"
    """
    from .SyzAnalyze import crash_analyzer as analyzer
    from .SyzVerify.scrape import pull_single_bug
    
    # Initialize DB and get bug metadata
    db = SyzkallBugDatabase(syzkall_kernel)
    md = db.get_bug_metadata(bug_id)
    if md is None:
        typer.echo(f"[+] Bug {bug_id} not in local database, pulling from syzbot...")
        md = pull_single_bug(db, bug_id)
        if md is None:
            typer.echo(f"[!] Failed to pull bug {bug_id} from syzbot")
            raise typer.Exit(code=1)
        typer.echo(f"[+] Successfully pulled: {md.title}")
    
    # Setup output directory
    if output_dir is None:
        output_dir = Path(f"analysis_{bug_id}")
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    typer.echo(f"[+] Pipeline for Bug {bug_id}")
    typer.echo(f"[+] Output directory: {output_dir}")
    
    summary = {"bug_id": bug_id, "steps": {}}
    
    # Step 1: Static Analysis to get crash info
    typer.echo("\n[STEP 1] Static Analysis...")
    parsed_crash = None
    static_result = None
    
    if not skip_static:
        try:
            # Parse crash log to get frames
            parsed_crash = analyzer.parse_crash_log(md.crash_report)
            
            # Get crash stack functions
            crash_stack_funcs = []
            if parsed_crash:
                seen = set()
                for frame in parsed_crash.get('frames', [])[:10]:
                    func = frame.get('func', '')
                    if func:
                        base_func = func.split('+')[0].split('.')[0].strip()
                        if base_func and base_func not in seen:
                            seen.add(base_func)
                            crash_stack_funcs.append(base_func)
            
            typer.echo(f"[+] Parsed {len(parsed_crash.get('frames', []))} stack frames")
            typer.echo(f"[+] Crash stack functions: {crash_stack_funcs[:5]}...")
            
            # Prepare reproducer
            c_repro_src = None
            if getattr(md, 'c_repro_url', None):
                p = md.save_c_repro()
                if p and Path(p).exists():
                    c_repro_src = str(p)
            if not c_repro_src and getattr(md, 'syz_repro_url', None):
                p = md.generate_c_repro(arch)
                if p and Path(p).exists():
                    c_repro_src = str(p)
            
            # Run static analysis
            if c_repro_src:
                static_result = analyzer.analyze(md.crash_report, c_repro_src, None, None)
                static_output = output_dir / "static_analysis.json"
                with open(static_output, 'w') as f:
                    json.dump(static_result, f, indent=2)
                typer.echo(f"[+] Static analysis saved: {static_output}")
                summary["steps"]["static"] = {"success": True, "frames": len(crash_stack_funcs)}
            else:
                typer.echo("[!] No reproducer source available for static analysis")
                summary["steps"]["static"] = {"success": False, "error": "no reproducer"}
        except Exception as e:
            typer.echo(f"[!] Static analysis failed: {e}")
            summary["steps"]["static"] = {"success": False, "error": str(e)}
    else:
        typer.echo("[+] Skipping static analysis (--skip-static)")
        # Try to load prior results
        static_path = output_dir / "static_analysis.json"
        if static_path.exists():
            with open(static_path) as f:
                static_result = json.load(f)
            parsed_crash = static_result  # May contain frames
            typer.echo(f"[+] Loaded prior static results: {static_path}")
    
    # Ensure we have parsed_crash for dynamic analysis
    if parsed_crash is None:
        try:
            parsed_crash = analyzer.parse_crash_log(md.crash_report)
        except Exception:
            parsed_crash = {}
    
    # Step 2: Compile reproducer
    typer.echo("\n[STEP 2] Compiling reproducer...")
    try:
        repro_bin = md.compile_repro(arch)
        typer.echo(f"[+] Reproducer binary: {repro_bin}")
        summary["steps"]["compile"] = {"success": True, "binary": str(repro_bin)}
    except Exception as e:
        typer.echo(f"[!] Failed to compile reproducer: {e}")
        summary["steps"]["compile"] = {"success": False, "error": str(e)}
        raise typer.Exit(code=1)
    
    # Steps 3-6: Shared pipeline (dynamic → post-process → adapt → synthesize → verify)
    _run_shared_pipeline(
        bug_id=bug_id,
        output_dir=output_dir,
        parsed_crash=parsed_crash,
        repro_bin=str(repro_bin),
        arch=arch,
        root=root,
        ssh_host=ssh_host,
        ssh_port=ssh_port,
        ssh_user=ssh_user,
        ssh_password=ssh_password,
        ssh_key=ssh_key,
        persistent=persistent,
        already_running=already_running,
        start_cmd=start_cmd,
        run_cmd=run_cmd,
        stop_cmd=stop_cmd,
        instance=instance,
        gdb_port=gdb_port,
        adb_port=adb_port,
        dynamic_analysis=dynamic_analysis,
        setup_tunnels=setup_tunnels,
        runtime_logs_dir=runtime_logs_dir,
        kernel_image=kernel_image,
        vmlinux_path=vmlinux_path,
        system_map=system_map,
        extract_symbols=extract_symbols,
        extract_runtime_symbols=extract_runtime_symbols,
        goal=goal,
        platform=platform,
        timeout=timeout,
        verify_exploit=verify_exploit,
        exploit_start_cmd=exploit_start_cmd,
        model=model,
        planner=planner,
        debug=debug,
        verbose=verbose,
        summary=summary,
        step_offset=3,
    )


@app.command()
def synthesize(
    bug_id: Annotated[str, typer.Argument(help='Bug ID to synthesize exploit for')],
    goal: Annotated[str, typer.Option(help='Desired exploit goal (e.g., privilege_escalation, root_shell, container_escape)')] = 'privilege_escalation',
    platform: Annotated[Optional[str], typer.Option(help='Target platform: linux, android, or generic (auto-detect if not set)')] = None,
    kernel_research_path: Annotated[Optional[Path], typer.Option(help='Path to google/kernel-research repo')] = None,
    analysis_dir: Annotated[Optional[Path], typer.Option(help='Path to analysis_<bug_id> directory')] = None,
    vmlinux_path: Annotated[Optional[Path], typer.Option(help='Path to vmlinux for gadget analysis')] = None,
    verbose: Annotated[bool, typer.Option(help='Print planner output')] = False,
    debug: Annotated[bool, typer.Option(help='Enable debug output')] = False,
    time_limit: Annotated[int, typer.Option(help='Planner time limit in seconds')] = 300,
    model: Annotated[str, typer.Option(help='LLM model to use (e.g. gpt-4o, openrouter/anthropic/claude-sonnet-4-20250514)')] = 'gpt-4o',
    # Exploit verification options
    verify_exploit: Annotated[bool, typer.Option('--verify/--no-verify', help='Verify synthesized exploit on device')] = False,
    arch: Annotated[str, typer.Option(help='Architecture for compilation (arm64/x86_64)')] = 'arm64',
    ssh_host: Annotated[Optional[str], typer.Option(help='SSH host for Cuttlefish')] = None,
    instance: Annotated[Optional[int], typer.Option(help='Cuttlefish instance number')] = None,
    start_cmd: Annotated[Optional[str], typer.Option(help='Command to start Cuttlefish')] = None,
    stop_cmd: Annotated[Optional[str], typer.Option(help='Command to stop Cuttlefish')] = None,
):
    """Synthesize an exploit plan using SyzAnalyze + kernelXDK primitives.
    
    Supports Linux kernel and Android kernel exploitation. Platform is auto-detected
    from analysis data if not specified.
    
    Use --verify to test the synthesized exploit on a device after synthesis.
    This will:
    1. Stop the instance (clean state)
    2. Start the instance (fresh boot)
    3. Push the compiled exploit
    4. Run as non-root user
    5. Verify privilege escalation to root
    
    Example with verification:
        syzploit synthesize abc123 --verify --arch arm64 \\
            --ssh-host INGOTS-ARM --instance 20 \\
            --start-cmd "cd ~/cuttlefish && ./gdb_run.sh 20" \\
            --stop-cmd "cd ~/cuttlefish && ./stop.sh 20"
    """
    from .SyzVerify.run_bug import test_exploit_on_device
    
    res = Synthesizer.synthesize(
        bug_id=str(bug_id),
        goal=str(goal),
        kernel_research_path=str(kernel_research_path) if kernel_research_path else None,
        analysis_dir=str(analysis_dir) if analysis_dir else None,
        vmlinux_path=str(vmlinux_path) if vmlinux_path else None,
        platform=platform,
        model=model,
        verbose=verbose,
        debug=debug,
        time_limit=time_limit,
    )

    # Check whether the PDDL path actually produced exploit code
    pddl_produced_exploit = bool(res.get("exploits"))

    # ── LLM fallback: if PDDL didn't produce a usable exploit, try exploit_generator ──
    if not pddl_produced_exploit:
        typer.echo("[~] PDDL synthesis did not produce an exploit — falling back to LLM-based generation…")
        try:
            from .Synthesizer.exploit_generator import generate_exploit

            # Resolve analysis_dir from multiple sources
            _ad = str(analysis_dir) if analysis_dir else res.get('plan', {}).get('target_info', {}).get('analysis_dir')
            if not _ad:
                _ad = f"analysis_{bug_id}"

            llm_result = generate_exploit(
                analysis_dir=_ad,
                target_arch=arch,
                kernel_version="",
                output_dir=_ad,
                skip_llm=False,
                model=model,
                use_existing_plan=False,
                use_reference=False,
            )

            if llm_result.get('success'):
                typer.echo(f"[+] LLM exploit generation succeeded!")
                typer.echo(f"    Vulnerability: {llm_result.get('vulnerability_type')}")
                typer.echo(f"    Target: {llm_result.get('target_struct')}")
                typer.echo(f"    Technique: {llm_result.get('technique')}")
                for step in llm_result.get('steps', []):
                    typer.echo(f"      - {step}")
                # Merge outputs into the PDDL result so downstream code can find them
                outputs = llm_result.get('outputs', {})
                if outputs.get('exploit'):
                    res.setdefault("exploits", []).append(outputs['exploit'])
                res["llm_generation"] = llm_result
            else:
                typer.echo("[!] LLM-based exploit generation also failed")
        except Exception as e:
            typer.echo(f"[!] LLM-based exploit generation failed: {e}")
            if debug:
                typer.echo(traceback.format_exc())
    
    # Save a summary in the analysis directory
    ad = None
    try:
        ad = res.get('plan', {}).get('target_info', {}).get('analysis_dir')
        if ad:
            out = Path(ad) / 'synth_summary.json'
            with out.open('w') as f:
                json.dump(res, f, indent=2)
            typer.echo(f"[+] Synthesizer summary -> {out}")
        else:
            typer.echo("[+] Synthesizer completed; no analysis_dir available to write summary.")
    except Exception:
        typer.echo("[+] Synthesizer completed.")
    
    # Verify exploit if requested
    if verify_exploit:
        typer.echo("\n[VERIFY] Testing synthesized exploit on device...")
        
        # Find the compiled exploit
        exploit_path = None
        if ad:
            synth_output = Path(ad) / 'synth_output'
            if synth_output.exists():
                # Look for executable in synth_output
                for p in synth_output.iterdir():
                    if p.is_file() and os.access(p, os.X_OK):
                        exploit_path = str(p)
                        break
                # Also check for exploit_*.c and compile it
                if not exploit_path:
                    for p in synth_output.glob('exploit_*.c'):
                        compiled = synth_output / f'exploit_{arch}'
                        compile_script = Path.cwd() / f"compile_{arch}.sh"
                        if compile_script.exists():
                            os.system(f'"{compile_script}" "{p}" "{compiled}"')
                            if compiled.exists():
                                exploit_path = str(compiled)
                                break
            
            # Also check analysis dir root for exploit files
            if not exploit_path:
                analysis_path = Path(ad)
                for p in analysis_path.glob('exploit_*.c'):
                    compiled = analysis_path / f'exploit_{arch}'
                    compile_script = Path.cwd() / f"compile_{arch}.sh"
                    if compile_script.exists():
                        os.system(f'"{compile_script}" "{p}" "{compiled}"')
                        if compiled.exists():
                            exploit_path = str(compiled)
                            break
        
        if not exploit_path:
            typer.echo("[!] No exploit binary found to verify. Check synth_output directory.")
        else:
            typer.echo(f"[+] Found exploit: {exploit_path}")
            
            verify_result = test_exploit_on_device(
                exploit_path=exploit_path,
                arch=arch,
                ssh_host=ssh_host,
                instance=instance,
                start_cmd=start_cmd,
                stop_cmd=stop_cmd,
                log_dir=str(Path(ad) / 'verification') if ad else None,
            )
            
            if verify_result.get('success'):
                typer.echo("[✓] EXPLOIT VERIFICATION PASSED - Privilege escalation achieved!")
            else:
                typer.echo("[!] Exploit verification failed")
                if verify_result.get('error'):
                    typer.echo(f"    Error: {verify_result['error']}")


@app.command(name="test-exploit")
def test_exploit(
    exploit_path: Annotated[Path, typer.Argument(help='Path to compiled exploit binary')],
    arch: Annotated[str, typer.Option(help='Architecture (arm64/x86_64)')] = 'arm64',
    ssh_host: Annotated[Optional[str], typer.Option(help='SSH host for Cuttlefish')] = None,
    ssh_port: Annotated[int, typer.Option(help='SSH port')] = 22,
    adb_port: Annotated[int, typer.Option(help='ADB port')] = 6520,
    instance: Annotated[Optional[int], typer.Option(help='Cuttlefish instance number')] = None,
    start_cmd: Annotated[Optional[str], typer.Option(help='Command to start Cuttlefish')] = None,
    stop_cmd: Annotated[Optional[str], typer.Option(help='Command to stop Cuttlefish')] = None,
    timeout: Annotated[int, typer.Option(help='Exploit execution timeout in seconds')] = 120,
    log_dir: Annotated[Optional[Path], typer.Option(help='Directory to save logs')] = None,
    persistent: Annotated[bool, typer.Option('--persistent/--no-persistent', help='Persistent mode - assume instance is running, keep it running')] = False,
    gdb_port: Annotated[int, typer.Option(help='GDB port for Crosvm kernel')] = 1234,
    setup_tunnels: Annotated[bool, typer.Option(help='Set up SSH tunnels for remote access')] = False,
):
    """
    Test an exploit binary for privilege escalation on a Cuttlefish device.
    
    This command:
    1. Stops the instance (if stop_cmd provided) - skipped if --persistent
    2. Starts the instance (if start_cmd provided) - skipped if --persistent
    3. Pushes the exploit to the device
    4. Runs the exploit as a non-root user
    5. Verifies if privilege escalation to root was achieved
    
    Examples:
        # Test on already-running instance (persistent mode)
        syzploit test-exploit ./exploit_arm64 --instance 20 --persistent
        
        # Full cycle with stop/start
        syzploit test-exploit ./exploit_arm64 --ssh-host INGOTS-ARM --instance 20 \\
            --start-cmd "cd ~/cuttlefish && ./gdb_run.sh 20" \\
            --stop-cmd "cd ~/cuttlefish && ./stop.sh 20"
    """
    from .SyzVerify.run_bug import test_exploit_on_device
    
    if not exploit_path.exists():
        typer.echo(f"[!] Exploit binary not found: {exploit_path}")
        raise typer.Exit(code=1)
    
    result = test_exploit_on_device(
        exploit_path=str(exploit_path),
        arch=arch,
        ssh_host=ssh_host,
        ssh_port=ssh_port,
        adb_port=adb_port,
        instance=instance,
        start_cmd=start_cmd,
        stop_cmd=stop_cmd,
        timeout=timeout,
        log_dir=str(log_dir) if log_dir else None,
        persistent=persistent,
        gdb_port=gdb_port,
        setup_tunnels=setup_tunnels,
    )
    
    if result.get('success'):
        typer.echo("\n[✓] EXPLOIT VERIFICATION PASSED")
        typer.echo("    Privilege escalation achieved!")
        typer.echo(f"    Initial UID: {result.get('initial_uid')}")
        typer.echo(f"    Final UID: {result.get('final_uid')}")
    else:
        typer.echo("\n[✗] EXPLOIT VERIFICATION FAILED")
        if result.get('error'):
            typer.echo(f"    Error: {result['error']}")
        if result.get('crash_occurred'):
            typer.echo("    Note: A crash was detected during execution")
        raise typer.Exit(code=1)


@app.command(name="test-exploit-source")
def test_exploit_source(
    source_path: Annotated[Path, typer.Argument(help='Path to exploit C source file')],
    arch: Annotated[str, typer.Option(help='Architecture (arm64/x86_64)')] = 'arm64',
    ssh_host: Annotated[Optional[str], typer.Option(help='SSH host for Cuttlefish')] = None,
    ssh_port: Annotated[int, typer.Option(help='SSH port')] = 22,
    adb_port: Annotated[int, typer.Option(help='ADB port')] = 6520,
    instance: Annotated[Optional[int], typer.Option(help='Cuttlefish instance number')] = None,
    start_cmd: Annotated[Optional[str], typer.Option(help='Command to start Cuttlefish')] = None,
    stop_cmd: Annotated[Optional[str], typer.Option(help='Command to stop Cuttlefish')] = None,
    timeout: Annotated[int, typer.Option(help='Exploit execution timeout in seconds')] = 120,
    log_dir: Annotated[Optional[Path], typer.Option(help='Directory to save logs')] = None,
    persistent: Annotated[bool, typer.Option('--persistent/--no-persistent', help='Persistent mode - assume instance is running, keep it running')] = False,
    output_binary: Annotated[Optional[Path], typer.Option(help='Path for compiled binary output')] = None,
):
    """
    Compile and test an exploit C source file for privilege escalation.
    
    This command:
    1. Compiles the C source file for the target architecture
    2. Stops the instance (clean state) - skipped if --persistent
    3. Starts the instance (fresh boot) - skipped if --persistent  
    4. Pushes the compiled exploit to the device
    5. Runs the exploit as a non-root user
    6. Verifies if privilege escalation to root was achieved
    7. Stops the instance - skipped if --persistent
    
    PERSISTENT MODE (--persistent):
    Use when the instance is already running and you want to keep it running.
    This skips stop/start steps and just pushes + runs + verifies.
    
    NON-PERSISTENT MODE (default):
    Full cycle: stop -> start -> test -> stop
    Ensures clean state for each test.
    
    Examples:
        # Compile and test on already-running instance (persistent)
        syzploit test-exploit-source ./exploit.c --arch arm64 --instance 20 --persistent
        
        # Full cycle with stop/start (non-persistent)
        syzploit test-exploit-source ./exploit.c --arch arm64 \\
            --ssh-host INGOTS-ARM --instance 20 \\
            --start-cmd "cd ~/cuttlefish && ./gdb_run.sh 20" \\
            --stop-cmd "cd ~/cuttlefish && ./stop.sh 20"
        
        # Specify output binary path
        syzploit test-exploit-source ./my_exploit.c --output-binary ./my_exploit_arm64
    """
    from .SyzVerify.run_bug import test_exploit_from_source
    
    if not source_path.exists():
        typer.echo(f"[!] Source file not found: {source_path}")
        raise typer.Exit(code=1)
    
    result = test_exploit_from_source(
        source_path=str(source_path),
        arch=arch,
        ssh_host=ssh_host,
        ssh_port=ssh_port,
        adb_port=adb_port,
        instance=instance,
        start_cmd=start_cmd,
        stop_cmd=stop_cmd,
        timeout=timeout,
        log_dir=str(log_dir) if log_dir else None,
        persistent=persistent,
        output_binary=str(output_binary) if output_binary else None,
    )
    
    if not result.get('compiled'):
        typer.echo("\n[✗] COMPILATION FAILED")
        if result.get('error'):
            typer.echo(f"    Error: {result['error']}")
        raise typer.Exit(code=1)
    
    verification = result.get('verification', {})
    if verification.get('success'):
        typer.echo("\n[✓] EXPLOIT VERIFICATION PASSED")
        typer.echo("    Privilege escalation achieved!")
        typer.echo(f"    Binary: {result.get('binary_path')}")
        typer.echo(f"    Initial UID: {verification.get('initial_uid')}")
        typer.echo(f"    Final UID: {verification.get('final_uid')}")
    else:
        typer.echo("\n[✗] EXPLOIT VERIFICATION FAILED")
        typer.echo(f"    Binary: {result.get('binary_path')}")
        if verification.get('error'):
            typer.echo(f"    Error: {verification['error']}")
        if verification.get('crash_occurred'):
            typer.echo("    Note: A crash was detected during execution")
        raise typer.Exit(code=1)



@app.command(name="generate-exploit")
def generate_exploit_cmd(
    analysis_dir: Annotated[Path, typer.Argument(help='Path to analysis directory with static_analysis.json')],
    arch: Annotated[str, typer.Option(help='Target architecture (arm64/x86_64)')] = 'arm64',
    kernel_version: Annotated[str, typer.Option(help='Target kernel version (for offset selection)')] = '',
    output_dir: Annotated[Optional[Path], typer.Option(help='Output directory (defaults to analysis_dir)')] = None,
    skip_llm: Annotated[bool, typer.Option('--skip-llm', help='Skip LLM generation, produce stubs only')] = False,
    template_only: Annotated[bool, typer.Option('--template-only', help='Generate only the template, no function implementations')] = False,
    model: Annotated[str, typer.Option(help='LLM model to use')] = 'gpt-5',
    use_existing_plan: Annotated[bool, typer.Option('--use-existing-plan/--new-plan', help='Use llm_planner_output.json if it exists')] = True,
    use_reference: Annotated[bool, typer.Option('--use-reference', help='Use reference implementations from badbinder (no LLM)')] = False,
):
    """
    Generate an exploit from vulnerability analysis.
    
    This command uses LLM to dynamically analyze the vulnerability and create
    an exploitation plan. It performs three stages:
    
    1. ANALYZE: LLM analyzes static_analysis.json to understand the vulnerability
       (or loads llm_planner_output.json if --use-existing-plan)
    2. PLAN: Generate exploitation plan with steps  
    3. IMPLEMENT: LLM generates function implementations
    
    Examples:
        # Generate full exploit with LLM assistance
        syzploit generate-exploit ./analysis_abc123 --arch arm64
        
        # Use existing plan from llm_planner_output.json
        syzploit generate-exploit ./analysis_abc123 --use-existing-plan
        
        # Generate template only (for manual implementation)
        syzploit generate-exploit ./analysis_abc123 --template-only
        
        # Generate with stubs (no LLM for function bodies)
        syzploit generate-exploit ./analysis_abc123 --skip-llm
        
        # Force new LLM plan even if llm_planner_output.json exists
        syzploit generate-exploit ./analysis_abc123 --new-plan
        
        # Use reference implementations from badbinder (no LLM needed)
        syzploit generate-exploit ./analysis_abc123 --use-reference
    
    Output files:
        - exploit_plan.json: Exploitation plan with steps
        - exploit_template.c: Code skeleton with stubs
        - exploit.c: Full implementation (if not --template-only)
    """
    from .Synthesizer.exploit_generator import (
        generate_exploit,
        ExploitGenerator,
    )
    
    # Validate analysis_dir
    if not analysis_dir.exists():
        typer.echo(f"[!] Analysis directory not found: {analysis_dir}")
        raise typer.Exit(code=1)
    
    static_analysis = analysis_dir / "static_analysis.json"
    if not static_analysis.exists():
        typer.echo(f"[!] static_analysis.json not found in {analysis_dir}")
        typer.echo("    Run 'syzploit analyze' first to generate vulnerability analysis.")
        raise typer.Exit(code=1)
    
    # Check for existing plan
    existing_plan = analysis_dir / "llm_planner_output.json"
    if use_existing_plan and existing_plan.exists():
        typer.echo(f"[*] Found existing plan: {existing_plan}")
    
    # Generate exploit
    typer.echo(f"[*] Generating exploit from: {analysis_dir}")
    typer.echo(f"    Architecture: {arch}")
    typer.echo(f"    Model: {model}")
    if kernel_version:
        typer.echo(f"    Kernel: {kernel_version}")
    
    if template_only:
        # Generate just the template (with existing plan support)
        from .Synthesizer.exploit_generator import ExploitPlan as GenExploitPlan
        
        generator = ExploitGenerator(model=model)
        
        # Load analysis
        with open(static_analysis) as f:
            analysis_data = json.load(f)
        
        # Try to use existing plan
        plan = None
        if use_existing_plan and existing_plan.exists():
            typer.echo("[*] Loading existing plan...")
            try:
                with open(existing_plan) as f:
                    plan_data = json.load(f)
                steps = []
                for step_name in plan_data.get("steps", []):
                    steps.append({
                        "name": step_name,
                        "description": step_name.replace("_", " "),
                        "requires": [],
                        "provides": [],
                    })
                plan = GenExploitPlan(
                    vulnerability_type=plan_data.get("vulnerability_type", "unknown"),
                    target_struct=plan_data.get("target_struct", "unknown"),
                    slab_cache="kmalloc-512",
                    technique=plan_data.get("exploitation_technique", ""),
                    steps=steps,
                    target_arch=arch,
                    target_kernel=kernel_version,
                )
            except Exception as e:
                typer.echo(f"[!] Failed to load existing plan: {e}")
        
        if plan is None:
            typer.echo("[*] Generating new plan with LLM...")
            plan = generator.generate_plan(
                analysis_data=analysis_data,
                target_arch=arch,
                kernel_version=kernel_version,
            )
        
        template = generator.generate_template(plan)
        
        out_dir = output_dir or analysis_dir
        template_path = out_dir / "exploit_template.c"
        with open(template_path, 'w') as f:
            f.write(template)
        
        plan_path = out_dir / "exploit_plan.json"
        plan_data = {
            "vulnerability_type": plan.vulnerability_type,
            "target_struct": plan.target_struct,
            "technique": plan.technique,
            "steps": [s["name"] for s in plan.steps],
        }
        with open(plan_path, 'w') as f:
            json.dump(plan_data, f, indent=2)
        
        typer.echo(f"\n[✓] Template generated:")
        typer.echo(f"    Vulnerability: {plan.vulnerability_type}")
        typer.echo(f"    Target: {plan.target_struct}")
        typer.echo(f"    Technique: {plan.technique}")
        typer.echo(f"    Steps: {len(plan.steps)}")
        for s in plan.steps:
            typer.echo(f"      - {s['name']}")
        typer.echo(f"    Plan: {plan_path}")
        typer.echo(f"    Template: {template_path}")
        return
    
    # Full generation
    result = generate_exploit(
        analysis_dir=str(analysis_dir),
        target_arch=arch,
        kernel_version=kernel_version,
        output_dir=str(output_dir) if output_dir else None,
        skip_llm=skip_llm,
        model=model,
        use_existing_plan=use_existing_plan,
        use_reference=use_reference,
    )
    
    if result.get('success'):
        typer.echo(f"\n[✓] Exploit generated successfully!")
        typer.echo(f"    Vulnerability: {result.get('vulnerability_type')}")
        typer.echo(f"    Target: {result.get('target_struct')}")
        typer.echo(f"    Technique: {result.get('technique')}")
        typer.echo(f"    Steps: {len(result.get('steps', []))}")
        for step in result.get('steps', []):
            typer.echo(f"      - {step}")
        for key, path in result.get('outputs', {}).items():
            typer.echo(f"    {key}: {path}")
    else:
        typer.echo(f"\n[!] Exploit generation failed")
        raise typer.Exit(code=1)


@app.command(name="adapt-poc")
def adapt_poc_cmd(
    analysis_dir: Annotated[Path, typer.Argument(
        help='Path to analysis directory with static_analysis.json and '
             'trace_analysis.json (or controller log sub-dir)')],
    arch: Annotated[str, typer.Option(
        help='Target architecture (arm64/x86_64)')] = 'arm64',
    output_dir: Annotated[Optional[Path], typer.Option(
        help='Output directory (defaults to analysis_dir)')] = None,
    model: Annotated[str, typer.Option(
        help='LLM model to use')] = 'gpt-5',
    skip_llm: Annotated[bool, typer.Option(
        '--skip-llm',
        help='Skip LLM; just prepend runtime addresses to original PoC'
    )] = False,
):
    """Adapt a syzbot PoC for a specific target device.

    Uses trace_analysis.json (runtime addresses, path verification,
    device profile) together with the original syzbot reproducer to
    produce an adapted PoC that works on a non-KASAN target device.

    Requires that test-cuttlefish (with --extract-runtime-symbols) has
    already been run so that trace_analysis.json exists in the analysis
    directory or one of its sub-directories.

    Examples:
        syzploit adapt-poc ./analysis_abc123 --arch arm64
        syzploit adapt-poc ./analysis_abc123 --skip-llm
    """
    from .SyzAnalyze.poc_adapter import adapt_poc

    result = adapt_poc(
        analysis_dir=str(analysis_dir),
        output_dir=str(output_dir) if output_dir else None,
        target_arch=arch,
        model=model,
        skip_llm=skip_llm,
    )

    if result.get("success"):
        typer.echo(f"\n[+] Adapted PoC: {result['adapted_poc']}")
        typer.echo(f"    Metadata:    {result.get('metadata_path')}")
        typer.echo(f"    Arch:        {result.get('arch')}")
        typer.echo(f"    Kernel:      {result.get('kernel_version', '?')}")
        typer.echo(f"    Verdict:     {result.get('verdict', '?')} "
                   f"({(result.get('confidence') or 0):.0%})")
    else:
        typer.echo(f"\n[!] PoC adaptation failed: {result.get('error')}")
        raise typer.Exit(code=1)



@app.command()
def pipeline(
    bug_id: Annotated[str, typer.Argument(help='Bug ID for end-to-end pipeline')],
    syzkall_kernel: Annotated[str, typer.Option(help='Kernel name for bug')] = 'android-5-10',
    qemu: Annotated[bool, typer.Option(help='Use QEMU VM')] = False,
    local: Annotated[bool, typer.Option(help='Use local cuttlefish instance')] = True,
    root: Annotated[bool, typer.Option(help='Run repro/exploit as root in VM')]=True,
    arch: Annotated[str, typer.Option(help='Architecture of kernel to analyze/run')]='x86_64',
    source_image: Annotated[Optional[Path], typer.Option(help='Path to kernel image (QEMU)')] = None,
    source_disk: Annotated[Optional[Path], typer.Option(help='Path to disk image (QEMU)')] = None,
    dynamic_analysis: Annotated[bool, typer.Option(help='Enable GDB-based dynamic analysis during analysis')] = True,
    gdb_port: Annotated[int, typer.Option(help='GDB port for dynamic analysis')] = 1234,
    setup_tunnels: Annotated[bool, typer.Option(help='Set up SSH tunnels for remote ADB/GDB access')] = False,
    goal: Annotated[str, typer.Option(help='Exploit goal for synthesis')] = 'privilege_escalation',
    platform: Annotated[Optional[str], typer.Option(help='Target platform: linux, android, or generic')] = None,
    model: Annotated[str, typer.Option(help='LLM model to use (e.g. gpt-4o, openrouter/anthropic/claude-sonnet-4-20250514)')] = 'gpt-4o',
    planner: Annotated[str, typer.Option(help='Planner strategy: pddl (PDDL+LLM stitcher), llm (pure LLM), auto (PDDL first, LLM fallback)')] = 'auto',
    debug: Annotated[bool, typer.Option(help='Enable debug output')] = False,
    verbose: Annotated[bool, typer.Option(help='Print planner output')] = False,
    # Exploit verification options
    verify_exploit: Annotated[bool, typer.Option('--verify/--no-verify', help='Verify synthesized exploit achieves privilege escalation')] = False,
    ssh_host: Annotated[Optional[str], typer.Option(help='SSH host for Cuttlefish (for verification)')] = None,
    instance: Annotated[Optional[int], typer.Option(help='Cuttlefish instance number (for verification)')] = None,
    start_cmd: Annotated[Optional[str], typer.Option(help='Command to start Cuttlefish (for verification)')] = None,
    stop_cmd: Annotated[Optional[str], typer.Option(help='Command to stop Cuttlefish (for verification)')] = None,
):
    """Run the full pipeline: verify crash with SyzVerify, analyze with SyzAnalyze,
    test generated primitive, run Synthesizer, and finally verify the generated exploit.

    Steps:
    1) Compile + run reproducer to confirm crash
    2) Perform static (+optional dynamic) analysis
    3) Compile + run generated primitive C (if available)
    4) Adapt PoC for target device
    5) Synthesize exploit (PDDL planning + LLM stitching, or pure LLM fallback)
    6) Run final exploit artifact if available
    7) Verify privilege escalation (if --verify)
    
    Planner modes:
    - auto (default): Try PDDL planning first, fall back to pure LLM if it fails
    - pddl: Use PDDL domain/problem generation + powerlifted planner + LLM stitcher
    - llm: Use pure LLM exploit generation (exploit_generator.py)

    Model examples (via litellm):
    - gpt-4o (default, needs OPENAI_API_KEY)
    - openrouter/anthropic/claude-sonnet-4-20250514 (needs OPENROUTER_API_KEY)
    - anthropic/claude-sonnet-4-20250514 (needs ANTHROPIC_API_KEY)
    
    Use --verify to add a final verification step that:
    - Stops the instance (clean slate)
    - Starts the instance (fresh boot)
    - Runs the exploit as non-root
    - Verifies privilege escalation to root
    
    Example with verification:
        syzploit pipeline abc123 --verify --arch arm64 \\
            --ssh-host INGOTS-ARM --instance 20 \\
            --start-cmd "cd ~/cuttlefish && ./gdb_run.sh 20" \\
            --stop-cmd "cd ~/cuttlefish && ./stop.sh 20"
    """
    from .SyzVerify.run_bug import test_exploit_on_device
    # Initialize DB and pull metadata
    db = SyzkallBugDatabase(syzkall_kernel)
    md = db.get_bug_metadata(bug_id)
    if md is None:
        typer.echo(f"[!] Invalid bug id: {bug_id}")
        raise typer.Exit(code=1)

    summary = {
        "bug_id": bug_id,
        "kernel": syzkall_kernel,
        "steps": {},
    }

    # Step 1: Compile and run original reproducer
    typer.echo("[STEP 1] Compiling reproducible binary from syzkaller repro...")
    repro_bin = md.compile_repro(arch)
    typer.echo(f"[INFO] Reproducer binary: {repro_bin}")
    try:
        if qemu:
            if not source_image or not source_disk:
                typer.echo("[!] QEMU selected but source_image/source_disk not provided")
                raise typer.Exit(code=2)
            v, t = test_repro_crashes_qemu(repro_bin, local, bug_id, 'syzkall_crashes', root, source_image, source_disk)
        else:
            v, t = test_repro_crashes(repro_bin, local, bug_id, 'syzkall_crashes', root)
        summary["steps"]["repro_run"] = {"crashed": bool(v), "type": t}
        if v:
            typer.echo("[✓] Crash detected with original repro")
        else:
            typer.echo("[!] No crash detected with original repro")
    except Exception as e:
        summary["steps"]["repro_run"] = {"error": str(e)}
        typer.echo(f"[!] Error running original repro: {e}")

    # Step 2: Analysis (static + optional dynamic)
    analysis_dir = Path(f"analysis_{bug_id}")
    typer.echo("[STEP 2] Running SyzAnalyze (static + optional dynamic)...")
    try:
        SyzAnalyze.analyze_bug(
            bug_id=bug_id,
            kernel_name=syzkall_kernel,
            qemu=qemu,
            source_image=source_image,
            source_disk=source_disk,
            dynamic_analysis=dynamic_analysis,
            gdb_port=gdb_port,
            arch=arch,
            output_dir=analysis_dir,
        )
        summary["steps"]["analyze"] = {"output_dir": str(analysis_dir)}
    except Exception as e:
        summary["steps"]["analyze"] = {"error": str(e)}
        typer.echo(f"[!] Analysis failed: {e}")

    # Decide whether to proceed based on static exploitability rating
    proceed_steps = False
    exploit_rating = None
    try:
        static_path = analysis_dir / 'static_analysis.json'
        if static_path.exists():
            with static_path.open('r') as sf:
                sdata = json.load(sf)
            parsed_llm = (sdata.get('llm_analysis', {}) or {}).get('openai_llm', {})
            parsed_llm = (parsed_llm.get('parsed', {}) if isinstance(parsed_llm, dict) else {})
            ov = parsed_llm.get('overview') if isinstance(parsed_llm, dict) else None
            if isinstance(ov, list) and ov:
                ov = ov[0]
            if isinstance(ov, dict):
                val = ov.get('exploitability')
                if isinstance(val, str):
                    exploit_rating = val.strip().lower()
            proceed_steps = exploit_rating in {'medium', 'high'}
    except Exception:
        proceed_steps = False

    # Step 3: Test generated primitive C (if present)
    typer.echo("[STEP 3] Testing generated primitive from analysis outputs...")
    primitive_result = {"attempted": False}
    try:
        if not proceed_steps:
            primitive_result["note"] = f"skipped due to exploitability rating: {exploit_rating or 'unknown'}"
        else:
            static_path = analysis_dir / 'static_analysis.json'
            if static_path.exists():
                with static_path.open('r') as sf:
                    sdata = json.load(sf)
                # Look for a generated reproducer source path
                repro_src = (sdata.get('reproducer', {}) or {})
                repro_src = repro_src.get('source_path') if isinstance(repro_src, dict) else None
                if repro_src and Path(repro_src).exists():
                    primitive_result["attempted"] = True
                    primitive_bin = analysis_dir / 'primitive'
                    compile_script = Path.cwd() / f"compile_{arch}.sh"
                    os.system(f'"{compile_script}" "{Path(repro_src).absolute()}" "{primitive_bin.absolute()}"')
                    if primitive_bin.exists():
                        if qemu:
                            v2, t2 = test_repro_crashes_qemu(primitive_bin, local, bug_id, str(analysis_dir), root, source_image, source_disk)
                        else:
                            v2, t2 = test_repro_crashes(primitive_bin, local, bug_id, str(analysis_dir), root)
                        primitive_result.update({"crashed": bool(v2), "type": t2, "binary": str(primitive_bin)})
                        typer.echo("[✓] Primitive run complete")
                    else:
                        primitive_result["error"] = "primitive binary not created"
                else:
                    primitive_result["note"] = "no generated reproducer source found"
            else:
                primitive_result["note"] = "static_analysis.json not found"
    except Exception as e:
        primitive_result["error"] = str(e)
        typer.echo(f"[!] Primitive test failed: {e}")
    summary["steps"]["primitive_run"] = primitive_result

    # Step 4: Synthesis (gated)
    if proceed_steps:
        typer.echo("[STEP 4] Running Synthesizer to build exploit plan...")
        synth_res = Synthesizer.synthesize(
            bug_id=bug_id,
            goal=goal,
            kernel_research_path=None,
            analysis_dir=str(analysis_dir),
            vmlinux_path=None,
            platform=platform,  # Can be None for auto-detect
            model=model,
            debug=debug,
            verbose=verbose,
        )
        summary["steps"]["synthesis"] = {"result": synth_res}
        typer.echo("[✓] Synthesis completed")
    else:
        summary["steps"]["synthesis"] = {"note": f"skipped due to exploitability rating: {exploit_rating or 'unknown'}"}
        typer.echo("[!] Skipping synthesis due to low exploitability rating")

    # Step 5: Final exploit run if artifact exists (gated)
    typer.echo("[STEP 5] Attempting final exploit run from synth_output...")
    final_result = {"attempted": False}
    try:
        if proceed_steps:
            outdir = Path(analysis_dir) / 'synth_output'
            if outdir.exists():
                # Find any executable file in synth_output
                exec_candidate = None
                for p in outdir.iterdir():
                    try:
                        mode_exec = os.access(p, os.X_OK)
                    except Exception:
                        mode_exec = False
                    if p.is_file() and mode_exec:
                        exec_candidate = p
                        break
                if exec_candidate:
                    final_result["attempted"] = True
                    if qemu:
                        v3, t3 = test_repro_crashes_qemu(exec_candidate, local, bug_id, str(outdir), root, source_image, source_disk)
                    else:
                        v3, t3 = test_repro_crashes(exec_candidate, local, bug_id, str(outdir), root)
                    final_result.update({"crashed": bool(v3), "type": t3, "binary": str(exec_candidate)})
                    typer.echo("[✓] Final exploit run complete")
                else:
                    final_result["note"] = "no executable artifact found in synth_output"
            else:
                final_result["note"] = "synth_output directory not found"
        else:
            final_result["note"] = f"skipped due to exploitability rating: {exploit_rating or 'unknown'}"
    except Exception as e:
        final_result["error"] = str(e)
        typer.echo(f"[!] Final exploit run failed: {e}")
    summary["steps"]["final_run"] = final_result

    # Step 6: Verify privilege escalation (if --verify)
    if verify_exploit:
        typer.echo("[STEP 6] Verifying exploit achieves privilege escalation...")
        verify_result = {"attempted": False}
        
        # Find exploit binary
        exploit_path = None
        if proceed_steps:
            outdir = Path(analysis_dir) / 'synth_output'
            if outdir.exists():
                for p in outdir.iterdir():
                    if p.is_file() and os.access(p, os.X_OK):
                        exploit_path = str(p)
                        break
                # Try compiling if only source exists
                if not exploit_path:
                    for p in outdir.glob('exploit_*.c'):
                        compiled = outdir / f'exploit_{arch}'
                        compile_script = Path.cwd() / f"compile_{arch}.sh"
                        if compile_script.exists():
                            os.system(f'"{compile_script}" "{p}" "{compiled}"')
                            if compiled.exists():
                                exploit_path = str(compiled)
                                break
            
            # Also check analysis dir root
            if not exploit_path:
                for p in analysis_dir.glob('exploit_*.c'):
                    compiled = analysis_dir / f'exploit_{arch}'
                    compile_script = Path.cwd() / f"compile_{arch}.sh"
                    if compile_script.exists():
                        os.system(f'"{compile_script}" "{p}" "{compiled}"')
                        if compiled.exists():
                            exploit_path = str(compiled)
                            break
        
        if exploit_path:
            verify_result["attempted"] = True
            typer.echo(f"[INFO] Testing exploit: {exploit_path}")
            
            try:
                result = test_exploit_on_device(
                    exploit_path=exploit_path,
                    arch=arch,
                    ssh_host=ssh_host,
                    instance=instance,
                    start_cmd=start_cmd,
                    stop_cmd=stop_cmd,
                    log_dir=str(analysis_dir / 'verification'),
                    gdb_port=gdb_port,
                    setup_tunnels=setup_tunnels,
                )
                
                verify_result["success"] = result.get("success", False)
                verify_result["privilege_escalated"] = result.get("privilege_escalated", False)
                verify_result["initial_uid"] = result.get("initial_uid")
                verify_result["final_uid"] = result.get("final_uid")
                verify_result["crash_occurred"] = result.get("crash_occurred", False)
                
                if result.get("success"):
                    typer.echo("[✓] EXPLOIT VERIFICATION PASSED - Privilege escalation achieved!")
                else:
                    typer.echo("[!] Exploit verification failed - privilege escalation not achieved")
                    
            except Exception as e:
                verify_result["error"] = str(e)
                typer.echo(f"[!] Verification failed: {e}")
        else:
            verify_result["note"] = "no exploit binary found"
            typer.echo("[!] No exploit binary found to verify")
        
        summary["steps"]["verification"] = verify_result
    
    # Save summary
    out = analysis_dir / 'pipeline_summary.json'
    with out.open('w') as f:
        json.dump(summary, f, indent=2)
    typer.echo(f"[+] Pipeline summary -> {out}")
    
    # Print final summary
    typer.echo("\n" + "=" * 60)
    typer.echo("PIPELINE SUMMARY")
    typer.echo("=" * 60)
    for step_name, step_data in summary["steps"].items():
        if isinstance(step_data, dict):
            if step_data.get("success") or step_data.get("crashed"):
                typer.echo(f"  {step_name}: ✓")
            elif step_data.get("error"):
                typer.echo(f"  {step_name}: ✗ ({step_data['error'][:50]}...)")
            elif step_data.get("note"):
                typer.echo(f"  {step_name}: - ({step_data['note'][:50]})")
            else:
                typer.echo(f"  {step_name}: ?")
    typer.echo("=" * 60)


# ═══════════════════════════════════════════════════════════════════════════
# CVE / Blog Post Analysis Commands
# ═══════════════════════════════════════════════════════════════════════════


@app.command(name="pipeline-cve")
def pipeline_cve(
    cve_id: Annotated[str, typer.Argument(help='CVE identifier (e.g. CVE-2023-20938)')],
    # ── CVE analysis options (the extra bits on top of pipeline-cuttlefish) ──
    blog_url: Annotated[Optional[List[str]], typer.Option(
        '--blog-url', help='Blog post URL(s) for additional context (can repeat). Optional.')] = None,
    extra_context: Annotated[Optional[str], typer.Option(
        '--context', help='Additional context (patch diff, notes, etc.)')] = None,
    kernel_name: Annotated[Optional[str], typer.Option(
        '--kernel', help='Kernel name for kexploit BTF offset resolution')] = None,
    skip_cve_analysis: Annotated[bool, typer.Option(
        '--skip-cve-analysis', help='Skip CVE analysis, reuse existing static_analysis.json')] = False,
    # ── Everything below is identical to pipeline-cuttlefish ──
    arch: Annotated[str, typer.Option(help='Architecture (arm64/x86_64)')] = 'arm64',
    root: Annotated[bool, typer.Option(help='Run reproducer/exploit as root')] = True,
    # Cuttlefish instance settings
    ssh_host: Annotated[str, typer.Option(help='SSH host for Cuttlefish (can be a ~/.ssh/config alias)')] = 'localhost',
    ssh_port: Annotated[int, typer.Option(help='SSH port for Cuttlefish')] = 22,
    ssh_user: Annotated[Optional[str], typer.Option(help='SSH user (optional, uses ssh config if not set)')] = None,
    ssh_key: Annotated[Optional[str], typer.Option(help='SSH key path (optional, uses ssh config if not set)')] = None,
    ssh_password: Annotated[Optional[str], typer.Option(help='SSH password (if no key)')] = None,
    # Persistence mode
    persistent: Annotated[bool, typer.Option(help='Persistent mode (keep Cuttlefish running)')] = True,
    already_running: Annotated[bool, typer.Option(help='Cuttlefish is already running')] = True,
    start_cmd: Annotated[Optional[str], typer.Option(help='Command to start Cuttlefish with GDB (e.g. ./gdb_run.sh)')] = None,
    run_cmd: Annotated[Optional[str], typer.Option(help='Command to start Cuttlefish WITHOUT GDB (e.g. ./run.sh). Used for symbol extraction. Auto-derived from --start-cmd if not set.')] = None,
    stop_cmd: Annotated[Optional[str], typer.Option(help='Command to stop Cuttlefish (non-persistent)')] = None,
    # Connection settings
    instance: Annotated[Optional[int], typer.Option(help='Cuttlefish instance number (auto-calculates ADB port: 6520 + instance - 1)')] = None,
    gdb_port: Annotated[int, typer.Option(help='Crosvm kernel GDB port')] = 1234,
    adb_port: Annotated[int, typer.Option(help='ADB port for Cuttlefish device (overridden by --instance)')] = 6520,
    dynamic_analysis: Annotated[bool, typer.Option(help='Enable GDB-based dynamic analysis')] = True,
    setup_tunnels: Annotated[bool, typer.Option(help='Set up SSH tunnels for remote ADB/GDB access')] = False,
    # Cuttlefish runtime logs
    runtime_logs_dir: Annotated[Optional[str], typer.Option(help='Path to cuttlefish runtime logs dir')] = None,
    # Kernel symbol extraction options
    kernel_image: Annotated[Optional[str], typer.Option(help='Path to kernel Image file (local or remote)')] = None,
    vmlinux_path: Annotated[Optional[str], typer.Option(help='Path to vmlinux with debug symbols')] = None,
    system_map: Annotated[Optional[str], typer.Option(help='Path to System.map for symbol resolution')] = None,
    extract_symbols: Annotated[bool, typer.Option(help='Auto-extract vmlinux from kernel Image')] = True,
    extract_runtime_symbols: Annotated[bool, typer.Option(help='Extract kallsyms from running VM at runtime for accurate symbol addresses')] = True,
    # Pipeline options
    skip_static: Annotated[bool, typer.Option(help='Skip static analysis (crash-log based)')] = False,
    ignore_exploitability: Annotated[bool, typer.Option(help='Run dynamic even if exploitability is low')] = False,
    goal: Annotated[str, typer.Option(help='Exploit goal for synthesis')] = 'privilege_escalation',
    platform: Annotated[Optional[str], typer.Option(help='Target platform: linux, android, or generic')] = None,
    timeout: Annotated[int, typer.Option(help='Test timeout in seconds')] = 120,
    output_dir: Annotated[Optional[Path], typer.Option(help='Output directory for logs')] = None,
    # Exploit verification
    verify_exploit: Annotated[bool, typer.Option('--verify/--no-verify', help='Verify exploit for privilege escalation at the end')] = True,
    exploit_start_cmd: Annotated[Optional[str], typer.Option(help='Command to start Cuttlefish for exploit verification (without GDB). If provided, used instead of start_cmd for verification step')] = None,
    model: Annotated[str, typer.Option(help='LLM model to use (e.g. gpt-4o, openrouter/anthropic/claude-sonnet-4-20250514)')] = 'gpt-4o',
    planner: Annotated[str, typer.Option(help='Planner strategy: pddl (PDDL+LLM stitcher), llm (pure LLM), auto (PDDL first, LLM fallback)')] = 'auto',
    debug: Annotated[bool, typer.Option(help='Enable debug output')] = False,
    verbose: Annotated[bool, typer.Option(help='Print planner output')] = False,
):
    """
    Full pipeline: CVE analysis → static analysis → dynamic analysis → synthesis → verify.

    Identical to pipeline-cuttlefish but adds a CVE analysis step (Step 0)
    at the beginning. The CVE analysis fetches NVD/MITRE data, searches GitHub
    for existing PoCs, optionally fetches blog posts with deep code extraction,
    and uses an LLM to classify the vulnerability and generate a PoC+analysis.

    The generated static_analysis.json then feeds into the rest of the pipeline
    (Steps 1-6) exactly as pipeline-cuttlefish works — GDB dynamic analysis,
    post-processing, exploit synthesis, and Cuttlefish verification.

    Blog posts are OPTIONAL — without --blog-url, the pipeline still works
    using NVD/MITRE descriptions + GitHub PoC searches.

    Steps:
    0) CVE analysis (NVD/MITRE/blog/GitHub → static_analysis.json + poc.c)
    1) Static analysis (parse crash data from CVE analysis)
    2) Compile PoC as reproducer
    3) Dynamic analysis with Cuttlefish (GDB breakpoints, alloc/free tracing)
    4) Post-process for UAF/OOB detection
    5) Synthesize exploit plan
    6) Verify exploit achieves privilege escalation

    Examples:
        # Full pipeline with blog post
        syzploit pipeline-cve CVE-2023-20938 \\
            --blog-url "https://androidoffsec.withgoogle.com/posts/attacking-android-binder-analysis-and-exploitation-of-cve-2023-20938/" \\
            --ssh-host cuttlefish2 --setup-tunnels --instance 5 \\
            --kernel-image /home/jack/cuttlefish/package/kernel/Image \\
            --start-cmd "cd /home/jack/cuttlefish && ./gdb_run.sh 5" \\
            --stop-cmd "cd /home/jack/cuttlefish && ./stop.sh 5" \\
            --exploit-start-cmd "cd /home/jack/cuttlefish && ./run.sh 5" \\
            --platform android --planner auto \\
            --model openrouter/anthropic/claude-opus-4.5 \\
            --kernel ingots_5.10.107 --arch arm64 --debug

        # Without blog post (CVE data + GitHub PoCs only)
        syzploit pipeline-cve CVE-2024-1086 \\
            --ssh-host cuttlefish2 --setup-tunnels --instance 5 \\
            --kernel-image /home/jack/cuttlefish/package/kernel/Image \\
            --start-cmd "cd /home/jack/cuttlefish && ./gdb_run.sh 5" \\
            --stop-cmd "cd /home/jack/cuttlefish && ./stop.sh 5" \\
            --platform linux --debug

        # Skip CVE analysis, reuse existing output dir
        syzploit pipeline-cve CVE-2023-20938 --skip-cve-analysis \\
            --output-dir ./analysis_CVE-2023-20938 \\
            --ssh-host cuttlefish2 --setup-tunnels --instance 5 \\
            --start-cmd "cd /home/jack/cuttlefish && ./gdb_run.sh 5" \\
            --stop-cmd "cd /home/jack/cuttlefish && ./stop.sh 5"
    """
    from .SyzAnalyze.cve_analyzer import analyze_cve as _analyze_cve

    # Setup output directory (use cve_id as bug_id throughout the rest)
    bug_id = cve_id
    if output_dir is None:
        output_dir = Path(f"analysis_{bug_id}")
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    typer.echo(f"[+] CVE Pipeline for {cve_id}")
    typer.echo(f"[+] Output directory: {output_dir}")
    if blog_url:
        for u in blog_url:
            typer.echo(f"[+] Blog URL: {u}")
    else:
        typer.echo("[+] No blog URL — using NVD/MITRE data + GitHub PoC search only")

    summary = {"cve_id": cve_id, "steps": {}}

    # ══════════════════════════════════════════════════════════════════════
    # STEP 0: CVE Analysis (the only part that differs from pipeline-cuttlefish)
    # ══════════════════════════════════════════════════════════════════════
    if not skip_cve_analysis:
        typer.echo("\n[STEP 0] CVE Analysis — fetching NVD/MITRE/blog/GitHub data...")
        try:
            cve_result = _analyze_cve(
                cve_id=cve_id,
                output_dir=str(output_dir),
                model=model,
                generate_poc=True,
                blog_urls=blog_url,
                extra_context=extra_context,
                debug=debug,
            )
            analysis_json = cve_result.analysis_json
            vuln_type = analysis_json.get("vuln_type", "unknown")
            target_struct = analysis_json.get("target_struct", "")
            hints = analysis_json.get("exploitation_hints", {})
            code_analysis = analysis_json.get("code_analysis", {})

            typer.echo(f"[+] Vulnerability type: {vuln_type}")
            if target_struct:
                typer.echo(f"[+] Target struct: {target_struct}")
            typer.echo(f"[+] Exploitability: "
                       f"{analysis_json.get('openai_llm', {}).get('parsed', {}).get('overview', {}).get('exploitability', '?')}")
            typer.echo(f"[+] Technique: {hints.get('technique', '?')}")
            if code_analysis.get("trigger_syscalls"):
                typer.echo(f"[+] Trigger syscalls: {', '.join(code_analysis['trigger_syscalls'])}")
            if code_analysis.get("spray_objects"):
                typer.echo(f"[+] Spray objects: {', '.join(code_analysis['spray_objects'])}")
            if code_analysis.get("code_snippets"):
                typer.echo(f"[+] Extracted {len(code_analysis['code_snippets'])} code snippets from blog")
            if cve_result.github_pocs:
                typer.echo(f"[+] GitHub PoCs: {len(cve_result.github_pocs)} found")
                for p in cve_result.github_pocs[:3]:
                    typer.echo(f"      - {p['name']} ({p['stars']}★)")
            if cve_result.poc_source:
                typer.echo(f"[+] Generated PoC: {output_dir / 'poc.c'}")

            summary["steps"]["cve_analysis"] = {
                "success": True,
                "vuln_type": vuln_type,
                "target_struct": target_struct,
                "technique": hints.get("technique", ""),
                "code_snippets": len(code_analysis.get("code_snippets", [])),
                "github_pocs": len(cve_result.github_pocs),
                "blog_urls": blog_url or [],
            }
        except Exception as e:
            typer.echo(f"[!] CVE analysis failed: {e}")
            if debug:
                typer.echo(traceback.format_exc())
            summary["steps"]["cve_analysis"] = {"success": False, "error": str(e)}
    else:
        typer.echo("\n[STEP 0] Skipping CVE analysis (--skip-cve-analysis)")
        sa_path = output_dir / "static_analysis.json"
        if sa_path.exists():
            typer.echo(f"[+] Loaded existing: {sa_path}")
            summary["steps"]["cve_analysis"] = {"success": True, "reused": True}
        else:
            typer.echo(f"[!] No static_analysis.json in {output_dir}")

    # ── kexploit enrichment (optional, runs before the main pipeline) ──
    if kernel_name:
        typer.echo(f"\n[STEP 0b] kexploit enrichment for kernel={kernel_name}...")
        try:
            from .Synthesizer.adapters.kexploit_adapter import (
                resolve_struct_offsets_from_kexploit, kexploit_available,
            )
            sa_path = output_dir / "static_analysis.json"
            if sa_path.exists():
                with open(sa_path) as f:
                    _aj = json.load(f)
                target_struct = _aj.get("target_struct", "")
            else:
                target_struct = ""
            if kexploit_available() and target_struct:
                offsets = resolve_struct_offsets_from_kexploit(
                    kernel_name, target_struct, debug=debug
                )
                if offsets:
                    typer.echo(f"[+] Resolved offsets for {target_struct}: {offsets}")
                    summary["steps"]["kexploit"] = {"success": True, "offsets": str(offsets)}
                else:
                    typer.echo(f"[~] No offsets found for {target_struct}")
            elif not kexploit_available():
                typer.echo("[~] kexploit not available, skipping")
        except Exception as e:
            typer.echo(f"[~] kexploit enrichment failed: {e}")

    # ══════════════════════════════════════════════════════════════════════
    # From here on, run the EXACT same pipeline as pipeline-cuttlefish
    # using the CVE analysis output (static_analysis.json + poc.c) as inputs.
    # ══════════════════════════════════════════════════════════════════════

    # Build a parsed_crash from the CVE analysis (so dynamic analysis has breakpoint targets)
    parsed_crash = None
    static_result = None
    sa_path = output_dir / "static_analysis.json"
    if sa_path.exists():
        with open(sa_path) as f:
            static_result = json.load(f)

        # Build parsed_crash from the CVE analysis frames + key_functions
        frames = static_result.get("parsed", {}).get("frames", [])
        key_funcs = static_result.get("exploitation_hints", {}).get("key_functions", [])
        vuln_path = static_result.get("code_analysis", {}).get("vulnerable_path", [])

        crash_stack_funcs = []
        seen = set()
        # Frames from the analysis
        for fr in frames:
            func = fr.get("function", "")
            if func and func not in seen:
                seen.add(func)
                crash_stack_funcs.append(func)
        # Key functions from exploitation hints
        for func in key_funcs:
            if func and func not in seen:
                seen.add(func)
                crash_stack_funcs.append(func)
        # Vulnerable call path
        for func in vuln_path:
            if func and func not in seen:
                seen.add(func)
                crash_stack_funcs.append(func)

        # Construct a parsed_crash compatible with CuttlefishKernelGDB
        # Use "function" key to match what generate_kernel_gdb_script() expects
        parsed_crash = {
            "crash_type": static_result.get("parsed", {}).get("kind", ""),
            "corrupted_function": crash_stack_funcs[0] if crash_stack_funcs else "",
            "stack_frames": [{"function": f, "func": f} for f in crash_stack_funcs],
            "frames": [{"function": f, "func": f} for f in crash_stack_funcs],
            "access": static_result.get("parsed", {}).get("access", {}),
        }
        typer.echo(f"[+] Breakpoint targets from CVE analysis: {crash_stack_funcs[:8]}...")

    # Step 1: Compile the PoC as a reproducer
    typer.echo("\n[STEP 1] Compiling PoC as reproducer...")
    repro_bin = None
    poc_path = output_dir / "poc.c"

    if poc_path.exists():
        out_bin = str((output_dir / f"poc_{arch}").resolve())
        success, error = compile_exploit(
            source_path=str(poc_path.resolve()),
            output_path=out_bin,
            arch=arch,
        )
        
        if success and Path(out_bin).exists():
            repro_bin = out_bin
            typer.echo(f"[+] Compiled PoC: {repro_bin}")
            summary["steps"]["compile_poc"] = {"success": True, "binary": repro_bin}
        else:
            typer.echo(f"[!] PoC compilation failed: {error[:200] if error else 'unknown'}")
            summary["steps"]["compile_poc"] = {"success": False, "error": error or "compilation failed"}
    else:
        typer.echo("[!] No poc.c found — skipping compilation")
        summary["steps"]["compile_poc"] = {"success": False, "error": "no poc.c"}

    # Steps 2-5: Shared pipeline (dynamic → post-process → adapt → synthesize → verify)
    _run_shared_pipeline(
        bug_id=bug_id,
        output_dir=output_dir,
        parsed_crash=parsed_crash,
        repro_bin=repro_bin,
        arch=arch,
        root=root,
        ssh_host=ssh_host,
        ssh_port=ssh_port,
        ssh_user=ssh_user,
        ssh_password=ssh_password,
        ssh_key=ssh_key,
        persistent=persistent,
        already_running=already_running,
        start_cmd=start_cmd,
        run_cmd=run_cmd,
        stop_cmd=stop_cmd,
        instance=instance,
        gdb_port=gdb_port,
        adb_port=adb_port,
        dynamic_analysis=dynamic_analysis,
        setup_tunnels=setup_tunnels,
        runtime_logs_dir=runtime_logs_dir,
        kernel_image=kernel_image,
        vmlinux_path=vmlinux_path,
        system_map=system_map,
        extract_symbols=extract_symbols,
        extract_runtime_symbols=extract_runtime_symbols,
        goal=goal,
        platform=platform,
        timeout=timeout,
        verify_exploit=verify_exploit,
        exploit_start_cmd=exploit_start_cmd,
        model=model,
        planner=planner,
        debug=debug,
        verbose=verbose,
        summary=summary,
        step_offset=2,
    )


@app.command(name="analyze-cve")
def analyze_cve_cmd(
    cve_id: Annotated[str, typer.Argument(help='CVE identifier (e.g. CVE-2023-20938)')],
    output_dir: Annotated[Optional[Path], typer.Option(
        help='Output directory (default: cve_analysis_<CVE-ID>)')] = None,
    model: Annotated[str, typer.Option(
        help='LLM model to use for analysis')] = 'gpt-4o',
    blog_url: Annotated[Optional[List[str]], typer.Option(
        '--blog-url', help='Blog post URL(s) to include as context (can repeat)')] = None,
    extra_context: Annotated[Optional[str], typer.Option(
        '--context', help='Additional context (e.g. patch diff, notes)')] = None,
    no_poc: Annotated[bool, typer.Option(
        '--no-poc', help='Skip PoC generation')] = False,
    no_synthesize: Annotated[bool, typer.Option(
        '--no-synthesize', help='Skip exploit synthesis (analysis + PoC only)')] = False,
    platform: Annotated[str, typer.Option(
        help='Target platform: linux, android, generic')] = 'linux',
    planner: Annotated[str, typer.Option(
        help='Planner: auto, llm, powerlifted')] = 'auto',
    kernel_name: Annotated[Optional[str], typer.Option(
        '--kernel', help='Kernel name for kexploit BTF offset resolution')] = None,
    debug: Annotated[bool, typer.Option(help='Enable debug output')] = False,
):
    """Analyze a CVE and produce a pipeline-ready analysis + PoC.

    Fetches CVE data from NVD/MITRE, searches GitHub for existing PoCs,
    optionally fetches blog posts, then uses an LLM to produce:
      - static_analysis.json (feeds into synthesize/generate-exploit)
      - poc.c (compilable PoC skeleton)

    With --no-synthesize, only analysis + PoC are produced.
    Without it, the full synthesis pipeline runs automatically.

    Examples:
        syzploit analyze-cve CVE-2023-20938
        syzploit analyze-cve CVE-2024-1086 --blog-url https://example.com/writeup
        syzploit analyze-cve CVE-2023-4244 --platform linux --planner llm
        syzploit analyze-cve CVE-2023-20938 --no-synthesize --model gpt-5
    """
    from .SyzAnalyze.cve_analyzer import run_cve_pipeline, analyze_cve

    if no_synthesize:
        result = analyze_cve(
            cve_id=cve_id,
            output_dir=str(output_dir) if output_dir else None,
            model=model,
            generate_poc=not no_poc,
            blog_urls=blog_url,
            extra_context=extra_context,
            debug=debug,
        )
        typer.echo(f"\n[+] Analysis complete: {result.output_dir}")
        typer.echo(f"    CVE:           {result.cve_id}")
        vuln_type = result.analysis_json.get("vuln_type", "unknown")
        typer.echo(f"    Vuln type:     {vuln_type}")
        target_struct = result.analysis_json.get("target_struct", "")
        if target_struct:
            typer.echo(f"    Target struct: {target_struct}")
        if result.poc_source:
            typer.echo(f"    PoC:           {os.path.join(result.output_dir, 'poc.c')}")
        if result.github_pocs:
            typer.echo(f"    GitHub PoCs:   {len(result.github_pocs)} found")
            for p in result.github_pocs[:3]:
                typer.echo(f"      - {p['name']} ({p['stars']}★)")
    else:
        result = run_cve_pipeline(
            cve_id=cve_id,
            output_dir=str(output_dir) if output_dir else None,
            model=model,
            blog_urls=blog_url,
            extra_context=extra_context,
            kernel_name=kernel_name,
            platform=platform,
            planner=planner,
            synthesize=True,
            debug=debug,
        )
        typer.echo(f"\n[+] CVE pipeline complete: {result['analysis_dir']}")
        typer.echo(f"    CVE:           {result['cve_id']}")
        if result.get("poc_source"):
            typer.echo(f"    PoC:           {os.path.join(result['analysis_dir'], 'poc.c')}")
        synth = result.get("synthesis", {})
        if synth.get("exploits"):
            typer.echo(f"    Exploits:      {synth['exploits']}")
        elif synth.get("error"):
            typer.echo(f"    Synthesis:     FAILED ({synth['error'][:60]})")


@app.command(name="analyze-blog")
def analyze_blog_cmd(
    url: Annotated[str, typer.Argument(help='URL of the security blog post')],
    output_dir: Annotated[Optional[Path], typer.Option(
        help='Output directory')] = None,
    model: Annotated[str, typer.Option(
        help='LLM model to use')] = 'gpt-4o',
    extra_context: Annotated[Optional[str], typer.Option(
        '--context', help='Additional context')] = None,
    no_poc: Annotated[bool, typer.Option(
        '--no-poc', help='Skip PoC generation')] = False,
    no_synthesize: Annotated[bool, typer.Option(
        '--no-synthesize', help='Skip synthesis')] = False,
    platform: Annotated[str, typer.Option(
        help='Target platform')] = 'linux',
    planner: Annotated[str, typer.Option(
        help='Planner: auto, llm, powerlifted')] = 'auto',
    debug: Annotated[bool, typer.Option(help='Enable debug output')] = False,
):
    """Analyze a security blog post and produce a pipeline-ready analysis + PoC.

    Fetches the blog post, extracts vulnerability narrative and code blocks,
    then uses an LLM to classify the vulnerability and generate:
      - static_analysis.json
      - poc.c

    Examples:
        syzploit analyze-blog https://blog.example.com/kernel-exploit-writeup
        syzploit analyze-blog https://example.com/post --no-synthesize
    """
    from .SyzAnalyze.cve_analyzer import run_blog_pipeline, analyze_blog_post

    if no_synthesize:
        result = analyze_blog_post(
            url=url,
            output_dir=str(output_dir) if output_dir else None,
            model=model,
            generate_poc=not no_poc,
            extra_context=extra_context,
            debug=debug,
        )
        typer.echo(f"\n[+] Blog analysis complete: {result.output_dir}")
        if result.cve_id:
            typer.echo(f"    CVE detected:  {result.cve_id}")
        vuln_type = result.analysis_json.get("vuln_type", "unknown")
        typer.echo(f"    Vuln type:     {vuln_type}")
        if result.poc_source:
            typer.echo(f"    PoC:           {os.path.join(result.output_dir, 'poc.c')}")
    else:
        result = run_blog_pipeline(
            url=url,
            output_dir=str(output_dir) if output_dir else None,
            model=model,
            extra_context=extra_context,
            platform=platform,
            planner=planner,
            synthesize=True,
            debug=debug,
        )
        typer.echo(f"\n[+] Blog pipeline complete: {result['analysis_dir']}")
        if result.get("cve_id"):
            typer.echo(f"    CVE:           {result['cve_id']}")
        synth = result.get("synthesis", {})
        if synth.get("exploits"):
            typer.echo(f"    Exploits:      {synth['exploits']}")


# ═══════════════════════════════════════════════════════════════════════════
# kexploit Integration Commands
# ═══════════════════════════════════════════════════════════════════════════

@app.command(name="adapt-kernel")
def adapt_kernel_cmd(
    exploit_path: Annotated[Path, typer.Argument(
        help='Path to exploit C source file')],
    old_kernel: Annotated[str, typer.Option(
        '--from', help='Source kernel name (e.g. lts-6.1.36)')],
    new_kernel: Annotated[str, typer.Option(
        '--to', help='Target kernel name (e.g. lts-6.1.52)')],
    output: Annotated[Optional[Path], typer.Option(
        '-o', help='Output file (default: <exploit>_adapted.c)')] = None,
    debug: Annotated[bool, typer.Option(help='Enable debug output')] = False,
):
    """Adapt an annotated exploit to a new kernel version using kexploit.

    Uses kexploit's KernelAdapter to translate kernel addresses, ROP gadgets,
    and data values between kernel versions using symbol tables, Ghidra
    analysis, and BinDiff-style basic-block matching.

    The exploit must first be annotated (use `annotate-exploit`).

    Requires: kexploit package installed.

    Examples:
        syzploit adapt-kernel exploit.c --from lts-6.1.36 --to lts-6.1.52
    """
    from .Synthesizer.adapters.kexploit_adapter import adapt_exploit_to_kernel, kexploit_available

    if not kexploit_available():
        typer.echo("[!] kexploit package not installed. Install ingots_tools/kexploit first.")
        raise typer.Exit(code=1)

    source = exploit_path.read_text()
    result = adapt_exploit_to_kernel(source, old_kernel, new_kernel, debug=debug)

    if result.success and result.adapted_files:
        out_path = output or exploit_path.with_stem(exploit_path.stem + "_adapted")
        out_path.write_text(result.adapted_files[0])
        typer.echo(f"[+] Adapted exploit: {out_path}")
        typer.echo(f"    {old_kernel} -> {new_kernel}")
        if result.errors:
            typer.echo(f"    Warnings: {len(result.errors)}")
            for e in result.errors:
                typer.echo(f"      - {e}")
    else:
        typer.echo(f"[!] Adaptation failed:")
        for e in result.errors:
            typer.echo(f"    - {e}")
        raise typer.Exit(code=1)


@app.command(name="annotate-exploit")
def annotate_exploit_cmd(
    exploit_path: Annotated[Path, typer.Argument(
        help='Path to exploit C source file')],
    kernel: Annotated[str, typer.Option(
        help='Kernel name the exploit was written for')],
    output: Annotated[Optional[Path], typer.Option(
        '-o', help='Output file (default: overwrite in-place)')] = None,
    no_llm: Annotated[bool, typer.Option(
        '--no-llm', help='Use heuristic scoring instead of LLM')] = False,
    model: Annotated[str, typer.Option(
        help='LLM model for annotation')] = 'gpt-4o',
    debug: Annotated[bool, typer.Option(help='Enable debug output')] = False,
):
    """Annotate an exploit source with kexploit kernel-address markers.

    Inserts __kexploit_kernel_address(...) and __kexploit_rop_address(...)
    pseudo-calls at detected kernel constants, making the exploit portable
    to other kernel versions via `adapt-kernel`.

    Requires: kexploit package installed.

    Examples:
        syzploit annotate-exploit exploit.c --kernel lts-6.1.36
        syzploit annotate-exploit exploit.c --kernel lts-6.1.36 --no-llm
    """
    from .Synthesizer.adapters.kexploit_adapter import annotate_exploit_source, kexploit_available

    if not kexploit_available():
        typer.echo("[!] kexploit package not installed. Install ingots_tools/kexploit first.")
        raise typer.Exit(code=1)

    source = exploit_path.read_text()
    annotated = annotate_exploit_source(
        source, kernel, use_llm=not no_llm, model=model, debug=debug
    )

    out_path = output or exploit_path
    out_path.write_text(annotated)
    typer.echo(f"[+] Annotated exploit: {out_path}")


@app.command(name="kexploit-info")
def kexploit_info_cmd(
    kernel_name: Annotated[Optional[str], typer.Option(
        '--kernel', help='Query heap objects for this kernel')] = None,
    struct_name: Annotated[Optional[str], typer.Option(
        '--struct', help='Filter to specific struct name')] = None,
    debug: Annotated[bool, typer.Option(help='Enable debug output')] = False,
):
    """Show available kexploit integration capabilities and kernel data.

    Without --kernel: shows which kexploit components are available.
    With --kernel: queries the ObjectDb for heap objects and slab caches.

    Examples:
        syzploit kexploit-info
        syzploit kexploit-info --kernel ingots_5.10.107
        syzploit kexploit-info --kernel ingots_5.10.107 --struct pipe_buffer
    """
    from .Synthesizer.adapters.kexploit_adapter import (
        kexploit_available,
        kexploit_agent_available,
        load_heap_objects_from_object_db,
    )

    typer.echo("kexploit Integration Status:")
    typer.echo(f"  kexploit core:   {'AVAILABLE' if kexploit_available() else 'not installed'}")
    typer.echo(f"  kexploit_agent:  {'AVAILABLE' if kexploit_agent_available() else 'not installed'}")

    if kernel_name and kexploit_available():
        objects = load_heap_objects_from_object_db(kernel_name, debug=debug)
        if struct_name:
            objects = [o for o in objects if o.struct_name == struct_name]

        typer.echo(f"\n  Heap objects for {kernel_name}: {len(objects)}")
        for obj in objects[:20]:
            typer.echo(f"    {obj.struct_name:30s}  size={obj.struct_size:6d}  "
                       f"cache={obj.slab_cache:20s}  flags={obj.allocation_flags}")
        if len(objects) > 20:
            typer.echo(f"    ... and {len(objects) - 20} more")


def main():
    load_env()
    app()

if __name__ == "__main__":
    main()
