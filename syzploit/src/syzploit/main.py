from pathlib import Path
from typing import Optional
from typing_extensions import Annotated

from dotenv import load_dotenv
import typer
from . import SyzVerify
from . import SyzAnalyze
from . import Synthesizer
from .SyzVerify.bug_db import SyzkallBugDatabase
from .SyzVerify.run_bug import test_repro_crashes, test_repro_crashes_qemu
import json
import os

app = typer.Typer(help="Syzkall/Syzbot tooling for pulling, testing, and analyzing bugs.")


# TODO: decide if this will even be apart of kexploit
@app.command()
def pull(
    syzkall_kernel: Annotated[str, typer.Option(help='Kernel name to pull bugs for')] = 'android-5-10',
):
    """Pull bugs from syzbot for a given kernel version"""
    SyzVerify.pull(syzkall_kernel)

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
):
    """Test all bugs from syzbot for a given kernel version"""
    SyzVerify.test_all(local, arch, syzkall_kernel, qemu, root, source_image, source_disk, source, outdir_name, dynamic_analysis, gdb_port)

# Probably temprorary command
@app.command()
def collectstats(
    syzkall_kernel: Annotated[str, typer.Option(help='Kernel name to pull bugs for')] = 'android-5-10',
    outfile: Annotated[str, typer.Option(help='Output file to write stats to')] = 'syzkall_stats',
):
    """ Collect stats on bugs from syzbot """
    SyzVerify.collect_stats(syzkall_kernel, outfile)

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
):
    """Analyze a specific bug with static and optional dynamic analysis"""
    if dynamic_only:
        skip_static = True
        ignore_exploitability = True
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
    )

@app.command()
def synthesize(
    bug_id: Annotated[str, typer.Argument(help='Bug ID to synthesize exploit for')],
    goal: Annotated[str, typer.Option(help='Desired exploit goal (e.g., privilege_escalation, shell)')] = 'privilege_escalation',
    kernel_research_path: Annotated[Optional[Path], typer.Option(help='Path to google/kernel-research repo')] = None,
    chainreactor_path: Annotated[Optional[Path], typer.Option(help='Path to ucsb-seclab/chainreactor repo')] = None,
    analysis_dir: Annotated[Optional[Path], typer.Option(help='Path to analysis_<bug_id> directory')] = None,
    vmlinux_path: Annotated[Optional[Path], typer.Option(help='Path to vmlinux for gadget analysis')] = None,
):
    """Synthesize an exploit plan using SyzAnalyze + kernelXDK primitives, optionally via ChainReactor."""
    res = Synthesizer.synthesize(
        bug_id=str(bug_id),
        goal=str(goal),
        kernel_research_path=str(kernel_research_path) if kernel_research_path else None,
        chainreactor_path=str(chainreactor_path) if chainreactor_path else None,
        analysis_dir=str(analysis_dir) if analysis_dir else None,
        vmlinux_path=str(vmlinux_path) if vmlinux_path else None,
    )
    # Save a summary in the analysis directory
    try:
        ad = res.get('plan', {}).get('target_info', {}).get('analysis_dir')
        if ad:
            out = Path(ad) / 'synth_summary.json'
            with out.open('w') as f:
                import json
                json.dump(res, f, indent=2)
            typer.echo(f"[+] Synthesizer summary -> {out}")
        else:
            typer.echo("[+] Synthesizer completed; no analysis_dir available to write summary.")
    except Exception:
        typer.echo("[+] Synthesizer completed.")

@app.command(name="chainreactor_run")
def chainreactor_run(
    analysis_dir: Annotated[Path, typer.Argument(help='Path to analysis_<bug_id> directory with pddl')],
    chainreactor_path: Annotated[Path, typer.Option(help='Path to ucsb-seclab/chainreactor repo')],
    verbose: Annotated[bool, typer.Option(help='Print solver stdout/stderr')] = True,
):
    """Run ChainReactor on previously generated PDDL without rerunning dynamic analysis.

    Expects domain.pddl and problem.pddl under <analysis_dir>/pddl.
    """
    try:
        from .Synthesizer.chainreactor_integration import ChainReactor
        pddl_dir = analysis_dir / 'pddl'
        domain = pddl_dir / 'domain.pddl'
        problem = pddl_dir / 'problem.pddl'
        if not domain.exists() or not problem.exists():
            typer.echo(f"[!] Missing PDDL: {domain} or {problem}")
            raise typer.Exit(code=2)
        cr = ChainReactor(str(chainreactor_path))
        typer.echo(f"[INFO] Using domain: {domain}")
        typer.echo(f"[INFO] Using problem: {problem}")
        res = cr.solve_with_pddl(str(domain), str(problem), str(pddl_dir))
        # write summary next to PDDL
        summary = pddl_dir / 'solve_summary.json'
        with summary.open('w') as f:
            import json
            json.dump(res, f, indent=2)
        if verbose:
            stdout = (res.get('stdout') or '').strip()
            stderr = (res.get('stderr') or '').strip()
            if stdout:
                typer.echo("[SOLVER STDOUT]\n" + stdout)
            if stderr:
                typer.echo("[SOLVER STDERR]\n" + stderr)
        ok = bool(res.get('success'))
        plans = res.get('plans') or []
        hint = res.get('hint')
        if hint:
            typer.echo(f"[HINT] {hint}")
        if ok:
            typer.echo(f"[✓] ChainReactor succeeded. Plans: {len(plans)}. Outputs in {pddl_dir}")
        else:
            typer.echo(f"[!] ChainReactor failed. See {summary} for details.")
    except Exception as e:
        typer.echo(f"[!] chainreactor_run failed: {e}")

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
    goal: Annotated[str, typer.Option(help='Exploit goal for synthesis')] = 'privilege_escalation',
):
    """Run the full pipeline: verify crash with SyzVerify, analyze with SyzAnalyze,
    test generated primitive, run Synthesizer, and finally verify the generated exploit.

    Steps:
    1) Compile + run reproducer to confirm crash
    2) Perform static (+optional dynamic) analysis
    3) Compile + run generated primitive C (if available)
    4) Synthesize exploit plan (optionally via ChainReactor)
    5) Run final exploit artifact if available
    """
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
            chainreactor_path=None,
            analysis_dir=str(analysis_dir),
            vmlinux_path=None,
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

    # Save summary
    out = analysis_dir / 'pipeline_summary.json'
    with out.open('w') as f:
        json.dump(summary, f, indent=2)
    typer.echo(f"[+] Pipeline summary -> {out}")

def main():
    load_dotenv()
    app()

if __name__ == "__main__":
    main()
