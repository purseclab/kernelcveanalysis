"""
app_agent — Agentic Android app security analysis loop.

LLM-driven orchestration that:
    1. Analyzes the APK (manifest, permissions, components)
    2. Scans for vulnerabilities (static + optional LLM)
    3. Generates exploits for discovered vulns
    4. Tests exported components via intents
    5. Fuzzes IPC interfaces
    6. Captures network traffic
    7. Verifies exploits on the device
    8. Produces a comprehensive security report

The agent decides which tools to run and in what order based on findings.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from rich.console import Console
from rich.table import Table

console = Console()


@dataclass
class AppAgentConfig:
    """Configuration for the app security agent."""
    apk_path: str
    output_dir: str
    adb_serial: str = "localhost:6537"
    adb_binary: str = "adb"
    package_name: str = ""  # auto-detected from APK
    scan_mode: str = "static"  # "static", "llm", "hybrid"
    fuzz: bool = True
    fuzz_max_per_component: int = 15
    capture_traffic: bool = True
    traffic_duration: int = 15
    verify_exploits: bool = True
    llm_cfg: Any = None  # syzploit Config for LLM calls
    # Hybrid mode
    kernel_cve: str = ""  # CVE to chain with (e.g. "CVE-2023-20938")
    kernel_exploit_path: str = ""  # path to compiled kernel exploit binary
    # LLM decision mode
    llm_decisions: bool = False  # use LLM to decide tool order (vs fixed pipeline)


@dataclass
class AppAgentResult:
    """Complete app security assessment result."""
    package_name: str = ""
    apk_path: str = ""
    start_time: float = 0
    end_time: float = 0
    steps_completed: List[Dict[str, Any]] = field(default_factory=list)
    analysis: Optional[Dict[str, Any]] = None
    vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)
    exploits_generated: int = 0
    exploits_verified: int = 0
    exploits_successful: int = 0
    fuzz_tests: int = 0
    fuzz_crashes: int = 0
    fuzz_interesting: int = 0
    connections_found: int = 0
    cleartext_urls: int = 0
    hybrid_chains: int = 0
    hybrid_successful: int = 0
    decisions: List[Dict[str, Any]] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    @property
    def duration_sec(self) -> int:
        return int(self.end_time - self.start_time) if self.end_time else 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "package_name": self.package_name,
            "apk_path": self.apk_path,
            "duration_sec": self.duration_sec,
            "steps_completed": self.steps_completed,
            "vulnerability_count": len(self.vulnerabilities),
            "vulnerabilities": self.vulnerabilities,
            "exploits_generated": self.exploits_generated,
            "exploits_verified": self.exploits_verified,
            "exploits_successful": self.exploits_successful,
            "fuzz_tests": self.fuzz_tests,
            "fuzz_crashes": self.fuzz_crashes,
            "fuzz_interesting": self.fuzz_interesting,
            "connections_found": self.connections_found,
            "cleartext_urls": self.cleartext_urls,
            "hybrid_chains": self.hybrid_chains,
            "hybrid_successful": self.hybrid_successful,
            "decisions": self.decisions,
            "errors": self.errors,
        }


def _log_step(result: AppAgentResult, name: str, detail: str, success: bool = True):
    """Log a completed step."""
    result.steps_completed.append({
        "step": name,
        "detail": detail,
        "success": success,
        "time": time.time(),
    })


def run_app_agent(config: AppAgentConfig) -> AppAgentResult:
    """
    Run the full app security agent pipeline.

    Steps:
        1. analyze_apk — Parse manifest, permissions, components
        2. scan_vulnerabilities — Static + optional LLM vulnerability scan
        3. test_intents — Test exported components
        4. generate_exploits — Create exploit scripts from vulns
        5. fuzz_components — Fuzz IPC interfaces (if enabled)
        6. capture_traffic — Monitor network activity (if enabled)
        7. verify_exploits — Run and verify generated exploits (if enabled)
        8. generate_report — Produce final security report
    """
    result = AppAgentResult(
        apk_path=config.apk_path,
        start_time=time.time(),
    )

    out_dir = Path(config.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    # ── Step 1: Analyze APK ──────────────────────────────────────────
    console.print("\n[bold cyan]Step 1/7:[/] Analyzing APK…")
    try:
        from .app_analyzer import analyze_apk
        analysis = analyze_apk(config.apk_path)
        result.package_name = analysis.package_name
        config.package_name = analysis.package_name
        result.analysis = analysis.to_dict()

        console.print(f"  Package: [bold]{analysis.package_name}[/]")
        console.print(f"  Version: {analysis.version_name} ({analysis.version_code})")
        console.print(f"  SDK: min={analysis.min_sdk}, target={analysis.target_sdk}")
        console.print(f"  Permissions: {len(analysis.permissions)} ({len(analysis.dangerous_permissions)} dangerous)")
        console.print(f"  Components: {len(analysis.components)} ({len(analysis.exported_components)} exported)")
        console.print(f"  Manifest vulns: {len(analysis.vulnerabilities)}")

        # Add manifest vulns to result
        for v in analysis.vulnerabilities:
            result.vulnerabilities.append(v.to_dict())

        _log_step(result, "analyze_apk",
                  f"{analysis.package_name}: {len(analysis.components)} components, "
                  f"{len(analysis.vulnerabilities)} manifest vulns")

        # Save analysis report
        (out_dir / "app_analysis_report.json").write_text(
            json.dumps(analysis.to_dict(), indent=2))

        # Decompile APK for source-level scanning
        try:
            from .decompiler import decompile_apk as _decompile
            decompiled_dir = out_dir / "decompiled"
            src_path = _decompile(config.apk_path, str(decompiled_dir))
            if src_path:
                console.print(f"  Decompiled source: {src_path}")
                _log_step(result, "decompile_apk", f"source at {src_path}")
            else:
                console.print(f"  [dim]Decompilation produced no Java source[/]")
        except Exception as exc:
            console.print(f"  [dim]Decompilation skipped: {exc}[/]")

    except Exception as exc:
        result.errors.append(f"analyze_apk: {exc}")
        console.print(f"  [red]Failed: {exc}[/]")
        _log_step(result, "analyze_apk", str(exc), success=False)
        result.end_time = time.time()
        return result

    # ── Step 2: Vulnerability Scan ───────────────────────────────────
    console.print("\n[bold cyan]Step 2/7:[/] Scanning for vulnerabilities…")
    scan_vulns = []
    try:
        from .vuln_scanner import scan_static, scan_hybrid

        # Check if APK was decompiled (we use androguard's dex classes)
        # For now, use the manifest-based vulns from step 1
        # Static scan needs decompiled source — skip if no source dir
        decompiled_dir = out_dir / "decompiled"
        if decompiled_dir.exists():
            if config.scan_mode == "hybrid" and config.llm_cfg:
                scan_vulns = scan_hybrid(str(decompiled_dir), config.llm_cfg)
            else:
                scan_vulns = scan_static(str(decompiled_dir))
            console.print(f"  Source scan: {len(scan_vulns)} additional vulns")
        else:
            console.print(f"  [dim]No decompiled source — using manifest analysis only[/]")

        # Merge with manifest vulns (dedup)
        seen = {(v["name"], v.get("component", "")) for v in result.vulnerabilities}
        for v in scan_vulns:
            key = (v.name, v.component)
            if key not in seen:
                result.vulnerabilities.append(v.to_dict())
                seen.add(key)

        total = len(result.vulnerabilities)
        console.print(f"  Total vulnerabilities: [bold]{total}[/]")
        _log_step(result, "scan_vulnerabilities",
                  f"{total} total ({len(scan_vulns)} from source scan)")

    except Exception as exc:
        result.errors.append(f"scan_vulnerabilities: {exc}")
        console.print(f"  [yellow]Scan error: {exc}[/]")
        _log_step(result, "scan_vulnerabilities", str(exc), success=False)

    # ── Step 3: Test Exported Components ─────────────────────────────
    console.print("\n[bold cyan]Step 3/7:[/] Testing exported components…")
    try:
        from .intent_crafter import test_exported_components
        if analysis.exported_components:
            intent_results = test_exported_components(
                analysis.package_name,
                [c.to_dict() for c in analysis.exported_components],
                adb_serial=config.adb_serial,
                adb_binary=config.adb_binary,
            )
            successes = sum(1 for r in intent_results if r.success)
            console.print(f"  Tested {len(intent_results)} intents: {successes} OK")
            _log_step(result, "test_intents",
                      f"{len(intent_results)} intents, {successes} successful")

            # Save intent results
            (out_dir / "intent_test_report.json").write_text(
                json.dumps([r.to_dict() for r in intent_results], indent=2))
        else:
            console.print("  [dim]No exported components[/]")
            _log_step(result, "test_intents", "no exported components")

    except Exception as exc:
        result.errors.append(f"test_intents: {exc}")
        console.print(f"  [yellow]Intent test error: {exc}[/]")
        _log_step(result, "test_intents", str(exc), success=False)

    # ── Step 4: Generate Exploits ────────────────────────────────────
    console.print("\n[bold cyan]Step 4/7:[/] Generating exploit scripts…")
    exploits = []
    try:
        from .exploit_generator import generate_all_exploits, save_exploits
        from .app_analyzer import AppVulnerability

        # Convert back to AppVulnerability objects
        vuln_objects = [
            AppVulnerability(**{k: v for k, v in vd.items()
                              if k in AppVulnerability.__dataclass_fields__})
            for vd in result.vulnerabilities
        ]

        # Build source + manifest context for LLM exploit generation
        _source_dir = ""
        _manifest_ctx = ""
        _decompiled = out_dir / "decompiled" / "sources"
        if _decompiled.exists():
            _source_dir = str(_decompiled)
        if analysis:
            _manifest_parts = [
                f"Package: {analysis.package_name}",
                f"Permissions: {', '.join(analysis.dangerous_permissions[:10])}",
                f"Exported: {len(analysis.exported_components)} components",
            ]
            for c in analysis.exported_components[:10]:
                _manifest_parts.append(
                    f"  [{c.component_type}] {c.name} "
                    f"(perm={c.permission or 'none'}, "
                    f"auth={c.authorities})"
                )
                for dl in c.deeplinks[:2]:
                    _manifest_parts.append(f"    deeplink: {dl}")
            _manifest_ctx = "\n".join(_manifest_parts)

        exploits = generate_all_exploits(
            vuln_objects,
            package_name=config.package_name,
            adb_serial=config.adb_serial,
            adb_binary=config.adb_binary,
            cfg=config.llm_cfg,
            source_dir=_source_dir,
            manifest_context=_manifest_ctx,
        )
        result.exploits_generated = len(exploits)
        console.print(f"  Generated {len(exploits)} exploit scripts")

        if exploits:
            saved = save_exploits(exploits, str(out_dir / "exploits"))
            console.print(f"  Saved to {out_dir / 'exploits'}/")

        _log_step(result, "generate_exploits", f"{len(exploits)} exploits generated")

    except Exception as exc:
        result.errors.append(f"generate_exploits: {exc}")
        console.print(f"  [yellow]Exploit gen error: {exc}[/]")
        _log_step(result, "generate_exploits", str(exc), success=False)

    # ── Step 5: Fuzz IPC ─────────────────────────────────────────────
    if config.fuzz:
        console.print("\n[bold cyan]Step 5/7:[/] Fuzzing IPC interfaces…")
        try:
            from .ipc_fuzzer import fuzz_exported_components
            if analysis.exported_components:
                # Limit fuzzing to max 20 components to avoid hour-long runs
                # on apps like Settings (250+ exports)
                _fuzz_components = [c.to_dict() for c in analysis.exported_components]
                if len(_fuzz_components) > 20:
                    console.print(f"  [dim]Limiting fuzz to 20/{len(_fuzz_components)} components[/]")
                    _fuzz_components = _fuzz_components[:20]
                fuzz_report = fuzz_exported_components(
                    analysis.package_name,
                    _fuzz_components,
                    adb_serial=config.adb_serial,
                    adb_binary=config.adb_binary,
                    max_tests_per_component=config.fuzz_max_per_component,
                )
                result.fuzz_tests = fuzz_report.total_tests
                result.fuzz_crashes = fuzz_report.crashes
                result.fuzz_interesting = fuzz_report.interesting

                console.print(f"  Tests: {fuzz_report.total_tests}")
                console.print(f"  Crashes: [red]{fuzz_report.crashes}[/]")
                console.print(f"  Interesting: [yellow]{fuzz_report.interesting}[/]")

                (out_dir / "fuzz_report.json").write_text(
                    json.dumps(fuzz_report.to_dict(), indent=2))

                _log_step(result, "fuzz_ipc",
                          f"{fuzz_report.total_tests} tests, {fuzz_report.crashes} crashes")
            else:
                console.print("  [dim]No exported components to fuzz[/]")
                _log_step(result, "fuzz_ipc", "skipped: no exported components")

        except Exception as exc:
            result.errors.append(f"fuzz_ipc: {exc}")
            console.print(f"  [yellow]Fuzz error: {exc}[/]")
            _log_step(result, "fuzz_ipc", str(exc), success=False)
    else:
        console.print("\n[dim]Step 5/7: Fuzzing skipped (--no-fuzz)[/]")
        _log_step(result, "fuzz_ipc", "skipped by config")

    # ── Step 6: Capture Traffic ──────────────────────────────────────
    if config.capture_traffic:
        console.print(f"\n[bold cyan]Step 6/7:[/] Capturing traffic ({config.traffic_duration}s)…")
        try:
            from .traffic_capture import capture_app_traffic
            traffic = capture_app_traffic(
                config.package_name,
                duration=config.traffic_duration,
                adb_serial=config.adb_serial,
                adb_binary=config.adb_binary,
            )
            result.connections_found = len(traffic.connections)
            result.cleartext_urls = len(traffic.cleartext_urls)

            console.print(f"  Connections: {len(traffic.connections)}")
            console.print(f"  URLs: {len(traffic.urls_found)}")
            console.print(f"  Cleartext: [red]{len(traffic.cleartext_urls)}[/]")

            (out_dir / "traffic_report.json").write_text(
                json.dumps(traffic.to_dict(), indent=2))

            _log_step(result, "capture_traffic",
                      f"{len(traffic.connections)} connections, "
                      f"{len(traffic.cleartext_urls)} cleartext")

        except Exception as exc:
            result.errors.append(f"capture_traffic: {exc}")
            console.print(f"  [yellow]Traffic capture error: {exc}[/]")
            _log_step(result, "capture_traffic", str(exc), success=False)
    else:
        console.print("\n[dim]Step 6/7: Traffic capture skipped[/]")
        _log_step(result, "capture_traffic", "skipped by config")

    # ── Step 7: Verify Exploits ──────────────────────────────────────
    if config.verify_exploits and exploits:
        console.print(f"\n[bold cyan]Step 7/7:[/] Verifying {len(exploits)} exploit(s)…")
        try:
            from .app_verify import verify_all_exploits
            verify_results = verify_all_exploits(
                exploits,
                config.package_name,
                adb_serial=config.adb_serial,
                adb_binary=config.adb_binary,
            )
            result.exploits_verified = len(verify_results)
            result.exploits_successful = sum(1 for r in verify_results if r.success)

            for vr in verify_results:
                status = "[green]SUCCESS[/]" if vr.success else "[dim]no impact[/]"
                console.print(f"  {status} {vr.exploit_name} ({vr.duration_ms}ms)")
                for ind in vr.indicators[:2]:
                    console.print(f"    → {ind[:100]}")

            (out_dir / "verify_results.json").write_text(
                json.dumps([r.to_dict() for r in verify_results], indent=2))

            _log_step(result, "verify_exploits",
                      f"{result.exploits_successful}/{result.exploits_verified} successful")

        except Exception as exc:
            result.errors.append(f"verify_exploits: {exc}")
            console.print(f"  [yellow]Verify error: {exc}[/]")
            _log_step(result, "verify_exploits", str(exc), success=False)
    else:
        console.print("\n[dim]Step 7/8: Verification skipped[/]")
        _log_step(result, "verify_exploits", "skipped")

    # ── Step 8: Hybrid Analysis (if kernel CVE provided) ────────────
    if config.kernel_cve:
        console.print(f"\n[bold cyan]Step 8/8:[/] Hybrid analysis ({config.kernel_cve})…")
        try:
            from .hybrid_mode import run_hybrid_analysis
            hybrid = run_hybrid_analysis(
                app_vulns=result.vulnerabilities,
                kernel_cve=config.kernel_cve,
                kernel_exploit_path=config.kernel_exploit_path,
                adb_serial=config.adb_serial,
                adb_binary=config.adb_binary,
                test_chains=bool(config.kernel_exploit_path),
            )
            result.hybrid_chains = len(hybrid.chains_identified)
            result.hybrid_successful = hybrid.chains_successful

            console.print(f"  Chains identified: {len(hybrid.chains_identified)}")
            for chain in hybrid.chains_identified:
                status = "[green]✓[/]" if chain.success else "[dim]identified[/]"
                console.print(f"  {status} {chain.name}: {chain.delivery_method}")
                console.print(f"    App: {chain.app_vulnerability} → Kernel: {chain.kernel_vulnerability}")

            if hybrid.chains_successful:
                console.print(f"\n  [bold green]{hybrid.chains_successful} hybrid chain(s) verified![/]")

            (out_dir / "hybrid_report.json").write_text(
                json.dumps(hybrid.to_dict(), indent=2))

            _log_step(result, "hybrid_analysis",
                      f"{len(hybrid.chains_identified)} chains, {hybrid.chains_successful} successful")

        except Exception as exc:
            result.errors.append(f"hybrid_analysis: {exc}")
            console.print(f"  [yellow]Hybrid analysis error: {exc}[/]")
            _log_step(result, "hybrid_analysis", str(exc), success=False)
    else:
        console.print("\n[dim]Step 8/8: Hybrid analysis skipped (no --kernel-cve)[/]")
        _log_step(result, "hybrid_analysis", "skipped: no kernel CVE")

    # ── Final Report ─────────────────────────────────────────────────
    result.end_time = time.time()

    console.print(f"\n{'═' * 60}")
    console.print(f"[bold]═══ App Security Report: {result.package_name} ═══[/]")
    console.print(f"{'═' * 60}")

    table = Table(show_header=True, header_style="bold")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", justify="right")
    table.add_row("Duration", f"{result.duration_sec}s")
    table.add_row("Vulnerabilities", str(len(result.vulnerabilities)))
    table.add_row("Exploits Generated", str(result.exploits_generated))
    table.add_row("Exploits Verified", str(result.exploits_verified))
    table.add_row("Exploits Successful", str(result.exploits_successful))
    table.add_row("Fuzz Tests", str(result.fuzz_tests))
    table.add_row("Fuzz Crashes", str(result.fuzz_crashes))
    table.add_row("Network Connections", str(result.connections_found))
    table.add_row("Cleartext URLs", str(result.cleartext_urls))
    table.add_row("Hybrid Chains", str(result.hybrid_chains))
    table.add_row("Hybrid Successful", str(result.hybrid_successful))
    table.add_row("Errors", str(len(result.errors)))
    console.print(table)

    # Vulnerability summary by severity
    sev_counts: Dict[str, int] = {}
    for v in result.vulnerabilities:
        s = v.get("severity", "unknown")
        sev_counts[s] = sev_counts.get(s, 0) + 1

    if sev_counts:
        console.print("\n[bold]Vulnerability Breakdown:[/]")
        for sev in ("critical", "high", "medium", "low", "info"):
            count = sev_counts.get(sev, 0)
            if count:
                color = {"critical": "red", "high": "red", "medium": "yellow",
                         "low": "cyan", "info": "dim"}.get(sev, "white")
                console.print(f"  [{color}]{sev.upper():8s}: {count}[/{color}]")

    # Save final report
    report_path = out_dir / "app_security_report.json"
    report_path.write_text(json.dumps(result.to_dict(), indent=2))
    console.print(f"\n📄 Full report: {report_path}")

    # List all saved reports
    console.print(f"\n[bold]═══ Reports ═══[/]")
    for f in sorted(out_dir.glob("*.json")):
        console.print(f"  📄 {f}")

    return result
