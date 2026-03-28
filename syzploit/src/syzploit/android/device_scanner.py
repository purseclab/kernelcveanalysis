"""
device_scanner — Autonomous full-device security scanner.

Connects to an Android device, enumerates all installed apps, pulls each APK,
analyzes them for vulnerabilities, ranks by severity, and produces a
comprehensive device security report.

Usage:
    syzploit scan-device --device localhost:6537 --output-dir ./device_audit
"""

from __future__ import annotations

import json
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn

console = Console()


@dataclass
class AppScore:
    """Security score for a single app."""
    package_name: str
    apk_path: str = ""
    version: str = ""
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0
    exported_components: int = 0
    dangerous_permissions: int = 0
    has_native_libs: bool = False
    debuggable: bool = False
    score: float = 0.0  # 0-100, lower = more secure
    vulns: List[Dict[str, Any]] = field(default_factory=list)
    analyzed: bool = False
    error: str = ""

    def compute_score(self) -> float:
        """Compute risk score (0-100). Higher = riskier."""
        self.score = (
            self.critical * 25
            + self.high * 10
            + self.medium * 3
            + self.low * 1
            + self.exported_components * 2
            + self.dangerous_permissions * 1.5
            + (20 if self.debuggable else 0)
        )
        return self.score

    @property
    def total_vulns(self) -> int:
        return self.critical + self.high + self.medium + self.low + self.info

    def to_dict(self) -> Dict[str, Any]:
        return {
            "package_name": self.package_name,
            "version": self.version,
            "risk_score": round(self.score, 1),
            "critical": self.critical,
            "high": self.high,
            "medium": self.medium,
            "low": self.low,
            "info": self.info,
            "total_vulns": self.total_vulns,
            "exported_components": self.exported_components,
            "dangerous_permissions": self.dangerous_permissions,
            "debuggable": self.debuggable,
            "has_native_libs": self.has_native_libs,
            "analyzed": self.analyzed,
            "error": self.error,
        }


@dataclass
class DeviceScanResult:
    """Complete device security scan result."""
    device_serial: str = ""
    kernel_version: str = ""
    android_version: str = ""
    security_patch: str = ""
    selinux_mode: str = ""
    total_apps: int = 0
    apps_analyzed: int = 0
    apps_with_vulns: int = 0
    total_critical: int = 0
    total_high: int = 0
    app_scores: List[AppScore] = field(default_factory=list)
    kernel_analysis: Optional[Dict[str, Any]] = None
    duration_sec: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "device_serial": self.device_serial,
            "kernel_version": self.kernel_version,
            "android_version": self.android_version,
            "security_patch": self.security_patch,
            "selinux_mode": self.selinux_mode,
            "total_apps": self.total_apps,
            "apps_analyzed": self.apps_analyzed,
            "apps_with_vulns": self.apps_with_vulns,
            "total_critical": self.total_critical,
            "total_high": self.total_high,
            "app_scores": [a.to_dict() for a in self.app_scores],
            "kernel_analysis": self.kernel_analysis,
            "duration_sec": self.duration_sec,
        }


def _adb(cmd: str, serial: str, adb_bin: str, timeout: int = 15) -> Tuple[int, str]:
    """Run ADB shell command."""
    try:
        r = subprocess.run(
            [adb_bin, "-s", serial, "shell", cmd],
            capture_output=True, text=True, timeout=timeout,
        )
        return r.returncode, r.stdout.strip()
    except Exception:
        return -1, ""


def _adb_pull(remote: str, local: str, serial: str, adb_bin: str) -> bool:
    """Pull file from device."""
    try:
        r = subprocess.run(
            [adb_bin, "-s", serial, "pull", remote, local],
            capture_output=True, text=True, timeout=120,
        )
        return r.returncode == 0
    except Exception:
        return False


# ── Package Enumeration ──────────────────────────────────────────────


def list_installed_apps(
    serial: str,
    adb_bin: str,
    include_system: bool = False,
    third_party_only: bool = False,
) -> List[str]:
    """List installed packages on the device. Retries if PM not ready."""
    cmd = "pm list packages -3" if third_party_only else "pm list packages"

    # Retry — package manager may not be ready immediately after boot
    for attempt in range(6):
        rc, out = _adb(cmd, serial, adb_bin, timeout=30)
        packages = []
        for line in out.splitlines():
            line = line.strip()
            if line.startswith("package:"):
                packages.append(line.replace("package:", ""))

        if packages:
            return sorted(packages)

        # PM not ready — wait and retry
        if attempt < 5:
            import time
            time.sleep(10)

    return []


def get_apk_path(package: str, serial: str, adb_bin: str) -> str:
    """Get the APK path on device for a package."""
    rc, out = _adb(f"pm path {package}", serial, adb_bin)
    if rc != 0 or not out:
        return ""
    # Take first line: "package:/system/app/Music/Music.apk"
    first_line = out.splitlines()[0].strip()
    return first_line.replace("package:", "")


def pull_apk(
    package: str,
    output_dir: str,
    serial: str,
    adb_bin: str,
) -> Optional[str]:
    """Pull APK from device to local filesystem."""
    remote_path = get_apk_path(package, serial, adb_bin)
    if not remote_path:
        return None

    local_path = str(Path(output_dir) / f"{package}.apk")
    if _adb_pull(remote_path, local_path, serial, adb_bin):
        return local_path
    return None


# ── Device Info ──────────────────────────────────────────────────────


def collect_device_info(serial: str, adb_bin: str) -> Dict[str, str]:
    """Collect basic device information."""
    info = {}
    for key, cmd in [
        ("kernel_version", "uname -r"),
        ("android_version", "getprop ro.build.version.release"),
        ("security_patch", "getprop ro.build.version.security_patch"),
        ("build_type", "getprop ro.build.type"),
        ("device_model", "getprop ro.product.model"),
        ("selinux", "getenforce"),
        ("cpu_abi", "getprop ro.product.cpu.abi"),
        ("sdk_version", "getprop ro.build.version.sdk"),
    ]:
        _, val = _adb(cmd, serial, adb_bin)
        info[key] = val
    return info


# ── Full Device Scan ─────────────────────────────────────────────────


def scan_device(
    serial: str = "localhost:6537",
    adb_bin: str = "adb",
    output_dir: str = "./device_audit",
    include_system: bool = True,
    max_apps: int = 0,  # 0 = all
    skip_packages: Optional[List[str]] = None,
) -> DeviceScanResult:
    """
    Full autonomous device security scan.

    1. Collects device info (kernel, Android version, SELinux)
    2. Lists all installed apps
    3. Pulls each APK
    4. Analyzes for vulnerabilities
    5. Ranks by risk score
    6. Produces comprehensive report
    """
    start_time = time.time()
    result = DeviceScanResult(device_serial=serial)
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    apk_dir = out / "apks"
    apk_dir.mkdir(exist_ok=True)

    skip = set(skip_packages or [])

    # ── Step 1: Device info ──────────────────────────────────────
    console.print("\n[bold cyan]Step 1:[/] Collecting device information…")
    device_info = collect_device_info(serial, adb_bin)
    result.kernel_version = device_info.get("kernel_version", "")
    result.android_version = device_info.get("android_version", "")
    result.security_patch = device_info.get("security_patch", "")
    result.selinux_mode = device_info.get("selinux", "")

    console.print(f"  Kernel: {result.kernel_version}")
    console.print(f"  Android: {result.android_version}")
    console.print(f"  Security patch: {result.security_patch}")
    console.print(f"  SELinux: {result.selinux_mode}")

    (out / "device_info.json").write_text(json.dumps(device_info, indent=2))

    # ── Step 2: List apps ────────────────────────────────────────
    console.print("\n[bold cyan]Step 2:[/] Enumerating installed apps…")
    # Get third-party apps first (these include challenge APKs)
    third_party = list_installed_apps(serial, adb_bin, third_party_only=True)
    if include_system:
        system_apps = list_installed_apps(serial, adb_bin, include_system=True)
        # Remove third-party from system list to avoid dupes
        system_only = [p for p in system_apps if p not in set(third_party)]
        # Third-party first, then system
        packages = third_party + system_only
    else:
        packages = third_party
    packages = [p for p in packages if p not in skip]
    if max_apps > 0:
        packages = packages[:max_apps]
    result.total_apps = len(packages)
    if third_party:
        console.print(f"  Found {len(packages)} packages ({len(third_party)} third-party first)")

    # ── Step 3: Pull + Analyze each app ──────────────────────────
    console.print(f"\n[bold cyan]Step 3:[/] Analyzing {len(packages)} apps…")

    from .app_analyzer import analyze_apk

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Scanning apps…", total=len(packages))

        for i, pkg in enumerate(packages):
            progress.update(task, description=f"[{i+1}/{len(packages)}] {pkg}")
            app_score = AppScore(package_name=pkg)

            try:
                # Pull APK
                local_apk = pull_apk(pkg, str(apk_dir), serial, adb_bin)
                if not local_apk:
                    app_score.error = "Failed to pull APK"
                    result.app_scores.append(app_score)
                    progress.advance(task)
                    continue

                app_score.apk_path = local_apk

                # Analyze
                analysis = analyze_apk(local_apk)
                app_score.analyzed = True
                app_score.version = analysis.version_name
                app_score.exported_components = len(analysis.exported_components)
                app_score.dangerous_permissions = len(analysis.dangerous_permissions)
                app_score.has_native_libs = len(analysis.native_libraries) > 0
                app_score.debuggable = analysis.debuggable

                # Count vulns by severity
                for v in analysis.vulnerabilities:
                    sev = v.severity
                    if sev == "critical":
                        app_score.critical += 1
                    elif sev == "high":
                        app_score.high += 1
                    elif sev == "medium":
                        app_score.medium += 1
                    elif sev == "low":
                        app_score.low += 1
                    else:
                        app_score.info += 1
                    app_score.vulns.append(v.to_dict())

                app_score.compute_score()
                result.apps_analyzed += 1
                if app_score.total_vulns > 0:
                    result.apps_with_vulns += 1

            except Exception as exc:
                app_score.error = str(exc)[:200]

            result.app_scores.append(app_score)
            progress.advance(task)

    # ── Step 4: Sort by risk score ───────────────────────────────
    result.app_scores.sort(key=lambda a: a.score, reverse=True)
    result.total_critical = sum(a.critical for a in result.app_scores)
    result.total_high = sum(a.high for a in result.app_scores)

    # ── Step 5: Display results ──────────────────────────────────
    console.print(f"\n{'═' * 70}")
    console.print(f"[bold]═══ Device Security Report: {serial} ═══[/]")
    console.print(f"{'═' * 70}")

    # Summary table
    summary = Table(show_header=True, header_style="bold")
    summary.add_column("Metric", style="cyan")
    summary.add_column("Value", justify="right")
    summary.add_row("Kernel", result.kernel_version)
    summary.add_row("Android", result.android_version)
    summary.add_row("Security Patch", result.security_patch)
    summary.add_row("SELinux", result.selinux_mode)
    summary.add_row("Total Apps", str(result.total_apps))
    summary.add_row("Apps Analyzed", str(result.apps_analyzed))
    summary.add_row("Apps with Vulns", str(result.apps_with_vulns))
    summary.add_row("Total CRITICAL", str(result.total_critical))
    summary.add_row("Total HIGH", str(result.total_high))
    console.print(summary)

    # Top risky apps
    risky = [a for a in result.app_scores if a.score > 0 and a.analyzed]
    if risky:
        console.print(f"\n[bold]Top {min(20, len(risky))} Riskiest Apps:[/]")
        risk_table = Table(show_header=True, header_style="bold")
        risk_table.add_column("#", style="dim", width=3)
        risk_table.add_column("Package", style="cyan")
        risk_table.add_column("Score", justify="right", style="red")
        risk_table.add_column("Crit", justify="right")
        risk_table.add_column("High", justify="right")
        risk_table.add_column("Med", justify="right")
        risk_table.add_column("Exported", justify="right")
        risk_table.add_column("Perms", justify="right")

        for i, app in enumerate(risky[:20], 1):
            risk_table.add_row(
                str(i),
                app.package_name[:45],
                f"{app.score:.0f}",
                str(app.critical) if app.critical else "",
                str(app.high) if app.high else "",
                str(app.medium) if app.medium else "",
                str(app.exported_components),
                str(app.dangerous_permissions),
            )
        console.print(risk_table)

    # ── Step 6: Save report ──────────────────────────────────────
    result.duration_sec = int(time.time() - start_time)

    report_path = out / "device_security_report.json"
    report_path.write_text(json.dumps(result.to_dict(), indent=2))
    console.print(f"\n📄 Full report: {report_path}")
    console.print(f"⏱  Duration: {result.duration_sec}s")

    # Per-app reports for top risky apps
    per_app_dir = out / "per_app"
    per_app_dir.mkdir(exist_ok=True)
    for app in risky[:10]:
        app_report = per_app_dir / f"{app.package_name}.json"
        app_report.write_text(json.dumps({
            **app.to_dict(),
            "vulnerabilities": app.vulns,
        }, indent=2))

    console.print(f"📄 Per-app reports: {per_app_dir}/ ({min(10, len(risky))} apps)")

    return result


def full_device_audit(
    serial: str = "localhost:6537",
    adb_bin: str = "adb",
    output_dir: str = "./device_audit",
    include_system: bool = True,
    max_apps: int = 0,
    deep_scan_top: int = 3,
    fuzz: bool = True,
    traffic: bool = True,
    kernel_cve: str = "",
    kernel_exploit_path: str = "",
    llm_cfg: Any = None,
) -> DeviceScanResult:
    """
    One-command full device audit:
        1. Scan all apps (pull APKs, analyze, rank by risk)
        2. Deep-dive top N riskiest apps (fuzz, traffic, exploit gen, verify)
        3. Hybrid kernel+app analysis if CVE provided
        4. Produce comprehensive device security report
    """
    out = Path(output_dir)

    # ── Phase 1: Scan all apps ───────────────────────────────────
    console.print("\n[bold]╔══════════════════════════════════════════════╗[/]")
    console.print("[bold]║   PHASE 1: FULL DEVICE APP SCAN              ║[/]")
    console.print("[bold]╚══════════════════════════════════════════════╝[/]")

    scan_result = scan_device(
        serial=serial, adb_bin=adb_bin, output_dir=output_dir,
        include_system=include_system, max_apps=max_apps,
    )

    # ── Phase 2: Deep-dive top riskiest apps ─────────────────────
    # Prioritize third-party/challenge apps over system apps for deep scan
    _system_prefixes = ("com.android.", "android.", "com.google.", "com.qualcomm.")
    risky = [a for a in scan_result.app_scores if a.score > 0 and a.analyzed]
    third_party_risky = [a for a in risky
                         if not any(a.package_name.startswith(p) for p in _system_prefixes)]
    system_risky = [a for a in risky
                    if any(a.package_name.startswith(p) for p in _system_prefixes)]
    # Third-party first, then system (each sorted by score)
    prioritized = third_party_risky + system_risky
    top_apps = prioritized[:deep_scan_top]

    if top_apps:
        console.print(f"\n[bold]╔══════════════════════════════════════════════╗[/]")
        console.print(f"[bold]║   PHASE 2: DEEP ANALYSIS (top {len(top_apps)} apps)        ║[/]")
        console.print(f"[bold]╚══════════════════════════════════════════════╝[/]")

        from .app_agent import run_app_agent, AppAgentConfig

        for i, app in enumerate(top_apps, 1):
            console.print(f"\n[bold cyan]── Deep scan {i}/{len(top_apps)}: {app.package_name} "
                          f"(risk score: {app.score:.0f}) ──[/]")

            if not app.apk_path or not Path(app.apk_path).exists():
                console.print(f"  [yellow]Skipping: APK not available[/]")
                continue

            app_out = out / "deep_analysis" / app.package_name
            try:
                config = AppAgentConfig(
                    apk_path=app.apk_path,
                    output_dir=str(app_out),
                    adb_serial=serial,
                    adb_binary=adb_bin,
                    fuzz=fuzz,
                    fuzz_max_per_component=5,  # Keep low for large apps like Settings
                    capture_traffic=traffic,
                    traffic_duration=10,
                    verify_exploits=True,
                    kernel_cve=kernel_cve,
                    kernel_exploit_path=kernel_exploit_path,
                    llm_cfg=llm_cfg,
                )
                run_app_agent(config)
            except Exception as exc:
                console.print(f"  [yellow]Deep scan failed: {exc}[/]")

    # ── Phase 3: Summary ─────────────────────────────────────────
    console.print(f"\n[bold]╔══════════════════════════════════════════════╗[/]")
    console.print(f"[bold]║   AUDIT COMPLETE                             ║[/]")
    console.print(f"[bold]╚══════════════════════════════════════════════╝[/]")

    console.print(f"\n  Apps scanned: {scan_result.apps_analyzed}")
    console.print(f"  Apps with vulns: {scan_result.apps_with_vulns}")
    console.print(f"  CRITICAL vulns: [red]{scan_result.total_critical}[/]")
    console.print(f"  HIGH vulns: [red]{scan_result.total_high}[/]")
    console.print(f"  Deep-scanned: {len(top_apps)} apps")
    console.print(f"\n📄 Full report: {out / 'device_security_report.json'}")

    return scan_result
