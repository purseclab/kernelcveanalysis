"""
analysis.benchmark — Exploit reliability benchmarking.

Runs an exploit binary N times on the target and collects statistics:
  - Success rate (privilege escalation)
  - Timing distribution (mean, p50, p95, p99)
  - Crash rate and KASAN hit rate
  - Failure mode classification
"""

from __future__ import annotations

import statistics
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from ..core.log import console


@dataclass
class BenchmarkResult:
    """Aggregate statistics from N exploit runs."""

    runs: int = 0
    successes: int = 0
    crashes: int = 0
    kasan_hits: int = 0
    timeouts: int = 0
    device_instabilities: int = 0

    # Timing (seconds)
    timing_all: List[float] = field(default_factory=list)
    timing_success: List[float] = field(default_factory=list)

    # Per-run details
    run_details: List[Dict[str, Any]] = field(default_factory=list)

    # Failure mode classification
    failure_modes: Dict[str, int] = field(default_factory=dict)

    @property
    def success_rate(self) -> float:
        return self.successes / self.runs if self.runs else 0.0

    @property
    def crash_rate(self) -> float:
        return self.crashes / self.runs if self.runs else 0.0

    @property
    def kasan_rate(self) -> float:
        return self.kasan_hits / self.runs if self.runs else 0.0

    @property
    def timeout_rate(self) -> float:
        return self.timeouts / self.runs if self.runs else 0.0

    def _percentile(self, data: List[float], p: float) -> float:
        if not data:
            return 0.0
        sorted_data = sorted(data)
        k = (len(sorted_data) - 1) * (p / 100.0)
        f = int(k)
        c = f + 1
        if c >= len(sorted_data):
            return sorted_data[-1]
        return sorted_data[f] + (k - f) * (sorted_data[c] - sorted_data[f])

    @property
    def mean_time(self) -> float:
        return statistics.mean(self.timing_all) if self.timing_all else 0.0

    @property
    def p50_time(self) -> float:
        return self._percentile(self.timing_all, 50)

    @property
    def p95_time(self) -> float:
        return self._percentile(self.timing_all, 95)

    @property
    def p99_time(self) -> float:
        return self._percentile(self.timing_all, 99)

    @property
    def mean_success_time(self) -> float:
        return statistics.mean(self.timing_success) if self.timing_success else 0.0

    def summary(self) -> str:
        lines = [
            f"=== Exploit Benchmark: {self.runs} runs ===",
            f"  Success rate    : {self.success_rate:.1%} ({self.successes}/{self.runs})",
            f"  Crash rate      : {self.crash_rate:.1%} ({self.crashes}/{self.runs})",
            f"  KASAN hit rate  : {self.kasan_rate:.1%} ({self.kasan_hits}/{self.runs})",
            f"  Timeout rate    : {self.timeout_rate:.1%} ({self.timeouts}/{self.runs})",
            f"  Device unstable : {self.device_instabilities}",
            "",
            f"  Timing (all runs):",
            f"    Mean : {self.mean_time:.2f}s",
            f"    p50  : {self.p50_time:.2f}s",
            f"    p95  : {self.p95_time:.2f}s",
            f"    p99  : {self.p99_time:.2f}s",
        ]
        if self.timing_success:
            lines.extend([
                f"  Timing (successful runs only):",
                f"    Mean : {self.mean_success_time:.2f}s",
            ])
        if self.failure_modes:
            lines.append(f"  Failure modes:")
            for mode, count in sorted(
                self.failure_modes.items(), key=lambda x: -x[1]
            ):
                lines.append(f"    {mode}: {count}")
        return "\n".join(lines)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "runs": self.runs,
            "successes": self.successes,
            "crashes": self.crashes,
            "kasan_hits": self.kasan_hits,
            "timeouts": self.timeouts,
            "device_instabilities": self.device_instabilities,
            "success_rate": self.success_rate,
            "crash_rate": self.crash_rate,
            "kasan_rate": self.kasan_rate,
            "timing": {
                "mean": self.mean_time,
                "p50": self.p50_time,
                "p95": self.p95_time,
                "p99": self.p99_time,
                "mean_success": self.mean_success_time,
            },
            "failure_modes": self.failure_modes,
            "run_details": self.run_details,
        }


def _classify_failure(result: Dict[str, Any]) -> str:
    """Classify the failure mode of a single verification run."""
    if result.get("privilege_escalated"):
        return "success"
    if not result.get("device_stable", True):
        return "device_instability"
    if result.get("crash_occurred"):
        crash_pat = result.get("crash_pattern", "")
        if "KASAN" in crash_pat or "kasan" in crash_pat.lower():
            return "kasan_crash"
        if "BUG:" in crash_pat or "Oops:" in crash_pat:
            return "kernel_oops"
        return "crash_unknown"
    output = result.get("exploit_output", "")
    if not output or "Killed" in output:
        return "timeout_or_killed"
    feedback = result.get("failure_reason", "")
    if "uid" in feedback.lower():
        return "no_privilege_escalation"
    if "binary" in feedback.lower() or "compile" in feedback.lower():
        return "binary_error"
    return "unknown"


def benchmark_exploit(
    binary_path: str,
    *,
    runs: int = 10,
    ssh_host: str = "",
    ssh_port: int = 22,
    instance: Optional[int] = None,
    start_cmd: Optional[str] = None,
    stop_cmd: Optional[str] = None,
    exploit_start_cmd: Optional[str] = None,
    gdb_port: int = 1234,
    setup_tunnels: bool = False,
    persistent: bool = True,
    timeout: int = 120,
    cooldown: int = 5,
    reboot_on_crash: bool = True,
    arch: str = "arm64",
) -> BenchmarkResult:
    """Run an exploit N times and collect reliability statistics.

    Parameters
    ----------
    binary_path
        Path to the compiled exploit binary.
    runs
        Number of times to run the exploit.
    cooldown
        Seconds to wait between runs.
    reboot_on_crash
        If True, restart the VM after a crash before continuing.
    """
    from ..infra.verification import verify_exploit

    result = BenchmarkResult()
    result.runs = runs

    console.print(f"[bold]Benchmarking exploit: {runs} runs[/]")
    console.print(f"  Binary: {binary_path}")
    console.print(f"  Cooldown: {cooldown}s between runs")

    for i in range(runs):
        console.print(f"\n  [dim]── Run {i + 1}/{runs} ──[/]")

        start_time = time.time()
        try:
            vr = verify_exploit(
                binary_path,
                ssh_host=ssh_host,
                ssh_port=ssh_port,
                instance=instance,
                start_cmd=start_cmd,
                stop_cmd=stop_cmd,
                exploit_start_cmd=exploit_start_cmd,
                gdb_port=gdb_port,
                setup_tunnels=setup_tunnels,
                persistent=True,  # Always persistent in benchmark mode
                timeout=timeout,
                arch=arch,
            )
        except Exception as e:
            elapsed = time.time() - start_time
            vr = {
                "success": False,
                "privilege_escalated": False,
                "crash_occurred": False,
                "device_stable": False,
                "failure_reason": f"Exception: {e}",
                "exploit_output": "",
                "dmesg_new": "",
                "crash_pattern": "",
            }
            result.device_instabilities += 1

        elapsed = time.time() - start_time
        result.timing_all.append(elapsed)

        # Classify result
        mode = _classify_failure(vr)

        if vr.get("privilege_escalated"):
            result.successes += 1
            result.timing_success.append(elapsed)
            console.print(f"    [green]SUCCESS[/] ({elapsed:.1f}s)")
        else:
            console.print(
                f"    [red]FAIL[/] — {mode} ({elapsed:.1f}s)"
            )

        if vr.get("crash_occurred"):
            result.crashes += 1
            dmesg = vr.get("dmesg_new", "") + vr.get("crash_pattern", "")
            if "KASAN" in dmesg or "kasan" in dmesg.lower():
                result.kasan_hits += 1

        if not vr.get("device_stable", True):
            result.device_instabilities += 1

        if mode == "timeout_or_killed":
            result.timeouts += 1

        result.failure_modes[mode] = result.failure_modes.get(mode, 0) + 1

        run_detail = {
            "run": i + 1,
            "success": bool(vr.get("privilege_escalated")),
            "crash": bool(vr.get("crash_occurred")),
            "elapsed": round(elapsed, 2),
            "mode": mode,
            "uid_before": vr.get("uid_before"),
            "uid_after": vr.get("uid_after"),
        }
        result.run_details.append(run_detail)

        # Cooldown or reboot between runs
        if i < runs - 1:
            if vr.get("crash_occurred") and reboot_on_crash and stop_cmd:
                console.print("    [dim]Rebooting after crash…[/]")
                # Next iteration of verify_exploit with persistent=True
                # will detect the device is down and wait for reboot
                time.sleep(cooldown * 2)
            else:
                time.sleep(cooldown)

    console.print(f"\n{result.summary()}")
    return result
