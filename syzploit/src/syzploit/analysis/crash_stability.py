"""
analysis.crash_stability — Measure crash/reproducer trigger reliability.

Runs a reproducer binary M times and measures how reliably it triggers
the vulnerability, helping the agent decide whether the trigger needs
a tight race loop or is deterministic.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from ..core.log import console


@dataclass
class StabilityResult:
    """Crash trigger stability measurement."""

    runs: int = 0
    crashes: int = 0
    crash_signature_matches: int = 0
    different_crashes: int = 0
    no_crashes: int = 0
    timeouts: int = 0
    device_instabilities: int = 0

    timing_to_crash: List[float] = field(default_factory=list)
    run_details: List[Dict[str, Any]] = field(default_factory=list)

    expected_signature: str = ""

    @property
    def crash_rate(self) -> float:
        return self.crashes / self.runs if self.runs else 0.0

    @property
    def signature_match_rate(self) -> float:
        return self.crash_signature_matches / self.runs if self.runs else 0.0

    @property
    def mean_crash_time(self) -> float:
        if not self.timing_to_crash:
            return 0.0
        return sum(self.timing_to_crash) / len(self.timing_to_crash)

    @property
    def is_deterministic(self) -> bool:
        """Returns True if crash triggers reliably (>90% rate)."""
        return self.crash_rate >= 0.9

    @property
    def is_race(self) -> bool:
        """Returns True if crash rate suggests a race condition (<70%)."""
        return 0.0 < self.crash_rate < 0.7

    @property
    def stability_verdict(self) -> str:
        if self.crash_rate >= 0.9:
            return "deterministic"
        elif self.crash_rate >= 0.7:
            return "mostly_reliable"
        elif self.crash_rate >= 0.3:
            return "race_dependent"
        elif self.crash_rate > 0:
            return "rare_trigger"
        else:
            return "no_crash"

    def summary(self) -> str:
        lines = [
            f"=== Crash Stability Analysis: {self.runs} runs ===",
            f"  Verdict         : {self.stability_verdict}",
            f"  Crash rate      : {self.crash_rate:.1%} ({self.crashes}/{self.runs})",
            f"  Signature match : {self.signature_match_rate:.1%} ({self.crash_signature_matches}/{self.runs})",
            f"  Different crash : {self.different_crashes}",
            f"  No crash        : {self.no_crashes}",
            f"  Timeouts        : {self.timeouts}",
        ]
        if self.timing_to_crash:
            import statistics
            lines.extend([
                f"  Crash timing:",
                f"    Mean   : {self.mean_crash_time:.2f}s",
                f"    StdDev : {statistics.stdev(self.timing_to_crash):.2f}s" if len(self.timing_to_crash) > 1 else "",
                f"    Min    : {min(self.timing_to_crash):.2f}s",
                f"    Max    : {max(self.timing_to_crash):.2f}s",
            ])
        if self.is_race:
            lines.append(
                f"  [!] Low crash rate suggests a RACE CONDITION. "
                f"Consider tight race loop or userfaultfd/FUSE timing."
            )
        return "\n".join(lines)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "runs": self.runs,
            "crashes": self.crashes,
            "crash_rate": self.crash_rate,
            "signature_match_rate": self.signature_match_rate,
            "verdict": self.stability_verdict,
            "is_deterministic": self.is_deterministic,
            "is_race": self.is_race,
            "mean_crash_time": self.mean_crash_time,
            "timing_to_crash": self.timing_to_crash,
            "run_details": self.run_details,
        }


def measure_crash_stability(
    binary_path: str,
    *,
    runs: int = 10,
    expected_functions: Optional[List[str]] = None,
    expected_crash_type: str = "",
    ssh_host: str = "",
    ssh_port: int = 22,
    instance: Optional[int] = None,
    start_cmd: Optional[str] = None,
    stop_cmd: Optional[str] = None,
    setup_tunnels: bool = False,
    persistent: bool = True,
    timeout: int = 60,
    cooldown: int = 5,
    arch: str = "arm64",
) -> StabilityResult:
    """Run a reproducer M times and measure crash trigger reliability.

    Parameters
    ----------
    binary_path
        Path to the compiled reproducer binary.
    runs
        Number of times to run the reproducer.
    expected_functions
        Functions expected in crash stack (for signature matching).
    expected_crash_type
        Expected crash type string (e.g. "KASAN: slab-use-after-free").
    cooldown
        Seconds to wait between runs.
    """
    from ..infra.verification import verify_reproducer

    result = StabilityResult(runs=runs, expected_signature=expected_crash_type)

    console.print(f"[bold]Crash stability analysis: {runs} runs[/]")
    console.print(f"  Binary: {binary_path}")
    if expected_crash_type:
        console.print(f"  Expected: {expected_crash_type}")

    for i in range(runs):
        console.print(f"  [dim]── Run {i + 1}/{runs} ──[/]")
        start_time = time.time()

        try:
            vr = verify_reproducer(
                binary_path,
                ssh_host=ssh_host,
                ssh_port=ssh_port,
                instance=instance,
                start_cmd=start_cmd,
                stop_cmd=stop_cmd,
                setup_tunnels=setup_tunnels,
                persistent=True,
                timeout=timeout,
                arch=arch,
            )
        except Exception as e:
            elapsed = time.time() - start_time
            vr = {
                "success": False,
                "crash_occurred": False,
                "device_stable": False,
                "crash_pattern": "",
                "dmesg_new": "",
                "failure_reason": str(e),
            }
            result.device_instabilities += 1

        elapsed = time.time() - start_time

        detail: Dict[str, Any] = {
            "run": i + 1,
            "elapsed": round(elapsed, 2),
            "crash": bool(vr.get("crash_occurred")),
        }

        if vr.get("crash_occurred"):
            result.crashes += 1
            result.timing_to_crash.append(elapsed)

            # Check if crash signature matches
            crash_pat = vr.get("crash_pattern", "") + vr.get("dmesg_new", "")
            signature_match = False
            if expected_crash_type and expected_crash_type.lower() in crash_pat.lower():
                signature_match = True
            elif expected_functions:
                matched = sum(
                    1 for f in expected_functions if f in crash_pat
                )
                if matched >= len(expected_functions) * 0.5:
                    signature_match = True
            elif not expected_crash_type and not expected_functions:
                # No expected signature — any crash counts as match
                signature_match = True

            if signature_match:
                result.crash_signature_matches += 1
                detail["signature_match"] = True
                console.print(f"    [green]CRASH (signature match)[/] ({elapsed:.1f}s)")
            else:
                result.different_crashes += 1
                detail["signature_match"] = False
                console.print(f"    [yellow]CRASH (different signature)[/] ({elapsed:.1f}s)")
        else:
            result.no_crashes += 1
            if not vr.get("device_stable", True):
                result.device_instabilities += 1
                console.print(f"    [red]DEVICE UNSTABLE[/] ({elapsed:.1f}s)")
            else:
                console.print(f"    [dim]no crash[/] ({elapsed:.1f}s)")

        result.run_details.append(detail)

        # Cooldown between runs
        if i < runs - 1:
            if vr.get("crash_occurred") or not vr.get("device_stable", True):
                time.sleep(cooldown * 2)  # longer cooldown after crash
            else:
                time.sleep(cooldown)

    console.print(f"\n{result.summary()}")
    return result
