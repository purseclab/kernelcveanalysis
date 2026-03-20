"""
reproducer.verifier — Run a compiled reproducer on the target and verify crash.
"""

from __future__ import annotations

import re
import subprocess
from typing import Optional, Tuple

from ..core.config import Config
from ..core.log import console
from ..core.models import Arch, ReproducerResult


def verify_reproducer(
    binary_path: str,
    *,
    ssh_host: str,
    ssh_port: int = 22,
    ssh_user: str = "root",
    ssh_key: Optional[str] = None,
    timeout: int = 60,
) -> Tuple[bool, str]:
    """
    Push the reproducer binary to the target machine via SSH/SCP,
    run it, and check dmesg for a crash.

    Returns ``(crashed, dmesg_output)``.

    A timeout is reported as a *possible* hang — NOT automatically
    claimed as a crash.  The caller should inspect the dmesg output
    (if available) to distinguish a real crash from a hang / slow run.
    """
    try:
        # Upload
        scp = ["scp", "-o", "StrictHostKeyChecking=no", "-P", str(ssh_port)]
        if ssh_key:
            scp += ["-i", ssh_key]
        scp += [binary_path, f"{ssh_user}@{ssh_host}:/tmp/syzploit_repro"]
        subprocess.run(scp, capture_output=True, timeout=30, check=True)

        # Run
        timed_out = False
        ssh = ["ssh", "-o", "StrictHostKeyChecking=no", "-p", str(ssh_port)]
        if ssh_key:
            ssh += ["-i", ssh_key]
        ssh += [f"{ssh_user}@{ssh_host}", "chmod +x /tmp/syzploit_repro && /tmp/syzploit_repro"]
        try:
            subprocess.run(ssh, capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True

        # Check dmesg — even after timeout the device may still be alive
        dmesg_cmd = ["ssh", "-o", "StrictHostKeyChecking=no", "-p", str(ssh_port)]
        if ssh_key:
            dmesg_cmd += ["-i", ssh_key]
        dmesg_cmd += [f"{ssh_user}@{ssh_host}", "dmesg | tail -80"]
        try:
            dmesg_out = subprocess.run(dmesg_cmd, capture_output=True, text=True, timeout=15)
            dmesg = dmesg_out.stdout
            crashed = bool(re.search(
                r"KASAN|BUG:|Oops|kernel panic|unable to handle kernel|Internal error",
                dmesg, re.IGNORECASE,
            ))
            if timed_out and not crashed:
                return False, (
                    f"Reproducer timed out after {timeout}s but no crash "
                    f"pattern found in dmesg. This may indicate a hang "
                    f"(not a crash). Last dmesg:\n{dmesg[-1000:]}"
                )
            return crashed, dmesg[-1000:]
        except (subprocess.TimeoutExpired, Exception):
            # Device unreachable after timeout — likely a real crash
            if timed_out:
                return True, (
                    "Reproducer timed out AND device became unreachable "
                    "(likely kernel panic/crash)"
                )
            return False, "Could not read dmesg after reproducer run"

    except subprocess.TimeoutExpired:
        return False, (
            f"Reproducer timed out after {timeout}s — device may be "
            "hung but this is NOT confirmed as a crash. Check dmesg "
            "manually to verify."
        )
    except Exception as exc:
        return False, f"Verification error: {exc}"
