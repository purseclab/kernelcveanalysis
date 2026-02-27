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
    """
    try:
        # Upload
        scp = ["scp", "-o", "StrictHostKeyChecking=no", "-P", str(ssh_port)]
        if ssh_key:
            scp += ["-i", ssh_key]
        scp += [binary_path, f"{ssh_user}@{ssh_host}:/tmp/syzploit_repro"]
        subprocess.run(scp, capture_output=True, timeout=30, check=True)

        # Run
        ssh = ["ssh", "-o", "StrictHostKeyChecking=no", "-p", str(ssh_port)]
        if ssh_key:
            ssh += ["-i", ssh_key]
        ssh += [f"{ssh_user}@{ssh_host}", "chmod +x /tmp/syzploit_repro && /tmp/syzploit_repro"]
        subprocess.run(ssh, capture_output=True, text=True, timeout=timeout)

        # Check dmesg
        dmesg_cmd = ["ssh", "-o", "StrictHostKeyChecking=no", "-p", str(ssh_port)]
        if ssh_key:
            dmesg_cmd += ["-i", ssh_key]
        dmesg_cmd += [f"{ssh_user}@{ssh_host}", "dmesg | tail -80"]
        dmesg_out = subprocess.run(dmesg_cmd, capture_output=True, text=True, timeout=15)
        dmesg = dmesg_out.stdout

        crashed = bool(re.search(r"KASAN|BUG:|Oops|kernel panic", dmesg, re.IGNORECASE))
        return crashed, dmesg[-1000:]

    except subprocess.TimeoutExpired:
        return True, "Reproducer timed out (likely crash/hang)"
    except Exception as exc:
        return False, f"Verification error: {exc}"
