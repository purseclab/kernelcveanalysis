"""
infra.ssh — SSH session management for remote kernel instances.

Provides a reusable ``SSHSession`` that wraps subprocess SSH/SCP calls,
with optional Paramiko fallback for persistent connections.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Optional, Tuple


class SSHSession:
    """
    Lightweight SSH session wrapper using subprocess.

    For simple command execution and file transfer to a remote kernel
    instance (QEMU guest or Cuttlefish).
    """

    def __init__(
        self,
        host: str,
        port: int = 22,
        user: str = "root",
        key: Optional[str] = None,
        timeout: int = 30,
    ) -> None:
        self.host = host
        self.port = port
        self.user = user
        self.key = key
        self.timeout = timeout

    def _ssh_base(self) -> list[str]:
        cmd = ["ssh", "-o", "StrictHostKeyChecking=no", "-p", str(self.port)]
        if self.key:
            cmd += ["-i", self.key]
        cmd.append(f"{self.user}@{self.host}")
        return cmd

    def _scp_base(self) -> list[str]:
        cmd = ["scp", "-o", "StrictHostKeyChecking=no", "-P", str(self.port)]
        if self.key:
            cmd += ["-i", self.key]
        return cmd

    def run(self, command: str, *, timeout: Optional[int] = None) -> Tuple[int, str, str]:
        """
        Execute a command on the remote machine.

        Returns ``(returncode, stdout, stderr)``.
        """
        cmd = self._ssh_base() + [command]
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout or self.timeout,
            )
            return result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return -1, "", "SSH command timed out"
        except Exception as exc:
            return -1, "", str(exc)

    def upload(self, local_path: str, remote_path: str) -> bool:
        """SCP a file to the remote machine."""
        cmd = self._scp_base() + [
            local_path,
            f"{self.user}@{self.host}:{remote_path}",
        ]
        try:
            result = subprocess.run(cmd, capture_output=True, timeout=self.timeout)
            return result.returncode == 0
        except Exception:
            return False

    def download(self, remote_path: str, local_path: str) -> bool:
        """SCP a file from the remote machine."""
        cmd = self._scp_base() + [
            f"{self.user}@{self.host}:{remote_path}",
            local_path,
        ]
        try:
            result = subprocess.run(cmd, capture_output=True, timeout=self.timeout)
            return result.returncode == 0
        except Exception:
            return False

    def is_alive(self) -> bool:
        """Quick connectivity check."""
        rc, _, _ = self.run("echo ok", timeout=10)
        return rc == 0

    def get_dmesg(self, lines: int = 100) -> str:
        """Fetch last N lines of dmesg."""
        _, out, _ = self.run(f"dmesg | tail -{lines}")
        return out

    def get_kallsyms(self) -> str:
        """Fetch /proc/kallsyms from the remote machine."""
        _, out, _ = self.run("cat /proc/kallsyms", timeout=60)
        return out
