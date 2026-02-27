"""
infra.vm — Virtual machine lifecycle management.

Supports QEMU (direct) and Cuttlefish (Android emulator) backends.
Handles startup, GDB stub attachment, SSH port forwarding, and teardown.
"""

from __future__ import annotations

import os
import signal
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from ..core.log import console
from .ssh import SSHSession


@dataclass
class VMConfig:
    """Configuration for a virtual machine instance."""

    # VM type
    backend: str = "qemu"  # "qemu" or "cuttlefish"

    # Kernel / image paths
    kernel_image: str = ""
    disk_image: str = ""
    initramfs: str = ""
    vmlinux: str = ""  # Uncompressed kernel for GDB symbols

    # QEMU settings
    arch: str = "arm64"
    memory: str = "4G"
    smp: int = 2
    qemu_extra_args: list[str] = field(default_factory=list)

    # Network / SSH
    ssh_port: int = 10022
    ssh_user: str = "root"
    ssh_key: Optional[str] = None

    # GDB
    gdb_port: int = 1234
    enable_gdb: bool = False

    # Cuttlefish specific
    cuttlefish_instance: int = 1
    cuttlefish_home: str = ""

    # Timeouts
    boot_timeout: int = 120


class VMController:
    """
    Manage the lifecycle of a QEMU or Cuttlefish VM.

    Usage::

        vm = VMController(VMConfig(kernel_image="bzImage", disk_image="rootfs.img"))
        vm.start()
        ssh = vm.ssh_session()
        ssh.run("uname -r")
        vm.stop()
    """

    def __init__(self, config: VMConfig) -> None:
        self.config = config
        self._process: Optional[subprocess.Popen] = None
        self._started = False

    @property
    def is_running(self) -> bool:
        if self._process is None:
            return False
        return self._process.poll() is None

    def start(self) -> None:
        """Start the VM."""
        if self.config.backend == "cuttlefish":
            self._start_cuttlefish()
        else:
            self._start_qemu()
        self._started = True

    def stop(self) -> None:
        """Stop the VM."""
        if self._process and self._process.poll() is None:
            self._process.terminate()
            try:
                self._process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self._process.kill()
        self._started = False
        console.print("[dim]VM stopped[/]")

    def ssh_session(self) -> SSHSession:
        """Return an SSH session connected to this VM."""
        return SSHSession(
            host="localhost",
            port=self.config.ssh_port,
            user=self.config.ssh_user,
            key=self.config.ssh_key,
        )

    def wait_for_boot(self) -> bool:
        """Wait until the VM is reachable via SSH."""
        deadline = time.time() + self.config.boot_timeout
        ssh = self.ssh_session()
        while time.time() < deadline:
            if ssh.is_alive():
                console.print("[green]VM is ready[/]")
                return True
            time.sleep(2)
        console.print("[red]VM boot timed out[/]")
        return False

    # ── QEMU backend ──────────────────────────────────────────────────

    def _start_qemu(self) -> None:
        cfg = self.config
        qemu_bin = f"qemu-system-{'aarch64' if cfg.arch == 'arm64' else 'x86_64'}"

        cmd = [
            qemu_bin,
            "-m", cfg.memory,
            "-smp", str(cfg.smp),
            "-nographic",
            "-no-reboot",
        ]

        if cfg.arch == "arm64":
            cmd += ["-machine", "virt", "-cpu", "cortex-a57"]
        else:
            cmd += ["-enable-kvm"]

        if cfg.kernel_image:
            cmd += ["-kernel", cfg.kernel_image]
        if cfg.disk_image:
            cmd += ["-drive", f"file={cfg.disk_image},format=raw"]
        if cfg.initramfs:
            cmd += ["-initrd", cfg.initramfs]

        # SSH port forwarding
        cmd += [
            "-net", "nic",
            "-net", f"user,hostfwd=tcp::{cfg.ssh_port}-:22",
        ]

        # GDB stub
        if cfg.enable_gdb:
            cmd += ["-gdb", f"tcp::{cfg.gdb_port}", "-S"]

        cmd += cfg.qemu_extra_args

        console.print(f"[bold]Starting QEMU ({cfg.arch})…[/]")
        self._process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    # ── Cuttlefish backend ────────────────────────────────────────────

    def _start_cuttlefish(self) -> None:
        cfg = self.config
        home = cfg.cuttlefish_home or os.path.expanduser("~/cuttlefish")

        cmd = [
            f"{home}/bin/launch_cvd",
            f"--num_instances={cfg.cuttlefish_instance}",
        ]

        if cfg.kernel_image:
            cmd += [f"--kernel_path={cfg.kernel_image}"]
        if cfg.initramfs:
            cmd += [f"--initramfs_path={cfg.initramfs}"]

        if cfg.enable_gdb:
            cmd += [f"--extra_kernel_cmdline=nokaslr"]

        console.print(f"[bold]Starting Cuttlefish (instance {cfg.cuttlefish_instance})…[/]")
        self._process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
