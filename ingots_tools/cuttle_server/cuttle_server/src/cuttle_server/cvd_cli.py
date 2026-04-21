from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass
from pathlib import Path

from .models import InstanceRecord


@dataclass(frozen=True, slots=True)
class LaunchResult:
    launch_command: list[str]
    adb_port: int
    adb_serial: str | None
    webrtc_port: int | None


class CuttlefishCli:
    """Handles spawning Cuttlefish instances."""

    def start_instance(self, record: InstanceRecord) -> LaunchResult:
        runtime_dir = record.runtime_dir
        runtime_dir.mkdir(parents=True, exist_ok=True)

        command = self._build_launch_command(record)
        subprocess.run(
            command,
            cwd=runtime_dir,
            env=self._build_env(record),
            check=True,
            capture_output=True,
            text=True,
        )
        adb_port = self._resolve_adb_port(record)
        return LaunchResult(
            launch_command=command,
            adb_port=adb_port,
            adb_serial=None,
            webrtc_port=None,
        )

    def stop_instance(self, record: InstanceRecord) -> None:
        command = [
            str(record.config.stop_binary),
            f"--instance_num={record.instance_num}",
        ]
        subprocess.run(
            command,
            cwd=record.runtime_dir,
            env=self._build_env(record),
            check=True,
            capture_output=True,
            text=True,
        )

    def _build_launch_command(self, record: InstanceRecord) -> list[str]:
        config = record.config
        command = [
            str(config.launch_binary),
            f"--base_instance_num={record.instance_num}",
            f"--cpus={config.cpus}",
            "--start_webrtc=true",
            f"--kernel_path={config.kernel_path}",
            f"--initramfs_path={config.initrd_path}",
            "--daemon",
            "--report_anonymous_usage_stats=n",
        ]
        if not config.selinux:
            command.append("--extra_kernel_cmdline=androidboot.selinux=permissive")
        return command

    @staticmethod
    def _resolve_adb_port(record: InstanceRecord) -> int:
        return 6520 + record.instance_num - 1

    @staticmethod
    def _build_env(record: InstanceRecord) -> dict[str, str]:
        env = os.environ.copy()
        env["HOME"] = str(record.runtime_dir.parent)
        return env
