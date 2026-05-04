from __future__ import annotations

import logging
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path

from .models import InstanceRecord

LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class LaunchResult:
    launch_command: list[str]
    adb_port: int
    adb_serial: str | None
    webrtc_port: int | None


@dataclass(frozen=True, slots=True)
class CuttlefishLogPaths:
    start_log: Path
    stop_log: Path


class CuttlefishCli:
    """Handles spawning Cuttlefish instances."""

    def __init__(self, *, start_timeout_sec: int = 120) -> None:
        self.start_timeout_sec = start_timeout_sec

    def start_instance(self, record: InstanceRecord) -> LaunchResult:
        runtime_dir = record.runtime_dir
        runtime_dir.mkdir(parents=True, exist_ok=True)

        command = self.build_start_command(record)
        self._run_command(
            command,
            record=record,
            action="start",
            timeout_sec=self.start_timeout_sec,
        )
        adb_port = self._resolve_adb_port(record)
        return LaunchResult(
            launch_command=command,
            adb_port=adb_port,
            adb_serial=None,
            webrtc_port=None,
        )

    def stop_instance(self, record: InstanceRecord) -> None:
        stop_command = [str(record.config.cvd_binary), "stop"]
        self._run_command(stop_command, record=record, action="stop", timeout_sec=None)

    def build_start_command(self, record: InstanceRecord) -> list[str]:
        config = record.config
        command = [
            str(config.cvd_binary),
            "start",
            f"--base_instance_num={record.instance_num}",
            f"--cpus={config.cpus}",
            "--start_webrtc=true",
        ]
        if config.kernel_path is not None:
            command.append(f"--kernel_path={config.kernel_path}")
        if config.initrd_path is not None:
            command.append(f"--initramfs_path={config.initrd_path}")
        command.extend(
            [
                "--daemon",
                "--report_anonymous_usage_stats=n",
            ]
        )
        if not config.selinux:
            command.append("--extra_kernel_cmdline=androidboot.selinux=permissive")
        return command

    def _build_start_command(self, record: InstanceRecord) -> list[str]:
        return self.build_start_command(record)

    @staticmethod
    def log_paths(record: InstanceRecord) -> CuttlefishLogPaths:
        return CuttlefishLogPaths(
            start_log=record.runtime_dir / "cvd-start.log",
            stop_log=record.runtime_dir / "cvd-stop.log",
        )

    @staticmethod
    def _resolve_adb_port(record: InstanceRecord) -> int:
        return 6520 + record.instance_num - 1

    @staticmethod
    def _build_env(record: InstanceRecord) -> dict[str, str]:
        env = os.environ.copy()
        env["HOME"] = str(record.runtime_dir)
        env["ANDROID_HOST_OUT"] = str(record.config.runtime_root)
        env["ANDROID_PRODUCT_OUT"] = str(record.config.runtime_root)
        return env

    def _run_command(
        self,
        command: list[str],
        *,
        record: InstanceRecord,
        action: str,
        timeout_sec: int | None,
    ) -> None:
        log_path = self._log_path_for_action(record, action)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            with log_path.open("a", encoding="utf-8") as log_handle:
                subprocess.run(
                    command,
                    cwd=record.runtime_dir,
                    env=self._build_env(record),
                    check=True,
                    stdout=log_handle,
                    stderr=subprocess.STDOUT,
                    text=True,
                    timeout=timeout_sec,
                )
        except subprocess.CalledProcessError as exc:
            log_tail = self.read_log_tail(log_path)
            LOGGER.exception(
                "cuttlefish %s command failed: command=%s log_path=%s log_tail=%r",
                action,
                command,
                log_path,
                log_tail,
            )
            raise RuntimeError(
                f"cuttlefish {action} command failed with exit code "
                f"{exc.returncode}; log: {log_path}; tail:\n{log_tail}"
            ) from exc
        except subprocess.TimeoutExpired as exc:
            log_tail = self.read_log_tail(log_path)
            LOGGER.exception(
                "cuttlefish %s command timed out: command=%s timeout=%s "
                "log_path=%s log_tail=%r",
                action,
                command,
                timeout_sec,
                log_path,
                log_tail,
            )
            raise RuntimeError(
                f"cuttlefish {action} command timed out after {timeout_sec}s; "
                f"log: {log_path}; tail:\n{log_tail}"
            ) from exc

    def _log_path_for_action(self, record: InstanceRecord, action: str) -> Path:
        paths = self.log_paths(record)
        if action == "start":
            return paths.start_log
        if action == "stop":
            return paths.stop_log
        return record.runtime_dir / f"cvd-{action}.log"

    @staticmethod
    def read_log_tail(path: Path, *, max_chars: int = 4096) -> str:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except FileNotFoundError:
            return ""
        if len(text) <= max_chars:
            return text
        return text[-max_chars:]
