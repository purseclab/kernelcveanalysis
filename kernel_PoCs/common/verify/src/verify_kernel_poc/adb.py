from __future__ import annotations

import shlex
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

from .models import VerifyError


class AdbError(VerifyError):
    pass


@dataclass(slots=True)
class ShellResult:
    output: str
    returncode: int
    timed_out: bool = False


class Adb:
    """Small ADB wrapper with the exact control the verifier needs."""

    def __init__(self, serial: str):
        self.serial = serial

    def adb_args(self, *args: str) -> list[str]:
        return ["adb", "-s", self.serial, *args]

    def _run(
        self,
        args: list[str],
        *,
        timeout: float | None = None,
        check: bool = True,
    ) -> subprocess.CompletedProcess[str]:
        try:
            result = subprocess.run(
                self.adb_args(*args),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=timeout,
            )
        except FileNotFoundError as exc:
            raise AdbError("adb was not found on PATH") from exc
        except subprocess.TimeoutExpired as exc:
            raise AdbError(f"adb command timed out: {' '.join(args)}") from exc
        if check and result.returncode != 0:
            raise AdbError(
                f"adb command failed ({result.returncode}): {' '.join(args)}\n"
                f"{result.stdout or ''}"
            )
        return result

    def shell(
        self,
        command: str,
        *,
        timeout: float = 60.0,
        check: bool = True,
    ) -> subprocess.CompletedProcess[str]:
        return self._run(
            ["shell", command],
            timeout=timeout,
            check=check,
        )

    def shell_text(self, command: str, *, timeout: float = 60.0) -> str:
        return self.shell(command, timeout=timeout).stdout.strip()

    def run_shell_process(
        self,
        command: str,
        *,
        timeout: float,
        stdin_text: str | None = None,
    ) -> ShellResult:
        try:
            process = subprocess.Popen(
                self.adb_args("shell", command),
                stdin=subprocess.PIPE if stdin_text is not None else subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
        except FileNotFoundError as exc:
            raise AdbError("adb was not found on PATH") from exc
        timed_out = False
        try:
            output, _ = process.communicate(input=stdin_text, timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            process.kill()
            output, _ = process.communicate()
        return ShellResult(
            output=output or "",
            returncode=process.returncode if process.returncode is not None else -1,
            timed_out=timed_out,
        )

    def popen_shell(self, command: str, *, output_file: BinaryIO) -> subprocess.Popen[str]:
        try:
            return subprocess.Popen(
                self.adb_args("shell", command),
                stdin=subprocess.DEVNULL,
                stdout=output_file,
                stderr=subprocess.STDOUT,
                text=True,
            )
        except FileNotFoundError as exc:
            raise AdbError("adb was not found on PATH") from exc

    def connect(self, *, timeout: float = 30.0) -> None:
        result = subprocess.run(
            ["adb", "connect", self.serial],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if result.returncode != 0:
            raise AdbError(
                f"adb connect {self.serial} failed: {result.stdout}{result.stderr}"
            )

    def wait_for_device(self, *, timeout: float = 180.0) -> None:
        self._run(["wait-for-device"], timeout=timeout)

    def wait_for_boot_completed(
        self,
        *,
        timeout: float = 300.0,
        poll_interval: float = 1.0,
    ) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            result = self.shell(
                "getprop sys.boot_completed",
                timeout=10.0,
                check=False,
            )
            if result.stdout.strip() == "1":
                return
            time.sleep(poll_interval)
        raise AdbError(
            f"timed out after {timeout:.0f}s waiting for {self.serial} to boot"
        )

    def push(self, local_path: Path, remote_path: str) -> None:
        self._run(["push", str(local_path), remote_path], timeout=120.0)

    def install(self, apk_path: Path) -> None:
        self._run(["install", "-r", str(apk_path)], timeout=180.0)

    def uninstall(self, package: str) -> bool:
        result = self._run(
            ["uninstall", package],
            timeout=120.0,
            check=False,
        )
        return result.returncode == 0

    def package_path(self, package: str) -> str:
        output = self.shell_text(f"pm path {shlex.quote(package)}")
        for line in output.splitlines():
            if line.startswith("package:"):
                return line.removeprefix("package:").strip()
        raise AdbError(f"could not find installed package {package}")

    def sha256sum(self, remote_path: str) -> str:
        output = self.shell_text(f"sha256sum {shlex.quote(remote_path)}")
        if not output:
            raise AdbError(f"sha256sum returned no output for {remote_path}")
        return output.split(maxsplit=1)[0]

    def root(self, *, timeout: float = 60.0) -> None:
        self._run(["root"], timeout=timeout, check=False)
        time.sleep(1.0)
        self.wait_for_device(timeout=timeout)
        time.sleep(1.0)

    def unroot(self, *, timeout: float = 60.0) -> None:
        self._run(["unroot"], timeout=timeout, check=False)
        time.sleep(1.0)
        self.wait_for_device(timeout=timeout)
        time.sleep(1.0)

    def forward(self, local_port: int, remote_port: int) -> None:
        self._run(
            ["forward", f"tcp:{local_port}", f"tcp:{remote_port}"],
            timeout=30.0,
        )

    def remove_forward(self, local_port: int) -> None:
        self._run(
            ["forward", "--remove", f"tcp:{local_port}"],
            timeout=30.0,
            check=False,
        )

    def reverse(self, remote_port: int, local_port: int) -> None:
        self._run(
            ["reverse", f"tcp:{remote_port}", f"tcp:{local_port}"],
            timeout=30.0,
        )

    def remove_reverse(self, remote_port: int) -> None:
        self._run(
            ["reverse", "--remove", f"tcp:{remote_port}"],
            timeout=30.0,
            check=False,
        )
