from __future__ import annotations

import posixpath
import secrets
import shlex
import socket
import sys
import time
from dataclasses import dataclass

from .adb import Adb
from .models import AdbIdentity, VerifyError


DEFAULT_FLAG_ROOT = "/data/local/tmp"


@dataclass(frozen=True, slots=True)
class RootFlag:
    directory: str
    path: str
    token: str
    remove_directory: bool = True


def _is_root(adb: Adb) -> bool:
    result = adb.shell("id", timeout=15.0, check=False)
    return result.returncode == 0 and "uid=0(" in result.stdout


def _run_as_root(adb: Adb, command: str, *, timeout: float = 60.0) -> None:
    if _is_root(adb):
        adb.shell(command, timeout=timeout)
        return

    # Prefer adb root: it works on Cuttlefish userdebug images even when no su
    # binary is installed. Fall back to su when adbd cannot be restarted as root.
    try:
        adb.root(timeout=timeout)
        if _is_root(adb):
            try:
                adb.shell(command, timeout=timeout)
                return
            finally:
                try:
                    adb.unroot(timeout=timeout)
                except Exception as exc:
                    print(
                        f"[verify] warning: adb unroot failed: {exc}",
                        file=sys.stderr,
                        flush=True,
                    )
        else:
            print(
                "[verify] adb root unavailable; falling back to su for root-flag setup",
                file=sys.stderr,
                flush=True,
            )
    except Exception as exc:
        print(
            f"[verify] adb root failed ({exc}); falling back to su for root-flag setup",
            file=sys.stderr,
            flush=True,
        )

    quoted_command = shlex.quote(command)
    failures: list[str] = []
    for su_command in (
        f"su 0 sh -c {quoted_command}",
        f"su root sh -c {quoted_command}",
        f"su -c {quoted_command}",
    ):
        result = adb.shell(su_command, timeout=timeout, check=False)
        if result.returncode == 0:
            return
        failures.append(f"{su_command}: {result.stdout.strip()}")

    raise VerifyError(
        "could not provision the root-only flag through adb root or su; the "
        "guest must allow adb root/unroot or provide 'su 0', 'su root', or "
        "'su -c'. Tried:\n" + "\n".join(failures)
    )


def provision_root_flag(
    adb: Adb,
    *,
    path_override: str | None = None,
) -> RootFlag:
    token = secrets.token_hex(16)
    remove_directory = True
    if path_override:
        flag_path = posixpath.normpath(path_override)
        directory = posixpath.dirname(flag_path)
        remove_directory = False
    else:
        directory = f"{DEFAULT_FLAG_ROOT}/kpoc-verify-{token[:12]}"
        flag_path = f"{directory}/flag"

    command = (
        "umask 077; "
        f"mkdir -p {shlex.quote(directory)}; "
        f"printf '%s' {shlex.quote(token)} > {shlex.quote(flag_path)}; "
        f"chown root:root {shlex.quote(flag_path)}; "
        f"chmod 0400 {shlex.quote(flag_path)}; "
        f"chmod 0700 {shlex.quote(directory)}"
    )
    _run_as_root(adb, command)

    # The PoC must run as a non-root user. If the flag is still readable here,
    # the guest is not running adbd as shell and root verification is meaningless.
    result = adb.shell(f"cat {shlex.quote(flag_path)}", timeout=15.0, check=False)
    if result.returncode == 0 and token in result.stdout:
        raise VerifyError(
            "guest shell can already read the root-only flag; refusing to run "
            "with meaningless root verification. Use an ADB target that runs "
            "as the non-root shell user."
        )

    return RootFlag(
        directory=directory,
        path=flag_path,
        token=token,
        remove_directory=remove_directory,
    )


def cleanup_root_flag(adb: Adb, flag: RootFlag) -> None:
    remove_target = flag.directory if flag.remove_directory else flag.path
    remove_flag = "-rf" if flag.remove_directory else "-f"
    try:
        _run_as_root(
            adb,
            f"rm {remove_flag} {shlex.quote(remove_target)}",
            timeout=30.0,
        )
    except Exception:
        # Cleanup is best-effort. A disposable guest is stopped afterwards.
        pass


def build_root_check_lines(
    flag: RootFlag | None,
    *,
    command: str | None,
    regex: str | None,
) -> list[str]:
    if command:
        rendered = command
        if flag is not None:
            rendered = rendered.replace("{flag}", shlex.quote(flag.path))
        return [rendered, "exit"]
    if regex is not None and flag is None:
        return ["id", "getenforce", "exit"]
    lines = ["id"]
    if flag is not None:
        lines.append(f"cat {shlex.quote(flag.path)}")
    lines.extend(["getenforce", "exit"])
    return lines


def pipeline_command(run_command: str, lines: list[str]) -> str:
    if not lines:
        return run_command
    printf_args = " ".join(shlex.quote(line) for line in lines)
    return f"printf '%s\\n' {printf_args} | {run_command}"


def collect_identity(adb: Adb) -> AdbIdentity:
    id_result = adb.shell("id", timeout=30.0, check=False)
    kernel_result = adb.shell("uname -r", timeout=30.0, check=False)
    selinux_result = adb.shell("getenforce", timeout=30.0, check=False)
    selinux = selinux_result.stdout.strip()
    if not selinux:
        selinux = "unknown"
    return AdbIdentity(
        uid_id=id_result.stdout.strip(),
        kernel=kernel_result.stdout.strip(),
        selinux=selinux,
    )


def token_matched(output: str, token: str | None) -> bool:
    return bool(token) and token in output


def root_uid_seen(output: str) -> bool:
    return "uid=0(" in output


def read_until_closed(
    connection: socket.socket,
    *,
    timeout: float,
) -> str:
    connection.settimeout(timeout)
    chunks: list[bytes] = []
    deadline = time.monotonic() + timeout
    while True:
        if time.monotonic() >= deadline:
            break
        try:
            data = connection.recv(65536)
        except TimeoutError:
            break
        except OSError:
            break
        if not data:
            break
        chunks.append(data)
    return b"".join(chunks).decode("utf-8", errors="replace")
