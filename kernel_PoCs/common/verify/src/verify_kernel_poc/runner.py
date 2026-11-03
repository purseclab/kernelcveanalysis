from __future__ import annotations

import shlex
import socket
import subprocess
import tempfile
import time
from dataclasses import dataclass
from typing import BinaryIO, Callable

from .adb import Adb, AdbError
from .models import RunPlan, UnsupportedError, VerifyError
from .rootcheck import pipeline_command, read_until_closed


APP_LOADER_CLASS = "com.purdue.kpoc.verify.Loader"


@dataclass(slots=True)
class RunOutcome:
    output: str
    command: str
    returncode: int
    timed_out: bool = False


def build_run_command(plan: RunPlan) -> str:
    poc_path = plan.app_path if plan.from_app and plan.app_path else plan.remote_path
    if plan.run_command:
        return plan.run_command.replace("{poc}", shlex.quote(poc_path))

    if plan.artifact == "shared":
        return f"LD_PRELOAD={shlex.quote(plan.remote_path)} /system/bin/sleep 200"

    if plan.artifact == "jni":
        raise UnsupportedError(
            "JNI artifacts need a host app; pass --from-app or --run-command"
        )

    args = " ".join(shlex.quote(arg) for arg in plan.poc_args)
    command = shlex.quote(plan.remote_path)
    if args:
        command = f"{command} {args}"
    return command


def build_app_intent(plan: RunPlan, *, pump: bool) -> str:
    if not (
        plan.from_app
        and plan.app_package
        and plan.app_apk_path
        and plan.app_path
        and plan.app_port
    ):
        raise VerifyError(
            "app mode requires an installed helper APK, app-local PoC path, "
            "and app port"
        )
    mode = plan.app_mode or ("jni" if plan.artifact == "jni" else "preload")
    return (
        f"am start -W -n {shlex.quote(plan.app_package)}/"
        f"{shlex.quote(APP_LOADER_CLASS.rsplit('.', 1)[0] + '.RunActivity')} "
        f"--es lib_path {shlex.quote(plan.app_path)} "
        f"--es apk_path {shlex.quote(plan.app_apk_path)} "
        f"--es mode {shlex.quote(mode)} "
        f"--ei port {plan.app_port} "
        f"--ez pump {'true' if pump else 'false'}"
    )


def _app_logs(adb: Adb) -> str:
    result = adb.shell(
        "logcat -d -s 'KPOC_VERIFY:*' 'AndroidRuntime:E'",
        timeout=20.0,
        check=False,
    )
    text = result.stdout.strip()
    if len(text) > 6000:
        text = "[... app logs truncated ...]\n" + text[-6000:]
    return text


def _launch_app(adb: Adb, plan: RunPlan, *, pump: bool) -> tuple[str, str]:
    intent = build_app_intent(plan, pump=pump)
    launch = adb.shell(intent, timeout=60.0, check=False)
    if launch.returncode != 0 or "Error:" in launch.stdout:
        raise VerifyError(f"failed to launch helper app: {launch.stdout.strip()}")
    return intent, launch.stdout


def run_app_payload(
    adb: Adb,
    plan: RunPlan,
    *,
    lines: list[str],
    timeout: float,
    on_output: Callable[[str], None] | None = None,
    run_only: bool = False,
) -> RunOutcome:
    if not run_only and plan.payload.kind == "listening_shell":
        return run_app_listening_payload(
            adb, plan, lines=lines, timeout=timeout, on_output=on_output
        )
    if not run_only and plan.payload.kind == "reverse_shell":
        return run_app_reverse_payload(
            adb, plan, lines=lines, timeout=timeout, on_output=on_output
        )
    if plan.app_port is None:
        raise VerifyError("app mode is missing its loopback port")
    intent, launch_output = _launch_app(adb, plan, pump=True)
    local_port = _free_port()
    adb.forward(local_port, plan.app_port)
    try:
        deadline = time.monotonic() + timeout
        last_error = ""
        while time.monotonic() < deadline:
            connection: socket.socket | None = None
            try:
                attempt_started = time.monotonic()
                connection = socket.create_connection(
                    ("127.0.0.1", local_port), timeout=2.0
                )
                with connection:
                    output = _socket_exchange(
                        connection,
                        lines=lines,
                        timeout=max(0.1, deadline - time.monotonic()),
                        on_output=on_output,
                    )
                if output or (
                    run_only and time.monotonic() - attempt_started > 0.5
                ):
                    return RunOutcome(output=output, command=intent, returncode=0)
                # ADB forward can accept before the guest-side app is listening.
                last_error = "forwarded connection closed before app output"
            except OSError as exc:
                last_error = str(exc)
                if connection is not None:
                    connection.close()
            time.sleep(0.2)
        raise VerifyError(
            "helper app did not produce output: "
            f"{last_error}\n{launch_output.strip()}\napp logs:\n{_app_logs(adb)}"
        )
    finally:
        adb.remove_forward(local_port)


def run_app_listening_payload(
    adb: Adb,
    plan: RunPlan,
    *,
    lines: list[str],
    timeout: float,
    on_output: Callable[[str], None] | None = None,
) -> RunOutcome:
    if plan.payload.port is None:
        raise VerifyError("listening shell metadata is missing a port")
    local_port = _free_port()
    adb.forward(local_port, plan.payload.port)
    try:
        intent, launch_output = _launch_app(adb, plan, pump=False)
        deadline = time.monotonic() + timeout
        last_error = ""
        while time.monotonic() < deadline:
            connection: socket.socket | None = None
            try:
                connection = socket.create_connection(
                    ("127.0.0.1", local_port), timeout=2.0
                )
                with connection:
                    output = _socket_exchange(
                        connection,
                        lines=lines,
                        timeout=max(0.1, deadline - time.monotonic()),
                        on_output=on_output,
                    )
                if output:
                    return RunOutcome(output=output, command=intent, returncode=0)
                last_error = "forwarded connection closed before shell output"
            except OSError as exc:
                last_error = str(exc)
                if connection is not None:
                    connection.close()
            time.sleep(0.2)
        raise VerifyError(
            "app listening shell did not respond: "
            f"{last_error}\n{launch_output.strip()}\napp logs:\n{_app_logs(adb)}"
        )
    finally:
        adb.remove_forward(local_port)


def run_app_reverse_payload(
    adb: Adb,
    plan: RunPlan,
    *,
    lines: list[str],
    timeout: float,
    on_output: Callable[[str], None] | None = None,
) -> RunOutcome:
    if plan.payload.port is None or plan.payload.ip is None:
        raise VerifyError("reverse shell metadata is missing ip or port")
    ip = plan.payload.ip
    loopback = ip in {"127.0.0.1", "localhost", "::1"}
    local_port = _free_port()
    reverse_enabled = False
    if loopback:
        adb.reverse(plan.payload.port, local_port)
        reverse_enabled = True
        bind_host = "127.0.0.1"
        bind_port = local_port
    else:
        bind_host = "0.0.0.0"
        bind_port = plan.payload.port

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((bind_host, bind_port))
    listener.listen(1)
    listener.settimeout(timeout)
    try:
        intent, launch_output = _launch_app(adb, plan, pump=False)
        try:
            connection, _ = listener.accept()
        except TimeoutError as exc:
            raise VerifyError(
                "app reverse shell did not connect: "
                f"{launch_output.strip()}\napp logs:\n{_app_logs(adb)}"
            ) from exc
        with connection:
            output = _socket_exchange(
                connection,
                lines=lines,
                timeout=max(0.1, timeout - 0.5),
                on_output=on_output,
            )
        return RunOutcome(output=output, command=intent, returncode=0)
    finally:
        listener.close()
        if reverse_enabled:
            adb.remove_reverse(plan.payload.port)


def run_shell_payload(
    adb: Adb,
    plan: RunPlan,
    *,
    lines: list[str],
    timeout: float,
    on_output: Callable[[str], None] | None = None,
) -> RunOutcome:
    run_command = build_run_command(plan)
    command = pipeline_command(run_command, lines)
    result = adb.run_shell_process(
        command, timeout=timeout, on_output=on_output
    )
    return RunOutcome(
        output=result.output,
        command=command,
        returncode=result.returncode,
        timed_out=result.timed_out,
    )


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _wait_process(
    process: subprocess.Popen[str],
    *,
    timeout: float,
    output_file: BinaryIO,
    output_prefix: str = "",
) -> tuple[str, int, bool]:
    timed_out = False
    try:
        process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        process.kill()
        process.wait()
    output_file.seek(0)
    combined = output_prefix + output_file.read().decode("utf-8", errors="replace")
    return (
        combined,
        process.returncode if process.returncode is not None else -1,
        timed_out,
    )


def _socket_exchange(
    connection: socket.socket,
    *,
    lines: list[str],
    timeout: float,
    on_output: Callable[[str], None] | None = None,
) -> str:
    script = "\n".join(lines)
    if script and not script.endswith("\n"):
        script += "\n"
    if script:
        connection.sendall(script.encode())
        # The root-check script ends with `exit`. ADB forwarding can close both
        # directions if the client half-closes before the shell replies.
    # With no script (run-only), keep the connection open and just stream the
    # payload's stdout until the caller's timeout.
    return read_until_closed(connection, timeout=timeout, on_output=on_output)


def _exchange_listening(
    port: int,
    *,
    deadline: float,
    process: subprocess.Popen[str],
    lines: list[str],
    on_output: Callable[[str], None] | None = None,
) -> tuple[str, str]:
    last_error = ""
    while time.monotonic() < deadline:
        if process.poll() is not None and process.returncode not in (None, 0):
            break
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=2.0) as connection:
                output = _socket_exchange(
                    connection,
                    lines=lines,
                    timeout=max(0.1, deadline - time.monotonic()),
                    on_output=on_output,
                )
                if output:
                    return output, ""
                # ADB can accept the host connection before the guest port opens.
                last_error = "forwarded connection closed before the shell responded"
        except OSError as exc:
            last_error = str(exc)
        time.sleep(min(0.2, max(0.0, deadline - time.monotonic())))
    return "", last_error


def run_listening_payload(
    adb: Adb,
    plan: RunPlan,
    *,
    lines: list[str],
    timeout: float,
    on_output: Callable[[str], None] | None = None,
) -> RunOutcome:
    if plan.payload.port is None:
        raise VerifyError("listening shell metadata is missing a port")
    run_command = build_run_command(plan)
    local_port = _free_port()
    with tempfile.TemporaryFile() as output_file:
        adb.forward(local_port, plan.payload.port)
        process: subprocess.Popen[str] | None = None
        try:
            process = adb.popen_shell(run_command, output_file=output_file)
            deadline = time.monotonic() + timeout
            connection_output, connect_error = _exchange_listening(
                local_port,
                deadline=deadline,
                process=process,
                lines=lines,
                on_output=on_output,
            )
            output, returncode, timed_out = _wait_process(
                process,
                timeout=max(0.1, deadline - time.monotonic()),
                output_file=output_file,
                output_prefix=connection_output,
            )
            if not connection_output and connect_error:
                output += f"\n[verify] unable to connect to listening shell: {connect_error}\n"
            return RunOutcome(
                output=output,
                command=run_command,
                returncode=returncode,
                timed_out=timed_out,
            )
        finally:
            if process is not None and process.poll() is None:
                process.kill()
                process.wait()
            adb.remove_forward(local_port)


def run_reverse_payload(
    adb: Adb,
    plan: RunPlan,
    *,
    lines: list[str],
    timeout: float,
    on_output: Callable[[str], None] | None = None,
) -> RunOutcome:
    if plan.payload.port is None or plan.payload.ip is None:
        raise VerifyError("reverse shell metadata is missing ip or port")
    run_command = build_run_command(plan)
    ip = plan.payload.ip
    loopback = ip in {"127.0.0.1", "localhost", "::1"}
    local_port = _free_port()
    reverse_enabled = False
    if loopback:
        # The payload connects to localhost inside the guest; adb reverse makes
        # that reach our host listener.
        adb.reverse(plan.payload.port, local_port)
        reverse_enabled = True
        bind_host = "127.0.0.1"
        bind_port = local_port
    else:
        bind_host = "0.0.0.0"
        bind_port = plan.payload.port

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((bind_host, bind_port))
    listener.listen(1)
    listener.settimeout(timeout)
    output_file = tempfile.TemporaryFile()
    process: subprocess.Popen[str] | None = None
    try:
        process = adb.popen_shell(run_command, output_file=output_file)
        connection_output = ""
        try:
            connection, _ = listener.accept()
        except TimeoutError:
            connection = None
        if connection is not None:
            with connection:
                connection_output = _socket_exchange(
                    connection,
                    lines=lines,
                    timeout=max(0.1, timeout - 0.5),
                    on_output=on_output,
                )
        output, returncode, timed_out = _wait_process(
            process,
            timeout=max(0.1, timeout - 1.0),
            output_file=output_file,
            output_prefix=connection_output,
        )
        return RunOutcome(
            output=output,
            command=run_command,
            returncode=returncode,
            timed_out=timed_out,
        )
    finally:
        listener.close()
        if process is not None and process.poll() is None:
            process.kill()
            process.wait()
        output_file.close()
        if reverse_enabled:
            adb.remove_reverse(plan.payload.port)


def run_payload(
    adb: Adb,
    plan: RunPlan,
    *,
    lines: list[str],
    timeout: float,
    on_output: Callable[[str], None] | None = None,
    run_only: bool = False,
) -> RunOutcome:
    if plan.from_app:
        return run_app_payload(
            adb,
            plan,
            lines=lines,
            timeout=timeout,
            on_output=on_output,
            run_only=run_only,
        )
    if run_only:
        # Start the payload and stream its process stdout without trying to
        # connect to its listening/reverse shell.
        return run_shell_payload(
            adb, plan, lines=[], timeout=timeout, on_output=on_output
        )
    if plan.payload.kind == "listening_shell":
        return run_listening_payload(
            adb, plan, lines=lines, timeout=timeout, on_output=on_output
        )
    if plan.payload.kind == "reverse_shell":
        return run_reverse_payload(
            adb, plan, lines=lines, timeout=timeout, on_output=on_output
        )
    return run_shell_payload(
        adb, plan, lines=lines, timeout=timeout, on_output=on_output
    )
