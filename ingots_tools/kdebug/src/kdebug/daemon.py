from __future__ import annotations

import json
import os
import signal
import socketserver
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

from libadb import AdbClient

from .frida_core import FridaManager, bootstrap_frida
from .lldb_core import LLDBManager
from .models import (
    AttachParams,
    DaemonMetadata,
    DaemonStatusView,
    DetachParams,
    EvalParams,
    GetMessagesParams,
    LoadScriptParams,
    LldbAttachPackageParams,
    LldbAttachPidParams,
    LldbGetConnectInfoParams,
    LldbStopSessionParams,
    ResumeParams,
    RpcCallParams,
    RpcRequest,
    RpcResponse,
    UnloadScriptParams,
)


class CliError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class DaemonPaths:
    state_dir: Path
    pidfile: Path
    metadata: Path
    socket: Path
    log: Path


@dataclass(frozen=True, slots=True)
class DaemonStatus:
    running: bool
    stale: bool
    metadata: DaemonMetadata | None


@dataclass(slots=True)
class TargetRuntime:
    target: str
    frida_server_path: Path
    lldb_server_root: Path
    adb: AdbClient
    frida: FridaManager | None = None
    lldb: LLDBManager | None = None

    def get_frida(self) -> FridaManager:
        if self.frida is None:
            self.frida = bootstrap_frida(self.adb, frida_server_path=self.frida_server_path)
        return self.frida

    def get_lldb(self) -> LLDBManager:
        if self.lldb is None:
            self.lldb = LLDBManager(self.adb, lldb_server_root=self.lldb_server_root)
        return self.lldb

    def shutdown(self) -> None:
        if self.lldb is not None:
            self.lldb.shutdown()
        if self.frida is not None:
            self.frida.shutdown()


def default_state_dir() -> Path:
    return Path.home() / ".local" / "state" / "kdebug"


def normalize_target(
    *,
    device: str | None = None,
    adb_host: str | None = None,
    adb_port: int | None = None,
) -> str | None:
    if device and (adb_host is not None or adb_port is not None):
        raise CliError("pass either --device or --adb-host/--adb-port, not both")
    if device:
        return device
    if adb_host is None and adb_port is None:
        return None
    if not adb_host or adb_port is None:
        raise CliError("pass both --adb-host and --adb-port together")
    return f"{adb_host}:{adb_port}"


def daemon_paths() -> DaemonPaths:
    state_dir = default_state_dir()
    return DaemonPaths(
        state_dir=state_dir,
        pidfile=state_dir / "daemon.pid",
        metadata=state_dir / "daemon.json",
        socket=state_dir / "daemon.sock",
        log=state_dir / "daemon.log",
    )


def get_daemon_status() -> DaemonStatus:
    paths = daemon_paths()
    metadata = _load_metadata(paths.metadata)
    if metadata is None:
        return DaemonStatus(running=False, stale=False, metadata=None)
    if _pid_is_running(metadata.pid):
        return DaemonStatus(running=True, stale=False, metadata=metadata)
    return DaemonStatus(running=False, stale=True, metadata=metadata)


def ensure_daemon_running() -> None:
    status = get_daemon_status()
    if status.running:
        return
    if status.stale:
        _cleanup_stale_files(daemon_paths())
    start_daemon()


def start_daemon() -> None:
    status = get_daemon_status()
    if status.running:
        return
    paths = daemon_paths()
    if status.stale:
        _cleanup_stale_files(paths)

    paths.state_dir.mkdir(parents=True, exist_ok=True)
    with paths.log.open("a", encoding="utf-8") as log_handle:
        process = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "kdebug.main",
                "daemon",
                "run-internal",
            ],
            stdin=subprocess.DEVNULL,
            stdout=log_handle,
            stderr=log_handle,
            start_new_session=True,
        )
    _wait_for_daemon_start(process)


def stop_daemon() -> bool:
    status = get_daemon_status()
    paths = daemon_paths()
    if not status.running:
        _cleanup_stale_files(paths)
        return False

    metadata = status.metadata
    assert metadata is not None
    os.kill(metadata.pid, signal.SIGTERM)
    deadline = time.time() + 5.0
    while time.time() < deadline:
        if not _pid_is_running(metadata.pid):
            break
        time.sleep(0.1)
    else:
        raise CliError(f"daemon pid {metadata.pid} did not exit after SIGTERM")
    _cleanup_stale_files(paths)
    return True


def status_view() -> DaemonStatusView:
    status = get_daemon_status()
    if status.running:
        metadata = status.metadata
        assert metadata is not None
        return DaemonStatusView(
            status="running",
            pid=metadata.pid,
            socket_path=metadata.socket_path,
        )
    if status.stale:
        metadata = status.metadata
        assert metadata is not None
        return DaemonStatusView(
            status="stale",
            pid=metadata.pid,
            socket_path=metadata.socket_path,
        )
    return DaemonStatusView(status="stopped")


class KdebugDaemon:
    def __init__(self):
        self.runtimes: dict[str, TargetRuntime] = {}

    def dispatch(self, action: str, params: dict[str, object]) -> dict[str, object]:
        if action == "daemon_list_targets":
            return {"targets": sorted(self.runtimes)}

        runtime = self._runtime_for_params(action, params)

        if action == "frida_list_apps":
            return {"apps": runtime.get_frida().list_apps()}
        if action == "frida_list_sessions":
            return {"sessions": runtime.get_frida().list_sessions()}
        if action == "frida_list_scripts":
            return {"scripts": runtime.get_frida().list_scripts()}
        if action == "frida_attach":
            validated = AttachParams.model_validate(params)
            return runtime.get_frida().attach(validated.package_name)
        if action == "frida_spawn":
            validated = AttachParams.model_validate(params)
            return runtime.get_frida().spawn(validated.package_name)
        if action == "frida_resume":
            validated = ResumeParams.model_validate(params)
            return runtime.get_frida().resume(validated.session_id)
        if action == "frida_detach":
            validated = DetachParams.model_validate(params)
            return runtime.get_frida().detach(validated.session_id)
        if action == "frida_load_script":
            validated = LoadScriptParams.model_validate(params)
            return runtime.get_frida().load_script(validated.session_id, validated.name, validated.source)
        if action == "frida_unload_script":
            validated = UnloadScriptParams.model_validate(params)
            return runtime.get_frida().unload_script(validated.script_id)
        if action == "frida_eval":
            validated = EvalParams.model_validate(params)
            return runtime.get_frida().eval(validated.session_id, validated.source)
        if action == "frida_rpc_call":
            validated = RpcCallParams.model_validate(params)
            return runtime.get_frida().rpc_call(validated.script_id, validated.method, args=validated.args)
        if action == "frida_get_messages":
            validated = GetMessagesParams.model_validate(params)
            return runtime.get_frida().get_messages(validated.script_id, clear=validated.clear)
        if action == "lldb_attach_package":
            validated = LldbAttachPackageParams.model_validate(params)
            return runtime.get_lldb().attach_package(validated.package_name)
        if action == "lldb_attach_pid":
            validated = LldbAttachPidParams.model_validate(params)
            return runtime.get_lldb().attach_pid(validated.pid)
        if action == "lldb_list_sessions":
            return {"sessions": runtime.get_lldb().list_sessions()}
        if action == "lldb_stop_session":
            validated = LldbStopSessionParams.model_validate(params)
            return runtime.get_lldb().stop_session(validated.session_id)
        if action == "lldb_get_connect_info":
            validated = LldbGetConnectInfoParams.model_validate(params)
            return runtime.get_lldb().get_connect_info(validated.session_id)
        raise KeyError(f"Unknown daemon action `{action}`")

    def shutdown(self) -> None:
        for runtime in self.runtimes.values():
            runtime.shutdown()

    def _runtime_for_params(self, action: str, params: dict[str, object]) -> TargetRuntime:
        del action
        target = _required_param(params, "target")
        frida_server_path = Path(_required_param(params, "frida_server_path"))
        lldb_server_root = Path(_required_param(params, "lldb_server_root"))

        runtime = self.runtimes.get(target)
        if runtime is None:
            _maybe_connect_network_target(target)
            runtime = TargetRuntime(
                target=target,
                frida_server_path=frida_server_path,
                lldb_server_root=lldb_server_root,
                adb=AdbClient(target),
            )
            self.runtimes[target] = runtime
            return runtime

        if runtime.frida_server_path.resolve() != frida_server_path.resolve():
            raise CliError(
                f"target `{target}` is already active with a different frida-server path: "
                f"{runtime.frida_server_path}"
            )
        if runtime.lldb_server_root.resolve() != lldb_server_root.resolve():
            raise CliError(
                f"target `{target}` is already active with a different lldb-server root: "
                f"{runtime.lldb_server_root}"
            )
        return runtime


class _RequestHandler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        request_line = self.rfile.readline()
        if not request_line:
            return
        try:
            request = RpcRequest.model_validate_json(request_line)
            result = self.server.daemon.dispatch(request.action, request.params)  # type: ignore[attr-defined]
            response = RpcResponse(ok=True, result=result)
        except Exception as exc:
            response = RpcResponse(ok=False, error=str(exc))
        self.wfile.write(response.model_dump_json().encode("utf-8"))
        self.wfile.write(b"\n")


class _UnixServer(socketserver.UnixStreamServer):
    allow_reuse_address = True

    def __init__(self, socket_path: str, daemon_instance: KdebugDaemon):
        super().__init__(socket_path, _RequestHandler)
        self.daemon = daemon_instance


def run_daemon_forever() -> None:
    paths = daemon_paths()
    paths.state_dir.mkdir(parents=True, exist_ok=True)
    _cleanup_socket(paths.socket)
    daemon_instance = KdebugDaemon()
    metadata = DaemonMetadata(
        pid=os.getpid(),
        socket_path=str(paths.socket),
    )
    _write_metadata(paths.metadata, metadata)
    paths.pidfile.write_text(f"{metadata.pid}\n", encoding="utf-8")

    stop_requested = False

    def _request_stop(_signum: int, _frame) -> None:
        nonlocal stop_requested
        stop_requested = True

    signal.signal(signal.SIGTERM, _request_stop)
    signal.signal(signal.SIGINT, _request_stop)

    server = _UnixServer(str(paths.socket), daemon_instance)
    server.timeout = 0.5
    try:
        while not stop_requested:
            server.handle_request()
    finally:
        server.server_close()
        daemon_instance.shutdown()
        _cleanup_stale_files(paths)


def _wait_for_daemon_start(process: subprocess.Popen[bytes]) -> None:
    deadline = time.time() + 5.0
    paths = daemon_paths()
    while time.time() < deadline:
        if process.poll() is not None:
            raise CliError(f"daemon exited early with status {process.returncode}")
        status = get_daemon_status()
        if status.running and paths.socket.exists():
            return
        time.sleep(0.1)
    raise CliError("daemon did not start before timeout")


def _load_metadata(path: Path) -> DaemonMetadata | None:
    if not path.is_file():
        return None
    try:
        return DaemonMetadata.model_validate_json(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise CliError(f"invalid daemon metadata {path}: {exc}") from exc


def _write_metadata(path: Path, metadata: DaemonMetadata) -> None:
    path.write_text(metadata.model_dump_json(indent=2) + "\n", encoding="utf-8")


def _pid_is_running(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


def _cleanup_socket(path: Path) -> None:
    try:
        path.unlink()
    except FileNotFoundError:
        pass


def _cleanup_stale_files(paths: DaemonPaths) -> None:
    for path in (paths.socket, paths.metadata, paths.pidfile):
        try:
            path.unlink()
        except FileNotFoundError:
            pass
    if paths.log.exists() and not paths.log.stat().st_size:
        paths.log.unlink()
    try:
        paths.state_dir.rmdir()
    except OSError:
        pass


def _maybe_connect_network_target(target: str) -> None:
    if ":" not in target:
        return
    try:
        subprocess.run(["adb", "connect", target], check=False, capture_output=True, text=True)
    except FileNotFoundError:
        raise CliError("adb command not found in PATH")


def _required_param(params: dict[str, object], key: str) -> str:
    value = params.get(key)
    if not isinstance(value, str) or not value:
        raise CliError(f"missing required daemon parameter `{key}`")
    return value
