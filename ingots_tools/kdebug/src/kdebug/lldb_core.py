from __future__ import annotations

import socket
import subprocess
from dataclasses import dataclass
from pathlib import Path
from shlex import quote
from time import sleep
from uuid import uuid4

from libadb import AdbClient

LLDB_SERVER_ASSET_ROOT = Path(__file__).resolve().parents[2] / "assets" / "lldb-server"
LLDB_SERVER_REMOTE_DIR = "/data/local/tmp/kdebug"
LLDB_SERVER_REMOTE_PATH = f"{LLDB_SERVER_REMOTE_DIR}/lldb-server"
LOCALHOST = "127.0.0.1"

ABI_ASSET_DIRS = {
    "arm64-v8a": "arm64-v8a",
    "armeabi-v7a": "armeabi-v7a",
    "x86": "x86",
    "x86_64": "x86_64",
}


@dataclass
class LldbSessionRecord:
    session_id: str
    pid: int
    package_name: str
    local_port: int
    remote_port: int
    server_pid: int
    abi: str
    lldb_server_host_path: Path
    remote_path: str


class LLDBManager:
    def __init__(self, adb: AdbClient, lldb_server_root: Path = LLDB_SERVER_ASSET_ROOT):
        self.adb = adb
        self.lldb_server_root = lldb_server_root
        self.sessions: dict[str, LldbSessionRecord] = {}

    def attach_package(self, package_name: str) -> dict[str, object]:
        matches = self.adb.get_processes_by_name(package_name)
        if not matches:
            raise KeyError(f"Package `{package_name}` is not running")
        if len(matches) > 1:
            pids = ", ".join(str(process.pid) for process in matches)
            raise KeyError(f"Package `{package_name}` matched multiple processes: {pids}")
        return self._attach_process(matches[0].pid, package_name)

    def attach_pid(self, pid: int) -> dict[str, object]:
        process = self.adb.get_process_by_pid(pid)
        if process is None:
            raise KeyError(f"PID `{pid}` is not running")
        return self._attach_process(process.pid, process.name)

    def list_sessions(self) -> list[dict[str, object]]:
        self._prune_dead_sessions()
        return [self._session_view(record) for record in self.sessions.values()]

    def stop_session(self, session_id: str) -> dict[str, object]:
        record = self._get_session(session_id)
        self._remove_forward(record.local_port)
        remote_process = self.adb.get_process_by_pid(record.server_pid)
        if remote_process is not None:
            remote_process.kill(force=True)
        self.sessions.pop(session_id, None)
        return {"session_id": session_id, "status": "stopped"}

    def get_connect_info(self, session_id: str) -> dict[str, object]:
        record = self._get_session(session_id)
        if self.adb.get_process_by_pid(record.server_pid) is None:
            self._remove_forward(record.local_port)
            self.sessions.pop(session_id, None)
            raise KeyError(f"LLDB session `{session_id}` is no longer running")
        view = self._session_view(record)
        view.update(
            {
                "host": LOCALHOST,
                "connect_host": LOCALHOST,
                "connect_port": record.local_port,
                "base_command": f"lldb -o {quote(f'gdb-remote {LOCALHOST}:{record.local_port}')}",
            }
        )
        return view

    def shutdown(self) -> None:
        for session_id in list(self.sessions):
            try:
                self.stop_session(session_id)
            except Exception:
                self.sessions.pop(session_id, None)

    def _attach_process(self, pid: int, package_name: str) -> dict[str, object]:
        self._prune_dead_sessions()
        abi = self._detect_device_abi()
        host_path = self._resolve_lldb_server_path(abi)
        self.adb.shell_text(f"mkdir -p {quote(LLDB_SERVER_REMOTE_DIR)}", root=True)
        self.adb.upload_file(host_path, Path(LLDB_SERVER_REMOTE_PATH), executable=True)

        local_port = self._allocate_local_port()
        remote_port = local_port
        log_path = f"{LLDB_SERVER_REMOTE_DIR}/lldb-server-{local_port}.log"
        launch_command = (
            f"nohup {quote(LLDB_SERVER_REMOTE_PATH)} gdbserver --attach {pid} :{remote_port} "
            f">{quote(log_path)} 2>&1 & echo $!"
        )
        raw_pid = self.adb.shell_text(launch_command, root=True).strip()
        if not raw_pid:
            raise RuntimeError("Failed to start lldb-server on device")
        try:
            server_pid = int(raw_pid.splitlines()[-1].strip())
        except ValueError as exc:
            raise RuntimeError(f"Unexpected lldb-server pid output: {raw_pid!r}") from exc

        self._wait_for_remote_process(server_pid)
        self.adb.run_adb("forward", f"tcp:{local_port}", f"tcp:{remote_port}", check=True, text=True)

        session_id = str(uuid4())
        record = LldbSessionRecord(
            session_id=session_id,
            pid=pid,
            package_name=package_name,
            local_port=local_port,
            remote_port=remote_port,
            server_pid=server_pid,
            abi=abi,
            lldb_server_host_path=host_path,
            remote_path=LLDB_SERVER_REMOTE_PATH,
        )
        self.sessions[session_id] = record
        return self._session_view(record)

    def _session_view(self, record: LldbSessionRecord) -> dict[str, object]:
        return {
            "session_id": record.session_id,
            "pid": record.pid,
            "package_name": record.package_name,
            "local_port": record.local_port,
            "remote_port": record.remote_port,
            "server_pid": record.server_pid,
            "abi": record.abi,
            "lldb_server_host_path": str(record.lldb_server_host_path),
            "remote_path": record.remote_path,
        }

    def _detect_device_abi(self) -> str:
        for prop in ("ro.product.cpu.abilist64", "ro.product.cpu.abilist", "ro.product.cpu.abi"):
            value = self.adb.shell_text(f"getprop {prop}").strip()
            if not value:
                continue
            for abi in [part.strip() for part in value.split(",") if part.strip()]:
                if abi in ABI_ASSET_DIRS:
                    return abi
        raise RuntimeError("Failed to detect a supported device ABI for lldb-server")

    def _resolve_lldb_server_path(self, abi: str) -> Path:
        if abi not in ABI_ASSET_DIRS:
            raise RuntimeError(f"Unsupported device ABI for lldb-server: {abi}")
        path = self.lldb_server_root / ABI_ASSET_DIRS[abi] / "lldb-server"
        if not path.is_file():
            raise FileNotFoundError(
                f"lldb-server binary not found for ABI `{abi}` at {path}. "
                "Place the bundled binary there before using `kdebug lldb`."
            )
        return path

    def _wait_for_remote_process(self, pid: int) -> None:
        for _ in range(10):
            if self.adb.get_process_by_pid(pid) is not None:
                return
            sleep(0.1)
        raise RuntimeError(f"lldb-server pid {pid} did not appear on the device")

    def _prune_dead_sessions(self) -> None:
        for session_id, record in list(self.sessions.items()):
            if self.adb.get_process_by_pid(record.server_pid) is None:
                self._remove_forward(record.local_port)
                self.sessions.pop(session_id, None)

    def _get_session(self, session_id: str) -> LldbSessionRecord:
        self._prune_dead_sessions()
        if session_id not in self.sessions:
            raise KeyError(f"Unknown LLDB session `{session_id}`")
        return self.sessions[session_id]

    def _remove_forward(self, local_port: int) -> None:
        try:
            self.adb.run_adb("forward", "--remove", f"tcp:{local_port}", check=False, text=True)
        except subprocess.SubprocessError:
            pass

    @staticmethod
    def _allocate_local_port() -> int:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind((LOCALHOST, 0))
            return int(sock.getsockname()[1])
