from __future__ import annotations

import json
import socket
from pathlib import Path

from .daemon import CliError, daemon_paths
from .models import RpcResponse


class KdebugDaemonClient:
    def __init__(self, target: str, frida_server_path: Path, lldb_server_root: Path):
        self.target = target
        self.frida_server_path = frida_server_path
        self.lldb_server_root = lldb_server_root
        self.paths = daemon_paths(target, frida_server_path, lldb_server_root)

    def call(self, action: str, **params) -> dict[str, object]:
        request = json.dumps({"action": action, "params": params}).encode("utf-8") + b"\n"
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                client.connect(str(self.paths.socket))
                client.sendall(request)
                response_line = self._recv_line(client)
        except FileNotFoundError as exc:
            raise CliError("daemon socket is missing; start the daemon first") from exc
        except ConnectionRefusedError as exc:
            raise CliError("failed to connect to daemon socket") from exc

        response = RpcResponse.model_validate_json(response_line)
        if not response.ok:
            raise CliError(response.error or "daemon request failed")
        return response.result or {}

    def list_apps(self) -> dict[str, object]:
        return self.call("frida_list_apps")

    def list_sessions(self) -> dict[str, object]:
        return self.call("frida_list_sessions")

    def list_scripts(self) -> dict[str, object]:
        return self.call("frida_list_scripts")

    def attach(self, package_name: str) -> dict[str, object]:
        return self.call("frida_attach", package_name=package_name)

    def spawn(self, package_name: str) -> dict[str, object]:
        return self.call("frida_spawn", package_name=package_name)

    def resume(self, session_id: str) -> dict[str, object]:
        return self.call("frida_resume", session_id=session_id)

    def detach(self, session_id: str) -> dict[str, object]:
        return self.call("frida_detach", session_id=session_id)

    def load_script(self, session_id: str, name: str, source: str) -> dict[str, object]:
        return self.call("frida_load_script", session_id=session_id, name=name, source=source)

    def unload_script(self, script_id: str) -> dict[str, object]:
        return self.call("frida_unload_script", script_id=script_id)

    def eval(self, session_id: str, source: str) -> dict[str, object]:
        return self.call("frida_eval", session_id=session_id, source=source)

    def rpc_call(self, script_id: str, method: str, args: list[str]) -> dict[str, object]:
        return self.call("frida_rpc_call", script_id=script_id, method=method, args=args)

    def get_messages(self, script_id: str, clear: bool = True) -> dict[str, object]:
        return self.call("frida_get_messages", script_id=script_id, clear=clear)

    def lldb_attach_package(self, package_name: str) -> dict[str, object]:
        return self.call("lldb_attach_package", package_name=package_name)

    def lldb_attach_pid(self, pid: int) -> dict[str, object]:
        return self.call("lldb_attach_pid", pid=pid)

    def lldb_list_sessions(self) -> dict[str, object]:
        return self.call("lldb_list_sessions")

    def lldb_stop_session(self, session_id: str) -> dict[str, object]:
        return self.call("lldb_stop_session", session_id=session_id)

    def lldb_get_connect_info(self, session_id: str) -> dict[str, object]:
        return self.call("lldb_get_connect_info", session_id=session_id)

    @staticmethod
    def _recv_line(client: socket.socket) -> bytes:
        chunks: list[bytes] = []
        while True:
            chunk = client.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)
            if b"\n" in chunk:
                break
        if not chunks:
            raise CliError("daemon closed the socket without a response")
        return b"".join(chunks).split(b"\n", 1)[0]
