from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from time import sleep
from typing import Any
from uuid import uuid4

from libadb import AdbClient

FRIDA_SERVER_HOST_PATH = Path(__file__).resolve().parents[2] / "assets" / "frida-server"
FRIDA_SERVER_REMOTE_PATH = "/data/local/tmp/frida-server"
FRIDA_SERVER_LOCAL_PORT = 27042
FRIDA_SERVER_REMOTE_PORT = 27042


@dataclass
class FridaSessionRecord:
    session_id: str
    package_name: str
    pid: int
    paused: bool
    session: Any = field(repr=False)


@dataclass
class FridaScriptRecord:
    script_id: str
    session_id: str
    name: str
    script: Any = field(repr=False)
    messages: list[dict[str, object | None]] = field(default_factory=list)


def load_frida_module():
    try:
        import frida
    except ImportError as exc:
        raise RuntimeError("The `frida` Python package is not installed. Run `uv sync` for the workspace.") from exc
    return frida


def bootstrap_frida(
    adb: AdbClient,
    frida_server_path: Path = FRIDA_SERVER_HOST_PATH,
    frida_loader=load_frida_module,
    local_port: int = FRIDA_SERVER_LOCAL_PORT,
    remote_port: int = FRIDA_SERVER_REMOTE_PORT,
) -> "FridaManager":
    if not frida_server_path.is_file():
        raise FileNotFoundError(
            f"frida-server binary not found at {frida_server_path}. "
            "Place the host binary there before starting android_app_mcp."
        )

    adb.upload_file(frida_server_path, Path(FRIDA_SERVER_REMOTE_PATH), executable=True)
    adb.run_adb("forward", f"tcp:{local_port}", f"tcp:{remote_port}", check=True, text=True)

    start_command = (
        "pidof frida-server >/dev/null 2>&1 || "
        f"nohup {FRIDA_SERVER_REMOTE_PATH} >/data/local/tmp/frida-server.log 2>&1 &"
    )
    adb.shell_text(start_command, root=True)

    frida = frida_loader()
    address = f"127.0.0.1:{local_port}"
    last_error = None
    for _ in range(10):
        try:
            device = frida.get_device_manager().add_remote_device(address)
            return FridaManager(device)
        except Exception as exc:
            last_error = exc
            sleep(0.2)

    raise RuntimeError(f"Failed to connect to frida-server at {address}: {last_error}")


class FridaManager:
    def __init__(self, device: Any):
        self.device = device
        self.sessions: dict[str, FridaSessionRecord] = {}
        self.scripts: dict[str, FridaScriptRecord] = {}

    def list_apps(self) -> list[dict[str, object | None]]:
        apps = []
        for app in self.device.enumerate_applications():
            apps.append(
                {
                    "identifier": app.identifier,
                    "name": app.name,
                    "pid": app.pid,
                }
            )
        return apps

    def attach(self, package_name: str) -> dict[str, object]:
        app = self._get_running_app(package_name)
        session = self.device.attach(app.pid)
        return self._register_session(package_name, int(app.pid), session, paused=False)

    def spawn(self, package_name: str) -> dict[str, object]:
        pid = int(self.device.spawn([package_name]))
        session = self.device.attach(pid)
        return self._register_session(package_name, pid, session, paused=True)

    def resume(self, session_id: str) -> dict[str, str]:
        record = self._get_session(session_id)
        self.device.resume(record.pid)
        record.paused = False
        return {"session_id": session_id, "status": "resumed"}

    def detach(self, session_id: str) -> dict[str, str]:
        record = self._get_session(session_id)
        for script_id in [script.script_id for script in self.scripts.values() if script.session_id == session_id]:
            self._remove_script(script_id, unload=True)
        record.session.detach()
        self.sessions.pop(session_id, None)
        return {"session_id": session_id, "status": "detached"}

    def load_script(self, session_id: str, name: str, source: str) -> dict[str, str]:
        record = self._get_session(session_id)
        script = record.session.create_script(source)
        script_id = str(uuid4())
        script_record = FridaScriptRecord(
            script_id=script_id,
            session_id=session_id,
            name=name,
            script=script,
        )
        script.on("message", self._make_message_handler(script_record))
        script.load()
        self.scripts[script_id] = script_record
        return {"script_id": script_id, "session_id": session_id, "name": name}

    def unload_script(self, script_id: str) -> dict[str, str]:
        self._remove_script(script_id, unload=True)
        return {"script_id": script_id, "status": "unloaded"}

    def eval(self, session_id: str, source: str) -> dict[str, object]:
        record = self._get_session(session_id)
        script = record.session.create_script(source)
        messages: list[dict[str, object | None]] = []
        script.on("message", self._make_buffer_handler(messages))
        try:
            script.load()
        finally:
            try:
                script.unload()
            except Exception:
                pass
        return {"session_id": session_id, "messages": messages}

    def rpc_call(self, script_id: str, method: str, args: list[object] | None = None) -> dict[str, object]:
        record = self._get_script(script_id)
        exports = getattr(record.script, "exports_sync", None)
        if exports is None:
            raise KeyError(f"Script `{script_id}` does not support synchronous RPC exports")
        fn = getattr(exports, method)
        result = fn(*(args or []))
        return {
            "script_id": script_id,
            "method": method,
            "result": result,
            "messages": self._drain_messages(record, clear=True),
        }

    def get_messages(self, script_id: str, clear: bool = True) -> dict[str, object]:
        record = self._get_script(script_id)
        return {
            "script_id": script_id,
            "messages": self._drain_messages(record, clear=clear),
        }

    def _get_running_app(self, package_name: str):
        for app in self.device.enumerate_applications():
            if app.identifier == package_name and app.pid is not None:
                return app
        raise KeyError(f"Package `{package_name}` is not running")

    def _register_session(self, package_name: str, pid: int, session: Any, paused: bool) -> dict[str, object]:
        session_id = str(uuid4())
        record = FridaSessionRecord(
            session_id=session_id,
            package_name=package_name,
            pid=pid,
            paused=paused,
            session=session,
        )
        self.sessions[session_id] = record

        if hasattr(session, "on"):
            try:
                session.on("detached", lambda *_args, sid=session_id: self._handle_detached(sid))
            except Exception:
                pass

        return {
            "session_id": session_id,
            "package_name": package_name,
            "pid": pid,
            "paused": paused,
        }

    def _handle_detached(self, session_id: str):
        if session_id not in self.sessions:
            return
        for script_id in [script.script_id for script in self.scripts.values() if script.session_id == session_id]:
            self._remove_script(script_id, unload=False)
        self.sessions.pop(session_id, None)

    def _remove_script(self, script_id: str, unload: bool):
        record = self._get_script(script_id)
        if unload:
            record.script.unload()
        self.scripts.pop(script_id, None)

    def _get_session(self, session_id: str) -> FridaSessionRecord:
        if session_id not in self.sessions:
            raise KeyError(f"Unknown Frida session `{session_id}`")
        return self.sessions[session_id]

    def _get_script(self, script_id: str) -> FridaScriptRecord:
        if script_id not in self.scripts:
            raise KeyError(f"Unknown Frida script `{script_id}`")
        return self.scripts[script_id]

    def _make_message_handler(self, record: FridaScriptRecord):
        return self._make_buffer_handler(record.messages)

    def _make_buffer_handler(self, buffer: list[dict[str, object | None]]):
        def handler(message: dict[str, object], _data: bytes | None = None):
            buffer.append(
                {
                    "type": str(message.get("type", "")),
                    "payload": message.get("payload"),
                    "description": message.get("description"),
                    "stack": message.get("stack"),
                }
            )

        return handler

    def _drain_messages(self, record: FridaScriptRecord, clear: bool) -> list[dict[str, object | None]]:
        out = list(record.messages)
        if clear:
            record.messages.clear()
        return out
