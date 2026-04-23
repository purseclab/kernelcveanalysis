import json
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from typer.testing import CliRunner

from kdebug.client import KdebugDaemonClient
from kdebug.daemon import (
    CliError,
    KdebugDaemon,
    _UnixServer,
    daemon_paths,
    default_state_dir,
    normalize_target,
)
from kdebug.frida_core import FRIDA_SERVER_REMOTE_PATH, FridaManager, bootstrap_frida
from kdebug.lldb_core import LLDB_SERVER_REMOTE_PATH, LLDBManager
from kdebug.main import app


class FakeApp:
    def __init__(self, identifier: str, name: str, pid: int | None):
        self.identifier = identifier
        self.name = name
        self.pid = pid


class FakeScript:
    def __init__(self, source: str):
        self.source = source
        self.handlers: dict[str, object] = {}
        self.unloaded = False
        self.exports_sync = FakeExports(self)

    def on(self, event: str, handler):
        self.handlers[event] = handler

    def load(self):
        if self.source.startswith("emit:"):
            self.emit_message({"type": "send", "payload": self.source.removeprefix("emit:")})

    def unload(self):
        self.unloaded = True

    def emit_message(self, message: dict[str, object]):
        handler = self.handlers.get("message")
        if handler is not None:
            handler(message, None)


class FakeExports:
    def __init__(self, script: FakeScript):
        self.script = script

    def ping(self, *args):
        self.script.emit_message({"type": "send", "payload": "rpc"})
        return list(args)


class FakeSession:
    def __init__(self):
        self.detached = False
        self.handlers: dict[str, object] = {}
        self.scripts: list[FakeScript] = []

    def on(self, event: str, handler):
        self.handlers[event] = handler

    def create_script(self, source: str):
        script = FakeScript(source)
        self.scripts.append(script)
        return script

    def detach(self):
        self.detached = True
        handler = self.handlers.get("detached")
        if handler is not None:
            handler("application-requested", None)


class FakeDevice:
    def __init__(self):
        self.apps = [
            FakeApp("com.example.app", "Example App", 31337),
            FakeApp("com.example.stopped", "Stopped App", None),
        ]
        self.sessions: list[FakeSession] = []
        self.spawned: list[list[str]] = []
        self.resumed: list[int] = []

    def enumerate_applications(self):
        return list(self.apps)

    def attach(self, pid: int):
        session = FakeSession()
        self.sessions.append(session)
        return session

    def spawn(self, argv: list[str]):
        self.spawned.append(argv)
        return 4242

    def resume(self, pid: int):
        self.resumed.append(pid)


class FakeDeviceManager:
    def __init__(self, device):
        self.device = device
        self.addresses: list[str] = []

    def add_remote_device(self, address: str):
        self.addresses.append(address)
        return self.device


class FakeFridaModule:
    def __init__(self, device):
        self.manager = FakeDeviceManager(device)

    def get_device_manager(self):
        return self.manager


class FakeAdbProcess:
    def __init__(self, adb, name: str, pid: int):
        self.adb = adb
        self.name = name
        self.pid = pid

    def kill(self, force: bool = False):
        self.adb.killed.append((self.pid, force))
        self.adb.processes.pop(self.pid, None)


class FakeAdbClient:
    def __init__(self, abi: str = "arm64-v8a"):
        self.abi = abi
        self.processes = {
            31337: FakeAdbProcess(self, "com.example.app", 31337),
        }
        self.killed: list[tuple[int, bool]] = []
        self.uploaded: list[tuple[Path, Path, bool]] = []
        self.forwarded: list[tuple[str, ...]] = []
        self.shell_commands: list[tuple[str, bool]] = []
        self.next_server_pid = 41000

    def get_processes_by_name(self, name: str):
        return [process for process in self.processes.values() if process.name == name]

    def get_process_by_pid(self, pid: int):
        return self.processes.get(pid)

    def shell_text(self, command: str, root: bool = False) -> str:
        self.shell_commands.append((command, root))
        if command.startswith("getprop "):
            prop = command.split()[-1]
            if prop == "ro.product.cpu.abilist64":
                return self.abi if "64" in self.abi else ""
            if prop == "ro.product.cpu.abilist":
                return self.abi
            if prop == "ro.product.cpu.abi":
                return self.abi
            return ""
        if command.startswith("mkdir -p "):
            return ""
        if "nohup" in command and "echo $!" in command:
            pid = self.next_server_pid
            self.next_server_pid += 1
            self.processes[pid] = FakeAdbProcess(self, "lldb-server", pid)
            return f"{pid}\n"
        return ""

    def upload_file(self, src_path: Path, dst_path: Path, executable: bool = False):
        self.uploaded.append((src_path, dst_path, executable))

    def run_adb(self, *args: str, check: bool = True, text: bool = False):
        self.forwarded.append(tuple(args))
        return subprocess.CompletedProcess(args=list(args), returncode=0, stdout="" if text else b"")


class TargetTests(unittest.TestCase):
    def test_normalize_target_accepts_device(self):
        self.assertEqual(normalize_target(device="127.0.0.1:5555"), "127.0.0.1:5555")

    def test_normalize_target_accepts_host_port(self):
        self.assertEqual(normalize_target(adb_host="127.0.0.1", adb_port=5555), "127.0.0.1:5555")

    def test_normalize_target_rejects_mixed_forms(self):
        with self.assertRaises(CliError):
            normalize_target(device="serial", adb_host="127.0.0.1", adb_port=5555)

    def test_daemon_paths_are_hashed_per_identity(self):
        first = daemon_paths("127.0.0.1:5555", Path("/tmp/a"), Path("/tmp/root-a"))
        second = daemon_paths("127.0.0.1:5555", Path("/tmp/a"), Path("/tmp/root-b"))
        self.assertNotEqual(first.state_dir, second.state_dir)
        self.assertTrue(str(first.state_dir).startswith(str(default_state_dir())))


class DaemonDispatchTests(unittest.TestCase):
    def test_dispatch_attach_and_list(self):
        manager = FridaManager(FakeDevice())
        daemon = KdebugDaemon(manager, Mock())

        attached = daemon.dispatch("frida_attach", {"package_name": "com.example.app"})
        sessions = daemon.dispatch("frida_list_sessions", {})

        self.assertEqual(attached["package_name"], "com.example.app")
        self.assertEqual(len(sessions["sessions"]), 1)

    def test_dispatch_rpc_round_trip(self):
        manager = FridaManager(FakeDevice())
        daemon = KdebugDaemon(manager, Mock())
        attached = daemon.dispatch("frida_attach", {"package_name": "com.example.app"})
        loaded = daemon.dispatch(
            "frida_load_script",
            {
                "session_id": attached["session_id"],
                "name": "demo",
                "source": "console.log('hi')",
            },
        )
        record = manager.scripts[loaded["script_id"]]
        record.script.emit_message({"type": "send", "payload": "before-rpc"})

        result = daemon.dispatch(
            "frida_rpc_call",
            {"script_id": loaded["script_id"], "method": "ping", "args": ["a", "b"]},
        )

        self.assertEqual(result["result"], ["a", "b"])
        self.assertEqual([message["payload"] for message in result["messages"]], ["before-rpc", "rpc"])

    def test_dispatch_lldb_attach_and_connect(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            asset = Path(tmpdir) / "arm64-v8a" / "lldb-server"
            asset.parent.mkdir(parents=True, exist_ok=True)
            asset.write_text("stub\n", encoding="utf-8")
            lldb = LLDBManager(FakeAdbClient(), lldb_server_root=Path(tmpdir))
            daemon = KdebugDaemon(FridaManager(FakeDevice()), lldb)

            attached = daemon.dispatch("lldb_attach_package", {"package_name": "com.example.app"})
            info = daemon.dispatch("lldb_get_connect_info", {"session_id": attached["session_id"]})

        self.assertEqual(attached["package_name"], "com.example.app")
        self.assertEqual(info["connect_host"], "127.0.0.1")


class ClientSocketTests(unittest.TestCase):
    def test_client_talks_to_unix_socket_server(self):
        manager = FridaManager(FakeDevice())
        daemon = KdebugDaemon(manager, Mock())
        with tempfile.TemporaryDirectory() as tmpdir:
            socket_path = Path(tmpdir) / "daemon.sock"
            server = _UnixServer(str(socket_path), daemon)
            thread = threading.Thread(target=server.handle_request)
            thread.start()
            try:
                client = KdebugDaemonClient("serial", Path("/tmp/frida-server"), Path("/tmp/lldb"))
                client.paths = Mock(socket=socket_path)
                result = client.attach("com.example.app")
            finally:
                thread.join(timeout=2.0)
                server.server_close()

        self.assertEqual(result["package_name"], "com.example.app")


class BootstrapTests(unittest.TestCase):
    def test_bootstrap_frida_uploads_starts_and_connects(self):
        from libadb import AdbClient

        adb = AdbClient("127.0.0.1:5555")
        device = FakeDevice()
        fake_frida = FakeFridaModule(device)

        with tempfile.NamedTemporaryFile() as tmp, patch.object(adb, "upload_file") as upload_file, patch.object(
            adb,
            "run_adb",
        ) as run_adb, patch.object(adb, "shell_text", return_value="") as shell_text:
            manager = bootstrap_frida(
                adb,
                frida_server_path=Path(tmp.name),
                frida_loader=lambda: fake_frida,
            )

        self.assertIsInstance(manager, FridaManager)
        upload_file.assert_called_once()
        self.assertEqual(str(upload_file.call_args.args[1]), FRIDA_SERVER_REMOTE_PATH)
        run_adb.assert_called_once()
        shell_text.assert_called_once()
        self.assertEqual(fake_frida.manager.addresses, ["127.0.0.1:27042"])


class LLDBManagerTests(unittest.TestCase):
    def test_attach_package_uploads_binary_and_creates_forward(self):
        adb = FakeAdbClient()
        with tempfile.TemporaryDirectory() as tmpdir:
            asset = Path(tmpdir) / "arm64-v8a" / "lldb-server"
            asset.parent.mkdir(parents=True, exist_ok=True)
            asset.write_text("stub\n", encoding="utf-8")
            manager = LLDBManager(adb, lldb_server_root=Path(tmpdir))

            attached = manager.attach_package("com.example.app")
            connect = manager.get_connect_info(attached["session_id"])

        self.assertEqual(attached["package_name"], "com.example.app")
        self.assertEqual(attached["remote_path"], LLDB_SERVER_REMOTE_PATH)
        self.assertEqual(adb.uploaded[0][1], Path(LLDB_SERVER_REMOTE_PATH))
        self.assertEqual(adb.forwarded[0][0], "forward")
        self.assertEqual(connect["connect_host"], "127.0.0.1")

    def test_attach_package_rejects_multiple_matches(self):
        adb = FakeAdbClient()
        adb.processes[31338] = FakeAdbProcess(adb, "com.example.app", 31338)
        with tempfile.TemporaryDirectory() as tmpdir:
            asset = Path(tmpdir) / "arm64-v8a" / "lldb-server"
            asset.parent.mkdir(parents=True, exist_ok=True)
            asset.write_text("stub\n", encoding="utf-8")
            manager = LLDBManager(adb, lldb_server_root=Path(tmpdir))

            with self.assertRaisesRegex(KeyError, "matched multiple processes"):
                manager.attach_package("com.example.app")

    def test_attach_package_requires_supported_abi_asset(self):
        adb = FakeAdbClient(abi="riscv64")
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = LLDBManager(adb, lldb_server_root=Path(tmpdir))

            with self.assertRaisesRegex(RuntimeError, "supported device ABI"):
                manager.attach_package("com.example.app")

    def test_stop_session_removes_forward(self):
        adb = FakeAdbClient()
        with tempfile.TemporaryDirectory() as tmpdir:
            asset = Path(tmpdir) / "arm64-v8a" / "lldb-server"
            asset.parent.mkdir(parents=True, exist_ok=True)
            asset.write_text("stub\n", encoding="utf-8")
            manager = LLDBManager(adb, lldb_server_root=Path(tmpdir))
            attached = manager.attach_package("com.example.app")

            stopped = manager.stop_session(attached["session_id"])

        self.assertEqual(stopped["status"], "stopped")
        self.assertEqual(adb.forwarded[-1][1], "--remove")


class CliTests(unittest.TestCase):
    def test_apps_command_auto_starts_daemon_and_renders_json(self):
        runner = CliRunner()
        fake_client = Mock()
        fake_client.list_apps.return_value = {
            "apps": [{"identifier": "com.example.app", "name": "Example App", "pid": 31337}]
        }

        with patch("kdebug.main.ensure_daemon_running") as ensure_mock, patch(
            "kdebug.main.KdebugDaemonClient",
            return_value=fake_client,
        ):
            result = runner.invoke(app, ["--device", "serial", "--json", "frida", "apps"])

        self.assertEqual(result.exit_code, 0, result.output)
        ensure_mock.assert_called_once()
        payload = json.loads(result.output)
        self.assertEqual(payload["apps"][0]["identifier"], "com.example.app")

    def test_load_script_reads_file(self):
        runner = CliRunner()
        fake_client = Mock()
        fake_client.load_script.return_value = {
            "script_id": "script-1",
            "session_id": "session-1",
            "name": "demo",
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            script_path = Path(tmpdir) / "hook.js"
            script_path.write_text("send('hi')\n", encoding="utf-8")
            with patch("kdebug.main.ensure_daemon_running"), patch(
                "kdebug.main.KdebugDaemonClient",
                return_value=fake_client,
            ):
                result = runner.invoke(
                    app,
                    [
                        "--device",
                        "serial",
                        "frida",
                        "load-script",
                        "session-1",
                        "--name",
                        "demo",
                        "--file",
                        str(script_path),
                    ],
                )

        self.assertEqual(result.exit_code, 0, result.output)
        fake_client.load_script.assert_called_once_with("session-1", "demo", "send('hi')\n")

    def test_daemon_status_human_output(self):
        runner = CliRunner()

        with patch("kdebug.main.status_view") as status_view_mock:
            status_view_mock.return_value = Mock(model_dump=lambda mode="json": {"status": "stopped"})
            result = runner.invoke(app, ["--device", "serial", "daemon", "status"])

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertEqual(result.output.strip(), "stopped")

    def test_lldb_attach_package_renders_json(self):
        runner = CliRunner()
        fake_client = Mock()
        fake_client.lldb_attach_package.return_value = {
            "session_id": "lldb-1",
            "package_name": "com.example.app",
            "pid": 31337,
            "local_port": 5555,
            "remote_port": 5555,
            "server_pid": 41000,
            "abi": "arm64-v8a",
            "lldb_server_host_path": "/tmp/lldb-server",
            "remote_path": LLDB_SERVER_REMOTE_PATH,
            "connect_port": 5555,
        }

        with patch("kdebug.main.ensure_daemon_running") as ensure_mock, patch(
            "kdebug.main.KdebugDaemonClient",
            return_value=fake_client,
        ):
            result = runner.invoke(app, ["--device", "serial", "--json", "lldb", "attach-package", "com.example.app"])

        self.assertEqual(result.exit_code, 0, result.output)
        ensure_mock.assert_called_once()
        payload = json.loads(result.output)
        self.assertEqual(payload["package_name"], "com.example.app")
        self.assertIn("lldb", payload["commands"][0])

    def test_lldb_connect_renders_binary_command(self):
        runner = CliRunner()
        fake_client = Mock()
        fake_client.lldb_get_connect_info.return_value = {
            "session_id": "lldb-1",
            "package_name": "com.example.app",
            "pid": 31337,
            "local_port": 5555,
            "remote_port": 5555,
            "server_pid": 41000,
            "abi": "arm64-v8a",
            "lldb_server_host_path": "/tmp/lldb-server",
            "remote_path": LLDB_SERVER_REMOTE_PATH,
            "connect_host": "127.0.0.1",
            "connect_port": 5555,
            "base_command": "lldb -o 'gdb-remote 127.0.0.1:5555'",
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            binary_path = Path(tmpdir) / "libtarget.so"
            with patch("kdebug.main.ensure_daemon_running"), patch(
                "kdebug.main.KdebugDaemonClient",
                return_value=fake_client,
            ):
                result = runner.invoke(
                    app,
                    [
                        "--device",
                        "serial",
                        "lldb",
                        "connect",
                        "lldb-1",
                        "--binary",
                        str(binary_path),
                    ],
                )

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("target create", result.output)


if __name__ == "__main__":
    unittest.main()
