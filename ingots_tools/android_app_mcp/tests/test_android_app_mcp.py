import unittest
from pathlib import Path
from tempfile import NamedTemporaryFile
from unittest.mock import Mock, patch

from typer.testing import CliRunner

from android_app_mcp.adb_tools import read_text_file, write_text_file
from android_app_mcp.cli import app
from android_app_mcp.frida_support import FRIDA_SERVER_REMOTE_PATH, FridaManager, bootstrap_frida
from android_app_mcp.server import create_server
from libadb import AdbClient, AdbCommandError
from mcp.server.fastmcp.exceptions import ToolError


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


class ServerTests(unittest.IsolatedAsyncioTestCase):
    async def test_server_registers_expected_tools(self):
        server = create_server(AdbClient("127.0.0.1:5555"), Mock())

        tools = await server.list_tools()

        self.assertEqual(
            sorted(tool.name for tool in tools),
            [
                "frida_attach",
                "frida_detach",
                "frida_eval",
                "frida_get_messages",
                "frida_list_apps",
                "frida_load_script",
                "frida_resume",
                "frida_rpc_call",
                "frida_spawn",
                "frida_unload_script",
                "install_app",
                "read_file",
                "run_shell",
                "write_file",
            ],
        )

    async def test_run_shell_tool_passes_root_flag(self):
        adb = AdbClient("127.0.0.1:5555")
        server = create_server(adb, Mock())

        with patch.object(adb, "shell_text", return_value="ok") as shell_text:
            result = await server.call_tool("run_shell", {"command": "id", "root": True})

        self.assertEqual(result[1], {"output": "ok"})
        shell_text.assert_called_once_with("id", root=True)

    async def test_frida_attach_tool_delegates(self):
        frida = Mock()
        frida.attach.return_value = {"session_id": "s1", "package_name": "com.example.app", "pid": 31337}
        server = create_server(AdbClient("127.0.0.1:5555"), frida)

        result = await server.call_tool("frida_attach", {"package_name": "com.example.app"})

        self.assertEqual(result[1]["session_id"], "s1")
        frida.attach.assert_called_once_with("com.example.app")

    async def test_install_app_tool_validates_host_path(self):
        server = create_server(AdbClient("127.0.0.1:5555"), Mock())

        with self.assertRaises(ToolError):
            await server.call_tool("install_app", {"apk_path": "/does/not/exist.apk"})


class AdbToolTests(unittest.TestCase):
    def test_read_text_file_preserves_trailing_newline(self):
        adb = AdbClient("127.0.0.1:5555")

        with patch.object(adb, "read_file", return_value=b"hello\n"):
            content = read_text_file(adb, "/tmp/demo.txt")

        self.assertEqual(content, "hello\n")

    def test_read_text_file_rejects_invalid_utf8(self):
        adb = AdbClient("127.0.0.1:5555")

        with patch.object(adb, "read_file", return_value=b"\xff\xfe"):
            with self.assertRaisesRegex(ValueError, "not valid UTF-8"):
                read_text_file(adb, "/tmp/binary.txt")

    def test_write_text_file_non_root_pushes_directly(self):
        adb = AdbClient("127.0.0.1:5555")

        with patch.object(adb, "upload_file") as upload_file, patch.object(
            adb, "shell_text", return_value=""
        ) as shell_text:
            bytes_written = write_text_file(
                adb,
                "/data/local/tmp/demo.txt",
                "demo",
                root=False,
                create_parents=True,
            )

        self.assertEqual(bytes_written, 4)
        upload_file.assert_called_once()
        uploaded_dst = upload_file.call_args.args[1]
        self.assertEqual(uploaded_dst, Path("/data/local/tmp/demo.txt"))
        shell_text.assert_called_once()
        self.assertIn("mkdir -p", shell_text.call_args.args[0])

    def test_write_text_file_root_uses_temp_push_and_cleanup(self):
        adb = AdbClient("127.0.0.1:5555")

        with patch.object(adb, "upload_file") as upload_file, patch.object(
            adb, "shell_text", return_value=""
        ) as shell_text, patch.object(adb, "run_shell") as run_shell_mock:
            bytes_written = write_text_file(
                adb,
                "/system/etc/demo.txt",
                "demo",
                root=True,
                create_parents=True,
            )

        self.assertEqual(bytes_written, 4)
        upload_file.assert_called_once()
        temp_dst = str(upload_file.call_args.args[1])
        self.assertTrue(temp_dst.startswith("/data/local/tmp/android-app-mcp-"))
        shell_text.assert_called_once()
        self.assertIn("mkdir -p", shell_text.call_args.args[0])
        self.assertIn("cp ", shell_text.call_args.args[0])
        run_shell_mock.assert_called_once()
        self.assertIn("rm -f", run_shell_mock.call_args.args[0])

    def test_write_text_file_root_cleans_up_after_failure(self):
        adb = AdbClient("127.0.0.1:5555")

        with patch.object(adb, "upload_file"), patch.object(
            adb, "shell_text", side_effect=AdbCommandError("cp")
        ), patch.object(adb, "run_shell") as run_shell_mock:
            with self.assertRaises(AdbCommandError):
                write_text_file(adb, "/system/etc/demo.txt", "demo", root=True)

        run_shell_mock.assert_called_once()
        self.assertIn("rm -f", run_shell_mock.call_args.args[0])


class FridaBootstrapTests(unittest.TestCase):
    def test_bootstrap_frida_requires_binary(self):
        adb = AdbClient("127.0.0.1:5555")

        with self.assertRaises(FileNotFoundError):
            bootstrap_frida(adb, frida_server_path=Path("/definitely/missing/frida-server"))

    def test_bootstrap_frida_uploads_starts_and_connects(self):
        adb = AdbClient("127.0.0.1:5555")
        device = FakeDevice()
        fake_frida = FakeFridaModule(device)

        with NamedTemporaryFile() as tmp, patch.object(adb, "upload_file") as upload_file, patch.object(
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


class FridaManagerTests(unittest.TestCase):
    def test_attach_load_rpc_messages_and_detach(self):
        device = FakeDevice()
        manager = FridaManager(device)

        attached = manager.attach("com.example.app")
        session_id = attached["session_id"]

        loaded = manager.load_script(session_id, "demo", "console.log('hi')")
        script_id = loaded["script_id"]
        record = manager.scripts[script_id]
        record.script.emit_message({"type": "send", "payload": "before-rpc"})

        rpc = manager.rpc_call(script_id, "ping", args=["a", "b"])
        self.assertEqual(rpc["result"], ["a", "b"])
        self.assertEqual([message["payload"] for message in rpc["messages"]], ["before-rpc", "rpc"])

        messages = manager.get_messages(script_id)
        self.assertEqual(messages["messages"], [])

        detached = manager.detach(session_id)
        self.assertEqual(detached["status"], "detached")
        self.assertNotIn(session_id, manager.sessions)
        self.assertNotIn(script_id, manager.scripts)

    def test_spawn_resume_eval_and_message_buffer(self):
        device = FakeDevice()
        manager = FridaManager(device)

        spawned = manager.spawn("com.example.app")
        session_id = spawned["session_id"]
        self.assertTrue(spawned["paused"])

        resumed = manager.resume(session_id)
        self.assertEqual(resumed["status"], "resumed")
        self.assertEqual(device.resumed, [4242])

        eval_result = manager.eval(session_id, "emit:loaded")
        self.assertEqual([message["payload"] for message in eval_result["messages"]], ["loaded"])

        loaded = manager.load_script(session_id, "persistent", "console.log('x')")
        script_id = loaded["script_id"]
        record = manager.scripts[script_id]
        record.script.emit_message({"type": "send", "payload": "one"})

        snapshot = manager.get_messages(script_id, clear=False)
        self.assertEqual([message["payload"] for message in snapshot["messages"]], ["one"])

        drained = manager.get_messages(script_id, clear=True)
        self.assertEqual([message["payload"] for message in drained["messages"]], ["one"])
        self.assertEqual(manager.get_messages(script_id)["messages"], [])


class CliTests(unittest.TestCase):
    def test_serve_command_bootstraps_frida_before_running_server(self):
        runner = CliRunner()
        fake_server = Mock()
        fake_frida = Mock()

        with patch("android_app_mcp.cli.create_server", return_value=fake_server) as create_server_mock, patch.object(
            AdbClient,
            "upload_tools",
        ) as upload_tools, patch("android_app_mcp.cli.bootstrap_frida", return_value=fake_frida) as bootstrap:
            result = runner.invoke(app, ["--adb-host", "10.0.2.2", "--adb-port", "5555"])

        self.assertEqual(result.exit_code, 0, result.output)
        adb = create_server_mock.call_args.args[0]
        self.assertIsInstance(adb, AdbClient)
        self.assertEqual(adb.remote_addr, "10.0.2.2:5555")
        upload_tools.assert_called_once_with()
        bootstrap.assert_called_once_with(adb)
        self.assertIs(create_server_mock.call_args.args[1], fake_frida)
        fake_server.run.assert_called_once_with(transport="stdio")


if __name__ == "__main__":
    unittest.main()
