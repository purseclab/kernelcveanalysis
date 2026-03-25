import subprocess
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from typer.testing import CliRunner

from android_app_mcp.adb_tools import read_text_file, write_text_file
from android_app_mcp.cli import app
from android_app_mcp.server import create_server
from libadb import AdbClient, AdbCommandError
from mcp.server.fastmcp.exceptions import ToolError


class ServerTests(unittest.IsolatedAsyncioTestCase):
    async def test_server_registers_expected_tools(self):
        server = create_server(AdbClient("127.0.0.1:5555"))

        tools = await server.list_tools()

        self.assertEqual(
            sorted(tool.name for tool in tools),
            ["install_app", "read_file", "run_shell", "write_file"],
        )

    async def test_run_shell_tool_passes_root_flag(self):
        adb = AdbClient("127.0.0.1:5555")
        server = create_server(adb)

        with patch.object(adb, "shell_text", return_value="ok") as shell_text:
            result = await server.call_tool("run_shell", {"command": "id", "root": True})

        self.assertEqual(result[1], {"output": "ok"})
        shell_text.assert_called_once_with("id", root=True)

    async def test_install_app_tool_validates_host_path(self):
        server = create_server(AdbClient("127.0.0.1:5555"))

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


class CliTests(unittest.TestCase):
    def test_serve_command_builds_server_for_remote_addr(self):
        runner = CliRunner()
        fake_server = Mock()

        with patch("android_app_mcp.cli.create_server", return_value=fake_server) as create_server_mock, patch.object(
            AdbClient,
            "upload_tools",
        ) as upload_tools:
            result = runner.invoke(app, ["--adb-host", "10.0.2.2", "--adb-port", "5555"])

        self.assertEqual(result.exit_code, 0, result.output)
        adb = create_server_mock.call_args.args[0]
        self.assertIsInstance(adb, AdbClient)
        self.assertEqual(adb.remote_addr, "10.0.2.2:5555")
        upload_tools.assert_called_once_with()
        fake_server.run.assert_called_once_with(transport="stdio")


if __name__ == "__main__":
    unittest.main()
