import subprocess
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from libadb import AdbClient, AdbCommandError, AdbProcess, Process


class AdbClientTests(unittest.TestCase):
    def test_run_adb_command_uses_client_remote_addr(self):
        adb = AdbClient("127.0.0.1:5555")

        with patch("libadb.adb.subprocess.run") as run:
            run.return_value = subprocess.CompletedProcess(args=[], returncode=0, stdout="ok\n")

            output = adb.run_adb_command("id")

        self.assertEqual(output, "ok")
        run.assert_called_once_with(
            ["adb", "-s", "127.0.0.1:5555", "shell", "id"],
            capture_output=True,
            text=True,
            check=True,
        )

    def test_run_adb_uses_client_remote_addr(self):
        adb = AdbClient("127.0.0.1:5555")

        with patch("libadb.adb.subprocess.run") as run:
            adb.run_adb("shell", "id")

        run.assert_called_once_with(
            ["adb", "-s", "127.0.0.1:5555", "shell", "id"],
            capture_output=True,
            text=False,
            check=True,
        )

    def test_run_shell_wraps_root_command(self):
        adb = AdbClient("127.0.0.1:5555")

        with patch("libadb.adb.subprocess.run") as run:
            adb.run_shell("id", root=True, check=False)

        run.assert_called_once_with(
            ["adb", "-s", "127.0.0.1:5555", "shell", "su root sh -c id"],
            capture_output=True,
            text=False,
            check=False,
        )

    def test_shell_text_raises_structured_error(self):
        adb = AdbClient("127.0.0.1:5555")

        with patch.object(
            adb,
            "run_shell",
            return_value=subprocess.CompletedProcess(args=[], returncode=1, stdout=b"out", stderr=b"err"),
        ):
            with self.assertRaises(AdbCommandError) as ctx:
                adb.shell_text("id")

        self.assertIn("stdout: out", str(ctx.exception))
        self.assertIn("stderr: err", str(ctx.exception))

    def test_upload_file_uses_client_remote_addr(self):
        adb = AdbClient("192.0.2.10:4444")

        with patch("libadb.adb.subprocess.run") as run:
            adb.upload_file(Path("/tmp/src"), Path("/data/local/tmp/dst"))

        run.assert_called_once_with(
            ["adb", "-s", "192.0.2.10:4444", "push", "/tmp/src", "/data/local/tmp/dst"],
            check=True,
        )

    def test_install_app_uses_client_remote_addr(self):
        adb = AdbClient("198.51.100.8:7777")

        with patch("libadb.adb.subprocess.run") as run:
            adb.install_app(Path("/tmp/app.apk"))

        run.assert_called_once_with(
            ["adb", "-s", "198.51.100.8:7777", "install", "/tmp/app.apk"],
            check=True,
        )

    def test_connect_uses_remote_addr(self):
        adb = AdbClient("198.51.100.8:7777")

        with patch("libadb.adb.subprocess.run") as run:
            adb.connect()

        run.assert_called_once_with(
            ["adb", "connect", "198.51.100.8:7777"],
            check=True,
            capture_output=True,
            text=True,
        )

    def test_disconnect_uses_remote_addr(self):
        adb = AdbClient("198.51.100.8:7777")

        with patch("libadb.adb.subprocess.run") as run:
            adb.disconnect()

        run.assert_called_once_with(
            ["adb", "disconnect", "198.51.100.8:7777"],
            check=True,
            capture_output=True,
            text=True,
        )

    def test_wait_for_device_uses_remote_addr(self):
        adb = AdbClient("198.51.100.8:7777")

        with patch("libadb.adb.subprocess.run") as run:
            adb.wait_for_device(timeout_sec=12.5)

        run.assert_called_once_with(
            ["adb", "-s", "198.51.100.8:7777", "wait-for-device"],
            check=True,
            capture_output=True,
            text=True,
            timeout=12.5,
        )

    def test_wait_for_boot_completed_polls_until_ready(self):
        adb = AdbClient("198.51.100.8:7777")

        with patch.object(adb, "shell_text", side_effect=["0", "1"]) as shell_text, patch(
            "libadb.adb.sleep"
        ) as sleep_mock:
            adb.wait_for_boot_completed(timeout_sec=5, poll_interval_sec=0.5)

        self.assertEqual(shell_text.call_count, 2)
        sleep_mock.assert_called_once_with(0.5)

    def test_get_all_process_binds_processes_to_same_client(self):
        adb = AdbClient("203.0.113.5:9999")
        ps_output = "USER PID PPID VSZ RSS WCHAN ADDR S NAME\nu0_a1 42 1 0 0 0 0 S toybox\n"

        with patch.object(adb, "run_adb_command", side_effect=[ps_output, "toybox\0--flag"]):
            processes = adb.get_all_process()
            cmdline = processes[0].cmdline()

        self.assertEqual(len(processes), 1)
        self.assertIs(processes[0].adb, adb)
        self.assertEqual(processes[0].pid, 42)
        self.assertEqual(cmdline, "toybox --flag")

    def test_process_read_memory_reuses_bound_client(self):
        adb = AdbClient("127.0.0.1:5555")
        proc = Process(adb=adb, name="target", pid=7)

        with patch.object(adb, "read_file", return_value=b"data") as read_file:
            data = proc.read_memory(0x1000, 16)

        self.assertEqual(data, b"data")
        read_file.assert_called_once_with("/proc/7/mem", 0x1000, 16)


class AdbProcessTests(unittest.TestCase):
    def test_adb_process_uses_client_remote_addr(self):
        adb = AdbClient("10.0.0.5:6000")
        fake_process = Mock()
        fake_process.cmdline.return_value = "sleep 1"

        with patch("libadb.adb.subprocess.Popen") as popen, patch("libadb.adb.sleep"), patch.object(
            AdbClient,
            "get_processes_by_name",
            return_value=[fake_process],
        ):
            proc = AdbProcess(adb, "sleep 1")

        popen.assert_called_once_with(
            ["adb", "-s", "10.0.0.5:6000", "shell", "sleep 1"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        self.assertIs(proc.process, fake_process)


if __name__ == "__main__":
    unittest.main()
