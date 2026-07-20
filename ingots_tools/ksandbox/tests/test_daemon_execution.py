from __future__ import annotations

import subprocess
import shutil
import sys
import tempfile
import time
import unittest
from pathlib import Path

from ksandbox.daemon_protocol import SOCKET_NAME
from ksandbox.docker_sandbox import SandboxDaemonClient


class DaemonExecutionTests(unittest.TestCase):
    manifest: Path
    daemon_binary: Path

    @classmethod
    def setUpClass(cls) -> None:
        repo_root = Path(__file__).resolve().parents[2]
        cls.manifest = repo_root / "ksandbox" / "daemon" / "Cargo.toml"
        subprocess.run(
            ["cargo", "build", "--manifest-path", str(cls.manifest)], check=True
        )
        cls.daemon_binary = cls.manifest.parent / "target" / "debug" / "ksandbox-daemon"

    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        runtime_dir = Path(self.tempdir.name)
        bin_dir = runtime_dir / "bin"
        bin_dir.mkdir()
        daemon = bin_dir / "ksandbox-daemon"
        shutil.copy2(self.daemon_binary, daemon)
        for name, candidates in {
            "rg": ("rg",),
            "fd": ("fd", "fdfind"),
        }.items():
            source = next((shutil.which(candidate) for candidate in candidates if shutil.which(candidate)), None)
            if source is None:
                self.skipTest(f"{name} is required for daemon contract tests")
            (bin_dir / name).symlink_to(source)
        self.proc = subprocess.Popen(
            [
                str(daemon),
                "--runtime-dir",
                str(runtime_dir),
            ],
        )
        self.socket_path = runtime_dir / SOCKET_NAME
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if self.socket_path.exists():
                break
            if self.proc.poll() is not None:
                raise RuntimeError(f"daemon exited early with code {self.proc.returncode}")
            time.sleep(0.05)
        else:
            self.proc.kill()
            raise RuntimeError("daemon socket did not appear")

    def tearDown(self) -> None:
        self.proc.terminate()
        try:
            self.proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait(timeout=3)
        self.tempdir.cleanup()

    def test_healthcheck(self) -> None:
        SandboxDaemonClient(self.socket_path).healthcheck()

    def test_exec_sync_preserves_separate_raw_streams(self) -> None:
        client = SandboxDaemonClient(self.socket_path, default_timeout_secs=5)
        result = client.exec_sync(
            [
                sys.executable,
                "-c",
                "import sys; print('out'); sys.stderr.write('err\\n'); print('A'*120)",
            ]
        )

        self.assertEqual(result.exit_code, 0)
        self.assertIn(b"out", result.stdout)
        self.assertIn(b"err", result.stderr)
        self.assertIn(b"A" * 120, result.stdout)

    def test_exec_sync_timeout_kills_and_raises(self) -> None:
        client = SandboxDaemonClient(self.socket_path, default_timeout_secs=1)
        with self.assertRaises(TimeoutError):
            client.exec_sync([sys.executable, "-c", "import time; time.sleep(3)"])

    def test_interactive_process_streams_and_accepts_stdin(self) -> None:
        client = SandboxDaemonClient(self.socket_path, default_timeout_secs=2)
        process = client.exec(
            [
                sys.executable,
                "-c",
                "import sys; data=sys.stdin.buffer.readline(); sys.stdout.buffer.write(b'out:'+data); sys.stderr.buffer.write(b'err:'+data)",
            ]
        )
        try:
            process.stdin_write(b"hello\n")
            process.close_stdin()
            self.assertEqual(process.wait_finish(), 0)
            self.assertEqual(process.read_stdout(), b"out:hello\n")
            self.assertEqual(process.read_stderr(), b"err:hello\n")
            self.assertEqual(process.read_stdout(), b"")
            self.assertEqual(process.read_stderr(), b"")
        finally:
            process.close()

    def test_shell_execution_is_explicit(self) -> None:
        client = SandboxDaemonClient(self.socket_path)
        result = client.exec_sync("printf shell-ok", shell=True)
        self.assertEqual(result.stdout, b"shell-ok")
        direct = client.exec_sync(
            [sys.executable, "-c", "import sys; print(sys.argv[1])", "$(literal); *"]
        )
        self.assertEqual(direct.stdout, b"$(literal); *\n")
        with self.assertRaises(TypeError):
            client.exec("printf direct-not-ok")

    def test_wait_timeout_leaves_process_available_for_kill(self) -> None:
        client = SandboxDaemonClient(self.socket_path, default_timeout_secs=1)
        process = client.exec([sys.executable, "-c", "import time; time.sleep(10)"])
        try:
            with self.assertRaises(TimeoutError):
                process.read_stdout(timeout_secs=0.05)
            with self.assertRaises(TimeoutError):
                process.wait_finish(timeout_secs=0.05)
            self.assertTrue(process.kill())
            self.assertEqual(process.wait_finish(), 137)
        finally:
            process.close()

    def test_read_write_and_edit_use_single_file_byte_rpc(self) -> None:
        client = SandboxDaemonClient(self.socket_path)
        base = Path(self.tempdir.name)
        sample = base / "sample.bin"
        subdir = base / "subdir"
        subdir.mkdir()

        write_result = client.write(str(sample), b"\x00alpha\nbeta\xff")
        self.assertIsNone(write_result.error)
        self.assertEqual(sample.read_bytes(), b"\x00alpha\nbeta\xff")

        duplicate_write = client.write(str(sample), b"other")
        self.assertEqual(duplicate_write.error, "already_exists")

        read_result = client.read(str(sample))
        self.assertIsNone(read_result.error)
        self.assertEqual(read_result.content, b"\x00alpha\nbeta\xff")

        missing_read = client.read(str(base / "missing.txt"))
        self.assertEqual(missing_read.error, "file_not_found")

        edit_result = client.edit(str(sample), b"beta", b"delta")
        self.assertIsNone(edit_result.error)
        self.assertEqual(edit_result.occurrences, 1)
        self.assertIn(b"delta", sample.read_bytes())

        multi_edit = client.edit(str(sample), b"a", b"z")
        self.assertEqual(multi_edit.error, "multiple_occurrences")
        self.assertGreater(multi_edit.occurrences, 1)

        listing = sorted(client.list(str(base)).entries, key=lambda item: item.path)
        self.assertIn((str(sample), False), [(item.path, item.is_dir) for item in listing])
        self.assertIn((str(subdir), True), [(item.path, item.is_dir) for item in listing])

    def test_grep_and_glob_return_structured_results(self) -> None:
        client = SandboxDaemonClient(self.socket_path)
        base = Path(self.tempdir.name)
        nested = base / "nested"
        nested.mkdir()
        txt_file = nested / "needle.txt"
        md_file = nested / "needle.md"
        hidden_file = base / ".secret.txt"

        txt_file.write_text("alpha\nfind-me\nomega\n")
        md_file.write_text("find-me\n")
        hidden_file.write_text("hidden\n")

        grep_result = client.grep("find-me", path=str(base), glob="*.txt")
        self.assertIsNone(grep_result.error)
        self.assertFalse(grep_result.timed_out)
        self.assertEqual(len(grep_result.matches), 1)
        self.assertTrue(grep_result.matches[0].path.endswith("needle.txt"))
        self.assertEqual(grep_result.matches[0].line, 2)
        self.assertEqual(grep_result.matches[0].text, "find-me")

        glob_result = client.glob("**/*.txt", path=str(base))
        self.assertIsNone(glob_result.error)
        glob_paths = {entry.path for entry in glob_result.entries}
        self.assertIn(str(txt_file), glob_paths)
        self.assertIn(str(hidden_file), glob_paths)


if __name__ == "__main__":
    unittest.main()
