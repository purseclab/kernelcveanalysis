from __future__ import annotations

import subprocess
import shutil
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

    def test_execute_returns_raw_bytes_without_truncation(self) -> None:
        client = SandboxDaemonClient(self.socket_path, default_timeout_secs=5)
        result = client.execute(
            "python3 -c \"import sys; print('out'); sys.stderr.write('err\\n'); print('A'*120)\""
        )

        self.assertEqual(result.exit_code, 0)
        self.assertIsNone(result.transport_error)
        self.assertIn(b"out", result.output)
        self.assertIn(b"err", result.output)
        self.assertIn(b"A" * 120, result.output)

    def test_execute_timeout_is_structured(self) -> None:
        client = SandboxDaemonClient(self.socket_path, default_timeout_secs=1)
        result = client.execute("python3 -c \"import time; time.sleep(3)\"")

        self.assertEqual(result.exit_code, 124)
        self.assertTrue(result.timed_out)
        self.assertEqual(result.timeout_secs, 1)
        self.assertEqual(result.output, b"")

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
