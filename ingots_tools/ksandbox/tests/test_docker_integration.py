from __future__ import annotations

import os
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest.mock import patch

from kexploit_utils import build_docker
from ksandbox.docker_sandbox import DockerSandboxProvider, MountInfo


@unittest.skipUnless(
    os.environ.get("KSANDBOX_RUN_DOCKER_TESTS") == "1",
    "set KSANDBOX_RUN_DOCKER_TESTS=1 to run Docker integration tests",
)
class DockerIntegrationTests(unittest.TestCase):
    def test_minimal_custom_image_uses_mounted_daemon_and_tools(self) -> None:
        tag = f"ksandbox-integration:{uuid.uuid4().hex}"
        fixtures = Path(__file__).resolve().parent / "fixtures"
        try:
            with tempfile.TemporaryDirectory() as tempdir:
                provider = DockerSandboxProvider(
                    default_timeout_secs=5,
                    database_path=Path(tempdir) / "sandboxes.sqlite3",
                )
                build_docker(
                    fixtures,
                    dockerfile=Path("minimal.Dockerfile"),
                    tag=tag,
                )
                mount_path = Path(tempdir) / "input"
                mount_path.mkdir()
                (mount_path / "sample.txt").write_text("alpha\nneedle\nomega\n")
                mount = MountInfo(mount_path, "input", "integration input", False)
                with patch(
                    "ksandbox.docker_sandbox._persistent_runtime_root",
                    return_value=Path(tempdir) / "runtimes",
                ), provider.create_and_run(tag, [mount]) as sandbox:
                    command = sandbox.exec_sync("printf arbitrary-image-ok", shell=True)
                    self.assertEqual(command.exit_code, 0)
                    self.assertEqual(command.stdout, b"arbitrary-image-ok")

                    direct = sandbox.exec_sync(["/bin/busybox", "printf", "argv-ok"])
                    self.assertEqual(direct.exit_code, 0)
                    self.assertEqual(direct.stdout, b"argv-ok")

                    process = sandbox.exec(["/bin/busybox", "cat"])
                    try:
                        process.stdin_write(b"interactive\n")
                        process.close_stdin()
                        self.assertEqual(process.wait_finish(), 0)
                        self.assertEqual(process.read_stdout(), b"interactive\n")
                    finally:
                        process.close()

                    mount_layout = sandbox.exec_sync(
                        "test ! -e /sandbox_runtime/bin && "
                        "! touch /opt/ksandbox/bin/must-not-write 2>/dev/null",
                        shell=True,
                    )
                    self.assertEqual(mount_layout.exit_code, 0)

                    grep = sandbox.grep("needle", "/data/input", "*.txt")
                    self.assertIsNone(grep.error)
                    self.assertEqual(len(grep.matches), 1)

                    glob = sandbox.glob("**/*.txt", "/data/input")
                    self.assertIsNone(glob.error)
                    self.assertEqual(len(glob.entries), 1)
        finally:
            provider.client.images.remove(tag, force=True)


if __name__ == "__main__":
    unittest.main()
