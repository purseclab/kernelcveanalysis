from __future__ import annotations

import os
import tempfile
import unittest
import uuid
from pathlib import Path

from ksandbox.docker_sandbox import DockerSandboxProvider, MountInfo


@unittest.skipUnless(
    os.environ.get("KSANDBOX_RUN_DOCKER_TESTS") == "1",
    "set KSANDBOX_RUN_DOCKER_TESTS=1 to run Docker integration tests",
)
class DockerIntegrationTests(unittest.TestCase):
    def test_minimal_custom_image_uses_mounted_daemon_and_tools(self) -> None:
        tag = f"ksandbox-integration:{uuid.uuid4().hex}"
        fixtures = Path(__file__).resolve().parent / "fixtures"
        provider = DockerSandboxProvider(image_tag=tag, default_timeout_secs=5)
        provider.build_image(fixtures, dockerfile="minimal.Dockerfile")
        try:
            with tempfile.TemporaryDirectory() as tempdir:
                mount_path = Path(tempdir)
                (mount_path / "sample.txt").write_text("alpha\nneedle\nomega\n")
                mount = MountInfo(mount_path, "input", "integration input", False)
                with provider.create_instance([mount]) as sandbox:
                    command = sandbox.execute("printf arbitrary-image-ok")
                    self.assertEqual(command.exit_code, 0)
                    self.assertEqual(command.output, b"arbitrary-image-ok")

                    mount_layout = sandbox.execute(
                        "test ! -e /sandbox_runtime/bin && "
                        "! touch /opt/ksandbox/bin/must-not-write 2>/dev/null"
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
