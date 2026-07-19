from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from ksandbox.docker_sandbox import (
    DAEMON_IN_CONTAINER,
    RUNTIME_DIR_IN_CONTAINER,
    TOOLS_DIR_IN_CONTAINER,
    DockerSandboxProvider,
    MountInfo,
)


class DockerSandboxProviderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.client = MagicMock()
        self.docker_patch = patch(
            "ksandbox.docker_sandbox.docker.from_env", return_value=self.client
        )
        self.docker_patch.start()

    def tearDown(self) -> None:
        self.docker_patch.stop()

    def test_build_image_accepts_custom_context_dockerfile_and_tag(self) -> None:
        provider = DockerSandboxProvider(image_tag="configured:latest")
        provider.build_image(".", dockerfile="images/Customfile", tag="custom:test")

        self.client.images.build.assert_called_once_with(
            path=str(Path(".").resolve()),
            dockerfile="images/Customfile",
            rm=True,
            tag="custom:test",
        )

    def test_create_overrides_entrypoint_and_cmd(self) -> None:
        image = MagicMock()
        image.attrs = {"Architecture": "amd64"}
        self.client.images.get.return_value = image
        container = MagicMock()
        container.id = "container-id"
        self.client.containers.run.return_value = container

        with tempfile.TemporaryDirectory() as tempdir, patch(
            "ksandbox.docker_sandbox.HOST_RUNTIME_ROOT", Path(tempdir)
        ), patch(
            "ksandbox.docker_sandbox.ensure_tool_bundle",
            return_value=Path(tempdir) / "shared-tools",
        ) as ensure_bundle, patch.object(
            DockerSandboxProvider, "_wait_for_daemon"
        ):
            mount_source = Path(tempdir) / "input"
            mount_source.mkdir()
            provider = DockerSandboxProvider(image_tag="custom:test")
            sandbox = provider.create_instance(
                [MountInfo(mount_source, "input", "test input", False)]
            )

            ensure_bundle.assert_called_once_with(client=self.client)
            kwargs = self.client.containers.run.call_args.kwargs
            self.assertEqual(kwargs["entrypoint"], [
                DAEMON_IN_CONTAINER,
                "--runtime-dir",
                RUNTIME_DIR_IN_CONTAINER,
            ])
            self.assertEqual(kwargs["command"], [])
            self.assertEqual(kwargs["working_dir"], "/")
            self.assertEqual(kwargs["volumes"][str(mount_source.resolve())]["mode"], "ro")
            self.assertEqual(
                kwargs["volumes"][str((Path(tempdir) / "shared-tools").resolve())],
                {"bind": TOOLS_DIR_IN_CONTAINER, "mode": "ro"},
            )
            self.assertEqual(
                kwargs["volumes"][str(sandbox.runtime_dir)],
                {"bind": RUNTIME_DIR_IN_CONTAINER, "mode": "rw"},
            )

    def test_create_rejects_non_amd64_image(self) -> None:
        image = MagicMock()
        image.attrs = {"Architecture": "arm64"}
        self.client.images.get.return_value = image
        provider = DockerSandboxProvider(image_tag="arm:test")

        with self.assertRaisesRegex(RuntimeError, "only linux/amd64"):
            provider.create_instance()


if __name__ == "__main__":
    unittest.main()
