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
        self.tempdir = tempfile.TemporaryDirectory()
        self.database_path = Path(self.tempdir.name) / "sandboxes.sqlite3"
        self.client = MagicMock()
        self.docker_patch = patch(
            "ksandbox.docker_sandbox.docker.from_env", return_value=self.client
        )
        self.docker_patch.start()

    def tearDown(self) -> None:
        self.docker_patch.stop()
        self.tempdir.cleanup()

    def test_create_overrides_entrypoint_and_cmd(self) -> None:
        image = MagicMock()
        image.attrs = {"Architecture": "amd64"}
        self.client.images.get.return_value = image
        container = MagicMock()
        container.id = "container-id"
        container.attrs = {}
        container.name = "sandbox-name"
        self.client.containers.create.return_value = container

        with tempfile.TemporaryDirectory() as tempdir, patch(
            "ksandbox.docker_sandbox._persistent_runtime_root", return_value=Path(tempdir)
        ), patch(
            "ksandbox.docker_sandbox.ensure_tool_bundle",
            return_value=Path(tempdir) / "shared-tools",
        ) as ensure_bundle, patch.object(
            DockerSandboxProvider, "_wait_for_daemon"
        ):
            mount_source = Path(tempdir) / "input"
            mount_source.mkdir()
            provider = DockerSandboxProvider(database_path=self.database_path)
            sandbox = provider.create(
                "custom:test",
                [MountInfo(mount_source, "input", "test input", False)],
            )

            ensure_bundle.assert_called_once_with(client=self.client)
            kwargs = self.client.containers.create.call_args.kwargs
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
        provider = DockerSandboxProvider(database_path=self.database_path)

        with self.assertRaisesRegex(RuntimeError, "only linux/amd64"):
            provider.create("arm:test")

    def test_start_stop_persists_state_and_rejects_second_handle(self) -> None:
        image = MagicMock()
        image.attrs = {"Architecture": "amd64"}
        self.client.images.get.return_value = image
        container = MagicMock()
        container.id = "container-id"
        container.attrs = {}
        container.name = "sandbox-name"
        container.status = "created"
        self.client.containers.create.return_value = container
        self.client.containers.get.return_value = container

        with tempfile.TemporaryDirectory() as tempdir, patch(
            "ksandbox.docker_sandbox._persistent_runtime_root", return_value=Path(tempdir)
        ), patch(
            "ksandbox.docker_sandbox.ensure_tool_bundle",
            return_value=Path(tempdir) / "shared-tools",
        ), patch.object(DockerSandboxProvider, "_wait_for_daemon"):
            mount_source = Path(tempdir) / "input"
            mount_source.mkdir()
            provider = DockerSandboxProvider(database_path=self.database_path)
            sandbox = provider.create(
                "custom:test", [MountInfo(mount_source, "input", "test", True)]
            )
            self.assertEqual(sandbox.state, "stopped")
            container.start.assert_not_called()

            sandbox.start()
            self.assertEqual(sandbox.state, "running")
            with self.assertRaisesRegex(RuntimeError, "already running"):
                provider.get_sandbox(sandbox.id).start()
            with self.assertRaisesRegex(RuntimeError, "pass force=True"):
                provider.delete(sandbox.id)

            (mount_source / "sandbox-write").write_text("persisted")
            sandbox.stop()
            self.assertEqual(provider.get_sandbox(sandbox.id).state, "stopped")
            sandbox.start()
            container.start.assert_called()
            sandbox.stop()
            provider.delete(sandbox.id)
            self.assertEqual(provider.list(), [])


if __name__ == "__main__":
    unittest.main()
