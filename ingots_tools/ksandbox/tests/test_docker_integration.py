from __future__ import annotations

import os
import socket
import tempfile
import threading
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
                    "ksandbox.docker_sandbox._runtime_root",
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

    def test_docker_internet_disabled_and_port_forwarding(self) -> None:
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

                # Set up a host echo server
                server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                server.bind(("127.0.0.1", 0))
                server.listen(5)
                host_port = server.getsockname()[1]

                server_stop = threading.Event()

                def echo_server_loop() -> None:
                    while not server_stop.is_set():
                        try:
                            server.settimeout(0.5)
                            conn, _ = server.accept()
                        except (socket.timeout, OSError):
                            continue
                        try:
                            data = conn.recv(1024)
                            conn.sendall(b"HOST_ECHO:" + data)
                            conn.close()
                        except Exception:
                            pass

                server_thread = threading.Thread(target=echo_server_loop, daemon=True)
                server_thread.start()

                try:
                    with patch(
                        "ksandbox.docker_sandbox._runtime_root",
                        return_value=Path(tempdir) / "runtimes",
                    ), provider.create_and_run(tag, [], allow_internet=False) as sandbox:
                        self.assertFalse(sandbox.allow_internet)

                        # Verify that external network is not configured (only lo exists, no route)
                        routes = sandbox.exec_sync(["/bin/busybox", "ip", "route"])
                        self.assertEqual(routes.exit_code, 0)
                        self.assertEqual(routes.stdout.strip(), b"")

                        # Expose host port to standard guest address 127.0.0.1:9090
                        with sandbox.expose_port(host_port=host_port, guest_addr="127.0.0.1", guest_port=9090):
                            result = sandbox.exec_sync(
                                "printf 'payload' | /bin/busybox nc 127.0.0.1 9090",
                                shell=True,
                            )
                            self.assertEqual(result.exit_code, 0)
                            self.assertEqual(result.stdout, b"HOST_ECHO:payload")

                        # Expose host port to secondary loopback address 127.0.0.2:9090
                        with sandbox.expose_port(host_port=host_port, guest_addr="127.0.0.2", guest_port=9090):
                            result2 = sandbox.exec_sync(
                                "printf 'payload2' | /bin/busybox nc 127.0.0.2 9090",
                                shell=True,
                            )
                            self.assertEqual(result2.exit_code, 0)
                            self.assertEqual(result2.stdout, b"HOST_ECHO:payload2")

                        # After exiting context, connecting should fail
                        fail_result = sandbox.exec_sync(
                            "printf 'payload' | /bin/busybox nc -w 1 127.0.0.1 9090",
                            shell=True,
                        )
                        self.assertNotEqual(fail_result.exit_code, 0)
                finally:
                    server_stop.set()
                    server.close()
                    server_thread.join(timeout=1.0)
        finally:
            provider.client.images.remove(tag, force=True)


if __name__ == "__main__":
    unittest.main()
