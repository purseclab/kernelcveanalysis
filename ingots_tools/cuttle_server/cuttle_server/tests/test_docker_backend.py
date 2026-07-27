import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from cuttle_types import CuttlefishBackendKind, InstanceState

from cuttle_server.backends.docker import (
    BACKEND_LABEL,
    CONTAINER_ADB_PORT,
    INSTANCE_ID_LABEL,
    MANAGED_LABEL,
    DockerCuttlefishBackend,
)
from cuttle_server.models import InstanceRecord, ResolvedLaunchConfig


def make_record(root: Path, *, state: InstanceState = InstanceState.STARTING) -> InstanceRecord:
    runtime_root = root / "cuttlefish"
    runtime_root.mkdir()
    kernel = root / "kernel"
    kernel.write_text("")
    initrd = root / "initrd"
    initrd.write_text("")
    return InstanceRecord(
        instance_id="11111111-2222-3333-4444-555555555555",
        owner_id="alice",
        state=state,
        instance_num=7,
        config=ResolvedLaunchConfig(
            template_name="phone",
            cpus=4,
            selinux=False,
            runtime_root=runtime_root,
            kernel_path=kernel,
            initrd_path=initrd,
            apps=[],
            backend=CuttlefishBackendKind.DOCKER,
            docker_image="cuttlefish:test",
            cvd_binary=runtime_root / "bin" / "cvd",
        ),
        runtime_dir=root / "instance",
        expires_at=None,
    )


class DockerCuttlefishBackendTests(unittest.TestCase):
    def test_start_uses_isolated_instance_and_dynamic_bound_adb_port(self):
        with tempfile.TemporaryDirectory() as tmp:
            record = make_record(Path(tmp))
            container = Mock()
            container.id = "container-id"
            container.status = "running"
            container.attrs = {
                "NetworkSettings": {
                    "Ports": {
                        f"{CONTAINER_ADB_PORT}/tcp": [{"HostPort": "49152"}]
                    }
                }
            }
            client = Mock()
            client.containers.create.return_value = container
            backend = DockerCuttlefishBackend(
                server_host="0.0.0.0",
                client=client,
            )

            with (
                patch.object(
                    backend,
                    "_available_devices",
                    return_value=["devices"],
                ),
                patch.object(
                    backend,
                    "_wait_for_adb_listener",
                ) as wait_for_adb,
            ):
                result = backend.start_instance(record)

        create_kwargs = client.containers.create.call_args.kwargs
        self.assertEqual(create_kwargs["image"], "cuttlefish:test")
        self.assertEqual(create_kwargs["entrypoint"], [])
        self.assertEqual(
            create_kwargs["ports"],
            {f"{CONTAINER_ADB_PORT}/tcp": ("0.0.0.0", None)},
        )
        self.assertEqual(create_kwargs["cap_add"], ["NET_ADMIN"])
        self.assertEqual(create_kwargs["network_mode"], "bridge")
        self.assertTrue(create_kwargs["init"])
        self.assertEqual(create_kwargs["labels"][MANAGED_LABEL], "true")
        self.assertEqual(
            create_kwargs["labels"][INSTANCE_ID_LABEL],
            record.instance_id,
        )
        self.assertEqual(
            create_kwargs["labels"][BACKEND_LABEL],
            CuttlefishBackendKind.DOCKER.value,
        )
        self.assertIn("--base_instance_num=1", create_kwargs["command"])
        self.assertIn("--start_webrtc=false", create_kwargs["command"])
        self.assertIn("--daemon=false", create_kwargs["command"])
        self.assertEqual(result.adb_port, 49152)
        self.assertEqual(result.adb_serial, "127.0.0.1:49152")
        self.assertEqual(result.backend_runtime_id, "container-id")
        wait_for_adb.assert_called_once_with(container, "127.0.0.1", 49152)

    def test_stop_force_removes_after_graceful_stop_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            record = make_record(Path(tmp), state=InstanceState.ACTIVE)
            record.backend_runtime_id = "container-id"
            container = Mock()
            container.id = "container-id"
            container.stop.side_effect = RuntimeError("launcher stuck")
            container.logs.return_value = b"cuttlefish output\n"
            client = Mock()
            client.containers.get.return_value = container
            backend = DockerCuttlefishBackend(
                server_host="0.0.0.0",
                client=client,
            )

            backend.stop_instance(record)

            container.kill.assert_called_once()
            container.remove.assert_called_once_with(force=True, v=True)
            stop_log = (record.runtime_dir / "cvd-stop.log").read_text()
            start_log = (record.runtime_dir / "cvd-start.log").read_text()

        self.assertIn("graceful stop failed", stop_log)
        self.assertIn("container removed", stop_log)
        self.assertIn("cuttlefish output", start_log)

    def test_reconcile_reports_missing_active_container(self):
        with tempfile.TemporaryDirectory() as tmp:
            record = make_record(Path(tmp), state=InstanceState.ACTIVE)
            client = Mock()
            client.containers.list.return_value = []
            backend = DockerCuttlefishBackend(
                server_host="127.0.0.1",
                client=client,
            )

            failures = backend.reconcile([record])

        self.assertEqual(len(failures), 1)
        self.assertEqual(failures[0].instance_id, record.instance_id)
        self.assertIn("missing", failures[0].reason)

    def test_reconcile_removes_orphaned_managed_container(self):
        container = Mock()
        container.labels = {
            MANAGED_LABEL: "true",
            INSTANCE_ID_LABEL: "orphan",
        }
        client = Mock()
        client.containers.list.return_value = [container]
        backend = DockerCuttlefishBackend(
            server_host="127.0.0.1",
            client=client,
        )

        failures = backend.reconcile([])

        self.assertEqual(failures, [])
        container.remove.assert_called_once_with(force=True, v=True)

    def test_hostname_binding_is_resolved(self):
        backend = DockerCuttlefishBackend(
            server_host="cuttlefish",
            client=Mock(),
        )
        with patch(
            "cuttle_server.backends.docker.socket.getaddrinfo",
            return_value=[
                (
                    2,
                    1,
                    6,
                    "",
                    ("192.0.2.10", 0),
                )
            ],
        ):
            self.assertEqual(
                backend._resolve_bind_host("cuttlefish"),
                "192.0.2.10",
            )


if __name__ == "__main__":
    unittest.main()
