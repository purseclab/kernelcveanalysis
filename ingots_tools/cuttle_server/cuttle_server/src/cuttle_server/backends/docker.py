from __future__ import annotations

import ipaddress
import logging
import shlex
import socket
import time
from pathlib import Path
from typing import Any, Sequence

import docker  # type: ignore[import-untyped]
from cuttle_types import CuttlefishBackendKind, CvdCommandMode, InstanceState

from ..models import InstanceRecord
from .base import BackendLogs, BackendReconcileFailure, LaunchResult

LOGGER = logging.getLogger(__name__)

CONTAINER_RUNTIME_ROOT = Path("/opt/cuttlefish")
CONTAINER_INSTANCE_HOME = Path("/var/lib/cuttlefish")
CONTAINER_INPUT_ROOT = Path("/cuttlefish-inputs")
CONTAINER_ADB_PORT = 6520
DOCKER_VSOCK_CID_BASE = 10_000
DOCKER_STOP_TIMEOUT_SEC = 10
MANAGED_LABEL = "cuttle_server.managed"
INSTANCE_ID_LABEL = "cuttle_server.instance_id"
OWNER_ID_LABEL = "cuttle_server.owner_id"
TEMPLATE_LABEL = "cuttle_server.template"
BACKEND_LABEL = "cuttle_server.backend"


class DockerCuttlefishBackend:
    """Runs one isolated Cuttlefish instance in each Docker container."""

    kind = CuttlefishBackendKind.DOCKER

    def __init__(
        self,
        *,
        server_host: str,
        start_timeout_sec: int = 120,
        client: Any | None = None,
    ) -> None:
        self.server_host = server_host
        self.start_timeout_sec = start_timeout_sec
        self._client = client

    @property
    def client(self) -> Any:
        if self._client is None:
            self._client = docker.from_env()
        return self._client

    def build_start_command(self, record: InstanceRecord) -> list[str]:
        config = record.config
        if config.command_mode == CvdCommandMode.LEGACY:
            command = [str(CONTAINER_RUNTIME_ROOT / "bin" / "launch_cvd")]
        else:
            command = [str(CONTAINER_RUNTIME_ROOT / "bin" / "cvd"), "start"]

        command.extend(
            [
                "--base_instance_num=1",
                f"--vsock_guest_cid={self._vsock_guest_cid(record)}",
                f"--cpus={config.cpus}",
                "--start_webrtc=false",
            ]
        )
        if config.kernel_path is not None:
            command.append(
                f"--kernel_path={CONTAINER_INPUT_ROOT / 'kernel'}"
            )
        if config.initrd_path is not None:
            command.append(
                f"--initramfs_path={CONTAINER_INPUT_ROOT / 'initrd'}"
            )
        command.extend(
            [
                "--daemon=false",
                "--report_anonymous_usage_stats=n",
            ]
        )
        if not config.selinux:
            command.append("--extra_kernel_cmdline=androidboot.selinux=permissive")
        return command

    @staticmethod
    def _vsock_guest_cid(record: InstanceRecord) -> int:
        return DOCKER_VSOCK_CID_BASE + record.instance_num - 1

    def start_instance(self, record: InstanceRecord) -> LaunchResult:
        image = record.config.docker_image
        if image is None:
            raise RuntimeError("docker-backed instance does not define docker_image")

        record.runtime_dir.mkdir(parents=True, exist_ok=True)
        command = self.build_start_command(record)
        self._write_start_header(record, command)
        bind_host = self._resolve_bind_host(self.server_host)
        container = None
        try:
            container = self.client.containers.create(
                image=image,
                command=command,
                name=f"cuttle-server-{record.instance_id.replace('-', '')}",
                detach=True,
                init=True,
                environment={
                    "HOME": str(CONTAINER_INSTANCE_HOME),
                    "ANDROID_HOST_OUT": str(CONTAINER_RUNTIME_ROOT),
                    "ANDROID_PRODUCT_OUT": str(CONTAINER_RUNTIME_ROOT),
                },
                volumes=self._build_volumes(record),
                devices=self._available_devices(),
                cap_add=["NET_ADMIN"],
                security_opt=["seccomp=unconfined"],
                network_mode="bridge",
                ports={
                    f"{CONTAINER_ADB_PORT}/tcp": (bind_host, None),
                },
                labels={
                    MANAGED_LABEL: "true",
                    INSTANCE_ID_LABEL: record.instance_id,
                    OWNER_ID_LABEL: record.owner_id,
                    TEMPLATE_LABEL: record.config.template_name,
                    BACKEND_LABEL: self.kind.value,
                },
                working_dir=str(CONTAINER_INSTANCE_HOME),
            )
            container.start()
            container.reload()
            host_port = self._published_adb_port(container)
            connect_host = self._connect_host(bind_host)
            self._wait_for_adb_listener(container, connect_host, host_port)
            return LaunchResult(
                launch_command=command,
                adb_port=host_port,
                adb_serial=f"{connect_host}:{host_port}",
                webrtc_port=None,
                backend_runtime_id=str(container.id),
            )
        except Exception as exc:
            if container is not None:
                self._snapshot_container_logs(record, container)
                self._force_remove(container)
            log_tail = self._read_text(self._start_log_path(record))[-4096:]
            raise RuntimeError(
                f"docker cuttlefish start failed: {exc}; "
                f"log: {self._start_log_path(record)}; tail:\n{log_tail}"
            ) from exc

    def stop_instance(self, record: InstanceRecord) -> None:
        container = self._find_container(record)
        if container is None:
            self._append_stop_log(record, "container already absent\n")
            return

        warnings: list[str] = []
        removal_error: Exception | None = None
        try:
            self._append_stop_log(
                record,
                f"stopping container {container.id} with "
                f"{DOCKER_STOP_TIMEOUT_SEC}s timeout\n",
            )
            try:
                container.stop(timeout=DOCKER_STOP_TIMEOUT_SEC)
            except Exception as exc:
                warnings.append(f"graceful stop failed: {exc}")
                try:
                    container.kill()
                except docker.errors.NotFound:
                    pass
                except Exception as kill_exc:
                    warnings.append(f"force kill failed: {kill_exc}")
        finally:
            self._snapshot_container_logs(record, container)
            try:
                container.remove(force=True, v=True)
            except docker.errors.NotFound:
                pass
            except Exception as remove_exc:
                removal_error = remove_exc

        if warnings:
            self._append_stop_log(record, f"{'; '.join(warnings)}\n")
        if removal_error is not None:
            message = f"container removal failed: {removal_error}"
            self._append_stop_log(record, f"{message}\n")
            raise RuntimeError(message) from removal_error
        self._append_stop_log(record, "container removed\n")

    def read_logs(self, record: InstanceRecord) -> BackendLogs:
        start_log = self._read_text(self._start_log_path(record))
        container = self._find_container(record)
        if container is not None:
            live_logs = self._container_logs(container)
            if live_logs and live_logs not in start_log:
                start_log = f"{start_log}{live_logs}"
        return BackendLogs(
            start_log=start_log,
            stop_log=self._read_text(self._stop_log_path(record)),
        )

    def reconcile(
        self, records: Sequence[InstanceRecord]
    ) -> list[BackendReconcileFailure]:
        docker_records = {
            record.instance_id: record
            for record in records
            if record.config.backend == self.kind
        }
        failures: list[BackendReconcileFailure] = []
        containers_by_instance: dict[str, Any] = {}

        try:
            containers = self.client.containers.list(
                all=True,
                filters={"label": f"{MANAGED_LABEL}=true"},
            )
        except Exception:
            LOGGER.exception("failed to list managed Cuttlefish containers")
            return []

        for container in containers:
            labels = self._container_labels(container)
            instance_id = labels.get(INSTANCE_ID_LABEL)
            record = docker_records.get(instance_id or "")
            if record is None or record.is_terminal:
                self._force_remove(container)
                continue
            if instance_id is not None:
                containers_by_instance[instance_id] = container

        for record in docker_records.values():
            if record.state != InstanceState.ACTIVE:
                continue
            container = containers_by_instance.get(record.instance_id)
            if container is None:
                failures.append(
                    BackendReconcileFailure(
                        instance_id=record.instance_id,
                        reason="managed Docker container is missing",
                    )
                )
                continue
            try:
                container.reload()
                status = str(container.status)
            except docker.errors.NotFound:
                status = "missing"
            except Exception:
                LOGGER.exception(
                    "failed to inspect Cuttlefish container for %s",
                    record.instance_id,
                )
                continue
            if status != "running":
                self._snapshot_container_logs(record, container)
                self._force_remove(container)
                failures.append(
                    BackendReconcileFailure(
                        instance_id=record.instance_id,
                        reason=f"managed Docker container is {status}",
                    )
                )
        return failures

    @staticmethod
    def _build_volumes(record: InstanceRecord) -> list[str]:
        volumes = [
            (
                f"{record.config.runtime_root}:"
                f"{CONTAINER_RUNTIME_ROOT}:ro"
            ),
            # A destination-only volume specification asks Docker to create an
            # anonymous volume. Container removal with v=True removes it.
            str(CONTAINER_INSTANCE_HOME),
        ]
        if record.config.kernel_path is not None:
            volumes.append(
                f"{record.config.kernel_path}:"
                f"{CONTAINER_INPUT_ROOT / 'kernel'}:ro"
            )
        if record.config.initrd_path is not None:
            volumes.append(
                f"{record.config.initrd_path}:"
                f"{CONTAINER_INPUT_ROOT / 'initrd'}:ro"
            )
        return volumes

    @staticmethod
    def _available_devices() -> list[str]:
        required_paths = (Path("/dev/kvm"), Path("/dev/net/tun"))
        missing = [str(path) for path in required_paths if not path.exists()]
        if missing:
            raise RuntimeError(
                "Docker Cuttlefish backend requires host devices: "
                + ", ".join(missing)
            )
        device_paths = (
            *required_paths,
            Path("/dev/vhost-net"),
            Path("/dev/vhost-vsock"),
        )
        return [
            f"{path}:{path}:rwm"
            for path in device_paths
            if path.exists()
        ]

    @staticmethod
    def _resolve_bind_host(host: str) -> str:
        try:
            return str(ipaddress.ip_address(host))
        except ValueError:
            pass

        try:
            addresses = socket.getaddrinfo(
                host,
                None,
                type=socket.SOCK_STREAM,
            )
        except socket.gaierror as exc:
            raise RuntimeError(
                f"server_host {host!r} cannot be resolved for Docker port binding"
            ) from exc
        if not addresses:
            raise RuntimeError(
                f"server_host {host!r} did not resolve for Docker port binding"
            )
        ipv4_addresses = [
            str(sockaddr[0])
            for family, _, _, _, sockaddr in addresses
            if family == socket.AF_INET
        ]
        if ipv4_addresses:
            return ipv4_addresses[0]
        return str(addresses[0][4][0])

    @staticmethod
    def _connect_host(bind_host: str) -> str:
        if bind_host == "0.0.0.0":
            return "127.0.0.1"
        if bind_host == "::":
            return "::1"
        return bind_host

    @staticmethod
    def _published_adb_port(container: Any) -> int:
        ports = container.attrs.get("NetworkSettings", {}).get("Ports", {})
        bindings = ports.get(f"{CONTAINER_ADB_PORT}/tcp")
        if not bindings:
            raise RuntimeError("Docker did not publish the Cuttlefish ADB port")
        return int(bindings[0]["HostPort"])

    def _wait_for_adb_listener(
        self,
        container: Any,
        connect_host: str,
        host_port: int,
    ) -> None:
        deadline = time.monotonic() + self.start_timeout_sec
        last_error: Exception | None = None
        while time.monotonic() < deadline:
            try:
                with socket.create_connection(
                    (connect_host, host_port),
                    timeout=1.0,
                ):
                    return
            except OSError as exc:
                last_error = exc
            container.reload()
            if str(container.status) != "running":
                raise RuntimeError(
                    f"container exited while waiting for ADB: {container.status}"
                )
            time.sleep(0.25)
        raise TimeoutError(
            f"timed out waiting for ADB at {connect_host}:{host_port}: {last_error}"
        )

    def _find_container(self, record: InstanceRecord) -> Any | None:
        if record.backend_runtime_id:
            try:
                return self.client.containers.get(record.backend_runtime_id)
            except docker.errors.NotFound:
                pass
        try:
            matches = self.client.containers.list(
                all=True,
                filters={"label": f"{INSTANCE_ID_LABEL}={record.instance_id}"},
            )
        except docker.errors.NotFound:
            return None
        return matches[0] if matches else None

    @staticmethod
    def _container_labels(container: Any) -> dict[str, str]:
        labels = getattr(container, "labels", None)
        if isinstance(labels, dict):
            return {str(key): str(value) for key, value in labels.items()}
        attrs = getattr(container, "attrs", {})
        raw_labels = attrs.get("Config", {}).get("Labels", {})
        return {str(key): str(value) for key, value in raw_labels.items()}

    def _snapshot_container_logs(self, record: InstanceRecord, container: Any) -> None:
        logs = self._container_logs(container)
        if not logs:
            return
        path = self._start_log_path(record)
        existing = self._read_text(path)
        header = existing.split("\n\n", maxsplit=1)[0]
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"{header}\n\n{logs}", encoding="utf-8")

    @staticmethod
    def _container_logs(container: Any) -> str:
        try:
            output = container.logs(stdout=True, stderr=True)
        except Exception:
            return ""
        if isinstance(output, bytes):
            return output.decode("utf-8", errors="replace")
        return str(output)

    @staticmethod
    def _force_remove(container: Any) -> None:
        try:
            container.remove(force=True, v=True)
        except docker.errors.NotFound:
            pass
        except Exception:
            LOGGER.exception("failed to force-remove Cuttlefish container")

    @staticmethod
    def _write_start_header(record: InstanceRecord, command: list[str]) -> None:
        path = DockerCuttlefishBackend._start_log_path(record)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"$ {shlex.join(command)}\n\n", encoding="utf-8")

    @staticmethod
    def _append_stop_log(record: InstanceRecord, text: str) -> None:
        path = DockerCuttlefishBackend._stop_log_path(record)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(text)

    @staticmethod
    def _start_log_path(record: InstanceRecord) -> Path:
        return record.runtime_dir / "cvd-start.log"

    @staticmethod
    def _stop_log_path(record: InstanceRecord) -> Path:
        return record.runtime_dir / "cvd-stop.log"

    @staticmethod
    def _read_text(path: Path) -> str:
        try:
            return path.read_text(encoding="utf-8", errors="replace")
        except FileNotFoundError:
            return ""
