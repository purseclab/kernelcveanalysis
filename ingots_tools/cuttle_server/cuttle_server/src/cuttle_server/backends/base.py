from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Protocol, Sequence

from cuttle_types import CuttlefishBackendKind

if TYPE_CHECKING:
    from ..models import InstanceRecord


@dataclass(frozen=True, slots=True)
class LaunchResult:
    launch_command: list[str]
    adb_port: int
    adb_serial: str | None
    webrtc_port: int | None
    backend_runtime_id: str | None = None


@dataclass(frozen=True, slots=True)
class BackendLogs:
    start_log: str
    stop_log: str
    kernel_log: str = ""
    launcher_log: str = ""
    logcat: str = ""


@dataclass(frozen=True, slots=True)
class BackendReconcileFailure:
    instance_id: str
    reason: str


class CuttlefishBackend(Protocol):
    kind: CuttlefishBackendKind

    def build_start_command(
        self, record: InstanceRecord, *, snapshot_dir: Path | None = None
    ) -> list[str]: ...

    def start_instance(
        self, record: InstanceRecord, *, snapshot_dir: Path | None = None
    ) -> LaunchResult:
        """Start the instance, restoring `snapshot_dir` when it is given."""
        ...

    def stop_instance(self, record: InstanceRecord) -> None: ...

    def read_logs(self, record: InstanceRecord) -> BackendLogs: ...

    def reconcile(
        self, records: Sequence[InstanceRecord]
    ) -> list[BackendReconcileFailure]: ...

    def take_snapshot(self, record: InstanceRecord, snapshot_dir: Path) -> None:
        """Snapshot the running instance into `snapshot_dir`.

        `snapshot_dir` must not exist yet. On failure nothing is left behind at
        `snapshot_dir` and the instance keeps running.
        """
        ...

    def host_tools_fingerprint(self, record: InstanceRecord) -> str:
        """Identify the host tools whose snapshots a restore can load."""
        ...
