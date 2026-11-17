from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

from cuttle_types import (
    CuttlefishBackendKind,
    CvdCommandMode,
    InstanceState,
    InstanceView,
    SnapshotState,
    SnapshotView,
    TemplateSummary,
    TemplateView,
)
from pydantic import BaseModel, Field

if TYPE_CHECKING:
    from .config import InstanceTemplate


def utc_now() -> datetime:
    return datetime.now(UTC)


class ResolvedLaunchConfig(BaseModel):
    template_name: str
    cpus: int = Field(ge=1, le=64)
    selinux: bool
    runtime_root: Path
    kernel_path: Path | None
    initrd_path: Path | None
    apps: list[Path] = Field(default_factory=list)
    load_apps: bool = True
    unmanaged: bool = False
    command_mode: CvdCommandMode = CvdCommandMode.CVD
    backend: CuttlefishBackendKind = CuttlefishBackendKind.HOST
    docker_image: str | None = None
    cvd_binary: Path
    # Launched with `--snapshot_compatible` and the flags it requires.
    snapshot_compatible: bool = False


TERMINAL_STATES = frozenset(
    {InstanceState.STOPPED, InstanceState.EXPIRED, InstanceState.CRASHED}
)
ACTIVE_STATES = frozenset(
    {InstanceState.STARTING, InstanceState.ACTIVE, InstanceState.STOPPING}
)


# Snapshots that occupy their name and their data directory. A failed snapshot
# holds neither and may be replaced by a new snapshot with the same name.
LIVE_SNAPSHOT_STATES = frozenset({SnapshotState.CREATING, SnapshotState.READY})


class InstanceRecord(BaseModel):
    instance_id: str
    owner_id: str
    instance_name: str | None = Field(default=None)
    state: InstanceState
    instance_num: int = Field(ge=1)
    config: ResolvedLaunchConfig
    runtime_dir: Path
    launch_command: list[str] = Field(default_factory=list)
    adb_port: int | None = None
    adb_serial: str | None = None
    webrtc_port: int | None = None
    backend_runtime_id: str | None = None
    expires_at: datetime | None
    failure_reason: str | None = None

    def is_expired(self, *, now: datetime | None = None) -> bool:
        if self.expires_at is None:
            return False
        current_time = now or utc_now()
        return self.expires_at <= current_time

    @property
    def effective_instance_name(self) -> str:
        return self.instance_name or self.instance_id

    @property
    def is_terminal(self) -> bool:
        return self.state in TERMINAL_STATES


def instance_view_from_record(record: InstanceRecord) -> InstanceView:
    return InstanceView(
        instance_id=record.instance_id,
        owner_id=record.owner_id,
        instance_name=record.effective_instance_name,
        state=record.state,
        instance_num=record.instance_num,
        template_name=record.config.template_name,
        cpus=record.config.cpus,
        selinux=record.config.selinux,
        kernel_path=record.config.kernel_path,
        initrd_path=record.config.initrd_path,
        apps=record.config.apps,
        load_apps=record.config.load_apps,
        unmanaged=record.config.unmanaged,
        snapshots_enabled=record.config.snapshot_compatible,
        command_mode=record.config.command_mode,
        backend=record.config.backend,
        docker_image=record.config.docker_image,
        runtime_dir=record.runtime_dir,
        launch_command=record.launch_command,
        adb_port=record.adb_port,
        adb_serial=record.adb_serial,
        webrtc_port=record.webrtc_port,
        expires_at=record.expires_at,
        failure_reason=record.failure_reason,
    )


def template_summary_from_template(template: "InstanceTemplate") -> TemplateSummary:
    return TemplateSummary(
        template_name=template.name,
        cpus=template.cpus,
        selinux=template.selinux,
        command_mode=template.command_mode,
        backend=template.backend,
        snapshot_supported=template.snapshot_supported,
    )


def template_view_from_template(template: "InstanceTemplate") -> TemplateView:
    return TemplateView(
        template_name=template.name,
        runtime_root=template.runtime_root,
        cpus=template.cpus,
        kernel_path=template.kernel_path,
        initrd_path=template.initrd_path,
        selinux=template.selinux,
        apps=list(template.apps),
        command_mode=template.command_mode,
        backend=template.backend,
        docker_image=template.docker_image,
        snapshot_supported=template.snapshot_supported,
    )


class SnapshotRecord(BaseModel):
    """A snapshot of one instance, persisted in the server database.

    Cuttlefish bakes the original instance's absolute paths, instance number and
    network device names into a snapshot, so the source instance's identity
    (`instance_num`, `runtime_dir`) is part of the record and is what a restore
    target must match.
    """

    snapshot_id: str
    snapshot_name: str
    owner_id: str
    state: SnapshotState
    source_instance_id: str
    source_instance_name: str
    template_name: str
    backend: CuttlefishBackendKind
    instance_num: int = Field(ge=1)
    # The source instance's runtime directory (Cuttlefish's HOME).
    runtime_dir: Path
    # Where the snapshot data lives, under the configured snapshot root.
    snapshot_dir: Path
    # Identifies the host tools that took the snapshot; a restore must use the
    # same ones because the saved device state is not stable across versions.
    host_tools_fingerprint: str
    size_bytes: int | None = None
    created_at: datetime
    failure_reason: str | None = None

    @property
    def is_failed(self) -> bool:
        return self.state == SnapshotState.FAILED


def snapshot_view_from_record(record: SnapshotRecord) -> SnapshotView:
    return SnapshotView(
        snapshot_id=record.snapshot_id,
        snapshot_name=record.snapshot_name,
        owner_id=record.owner_id,
        state=record.state,
        source_instance_id=record.source_instance_id,
        source_instance_name=record.source_instance_name,
        template_name=record.template_name,
        backend=record.backend,
        instance_num=record.instance_num,
        size_bytes=record.size_bytes,
        created_at=record.created_at,
        failure_reason=record.failure_reason,
    )
