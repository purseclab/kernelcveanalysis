from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

from cuttle_types import InstanceState, InstanceView, TemplateSummary, TemplateView
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
    kernel_path: Path
    initrd_path: Path
    apps: list[Path] = Field(default_factory=list)
    load_apps: bool = True
    cvd_binary: Path


TERMINAL_STATES = frozenset(
    {InstanceState.STOPPED, InstanceState.EXPIRED, InstanceState.CRASHED}
)
ACTIVE_STATES = frozenset(
    {InstanceState.STARTING, InstanceState.ACTIVE, InstanceState.STOPPING}
)


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
    )
