from __future__ import annotations

from datetime import datetime
from enum import Enum
from pathlib import Path

from pydantic import BaseModel, Field


class LaunchOverrides(BaseModel):
    cpus: int | None = Field(default=None, ge=1, le=64)
    selinux: bool | None = None
    load_apps: bool | None = None


class CreateInstanceRequest(BaseModel):
    template_name: str = Field(min_length=1, max_length=128)
    instance_name: str | None = Field(default=None, min_length=1, max_length=128)
    overrides: LaunchOverrides = Field(default_factory=LaunchOverrides)


class RenewLeaseRequest(BaseModel):
    timeout_sec: int | None = Field(default=None, ge=1)


class InstanceState(str, Enum):
    STARTING = "starting"
    ACTIVE = "active"
    STOPPING = "stopping"
    STOPPED = "stopped"
    CRASHED = "crashed"
    EXPIRED = "expired"


class InstanceView(BaseModel):
    instance_id: str
    owner_id: str
    instance_name: str
    state: InstanceState
    instance_num: int
    template_name: str
    cpus: int
    selinux: bool
    kernel_path: Path
    initrd_path: Path
    apps: list[Path]
    load_apps: bool
    runtime_dir: Path
    launch_command: list[str]
    adb_port: int | None
    adb_serial: str | None
    webrtc_port: int | None
    expires_at: datetime
    failure_reason: str | None


class CreateInstanceResponse(BaseModel):
    instance: InstanceView


class InstanceListResponse(BaseModel):
    instances: list[InstanceView]


class TemplateSummary(BaseModel):
    template_name: str
    cpus: int
    selinux: bool


class TemplateView(BaseModel):
    template_name: str
    runtime_root: Path
    cpus: int
    kernel_path: Path
    initrd_path: Path
    selinux: bool
    apps: list[Path]


class TemplateListResponse(BaseModel):
    templates: list[TemplateSummary]
