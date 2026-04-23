from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field


class DaemonMetadata(BaseModel):
    pid: int
    target: str
    frida_server_path: str
    lldb_server_root: str
    socket_path: str


class RpcRequest(BaseModel):
    action: str
    params: dict[str, Any] = Field(default_factory=dict)


class RpcResponse(BaseModel):
    ok: bool
    result: dict[str, Any] | None = None
    error: str | None = None


class TargetOptions(BaseModel):
    device: str | None = None
    adb_host: str | None = None
    adb_port: int | None = None


class ScriptSourceOptions(BaseModel):
    source: str | None = None
    file: Path | None = None
    stdin: bool = False


class AttachParams(BaseModel):
    package_name: str


class ResumeParams(BaseModel):
    session_id: str


class DetachParams(BaseModel):
    session_id: str


class LoadScriptParams(BaseModel):
    session_id: str
    name: str
    source: str


class UnloadScriptParams(BaseModel):
    script_id: str


class EvalParams(BaseModel):
    session_id: str
    source: str


class RpcCallParams(BaseModel):
    script_id: str
    method: str
    args: list[str] = Field(default_factory=list)


class GetMessagesParams(BaseModel):
    script_id: str
    clear: bool = True


class LldbAttachPackageParams(BaseModel):
    package_name: str


class LldbAttachPidParams(BaseModel):
    pid: int


class LldbStopSessionParams(BaseModel):
    session_id: str


class LldbGetConnectInfoParams(BaseModel):
    session_id: str


class DaemonStatusView(BaseModel):
    status: Literal["running", "stale", "stopped"]
    pid: int | None = None
    target: str | None = None
    socket_path: str | None = None
