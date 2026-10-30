from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


SUPPORTED_SCHEMA = 1

ARTIFACTS = frozenset({"executable", "shared", "jni"})
RUN_MODES = frozenset({"exec", "ld_preload", "jni"})
PAYLOAD_KINDS = frozenset({"shell", "listening_shell", "reverse_shell"})


class VerifyError(RuntimeError):
    exit_code = 2


class MetadataError(VerifyError):
    pass


class UnsupportedError(VerifyError):
    exit_code = 3


@dataclass(frozen=True, slots=True)
class PayloadSpec:
    kind: str = "shell"
    ip: str | None = None
    port: int | None = None

    @classmethod
    def from_dict(cls, data: Any) -> "PayloadSpec":
        if data is None:
            return cls()
        if not isinstance(data, dict):
            raise MetadataError("metadata payload must be an object")
        kind = str(data.get("kind", "shell"))
        if kind not in PAYLOAD_KINDS:
            raise MetadataError(f"unsupported payload kind: {kind}")
        ip_value = data.get("ip")
        ip = str(ip_value) if ip_value is not None else None
        port_value = data.get("port")
        port = int(port_value) if port_value is not None else None
        if port is not None and not (1 <= port <= 65535):
            raise MetadataError(f"invalid payload port: {port}")
        if kind == "reverse_shell" and not ip:
            raise MetadataError("reverse_shell metadata requires an ip")
        if kind in {"listening_shell", "reverse_shell"} and port is None:
            raise MetadataError(f"{kind} metadata requires a port")
        return cls(kind=kind, ip=ip, port=port)

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {"kind": self.kind}
        if self.ip is not None:
            result["ip"] = self.ip
        if self.port is not None:
            result["port"] = self.port
        return result


@dataclass(frozen=True, slots=True)
class Metadata:
    schema: int
    target: str
    arch: str | None
    artifact: str
    run: str
    entry: str | None
    linkage: str | None
    payload: PayloadSpec
    root_check_mode: str
    generator: str | None = None
    source: str = "embedded"

    @classmethod
    def from_dict(cls, data: Any, *, source: str = "embedded") -> "Metadata":
        if not isinstance(data, dict):
            raise MetadataError("metadata is not a JSON object")
        schema = int(data.get("schema", 0))
        if schema != SUPPORTED_SCHEMA:
            raise MetadataError(
                f"unsupported metadata schema {schema}; expected {SUPPORTED_SCHEMA}"
            )
        artifact = str(data.get("artifact", "executable"))
        if artifact not in ARTIFACTS:
            raise MetadataError(f"unsupported artifact: {artifact}")
        run = str(data.get("run", "exec"))
        if run not in RUN_MODES:
            raise MetadataError(f"unsupported run mode: {run}")
        root_check = data.get("root_check") or {}
        if not isinstance(root_check, dict):
            raise MetadataError("root_check must be an object")
        return cls(
            schema=schema,
            target=str(data.get("target", "unknown")),
            arch=str(data["arch"]) if data.get("arch") else None,
            artifact=artifact,
            run=run,
            entry=str(data["entry"]) if data.get("entry") else None,
            linkage=str(data["linkage"]) if data.get("linkage") else None,
            payload=PayloadSpec.from_dict(data.get("payload")),
            root_check_mode=str(root_check.get("mode", "shell")),
            generator=str(data["generator"]) if data.get("generator") else None,
            source=source,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "generator": self.generator,
            "target": self.target,
            "arch": self.arch,
            "artifact": self.artifact,
            "run": self.run,
            "entry": self.entry,
            "linkage": self.linkage,
            "payload": self.payload.to_dict(),
            "root_check": {"mode": self.root_check_mode},
            "source": self.source,
        }


@dataclass(frozen=True, slots=True)
class RunPlan:
    artifact: str
    run_mode: str
    payload: PayloadSpec
    run_command: str | None
    poc_args: tuple[str, ...]
    root_check_mode: str
    root_check_command: str | None
    root_check_regex: str | None
    remote_path: str
    local_path: str
    metadata: Metadata | None
    from_app: bool = False
    app_package: str | None = None
    app_apk: str | None = None
    app_apk_path: str | None = None
    app_path: str | None = None
    app_port: int | None = None
    app_mode: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "artifact": self.artifact,
            "run_mode": self.run_mode,
            "payload": self.payload.to_dict(),
            "run_command": self.run_command,
            "poc_args": list(self.poc_args),
            "root_check_mode": self.root_check_mode,
            "root_check_command": self.root_check_command,
            "root_check_regex": self.root_check_regex,
            "remote_path": self.remote_path,
            "local_path": self.local_path,
            "metadata": self.metadata.to_dict() if self.metadata else None,
            "from_app": self.from_app,
            "app_package": self.app_package,
            "app_apk": self.app_apk,
            "app_apk_path": self.app_apk_path,
            "app_path": self.app_path,
            "app_port": self.app_port,
            "app_mode": self.app_mode,
        }


@dataclass(slots=True)
class AdbIdentity:
    uid_id: str
    kernel: str
    selinux: str

    def to_dict(self) -> dict[str, str]:
        return {
            "id": self.uid_id,
            "kernel": self.kernel,
            "selinux": self.selinux,
        }


@dataclass(slots=True)
class VerificationResult:
    passed: bool
    exit_code: int
    reason: str
    template: str
    template_selinux: str | None
    instance_name: str
    instance_id: str | None
    adb_target: str
    local_poc: str
    remote_poc: str
    poc_sha256: str
    metadata: Metadata | None
    plan: RunPlan
    before: AdbIdentity | None
    after: AdbIdentity | None
    root_flag_path: str | None
    root_token_matched: bool
    root_uid_seen: bool
    attempts: int
    duration_sec: float
    output: str = ""
    command: str = ""
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "passed": self.passed,
            "exit_code": self.exit_code,
            "reason": self.reason,
            "template": self.template,
            "template_selinux": self.template_selinux,
            "instance_name": self.instance_name,
            "instance_id": self.instance_id,
            "adb_target": self.adb_target,
            "local_poc": self.local_poc,
            "remote_poc": self.remote_poc,
            "poc_sha256": self.poc_sha256,
            "metadata": self.metadata.to_dict() if self.metadata else None,
            "plan": self.plan.to_dict(),
            "before": self.before.to_dict() if self.before else None,
            "after": self.after.to_dict() if self.after else None,
            "root_flag_path": self.root_flag_path,
            "root_token_matched": self.root_token_matched,
            "root_uid_seen": self.root_uid_seen,
            "attempts": self.attempts,
            "duration_sec": round(self.duration_sec, 3),
            "output": self.output,
            "command": self.command,
            "warnings": self.warnings,
        }
