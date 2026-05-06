from __future__ import annotations

import tomllib
from dataclasses import dataclass
from pathlib import Path

from cuttle_types import CvdCommandMode
from pydantic import BaseModel, Field, ValidationError, field_validator


class ConfigError(ValueError):
    pass


DEFAULT_INSTANCE_RUNTIME_ROOT = Path("/tmp/cvd")


class ServerConfigFile(BaseModel):
    server_host: str = Field(default="127.0.0.1", min_length=1)
    server_port: int = Field(default=8000, ge=1, le=65535)
    auth_token: str = Field(min_length=1)
    admin_user_id: str = Field(min_length=1)
    database_path: Path
    instance_timeout_sec: int = Field(default=600, ge=0)
    cvd_start_timeout_sec: int = Field(default=120, ge=1)
    reconcile_interval_sec: int = Field(default=30, ge=1)
    base_instance_num: int = Field(default=0, ge=0)
    max_instances: int = Field(default=10, ge=1)


class TemplateConfigFile(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    runtime_root: Path
    command_mode: CvdCommandMode = CvdCommandMode.CVD
    cpus: int = Field(ge=1, le=64)
    kernel_path: Path | None = None
    initrd_path: Path | None = None
    selinux: bool
    apps: list[Path] = Field(default_factory=list)

    @field_validator("apps")
    @classmethod
    def validate_apps(cls, value: list[Path]) -> list[Path]:
        for path in value:
            if path.suffix.lower() not in [".apk", ".xapk", ".apkm"]:
                raise ValueError(
                    f"app path must end with .apk, .xapk, or .apkm: {path}"
                )
        return value


@dataclass(frozen=True, slots=True)
class InstanceTemplate:
    name: str
    runtime_root: Path
    command_mode: CvdCommandMode
    cvd_binary: Path
    cpus: int
    kernel_path: Path | None
    initrd_path: Path | None
    selinux: bool
    apps: tuple[Path, ...]


@dataclass(frozen=True, slots=True)
class CuttlefishSettings:
    server_host: str
    server_port: int
    auth_token: str
    admin_user_id: str
    database_path: Path
    instance_runtime_root: Path
    instance_timeout_sec: int | None
    cvd_start_timeout_sec: int
    reconcile_interval_sec: int
    base_instance_num: int
    max_instances: int
    templates: dict[str, InstanceTemplate]


def load_settings(config_dir: Path) -> CuttlefishSettings:
    config_dir = config_dir.expanduser().resolve()
    main_config_path = config_dir / "cuttle_server.toml"
    if not main_config_path.is_file():
        raise ConfigError(f"missing main config file: {main_config_path}")

    templates_dir = config_dir / "templates"
    if not templates_dir.is_dir():
        raise ConfigError(f"missing templates directory: {templates_dir}")

    main_config = _load_main_config(main_config_path, config_dir)
    templates: dict[str, InstanceTemplate] = {}
    for template_path in sorted(templates_dir.glob("*.toml")):
        template = _load_template(template_path)
        if template.name in templates:
            raise ConfigError(
                f"duplicate template name {template.name!r} in {template_path}"
            )
        templates[template.name] = template

    if not templates:
        raise ConfigError(f"no template TOML files found in {templates_dir}")

    return CuttlefishSettings(
        server_host=main_config.server_host,
        server_port=main_config.server_port,
        auth_token=main_config.auth_token,
        admin_user_id=main_config.admin_user_id,
        database_path=main_config.database_path,
        instance_runtime_root=DEFAULT_INSTANCE_RUNTIME_ROOT,
        instance_timeout_sec=(
            None
            if main_config.instance_timeout_sec == 0
            else main_config.instance_timeout_sec
        ),
        cvd_start_timeout_sec=main_config.cvd_start_timeout_sec,
        reconcile_interval_sec=main_config.reconcile_interval_sec,
        base_instance_num=main_config.base_instance_num,
        max_instances=main_config.max_instances,
        templates=templates,
    )


def _load_main_config(main_config_path: Path, config_dir: Path) -> ServerConfigFile:
    data = _read_toml(main_config_path)
    try:
        parsed = ServerConfigFile.model_validate(data)
    except ValidationError as exc:
        raise ConfigError(f"invalid main config {main_config_path}: {exc}") from exc

    return parsed.model_copy(
        update={
            "database_path": _resolve_path(parsed.database_path, config_dir),
        }
    )


def _load_template(template_path: Path) -> InstanceTemplate:
    data = _read_toml(template_path)
    try:
        parsed = TemplateConfigFile.model_validate(data)
    except ValidationError as exc:
        raise ConfigError(f"invalid template {template_path}: {exc}") from exc

    base_dir = template_path.parent
    runtime_root = _resolve_path(parsed.runtime_root, base_dir)
    kernel_path = _resolve_optional_path(parsed.kernel_path, base_dir)
    initrd_path = _resolve_optional_path(parsed.initrd_path, base_dir)
    apps = tuple(_resolve_path(path, base_dir) for path in parsed.apps)
    cvd_binary = runtime_root / "bin" / "cvd"
    launch_cvd_binary = runtime_root / "bin" / "launch_cvd"
    stop_cvd_binary = runtime_root / "bin" / "stop_cvd"

    required_binaries: tuple[tuple[Path, str], ...]
    if parsed.command_mode == CvdCommandMode.LEGACY:
        required_binaries = (
            (launch_cvd_binary, "launch_cvd binary"),
            (stop_cvd_binary, "stop_cvd binary"),
        )
    else:
        required_binaries = ((cvd_binary, "cvd binary"),)

    required_paths: tuple[tuple[Path | None, str], ...] = (
        *required_binaries,
        (kernel_path, "kernel path"),
        (initrd_path, "initrd path"),
    )
    for path, label in required_paths:
        if path is not None and not path.exists():
            raise ConfigError(
                f"template {parsed.name!r} {label} does not exist: {path}"
            )

    for app in apps:
        if not app.exists():
            raise ConfigError(f"template {parsed.name!r} app does not exist: {app}")

    return InstanceTemplate(
        name=parsed.name,
        runtime_root=runtime_root,
        command_mode=parsed.command_mode,
        cvd_binary=cvd_binary,
        cpus=parsed.cpus,
        kernel_path=kernel_path,
        initrd_path=initrd_path,
        selinux=parsed.selinux,
        apps=apps,
    )


def _read_toml(path: Path) -> dict[str, object]:
    try:
        with path.open("rb") as handle:
            data = tomllib.load(handle)
    except FileNotFoundError as exc:
        raise ConfigError(f"missing config file: {path}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"invalid TOML in {path}: {exc}") from exc
    return data


def _resolve_path(path: Path, base_dir: Path) -> Path:
    if path.is_absolute():
        return path
    return (base_dir / path).resolve()


def _resolve_optional_path(path: Path | None, base_dir: Path) -> Path | None:
    if path is None:
        return None
    return _resolve_path(path, base_dir)
