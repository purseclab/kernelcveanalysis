from __future__ import annotations

import tomllib
from dataclasses import dataclass
from pathlib import Path

from pydantic import BaseModel, Field, ValidationError


class CliConfigError(ValueError):
    pass


class CliConfigFile(BaseModel):
    server_host: str | None = None
    server_port: int | None = Field(default=None, ge=1, le=65535)
    auth_token: str | None = None
    user_id: str | None = None


@dataclass(frozen=True, slots=True)
class CliSettings:
    server_host: str
    server_port: int
    auth_token: str
    user_id: str


def default_config_path() -> Path:
    return Path.home() / ".config" / "cuttle_cli" / "config.toml"


def default_state_dir() -> Path:
    return Path.home() / ".local" / "state" / "cuttle_cli"


def load_cli_settings(
    *,
    server_host: str | None = None,
    server_port: int | None = None,
    auth_token: str | None = None,
    user_id: str | None = None,
    config_path: Path | None = None,
) -> CliSettings:
    path = config_path or default_config_path()
    file_config = _load_config_file(path) if path.is_file() else CliConfigFile()

    resolved_server_host = server_host or file_config.server_host or "127.0.0.1"
    resolved_server_port = server_port or file_config.server_port or 8000
    resolved_auth_token = auth_token or file_config.auth_token
    resolved_user_id = user_id or file_config.user_id

    if not resolved_auth_token:
        raise CliConfigError(
            f"missing auth token; set auth_token in {path} or pass --auth-token"
        )
    if not resolved_user_id:
        raise CliConfigError(
            f"missing user id; set user_id in {path} or pass --user-id"
        )

    return CliSettings(
        server_host=resolved_server_host,
        server_port=resolved_server_port,
        auth_token=resolved_auth_token,
        user_id=resolved_user_id,
    )


def _load_config_file(path: Path) -> CliConfigFile:
    try:
        with path.open("rb") as handle:
            data = tomllib.load(handle)
    except FileNotFoundError as exc:
        raise CliConfigError(f"missing cli config file: {path}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise CliConfigError(f"invalid TOML in {path}: {exc}") from exc

    try:
        return CliConfigFile.model_validate(data)
    except ValidationError as exc:
        raise CliConfigError(f"invalid cli config {path}: {exc}") from exc
