"""Positive build inputs supplied by a device/module/compiler inventory."""

from pathlib import Path
import posixpath
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .config_filter import ConfigValue


class AdditionalBuildInput(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    path: str
    mode: Literal["y", "m"]
    origin: str = Field(min_length=1, max_length=512)

    @field_validator("path")
    @classmethod
    def relative_source(cls, value: str) -> str:
        if (not value or posixpath.isabs(value) or posixpath.normpath(value) != value
                or value == ".." or value.startswith("../") or any(char in value for char in "\0\r\n")
                or not value.endswith((".c", ".h", ".S", ".s"))):
            raise ValueError("Build inputs require normalized repository-relative C/header/assembly paths")
        return value


class BuildInputManifest(BaseModel):
    """An inclusion superset: missing entries never prove build exclusion."""

    model_config = ConfigDict(frozen=True, extra="forbid")
    schema_version: Literal[1] = 1
    inputs: tuple[AdditionalBuildInput, ...] = Field(max_length=32768)

    @model_validator(mode="after")
    def unique_paths(self) -> "BuildInputManifest":
        if len({item.path for item in self.inputs}) != len(self.inputs):
            raise ValueError("Specify each additional build input once")
        return self

    @classmethod
    def load(cls, path: Path) -> "BuildInputManifest":
        if path.stat().st_size > 8 * 1024 * 1024:
            raise ValueError("Additional build-input manifest exceeds 8 MiB")
        return cls.model_validate_json(path.read_bytes())

    def inclusion_modes(self) -> dict[str, ConfigValue]:
        return {item.path: ConfigValue(item.mode) for item in self.inputs}
