from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
import re
from typing import Any, ClassVar, Generic, Self, Sequence, TypeVar
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, PrivateAttr, model_validator
from sqlalchemy import Boolean, DateTime, ForeignKey, Index, JSON, String, Uuid
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


NAME_PATTERN = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
TYPE_PATTERN = re.compile(r"^[a-z][a-z0-9_-]{0,63}$")


class OrmBase(DeclarativeBase):
    pass


class ArtifactRecord(OrmBase):
    """Common immutable row inherited by every artifact type."""

    __tablename__ = "artifacts"
    __table_args__ = (
        Index("ix_artifacts_type_name", "artifact_type", "name"),
        Index("ix_artifacts_parent_id", "parent_id"),
    )

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True)
    artifact_type: Mapped[str] = mapped_column(String(64), nullable=False)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    parent_id: Mapped[UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("artifacts.id", ondelete="RESTRICT"),
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(UTC),
    )
    shadowed: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
    )
    file_overrides: Mapped[dict[str, str]] = mapped_column(
        JSON,
        nullable=False,
        default=dict,
    )

    parent: Mapped[ArtifactRecord | None] = relationship(
        remote_side=lambda: ArtifactRecord.id,
        back_populates="children",
        foreign_keys=lambda: ArtifactRecord.parent_id,
    )
    children: Mapped[list[ArtifactRecord]] = relationship(
        back_populates="parent",
        foreign_keys=lambda: ArtifactRecord.parent_id,
    )

    __mapper_args__ = {
        "polymorphic_on": artifact_type,
        "polymorphic_identity": "_artifact",
    }


RecordT = TypeVar("RecordT", bound=ArtifactRecord)


class ArtifactMetadata(BaseModel, ABC, Generic[RecordT]):
    """Type-specific TOML metadata and ORM transition interface."""

    model_config = ConfigDict(
        arbitrary_types_allowed=True,
        extra="forbid",
        from_attributes=True,
    )

    _folder: Path | None = PrivateAttr(default=None)
    _header: ArtifactHeader | None = PrivateAttr(default=None)
    _file_overrides: dict[str, str] = PrivateAttr(default_factory=dict)

    mandatory_files: ClassVar[tuple[str, ...] | type[StrEnum] | Sequence[str | StrEnum]] = ()
    optional_files: ClassVar[tuple[str, ...] | type[StrEnum] | Sequence[str | StrEnum]] = ()

    @staticmethod
    def _normalize_files(val: object) -> tuple[str, ...]:
        if isinstance(val, type) and issubclass(val, StrEnum):
            return tuple(str(m.value) for m in val)
        if isinstance(val, (tuple, list, set)):
            return tuple(str(m.value if isinstance(m, StrEnum) else m) for m in val)
        return ()

    @classmethod
    def get_mandatory_files(cls) -> tuple[str, ...]:
        return cls._normalize_files(cls.mandatory_files)

    @classmethod
    def get_optional_files(cls) -> tuple[str, ...]:
        return cls._normalize_files(cls.optional_files)

    @classmethod
    def verify_directory(cls, folder: Path) -> None:
        from .errors import InvalidArtifactError

        target = Path(folder)
        for fname in cls.get_mandatory_files():
            fpath = target / fname
            if not fpath.is_file():
                raise InvalidArtifactError(f"missing mandatory file for artifact: {fname}")

    def verify_folder(self, folder: Path) -> None:
        from .errors import InvalidArtifactError

        target = Path(folder)
        for fname in self.get_mandatory_files():
            rel_path = self._resolve_relative_path(fname)
            fpath = target / rel_path
            if not fpath.is_file():
                raise InvalidArtifactError(f"missing mandatory file for artifact: {rel_path}")

    def bind_folder(self, folder: Path) -> Self:
        self._folder = Path(folder)
        return self

    @property
    def folder(self) -> Path | None:
        return self._folder

    @property
    def header(self) -> ArtifactHeader | None:
        return self._header

    @property
    def file_overrides(self) -> dict[str, str]:
        return dict(self._file_overrides)

    def set_file_overrides(self, overrides: dict[str, str]) -> Self:
        from .errors import InvalidArtifactError

        valid_keys = set(self.get_mandatory_files()) | set(self.get_optional_files())
        validated: dict[str, str] = {}
        for k, v in overrides.items():
            if k not in valid_keys:
                raise InvalidArtifactError(
                    f"unknown file override key '{k}'"
                )
            if not isinstance(v, str) or not v.strip():
                raise InvalidArtifactError(
                    f"file override for '{k}' must be a non-empty relative path"
                )
            path_val = Path(v.strip())
            if path_val.is_absolute():
                raise InvalidArtifactError(
                    f"file override for '{k}' cannot be an absolute path: '{v}'"
                )
            if ".." in path_val.parts:
                raise InvalidArtifactError(
                    f"file override for '{k}' cannot contain '..': '{v}'"
                )
            if str(path_val) == "artifact.toml":
                raise InvalidArtifactError(
                    f"file override for '{k}' cannot point to artifact.toml"
                )
            validated[k] = str(path_val)
        self._file_overrides = validated
        return self

    def _resolve_target_folder(self, folder: Path | None) -> Path:
        if folder is not None:
            return Path(folder)
        if self._folder is not None:
            return self._folder
        raise ValueError(
            "ArtifactMetadata is not bound to a folder; pass folder= explicitly or call bind_folder()"
        )

    def _as_filename(self, file: StrEnum | str) -> str:
        return str(file.value if isinstance(file, StrEnum) else file)

    def _resolve_relative_path(self, file: StrEnum | str) -> str:
        fname = self._as_filename(file)
        return self._file_overrides.get(fname, fname)

    def get_path(self, file: StrEnum | str, *, folder: Path | None = None) -> Path:
        fname = self._as_filename(file)
        mand = self.get_mandatory_files()
        if fname not in mand:
            opt = self.get_optional_files()
            if fname in opt:
                raise ValueError(
                    f"'{fname}' is an optional file; use get_optional_path() instead"
                )
            raise ValueError(f"'{fname}' is not a registered mandatory file")
        target_dir = self._resolve_target_folder(folder)
        rel_path = self._resolve_relative_path(fname)
        fpath = target_dir / rel_path
        if not fpath.is_file():
            raise FileNotFoundError(f"mandatory artifact file not found: {fpath}")
        return fpath

    def read_bytes(self, file: StrEnum | str, *, folder: Path | None = None) -> bytes:
        return self.get_path(file, folder=folder).read_bytes()

    def read_str(
        self, file: StrEnum | str, *, encoding: str = "utf-8", folder: Path | None = None
    ) -> str:
        return self.get_path(file, folder=folder).read_text(encoding=encoding)

    def get_optional_path(
        self, file: StrEnum | str, *, folder: Path | None = None
    ) -> Path | None:
        fname = self._as_filename(file)
        opt = self.get_optional_files()
        if fname not in opt:
            mand = self.get_mandatory_files()
            if fname in mand:
                raise ValueError(
                    f"'{fname}' is a mandatory file; use get_path() instead"
                )
            raise ValueError(f"'{fname}' is not a registered optional file")
        target_dir = self._resolve_target_folder(folder)
        rel_path = self._resolve_relative_path(fname)
        fpath = target_dir / rel_path
        return fpath if fpath.is_file() else None

    def read_optional_bytes(
        self, file: StrEnum | str, *, folder: Path | None = None
    ) -> bytes | None:
        fpath = self.get_optional_path(file, folder=folder)
        return fpath.read_bytes() if fpath is not None else None

    def read_optional_str(
        self, file: StrEnum | str, *, encoding: str = "utf-8", folder: Path | None = None
    ) -> str | None:
        fpath = self.get_optional_path(file, folder=folder)
        return fpath.read_text(encoding=encoding) if fpath is not None else None

    def validate_store(self, store: Any) -> None:
        """Optional hook called during write to validate relations against the store."""
        pass


    @classmethod
    @abstractmethod
    def default(cls) -> Self:
        """Return metadata used by a newly created artifact template."""

    @classmethod
    def template_folder(cls) -> Path | None:
        """Return optional files copied into a newly created template."""
        return None

    @abstractmethod
    def build_updated_record(self, old: RecordT | None) -> RecordT:
        """Build a fresh subtype row containing only type-specific fields."""

    @classmethod
    def from_record(cls, record: RecordT) -> Self:
        """Render canonical metadata from the authoritative ORM row."""
        return cls.model_validate(record, from_attributes=True)



class ArtifactHeader(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    artifact_type: str = Field(alias="type")
    name: str
    id: UUID | None = None
    parent_id: UUID | None = None

    @model_validator(mode="after")
    def validate_header(self) -> Self:
        if not TYPE_PATTERN.fullmatch(self.artifact_type):
            raise ValueError("artifact type must be a lowercase filesystem-safe slug")
        if not NAME_PATTERN.fullmatch(self.name):
            raise ValueError(
                "artifact name must contain 1-128 letters, digits, '.', '_', or '-'"
            )
        if self.id is None and self.parent_id is not None:
            raise ValueError("parent_id cannot be set when id is absent")
        return self


class ArtifactDocument(BaseModel):
    model_config = ConfigDict(extra="forbid")

    artifact: ArtifactHeader
    file_overrides: dict[str, str] = Field(default_factory=dict)
    metadata: dict[str, Any]

    @model_validator(mode="before")
    @classmethod
    def _normalize_overrides(cls, data: Any) -> Any:
        if isinstance(data, dict):
            if "file_overrides" not in data:
                if "file-overrides" in data:
                    data = dict(data)
                    data["file_overrides"] = data.pop("file-overrides")
                elif "files" in data:
                    data = dict(data)
                    data["file_overrides"] = data.pop("files")
        return data


# artifact info represents metadata returned by api actions, not anything stored internally
class ArtifactInfo(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: UUID
    artifact_type: str
    name: str
    parent_id: UUID | None
    created_at: datetime
    shadowed: bool
