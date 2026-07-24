from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import UTC, datetime
from pathlib import Path
import re
from typing import Any, Generic, Self, TypeVar
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator
from sqlalchemy import Boolean, DateTime, ForeignKey, Index, String, Uuid
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


# artifact document is deserialized from and serialized to toml
# it contains common header, and per artifact metadata
class ArtifactDocument(BaseModel):
    model_config = ConfigDict(extra="forbid")

    artifact: ArtifactHeader
    metadata: dict[str, Any]


# artifact info represents metadata returned by api actions, not anything stored internally
class ArtifactInfo(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: UUID
    artifact_type: str
    name: str
    parent_id: UUID | None
    created_at: datetime
    shadowed: bool
