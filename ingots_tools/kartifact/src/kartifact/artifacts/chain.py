from __future__ import annotations

from enum import StrEnum
from typing import Any, Self
from uuid import UUID

from pydantic import AliasChoices, BaseModel, Field
from sqlalchemy import ForeignKey, JSON, String, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from ..errors import InvalidArtifactError
from ..models import ArtifactMetadata, ArtifactRecord
from ..registry import ArtifactDefinition


class ChainType(StrEnum):
    REMOTE = "remote"
    LOCAL = "local"


class ChainStep(BaseModel):
    exploit: str
    role: str = ""
    chaining: str = ""


class ChainRecord(ArtifactRecord):
    __tablename__ = "chain_artifacts"

    id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("artifacts.id", ondelete="CASCADE"),
        primary_key=True,
    )
    target: Mapped[str] = mapped_column(String(128), nullable=False)
    chain_type: Mapped[str] = mapped_column(String(32), nullable=False)
    steps: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)

    __mapper_args__ = {"polymorphic_identity": "chain"}


class ChainMetadata(ArtifactMetadata[ChainRecord]):
    target: str
    chain_type: ChainType | str = Field(
        validation_alias=AliasChoices("chain_type", "type"),
    )
    steps: list[ChainStep] = Field(
        default_factory=list,
        validation_alias=AliasChoices("steps", "chain_steps"),
    )

    mandatory_files = ()
    optional_files = ()

    @classmethod
    def default(cls) -> Self:
        return cls(
            target="",
            chain_type=ChainType.LOCAL,
            steps=[],
        )

    def build_updated_record(self, old: ChainRecord | None) -> ChainRecord:
        del old
        return ChainRecord(
            target=self.target,
            chain_type=str(self.chain_type.value if isinstance(self.chain_type, ChainType) else self.chain_type),
            steps=[s.model_dump() for s in self.steps],
        )

    def validate_store(self, store: Any) -> None:
        if not self.target:
            raise InvalidArtifactError("chain metadata requires non-empty 'target'")
        store.ensure_artifact_exists("android_system", self.target)

        for idx, step in enumerate(self.steps):
            if not step.exploit:
                raise InvalidArtifactError(f"chain step #{idx + 1} requires non-empty 'exploit'")
            store.ensure_artifact_exists("exploit", step.exploit)


CHAIN_DEFINITION = ArtifactDefinition(
    type_name="chain",
    metadata_model=ChainMetadata,
    record_model=ChainRecord,
    supports_create=True,
)
