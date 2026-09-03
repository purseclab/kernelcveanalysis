from __future__ import annotations

from typing import Any, Self
from uuid import UUID

from pydantic import Field
from sqlalchemy import ForeignKey, JSON, String, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from ..models import ArtifactMetadata, ArtifactRecord
from ..registry import ArtifactDefinition


class AndroidSystemRecord(ArtifactRecord):
    __tablename__ = "android_system_artifacts"

    id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("artifacts.id", ondelete="CASCADE"),
        primary_key=True,
    )
    kernel_name: Mapped[str] = mapped_column(String(128), nullable=False)
    app_names: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)

    __mapper_args__ = {"polymorphic_identity": "android_system"}


class AndroidSystemMetadata(ArtifactMetadata[AndroidSystemRecord]):
    kernel_name: str
    app_names: list[str] = Field(default_factory=list)

    mandatory_files = ()
    optional_files = ()

    @classmethod
    def default(cls) -> Self:
        return cls(kernel_name="")

    def build_updated_record(self, old: AndroidSystemRecord | None) -> AndroidSystemRecord:
        del old
        return AndroidSystemRecord(
            kernel_name=self.kernel_name,
            app_names=list(self.app_names),
        )

    def validate_store(self, store: Any) -> None:
        if not self.kernel_name:
            from ..errors import InvalidArtifactError

            raise InvalidArtifactError("android_system metadata requires non-empty 'kernel_name'")
        store.ensure_artifact_exists("kernel", self.kernel_name)
        for app_name in self.app_names:
            store.ensure_artifact_exists("android_app", app_name)


ANDROID_SYSTEM_DEFINITION = ArtifactDefinition(
    type_name="android_system",
    metadata_model=AndroidSystemMetadata,
    record_model=AndroidSystemRecord,
    supports_create=True,
)
