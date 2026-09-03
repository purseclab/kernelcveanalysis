from __future__ import annotations

from enum import StrEnum
from typing import Self
from uuid import UUID

from sqlalchemy import ForeignKey, String, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from ..models import ArtifactMetadata, ArtifactRecord
from ..registry import ArtifactDefinition


class AppFile(StrEnum):
    APK = "app.apk"


class AndroidAppRecord(ArtifactRecord):
    __tablename__ = "android_app_artifacts"

    id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("artifacts.id", ondelete="CASCADE"),
        primary_key=True,
    )
    package_name: Mapped[str | None] = mapped_column(String(256), nullable=True)

    __mapper_args__ = {"polymorphic_identity": "android_app"}


class AndroidAppMetadata(ArtifactMetadata[AndroidAppRecord]):
    package_name: str | None = None

    mandatory_files = AppFile
    optional_files = ()

    @classmethod
    def default(cls) -> Self:
        return cls()

    def build_updated_record(self, old: AndroidAppRecord | None) -> AndroidAppRecord:
        del old
        return AndroidAppRecord(
            package_name=self.package_name,
        )


ANDROID_APP_DEFINITION = ArtifactDefinition(
    type_name="android_app",
    metadata_model=AndroidAppMetadata,
    record_model=AndroidAppRecord,
    supports_create=True,
)
