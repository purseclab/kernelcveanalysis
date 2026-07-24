from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
import shutil
import tempfile
from typing import Any, cast
from uuid import UUID, uuid4

from kexploit_utils import artifact_folder  # type: ignore[attr-defined]
from pydantic import ValidationError
from sqlalchemy import Engine, event, select
from sqlalchemy.engine import create_engine
from sqlalchemy.orm import Session, sessionmaker

from .errors import (
    ArtifactConflictError,
    ArtifactNotFoundError,
    InvalidArtifactError,
    SourceUpdateError,
    UnsafeArtifactEntryError,
)
from .filesystem import (
    atomic_write_text,
    cleanup_destination,
    copy_tree_contents,
    ensure_outside_storage,
    prepare_empty_destination,
    validate_tree,
)
from .models import ArtifactHeader, ArtifactInfo, ArtifactMetadata, ArtifactRecord
from .registry import ArtifactDefinition, ArtifactRegistry
from .toml_io import ARTIFACT_FILE_NAME, parse_artifact, render_artifact


class ArtifactStore:
    def __init__(
        self,
        registry: ArtifactRegistry,
        root: Path | None = None,
    ) -> None:
        self.registry = registry
        self.root = (root if root is not None else artifact_folder()).resolve()
        self.blob_folder = self.root / "blobs"
        self.database_path = self.root / "artifactdb.sqlite"
        self.root.mkdir(parents=True, exist_ok=True)
        self.blob_folder.mkdir(parents=True, exist_ok=True)

        self.engine = self._create_engine(self.database_path)
        ArtifactRecord.metadata.create_all(self.engine)
        self._sessions = sessionmaker(self.engine, expire_on_commit=False)

    @staticmethod
    def _create_engine(database_path: Path) -> Engine:
        engine = create_engine(f"sqlite:///{database_path}")

        @event.listens_for(engine, "connect")
        def enable_foreign_keys(dbapi_connection: Any, _: Any) -> None:
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()

        return engine

    def close(self) -> None:
        self.engine.dispose()

    def __enter__(self) -> ArtifactStore:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def create_template(
        self,
        artifact_type: str,
        folder: Path,
        *,
        name: str,
    ) -> Path:
        definition = self.registry.get(artifact_type)
        try:
            header = ArtifactHeader(type=artifact_type, name=name)
            metadata = definition.metadata_model.default()
        except ValidationError as exc:
            raise InvalidArtifactError(f"invalid artifact template: {exc}") from exc
        if not isinstance(metadata, definition.metadata_model):
            raise InvalidArtifactError("metadata default() returned the wrong model type")
        destination = Path(folder)
        ensure_outside_storage(destination, self.root)
        created = prepare_empty_destination(destination)

        try:
            template = definition.metadata_model.template_folder()
            if template is not None:
                template = Path(template)
                validate_tree(template)
                if (template / ARTIFACT_FILE_NAME).exists():
                    raise InvalidArtifactError(
                        "an artifact template folder cannot contain artifact.toml"
                    )
                copy_tree_contents(template, destination)
            output = destination / ARTIFACT_FILE_NAME
            atomic_write_text(output, render_artifact(header, metadata))
            return output
        except Exception:
            cleanup_destination(destination, created)
            raise

    def write_artifact(self, folder: Path) -> ArtifactInfo:
        source = Path(folder)
        ensure_outside_storage(source, self.root)
        validate_tree(source)
        artifact_toml = source / ARTIFACT_FILE_NAME
        if not artifact_toml.is_file():
            raise InvalidArtifactError(f"missing {ARTIFACT_FILE_NAME}: {artifact_toml}")

        header, metadata, definition = parse_artifact(artifact_toml, self.registry)
        new_id = uuid4()
        final_blob = self._blob_path(new_id, header.name)
        staging = Path(
            tempfile.mkdtemp(prefix=f".staging-{new_id.hex}-", dir=self.blob_folder)
        )
        final_created = False
        committed = False
        try:
            copy_tree_contents(source, staging, exclude_artifact_toml=True)
            with self._sessions() as session:
                session.connection().exec_driver_sql("BEGIN IMMEDIATE")
                old = self._validate_write_base(session, header, definition)
                record = metadata.build_updated_record(cast(Any, old))
                if not isinstance(record, definition.record_model):
                    raise InvalidArtifactError(
                        "metadata build_updated_record() returned the wrong "
                        "SQLAlchemy record type"
                    )

                record.id = new_id
                record.artifact_type = definition.type_name
                record.name = header.name
                record.parent_id = old.id if old is not None else None
                record.created_at = datetime.now(UTC)
                record.shadowed = False
                if old is not None and old.name == header.name:
                    old.shadowed = True
                session.add(record)
                session.flush()

                canonical_metadata = definition.metadata_model.from_record(record)
                if not isinstance(canonical_metadata, definition.metadata_model):
                    raise InvalidArtifactError(
                        "metadata from_record() returned the wrong model type"
                    )
                canonical_header = ArtifactHeader(
                    type=definition.type_name,
                    name=record.name,
                    id=record.id,
                    parent_id=record.parent_id,
                )
                rendered = render_artifact(canonical_header, canonical_metadata)
                (staging / ARTIFACT_FILE_NAME).write_text(rendered, encoding="utf-8")
                staging.rename(final_blob)
                final_created = True
                info = self._info_from_record(record)
                session.commit()
                committed = True
        except Exception:
            if staging.exists():
                shutil.rmtree(staging)
            if not committed and final_created and final_blob.exists():
                shutil.rmtree(final_blob)
            raise

        try:
            atomic_write_text(artifact_toml, rendered)
        except OSError as exc:
            raise SourceUpdateError(info, exc) from exc
        return info

    def list_artifacts(
        self,
        artifact_type: str,
        *,
        include_shadowed: bool = False,
    ) -> list[ArtifactInfo]:
        definition = self.registry.get(artifact_type)
        with self._sessions() as session:
            query = select(definition.record_model)
            if not include_shadowed:
                query = query.where(
                    definition.record_model.shadowed.is_(False)
                )
            query = query.order_by(
                definition.record_model.created_at.desc(),
                definition.record_model.id.desc(),
            )
            records = session.scalars(query)
            return [self._info_from_record(record) for record in records]

    def pull_artifact(self, artifact_id: UUID | str, destination: Path) -> ArtifactInfo:
        parsed_id = self._parse_uuid(artifact_id)
        ensure_outside_storage(destination, self.root)

        with self._sessions() as session:
            record = session.get(ArtifactRecord, parsed_id)
            if record is None:
                raise ArtifactNotFoundError(parsed_id)
            definition = self.registry.get(record.artifact_type)
            canonical_metadata = definition.metadata_model.from_record(record)
            if not isinstance(canonical_metadata, definition.metadata_model):
                raise InvalidArtifactError(
                    "metadata from_record() returned the wrong model type"
                )
            header = ArtifactHeader(
                type=record.artifact_type,
                name=record.name,
                id=record.id,
                parent_id=record.parent_id,
            )
            rendered = render_artifact(header, canonical_metadata)
            info = self._info_from_record(record)

        blob = self._blob_path(record.id, record.name)
        if not blob.is_dir():
            raise InvalidArtifactError(f"artifact blob is missing: {blob}")
        validate_tree(blob)
        created = prepare_empty_destination(destination)
        try:
            copy_tree_contents(blob, destination, exclude_artifact_toml=True)
            atomic_write_text(destination / ARTIFACT_FILE_NAME, rendered)
        except Exception:
            cleanup_destination(destination, created)
            raise
        return info

    # given a new header to write, and an artifact type definition, validates write is allowed
    # returns old parent being overwritten if it exists, or None if no parent
    def _validate_write_base(
        self,
        session: Session,
        header: ArtifactHeader,
        definition: ArtifactDefinition[Any, Any],
    ) -> ArtifactRecord | None:
        # first validate no duplicate non-shadowed names
        heads = list(
            session.scalars(
                select(definition.record_model).where(
                    definition.record_model.name == header.name,
                    definition.record_model.shadowed.is_(False),
                )
            )
        )
        if len(heads) > 1:
            raise ArtifactConflictError(
                f"artifact name has multiple visible heads: {definition.type_name}/{header.name}"
            )
        head = heads[0] if heads else None

        # creating a fresh artifact with no parent when one with name already exists not allowed
        if header.id is None:
            if head is not None:
                raise ArtifactConflictError(
                    f"artifact name already exists: {definition.type_name}/{header.name}"
                )
            return None

        old = session.get(ArtifactRecord, header.id)
        if old is None:
            raise ArtifactNotFoundError(header.id)
        if old.artifact_type != definition.type_name:
            raise ArtifactConflictError("an artifact revision cannot change type")
        if old.parent_id != header.parent_id:
            raise ArtifactConflictError("parent_id does not match the stored base revision")
        if head is not None and head.id != old.id:
            raise ArtifactConflictError(
                f"stale write: {definition.type_name}/{header.name} has a newer head"
            )
        return old

    @staticmethod
    def _info_from_record(record: ArtifactRecord) -> ArtifactInfo:
        created_at = record.created_at
        if created_at.tzinfo is None:
            created_at = created_at.replace(tzinfo=UTC)
        return ArtifactInfo(
            id=record.id,
            artifact_type=record.artifact_type,
            name=record.name,
            parent_id=record.parent_id,
            created_at=created_at,
            shadowed=record.shadowed,
        )

    def _blob_path(self, artifact_id: UUID, name: str) -> Path:
        return self.blob_folder / f"{artifact_id.hex}_{name}"

    @staticmethod
    def _parse_uuid(artifact_id: UUID | str) -> UUID:
        if isinstance(artifact_id, UUID):
            return artifact_id
        try:
            return UUID(artifact_id)
        except ValueError as exc:
            raise InvalidArtifactError(f"invalid artifact id: {artifact_id}") from exc
