from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Generic, Iterator, TypeVar

from sqlalchemy import inspect

from .errors import RegistryError, UnknownArtifactTypeError
from .models import (
    TYPE_PATTERN,
    ArtifactMetadata,
    ArtifactRecord,
    RecordT,
)


MetadataT = TypeVar("MetadataT", bound=ArtifactMetadata[Any])


@dataclass(frozen=True)
class ArtifactDefinition(Generic[MetadataT, RecordT]):
    type_name: str
    metadata_model: type[MetadataT]
    record_model: type[RecordT]


class ArtifactRegistry:
    def __init__(self) -> None:
        self._definitions: dict[str, ArtifactDefinition[Any, Any]] = {}

    def register(
        self, definition: ArtifactDefinition[MetadataT, RecordT]
    ) -> ArtifactDefinition[MetadataT, RecordT]:
        if not TYPE_PATTERN.fullmatch(definition.type_name):
            raise RegistryError(
                "artifact type must be a lowercase slug of at most 64 characters"
            )
        if definition.type_name in self._definitions:
            raise RegistryError(
                f"artifact type is already registered: {definition.type_name}"
            )
        if not issubclass(definition.metadata_model, ArtifactMetadata):
            raise RegistryError("metadata_model must inherit ArtifactMetadata")
        if (
            definition.record_model is ArtifactRecord
            or not issubclass(definition.record_model, ArtifactRecord)
        ):
            raise RegistryError("record_model must be an ArtifactRecord subtype")

        mapper = inspect(definition.record_model)
        if mapper.polymorphic_identity != definition.type_name:
            raise RegistryError(
                "record polymorphic_identity must match the definition type_name"
            )
        if mapper.inherits is None:
            raise RegistryError("record_model must use SQLAlchemy joined inheritance")
        if mapper.local_table is ArtifactRecord.__table__:
            raise RegistryError("record_model must have its own joined table")

        self._definitions[definition.type_name] = definition
        return definition

    def get(self, artifact_type: str) -> ArtifactDefinition[Any, Any]:
        try:
            return self._definitions[artifact_type]
        except KeyError as exc:
            raise UnknownArtifactTypeError(artifact_type) from exc

    def __iter__(self) -> Iterator[ArtifactDefinition[Any, Any]]:
        return iter(self._definitions.values())


default_registry = ArtifactRegistry()
