from __future__ import annotations

from uuid import UUID

from .models import ArtifactInfo


class KartifactError(Exception):
    """Base class for expected kartifact failures."""

    code = "kartifact_error"


class RegistryError(KartifactError):
    code = "registry_error"


class UnknownArtifactTypeError(KartifactError):
    code = "unknown_artifact_type"

    def __init__(self, artifact_type: str) -> None:
        super().__init__(f"unknown artifact type: {artifact_type}")
        self.artifact_type = artifact_type


class InvalidArtifactError(KartifactError):
    code = "invalid_artifact"


class ArtifactConflictError(KartifactError):
    code = "artifact_conflict"


class ArtifactNotFoundError(KartifactError):
    code = "artifact_not_found"

    def __init__(self, artifact_id: UUID | str) -> None:
        super().__init__(f"artifact not found: {artifact_id}")
        self.artifact_id = artifact_id


class DestinationNotEmptyError(KartifactError):
    code = "destination_not_empty"


class UnsafeArtifactEntryError(KartifactError):
    code = "unsafe_artifact_entry"


class SourceUpdateError(KartifactError):
    code = "source_update_failed"

    def __init__(self, artifact: ArtifactInfo, cause: OSError) -> None:
        super().__init__(
            f"artifact {artifact.id} was committed, but source artifact.toml "
            f"could not be updated: {cause}"
        )
        self.artifact = artifact
        self.cause = cause

