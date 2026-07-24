from __future__ import annotations

from pathlib import Path
import tomllib
from typing import Any

from pydantic import ValidationError
import tomli_w

from .errors import InvalidArtifactError
from .models import ArtifactDocument, ArtifactHeader, ArtifactMetadata
from .registry import ArtifactDefinition, ArtifactRegistry


ARTIFACT_FILE_NAME = "artifact.toml"


def parse_artifact(
    path: Path, registry: ArtifactRegistry
) -> tuple[ArtifactHeader, ArtifactMetadata[Any], ArtifactDefinition[Any, Any]]:
    try:
        raw = tomllib.loads(path.read_text(encoding="utf-8"))
        document = ArtifactDocument.model_validate(raw)
        definition = registry.get(document.artifact.artifact_type)
        metadata = definition.metadata_model.model_validate(document.metadata)
    except (OSError, tomllib.TOMLDecodeError, ValidationError) as exc:
        raise InvalidArtifactError(f"invalid {ARTIFACT_FILE_NAME}: {exc}") from exc
    return document.artifact, metadata, definition


def render_artifact(
    header: ArtifactHeader,
    metadata: ArtifactMetadata[Any],
) -> str:
    document: dict[str, Any] = {
        "artifact": header.model_dump(
            mode="json",
            by_alias=True,
            exclude_none=True,
        ),
        "metadata": metadata.model_dump(mode="json", exclude_none=True),
    }
    try:
        return tomli_w.dumps(document)
    except (TypeError, ValueError) as exc:
        raise InvalidArtifactError(f"metadata cannot be represented as TOML: {exc}") from exc

