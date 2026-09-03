from __future__ import annotations

from enum import StrEnum
from pathlib import Path
from typing import ClassVar, Iterator, Self
from uuid import UUID

import pytest  # type: ignore[import-not-found]
from sqlalchemy import ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column

from kartifact import (
    ArtifactDefinition,
    ArtifactMetadata,
    ArtifactRecord,
    ArtifactRegistry,
    ArtifactStore,
    InvalidArtifactError,
)
from kartifact.toml_io import ARTIFACT_FILE_NAME, render_artifact
from kartifact.models import ArtifactHeader


class SampleMandatoryFile(StrEnum):
    MAIN = "main.txt"
    DATA = "data.bin"


class SampleOptionalFile(StrEnum):
    EXTRA = "extra.txt"
    CONFIG = "config.json"


class SampleRecord(ArtifactRecord):
    __tablename__ = "sample_artifacts"

    id: Mapped[UUID] = mapped_column(
        ForeignKey("artifacts.id", ondelete="CASCADE"),
        primary_key=True,
    )
    title: Mapped[str] = mapped_column(String(100), default="title")

    __mapper_args__ = {"polymorphic_identity": "sample"}


class SampleMetadata(ArtifactMetadata[SampleRecord]):
    title: str = "sample"

    mandatory_files: ClassVar = SampleMandatoryFile
    optional_files: ClassVar = SampleOptionalFile

    @classmethod
    def default(cls) -> Self:
        return cls()

    def build_updated_record(self, old: SampleRecord | None) -> SampleRecord:
        del old
        return SampleRecord(title=self.title)


SAMPLE_DEFINITION = ArtifactDefinition(
    type_name="sample",
    metadata_model=SampleMetadata,
    record_model=SampleRecord,
)


@pytest.fixture
def registry() -> ArtifactRegistry:
    reg = ArtifactRegistry()
    reg.register(SAMPLE_DEFINITION)
    return reg


@pytest.fixture
def store(tmp_path: Path, registry: ArtifactRegistry) -> Iterator[ArtifactStore]:
    val = ArtifactStore(registry, tmp_path / "db")
    yield val
    val.close()


def test_metadata_file_definitions() -> None:
    assert SampleMetadata.get_mandatory_files() == ("main.txt", "data.bin")
    assert SampleMetadata.get_optional_files() == ("extra.txt", "config.json")
    assert SAMPLE_DEFINITION.mandatory_files == ("main.txt", "data.bin")
    assert SAMPLE_DEFINITION.optional_files == ("extra.txt", "config.json")


def test_metadata_read_methods_mandatory_and_optional(tmp_path: Path) -> None:
    folder = tmp_path / "artifact_folder"
    folder.mkdir()
    (folder / "main.txt").write_text("hello world", encoding="utf-8")
    (folder / "data.bin").write_bytes(b"\x01\x02\x03\x04")
    (folder / "extra.txt").write_text("optional extra", encoding="utf-8")

    meta = SampleMetadata(title="test").bind_folder(folder)

    # Mandatory methods
    assert meta.get_path(SampleMandatoryFile.MAIN) == folder / "main.txt"
    assert meta.read_str(SampleMandatoryFile.MAIN) == "hello world"
    assert meta.read_bytes(SampleMandatoryFile.DATA) == b"\x01\x02\x03\x04"

    # Reading with explicit folder
    assert meta.read_str(SampleMandatoryFile.MAIN, folder=folder) == "hello world"

    # Optional methods - present
    assert meta.get_optional_path(SampleOptionalFile.EXTRA) == folder / "extra.txt"
    assert meta.read_optional_str(SampleOptionalFile.EXTRA) == "optional extra"
    assert meta.read_optional_bytes(SampleOptionalFile.EXTRA) == b"optional extra"

    # Optional methods - missing
    assert meta.get_optional_path(SampleOptionalFile.CONFIG) is None
    assert meta.read_optional_bytes(SampleOptionalFile.CONFIG) is None
    assert meta.read_optional_str(SampleOptionalFile.CONFIG) is None

    # Missing mandatory file raises FileNotFoundError
    (folder / "main.txt").unlink()
    with pytest.raises(FileNotFoundError):
        meta.get_path(SampleMandatoryFile.MAIN)
    with pytest.raises(FileNotFoundError):
        meta.read_str(SampleMandatoryFile.MAIN)
    with pytest.raises(FileNotFoundError):
        meta.read_bytes(SampleMandatoryFile.MAIN)


def test_metadata_read_methods_validation_errors(tmp_path: Path) -> None:
    meta = SampleMetadata(title="test").bind_folder(tmp_path)

    # Calling mandatory method on an optional file raises ValueError
    with pytest.raises(ValueError, match="is an optional file; use get_optional_path"):
        meta.get_path(SampleOptionalFile.EXTRA)
    with pytest.raises(ValueError, match="is an optional file; use get_optional_path"):
        meta.read_str(SampleOptionalFile.EXTRA)

    # Calling optional method on a mandatory file raises ValueError
    with pytest.raises(ValueError, match="is a mandatory file; use get_path"):
        meta.get_optional_path(SampleMandatoryFile.MAIN)
    with pytest.raises(ValueError, match="is a mandatory file; use get_path"):
        meta.read_optional_bytes(SampleMandatoryFile.MAIN)

    # Calling with an unregistered file raises ValueError
    with pytest.raises(ValueError, match="is not a registered mandatory file"):
        meta.get_path("unregistered.txt")
    with pytest.raises(ValueError, match="is not a registered optional file"):
        meta.get_optional_path("unregistered.txt")

    # Calling without bound folder raises ValueError
    unbound_meta = SampleMetadata(title="test")
    with pytest.raises(ValueError, match="not bound to a folder"):
        unbound_meta.get_path(SampleMandatoryFile.MAIN)


def test_store_write_verifies_mandatory_files(tmp_path: Path, store: ArtifactStore) -> None:
    folder = tmp_path / "working"
    folder.mkdir()
    header = ArtifactHeader(type="sample", name="item-one")
    meta = SampleMetadata(title="hello")
    (folder / ARTIFACT_FILE_NAME).write_text(render_artifact(header, meta), encoding="utf-8")

    # Missing both main.txt and data.bin
    with pytest.raises(InvalidArtifactError, match="missing mandatory file for artifact: main.txt"):
        store.write_artifact(folder)

    (folder / "main.txt").write_text("content", encoding="utf-8")
    # Still missing data.bin
    with pytest.raises(InvalidArtifactError, match="missing mandatory file for artifact: data.bin"):
        store.write_artifact(folder)

    (folder / "data.bin").write_bytes(b"data")
    # Now valid!
    info = store.write_artifact(folder)
    assert info.name == "item-one"


def test_store_get_artifact_returns_bound_metadata(tmp_path: Path, store: ArtifactStore) -> None:
    folder = tmp_path / "working"
    folder.mkdir()
    header = ArtifactHeader(type="sample", name="item-two")
    meta = SampleMetadata(title="get_artifact_test")
    (folder / ARTIFACT_FILE_NAME).write_text(render_artifact(header, meta), encoding="utf-8")
    (folder / "main.txt").write_text("main data", encoding="utf-8")
    (folder / "data.bin").write_bytes(b"\xaa\xbb")
    (folder / "config.json").write_text('{"key": "val"}', encoding="utf-8")

    info = store.write_artifact(folder)

    # Fetch via store.get_artifact
    retrieved = store.get_artifact(info.id)
    assert isinstance(retrieved, SampleMetadata)
    assert retrieved.title == "get_artifact_test"
    assert retrieved.read_str(SampleMandatoryFile.MAIN) == "main data"
    assert retrieved.read_bytes(SampleMandatoryFile.DATA) == b"\xaa\xbb"
    assert retrieved.read_optional_str(SampleOptionalFile.CONFIG) == '{"key": "val"}'
    assert retrieved.read_optional_bytes(SampleOptionalFile.EXTRA) is None

    # Fetch with expected_type
    typed = store.get_artifact(info.id, SampleMetadata)
    assert typed.title == "get_artifact_test"

    # Type mismatch raises InvalidArtifactError
    class OtherRecord(ArtifactRecord):
        __tablename__ = "other_artifacts"
        id: Mapped[UUID] = mapped_column(ForeignKey("artifacts.id", ondelete="CASCADE"), primary_key=True)
        __mapper_args__ = {"polymorphic_identity": "other"}

    class OtherMetadata(ArtifactMetadata[OtherRecord]):
        @classmethod
        def default(cls) -> Self:
            return cls()
        def build_updated_record(self, old: OtherRecord | None) -> OtherRecord:
            del old
            return OtherRecord()

    with pytest.raises(InvalidArtifactError, match="is of type 'sample', expected 'OtherMetadata'"):
        store.get_artifact(info.id, OtherMetadata)


def test_file_overrides_resolution_and_reading(tmp_path: Path) -> None:
    folder = tmp_path / "working"
    sub = folder / "custom_dir"
    sub.mkdir(parents=True)
    (sub / "special_main.txt").write_text("overridden content", encoding="utf-8")
    (folder / "data.bin").write_bytes(b"\x99")

    meta = SampleMetadata(title="test").bind_folder(folder)
    meta.set_file_overrides({"main.txt": "custom_dir/special_main.txt"})

    assert meta.file_overrides == {"main.txt": "custom_dir/special_main.txt"}
    assert meta.get_path(SampleMandatoryFile.MAIN) == sub / "special_main.txt"
    assert meta.read_str(SampleMandatoryFile.MAIN) == "overridden content"

    # Default data.bin is still resolved to root of artifact
    assert meta.get_path(SampleMandatoryFile.DATA) == folder / "data.bin"

    # verify_folder verifies the overridden path
    meta.verify_folder(folder)

    # Missing overridden file fails verify_folder
    (sub / "special_main.txt").unlink()
    with pytest.raises(InvalidArtifactError, match="missing mandatory file for artifact: custom_dir/special_main.txt"):
        meta.verify_folder(folder)


def test_file_overrides_validation_errors() -> None:
    meta = SampleMetadata(title="test")

    # Unknown key
    with pytest.raises(InvalidArtifactError, match="unknown file override key 'bogus.txt'"):
        meta.set_file_overrides({"bogus.txt": "path.txt"})

    # Absolute path
    with pytest.raises(InvalidArtifactError, match="cannot be an absolute path"):
        meta.set_file_overrides({"main.txt": "/etc/passwd"})

    # Path traversal
    with pytest.raises(InvalidArtifactError, match="cannot contain '\\.\\.'"):
        meta.set_file_overrides({"main.txt": "../outside.txt"})

    # Target artifact.toml
    with pytest.raises(InvalidArtifactError, match="cannot point to artifact.toml"):
        meta.set_file_overrides({"main.txt": "artifact.toml"})


def test_file_overrides_in_toml_parsing_and_store_roundtrip(tmp_path: Path, store: ArtifactStore) -> None:
    folder = tmp_path / "working"
    folder.mkdir()
    sub = folder / "nested"
    sub.mkdir()
    (sub / "custom_main.txt").write_text("nested main", encoding="utf-8")
    (folder / "data.bin").write_bytes(b"\x12\x34")

    # Write artifact.toml with [file_overrides] table
    toml_content = """
[artifact]
type = "sample"
name = "overridden-artifact"

[file_overrides]
"main.txt" = "nested/custom_main.txt"

[metadata]
title = "override_title"
"""
    (folder / ARTIFACT_FILE_NAME).write_text(toml_content, encoding="utf-8")

    info = store.write_artifact(folder)

    # 1. Check get_artifact loads and uses the override
    retrieved = store.get_artifact(info.id, SampleMetadata)
    assert retrieved.file_overrides == {"main.txt": "nested/custom_main.txt"}
    assert retrieved.read_str(SampleMandatoryFile.MAIN) == "nested main"
    assert retrieved.read_bytes(SampleMandatoryFile.DATA) == b"\x12\x34"

    # 2. Check pull_artifact writes out [file_overrides]
    checkout = tmp_path / "checkout"
    store.pull_artifact(info.id, checkout)
    pulled_toml = (checkout / ARTIFACT_FILE_NAME).read_text(encoding="utf-8")
    assert "[file_overrides]" in pulled_toml
    assert '"main.txt" = "nested/custom_main.txt"' in pulled_toml
    assert (checkout / "nested" / "custom_main.txt").read_text(encoding="utf-8") == "nested main"


def test_toml_alternative_table_names_for_overrides(tmp_path: Path, registry: ArtifactRegistry) -> None:
    from kartifact.toml_io import parse_artifact

    folder = tmp_path / "test_files_table"
    folder.mkdir()
    (folder / "nested.txt").write_text("ok", encoding="utf-8")
    (folder / "data.bin").write_bytes(b"\x00")

    # Using [files] alias table
    toml_content = """
[artifact]
type = "sample"
name = "alias-test"

[files]
"main.txt" = "nested.txt"

[metadata]
title = "alias"
"""
    toml_file = folder / ARTIFACT_FILE_NAME
    toml_file.write_text(toml_content, encoding="utf-8")
    _, meta, _ = parse_artifact(toml_file, registry)
    assert meta.file_overrides == {"main.txt": "nested.txt"}
    assert meta.read_str(SampleMandatoryFile.MAIN) == "ok"
