from __future__ import annotations

from pathlib import Path
import json
import os
import shutil
import tomllib
from typing import ClassVar, Iterator, Self
from uuid import UUID
from uuid import uuid4

import pytest  # type: ignore[import-not-found]
from sqlalchemy import ForeignKey, String, select
from sqlalchemy.orm import Mapped, mapped_column
import tomli_w
from typer.testing import CliRunner

from kartifact import (
    ArtifactConflictError,
    ArtifactDefinition,
    ArtifactMetadata,
    ArtifactRecord,
    ArtifactRegistry,
    ArtifactStore,
    DestinationNotEmptyError,
    InvalidArtifactError,
    RegistryError,
    SourceUpdateError,
    UnsafeArtifactEntryError,
)
from kartifact import cli


class NoteRecord(ArtifactRecord):
    __tablename__ = "note_artifacts"

    id: Mapped[UUID] = mapped_column(
        ForeignKey("artifacts.id", ondelete="CASCADE"),
        primary_key=True,
    )
    value: Mapped[str] = mapped_column(String(200), nullable=False)

    __mapper_args__ = {"polymorphic_identity": "note"}


class NoteMetadata(ArtifactMetadata[NoteRecord]):
    value: str = "new note"

    template: ClassVar[Path | None] = None

    @classmethod
    def default(cls) -> Self:
        return cls()

    @classmethod
    def template_folder(cls) -> Path | None:
        return cls.template

    def build_updated_record(self, old: NoteRecord | None) -> NoteRecord:
        del old
        return NoteRecord(value=self.value.strip())


NOTE_DEFINITION = ArtifactDefinition(
    type_name="note",
    metadata_model=NoteMetadata,
    record_model=NoteRecord,
)


@pytest.fixture
def registry() -> ArtifactRegistry:
    value = ArtifactRegistry()
    value.register(NOTE_DEFINITION)
    return value


@pytest.fixture
def store(tmp_path: Path, registry: ArtifactRegistry) -> Iterator[ArtifactStore]:
    value = ArtifactStore(registry, tmp_path / "database")
    yield value
    value.close()


def read_toml(folder: Path) -> dict[str, object]:
    return tomllib.loads((folder / "artifact.toml").read_text(encoding="utf-8"))


def edit_document(folder: Path, update: object) -> None:
    document = read_toml(folder)
    assert isinstance(document["metadata"], dict)
    document["metadata"]["value"] = update
    (folder / "artifact.toml").write_text(tomli_w.dumps(document), encoding="utf-8")


def rename_document(folder: Path, name: str) -> None:
    document = read_toml(folder)
    assert isinstance(document["artifact"], dict)
    document["artifact"]["name"] = name
    (folder / "artifact.toml").write_text(tomli_w.dumps(document), encoding="utf-8")


def test_registry_rejects_duplicates(registry: ArtifactRegistry) -> None:
    with pytest.raises(RegistryError, match="already registered"):
        registry.register(NOTE_DEFINITION)


def test_create_template_copies_defaults_and_files(
    tmp_path: Path,
    store: ArtifactStore,
) -> None:
    template = tmp_path / "template"
    template.mkdir()
    (template / "README.txt").write_text("starter", encoding="utf-8")
    NoteMetadata.template = template
    try:
        destination = tmp_path / "working"
        output = store.create_template("note", destination, name="first-note")
    finally:
        NoteMetadata.template = None

    assert output == destination / "artifact.toml"
    assert (destination / "README.txt").read_text(encoding="utf-8") == "starter"
    document = read_toml(destination)
    assert document == {
        "artifact": {"type": "note", "name": "first-note"},
        "metadata": {"value": "new note"},
    }


def test_create_requires_empty_destination(tmp_path: Path, store: ArtifactStore) -> None:
    destination = tmp_path / "working"
    destination.mkdir()
    (destination / "keep").write_text("data", encoding="utf-8")

    with pytest.raises(DestinationNotEmptyError):
        store.create_template("note", destination, name="first-note")
    assert (destination / "keep").read_text(encoding="utf-8") == "data"


def test_write_versions_shadowing_and_named_fork(
    tmp_path: Path,
    store: ArtifactStore,
) -> None:
    working = tmp_path / "working"
    store.create_template("note", working, name="alpha")
    edit_document(working, "  first  ")
    first = store.write_artifact(working)
    first_document = read_toml(working)
    assert first_document["artifact"] == {
        "type": "note",
        "name": "alpha",
        "id": str(first.id),
    }
    assert first_document["metadata"] == {"value": "first"}
    assert (store.blob_folder / f"{first.id.hex}_alpha").is_dir()

    stale = tmp_path / "stale"
    shutil.copytree(working, stale)
    edit_document(working, "second")
    second = store.write_artifact(working)
    assert second.parent_id == first.id

    with pytest.raises(ArtifactConflictError, match="stale write"):
        store.write_artifact(stale)

    rename_document(stale, "beta")
    fork = store.write_artifact(stale)
    assert fork.parent_id == first.id
    assert fork.name == "beta"

    visible = store.list_artifacts("note")
    assert {(item.name, item.id) for item in visible} == {
        ("alpha", second.id),
        ("beta", fork.id),
    }
    all_revisions = store.list_artifacts("note", include_shadowed=True)
    assert len(all_revisions) == 3
    assert next(item for item in all_revisions if item.id == first.id).shadowed
    with store.engine.connect() as connection:
        rows = connection.execute(
            select(ArtifactRecord.id, ArtifactRecord.shadowed)
        ).tuples()
        persisted: dict[UUID, bool] = {
            artifact_id: shadowed for artifact_id, shadowed in rows
        }
    assert persisted == {
        first.id: True,
        second.id: False,
        fork.id: False,
    }


def test_named_fork_does_not_shadow_original_head(
    tmp_path: Path,
    store: ArtifactStore,
) -> None:
    original = tmp_path / "original"
    store.create_template("note", original, name="alpha")
    first = store.write_artifact(original)

    fork_folder = tmp_path / "fork"
    shutil.copytree(original, fork_folder)
    rename_document(fork_folder, "beta")
    fork = store.write_artifact(fork_folder)

    visible = store.list_artifacts("note")
    assert {(item.id, item.name, item.shadowed) for item in visible} == {
        (first.id, "alpha", False),
        (fork.id, "beta", False),
    }


def test_write_rejects_changed_parent_id(tmp_path: Path, store: ArtifactStore) -> None:
    working = tmp_path / "working"
    store.create_template("note", working, name="alpha")
    first = store.write_artifact(working)
    edit_document(working, "second")
    second = store.write_artifact(working)
    document = read_toml(working)
    assert isinstance(document["artifact"], dict)
    document["artifact"]["parent_id"] = str(uuid4())
    (working / "artifact.toml").write_text(tomli_w.dumps(document), encoding="utf-8")

    with pytest.raises(ArtifactConflictError, match="parent_id"):
        store.write_artifact(working)
    assert store.list_artifacts("note")[0].id == second.id


def test_pull_by_id_renders_authoritative_toml(
    tmp_path: Path,
    store: ArtifactStore,
) -> None:
    working = tmp_path / "working"
    store.create_template("note", working, name="alpha")
    (working / "payload.bin").write_bytes(b"payload")
    first = store.write_artifact(working)
    edit_document(working, "second")
    store.write_artifact(working)

    destination = tmp_path / "pulled"
    pulled = store.pull_artifact(first.id, destination)
    assert pulled.id == first.id
    assert pulled.shadowed
    assert (destination / "payload.bin").read_bytes() == b"payload"
    assert read_toml(destination)["artifact"] == {
        "type": "note",
        "name": "alpha",
        "id": str(first.id),
    }

    nonempty = tmp_path / "nonempty"
    nonempty.mkdir()
    (nonempty / "keep").touch()
    with pytest.raises(DestinationNotEmptyError):
        store.pull_artifact(first.id, nonempty)


def test_rejects_symlinks_and_special_files(tmp_path: Path, store: ArtifactStore) -> None:
    working = tmp_path / "working"
    store.create_template("note", working, name="alpha")
    (working / "link").symlink_to(working / "artifact.toml")
    with pytest.raises(UnsafeArtifactEntryError, match="symbolic link"):
        store.write_artifact(working)
    (working / "link").unlink()

    fifo = working / "pipe"
    os.mkfifo(fifo)
    try:
        with pytest.raises(UnsafeArtifactEntryError, match="regular files"):
            store.write_artifact(working)
    finally:
        fifo.unlink()


def test_source_update_failure_keeps_committed_revision(
    tmp_path: Path,
    store: ArtifactStore,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    working = tmp_path / "working"
    store.create_template("note", working, name="alpha")

    def fail_write(path: Path, text: str) -> None:
        del path, text
        raise OSError("read-only source")

    monkeypatch.setattr("kartifact.store.atomic_write_text", fail_write)
    with pytest.raises(SourceUpdateError) as raised:
        store.write_artifact(working)
    committed = raised.value.artifact
    assert store.list_artifacts("note")[0].id == committed.id
    assert (store.blob_folder / f"{committed.id.hex}_alpha").is_dir()


def test_invalid_toml_and_names(tmp_path: Path, store: ArtifactStore) -> None:
    with pytest.raises(InvalidArtifactError):
        store.create_template("note", tmp_path / "bad", name="../bad")

    working = tmp_path / "working"
    working.mkdir()
    (working / "artifact.toml").write_text("not = [valid", encoding="utf-8")
    with pytest.raises(InvalidArtifactError):
        store.write_artifact(working)


def test_cli_human_and_json_workflows(
    tmp_path: Path,
    registry: ArtifactRegistry,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "database"
    monkeypatch.setattr(cli, "_build_store", lambda: ArtifactStore(registry, root))
    runner = CliRunner()
    working = tmp_path / "working"

    created = runner.invoke(
        cli.app,
        ["create", "note", str(working), "--name", "cli-note"],
    )
    assert created.exit_code == 0, created.output
    assert "Created" in created.output

    written = runner.invoke(cli.app, ["--json", "write", str(working)])
    assert written.exit_code == 0, written.output
    written_payload = json.loads(written.stdout)
    assert written_payload["name"] == "cli-note"

    listed = runner.invoke(cli.app, ["--json", "list", "note"])
    assert listed.exit_code == 0, listed.output
    listed_payload = json.loads(listed.stdout)
    assert len(listed_payload["artifacts"]) == 1

    pulled = runner.invoke(
        cli.app,
        ["--json", "pull", written_payload["id"], str(tmp_path / "pulled")],
    )
    assert pulled.exit_code == 0, pulled.output
