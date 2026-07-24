# kartifact

Kartifact stores immutable, versioned artifact folders for the Ingots and
`kexploit` ecosystem. This package currently provides the generic storage and
type-definition framework; it intentionally does not define vulnerability,
exploit, kernel, application, Android-system, or chain artifact types yet.

## Storage

The default store is rooted at `kexploit_utils.artifact_folder()`, which resolves
to `$KEXPLOIT_DATA_DIR/artifacts`:

```text
artifacts/
├── artifactdb.sqlite
└── blobs/
    └── <uuid-hex>_<name>/
```

Every write creates a new UUID revision and blob. Existing database rows and
blobs are never updated in place, except that a same-name parent row's common
`shadowed` flag is set when its replacement is created.

## Python API

An artifact type has two inherited interfaces and one immutable definition that
pairs them:

```python
from pathlib import Path
from typing import Self
from uuid import UUID

from sqlalchemy import ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column

from kartifact import (
    ArtifactDefinition,
    ArtifactMetadata,
    ArtifactRecord,
    ArtifactRegistry,
    ArtifactStore,
)


class ExampleRecord(ArtifactRecord):
    __tablename__ = "example_artifacts"

    id: Mapped[UUID] = mapped_column(
        ForeignKey("artifacts.id"),
        primary_key=True,
    )
    description: Mapped[str] = mapped_column(String, nullable=False)

    __mapper_args__ = {"polymorphic_identity": "example"}


class ExampleMetadata(ArtifactMetadata[ExampleRecord]):
    description: str = ""

    @classmethod
    def default(cls) -> Self:
        return cls()

    @classmethod
    def template_folder(cls) -> Path | None:
        return None

    def build_updated_record(self, old: ExampleRecord | None) -> ExampleRecord:
        return ExampleRecord(description=self.description.strip())


EXAMPLE = ArtifactDefinition(
    type_name="example",
    metadata_model=ExampleMetadata,
    record_model=ExampleRecord,
)

registry = ArtifactRegistry()
registry.register(EXAMPLE)

with ArtifactStore(registry) as store:
    store.create_template("example", Path("work"), name="example-one")
    saved = store.write_artifact(Path("work"))
    visible = store.list_artifacts("example")
    store.pull_artifact(saved.id, Path("checkout"))
```

`ArtifactMetadata.build_updated_record()` returns a fresh subtype record
containing only the type-specific fields. Kartifact assigns the common ID, type,
name, parent, and creation time. `from_record()` renders authoritative database
values back to TOML and can be overridden when ORM and TOML field names do not
align.

The optional template folder contains every initial file except
`artifact.toml`; kartifact renders that file itself. Template and artifact trees
may contain only regular files and directories.

## `artifact.toml`

Templates omit revision fields:

```toml
[artifact]
type = "example"
name = "example-one"

[metadata]
description = ""
```

After writing, kartifact rewrites the working copy and stored blob with the new
revision identity:

```toml
[artifact]
type = "example"
name = "example-one"
id = "e0401d6e-ae87-49a2-a365-3bf654a68036"
parent_id = "2b3d9af1-24dd-47f7-94d6-668274a107ef"

[metadata]
description = "canonical database value"
```

On the next write, `id` identifies the revision being edited. `parent_id` is
read-only provenance and must still match that stored revision. Writing the same
name succeeds only when `id` is its current head. A stale revision can instead
be intentionally forked by changing to an unused name.

## CLI

The CLI uses kartifact's process-wide default registry. Future built-in artifact
types register their definitions there during package composition.

```bash
uv run kartifact create TYPE FOLDER --name NAME
uv run kartifact write FOLDER
uv run kartifact list TYPE
uv run kartifact list TYPE --include-shadowed
uv run kartifact pull REVISION_ID FOLDER
```

Place global `--json` before the command for machine-readable output:

```bash
uv run kartifact --json list TYPE
```

Create and pull require a missing or empty destination. Pull always addresses an
immutable UUID revision, including revisions hidden from the default list.
