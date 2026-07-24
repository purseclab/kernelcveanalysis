---
name: kartifact
description: Create, write, list, and pull versioned exploit artifact folders through the kartifact CLI.
---

# Kartifact CLI

Use kartifact when an unmanaged agent needs to exchange an artifact folder with
the Ingots artifact database. The artifact type must come from the task or that
type's documentation; kartifact intentionally has no type-discovery command.

## Rules

- Run the CLI from the Ingots Tools workspace with `uv run kartifact`.
- Do not modify `artifactdb.sqlite` or anything under the managed `blobs/`
  directory directly.
- Treat `artifact.id` in `artifact.toml` as the checked-out revision token.
- Do not edit `artifact.parent_id`; it is rendered provenance.
- Use a missing or empty folder for `create` and `pull`.
- Artifact trees may contain only regular files and directories. Do not add
  symlinks, sockets, pipes, or device files.
- Prefer `--json` when consuming output programmatically. It is a global option
  and must precede the command.

## Create a working template

```bash
uv run kartifact create <type> <folder> --name <safe-name>
```

The name may contain letters, digits, `.`, `_`, and `-`. Edit the generated
`artifact.toml` metadata and add the artifact's files before writing it.

## Store a revision

```bash
uv run kartifact --json write <folder>
```

A successful write creates an immutable database revision and rewrites the
working folder's `artifact.toml` with its new `id` and `parent_id`. Keep using
that rewritten folder for later revisions.

If a write reports a stale-head conflict, another revision already advanced the
same type/name. Either pull the newer revision and reapply the work, or choose a
new unused name in `artifact.toml` to create an intentional fork. Never remove
or replace the ID to bypass a conflict.

If kartifact reports `source_update_failed`, the returned artifact ID was
committed even though the working TOML could not be rewritten. Pull that ID into
a new empty folder before continuing.

## List artifacts

```bash
uv run kartifact list <type>
uv run kartifact --json list <type>
uv run kartifact --json list <type> --include-shadowed
```

The default list contains visible name heads. Use `--include-shadowed` when an
older immutable revision is needed.

## Pull an exact revision

```bash
uv run kartifact --json pull <revision-id> <empty-folder>
```

Pull always selects by UUID, copies that revision's files, and renders canonical
database metadata into `artifact.toml`.

