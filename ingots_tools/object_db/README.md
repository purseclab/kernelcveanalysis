# object_db

Kernel type layouts and allocation sites exported from CodeQL into SQLite, used by
`kexploit`. CodeQL queries are the sole source of type identity, sizes, alignment,
fields, and allocation-to-type links. Building an object database does not require
BTF, `bpftool`, or `vmlinux`.

Create a database from a CodeQL extraction of the target kernel build:

```bash
uv run objectdb create \
  --kernel my_kernel \
  --codeql-db /path/to/codeql-db \
  --linux-src /path/to/linux-src \
  --compile-commands /path/to/compile_commands.json
uv run objectdb --kernel my_kernel stats
uv run objectdb --kernel my_kernel sizeof file
uv run objectdb --kernel my_kernel field-offset file.f_pos_lock.wait_list
```

The CodeQL extraction must match the target architecture, kernel configuration,
generated headers, and compiler options. `--vmlinux` remains an optional metadata
reference for callers that also use a kernel binary; it does not affect extraction.

SQLite contains `types`, `fields`, `objects`, and `kmalloc_calls`. Types and links
use CodeQL entity IDs, scoped to the extracted CodeQL database. Types with the same
name remain separate. Structs and unions are available even when no allocation site
was found. Allocation queries currently report sites where an allocated record type
can be inferred; absence of a site is not proof that a type is never allocated.

When CodeQL resolves multiple declarations to one type ID, the displayed location
is a deterministic representative. Alternative field facts at the same member
index are all preserved; they do not establish a single consistent layout across
different translation units.

Rebuild older database schemas with `objectdb create`, including BTF-backed
databases and the initial CodeQL schema without field alternatives. They are rejected
with an explicit rebuild message, without modifying the old file. Object IDs change
with this schema; do not reuse IDs from an old database. Rebuilding replaces the
SQLite file only after all queries and imports succeed, so retries do not append
duplicate allocation records. Query operations open SQLite read-only.

The old low-level `Btf*` models and BTF persistence methods have been removed.
Use `ObjectDb.load_type_graph()` with `TypeInfo` and `TypeMember` for type inspection.
Standalone scripts that imported the old BTF models need updating.

High-level scan API:

```python
from pathlib import Path
from object_db import load_object_set

objects = load_object_set(Path("/path/to/object_db.sqlite"))
targets = objects.filter(lambda obj: obj.has_pointer_to_type_name("file"))
for obj in targets:
    for field in obj.fields_at_offset(0x20):
        if field.is_pointer():
            print(obj.type_name, field.path, field.type_name)
```

`fields` and `field_at_offset()` inspect immediate members. `iter_fields()`,
`fields_at_offset()`, and pointer predicates also traverse embedded structs, unions,
and fixed arrays, without following pointers. Overlapping union alternatives are
all retained. Each field includes its path, byte offset, bit offset within that byte,
and bitfield size. Missing offsets and sizes remain `None`.

`ObjectSet.all_kmalloc_calls()` exposes all imported calls. Filtering an `ObjectSet`
restricts its calls to the selected objects and excludes unlinked calls. Cache names
are source facts, not inferred reclaim compatibility; `None` means the cache name
was not supplied or could not be resolved.

Standalone script template:

```bash
uv run objectdb scaffold-script /tmp/object_scan.py
uv run /tmp/object_scan.py --db /path/to/object_db.sqlite
```

Run unit tests from this directory with `uv run python -m unittest discover -s tests`.
Run the real C extraction integration test with
`OBJECTDB_RUN_CODEQL_TESTS=1 uv run python -m unittest discover -s tests -p test_codeql_integration.py`
(requires `codeql` and `gcc`).
